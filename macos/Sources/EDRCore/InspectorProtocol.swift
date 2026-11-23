/// Sensor <-> inspector protocol. One inspector process handles one job:
///
///     inspector -> sensor  hello   {type, nonce}
///     sensor -> inspector  init    {type, rules_fd, roots, threshold, now}
///     inspector -> sensor  ready   {type}            (after pre-warm + sandbox)
///     sensor -> inspector  job     {type, job_id, file_fd, size, format_hint?, limits}
///     inspector -> sensor  stage1  {type, job_id, outcome, hits, detail, offset, fuel, format?}
///     inspector -> sensor  stage2  {type, job_id, outcome, width, height, frames, detail}  (if decode)
///
/// The rules fd arrives at `init` so YARA compiles during pre-warm, before the
/// job is known. Every inspector message is validated strictly; anything else
/// is PROTOCOL_VIOLATION.
public enum InspectorProtocol {
    public static let nonceLength = 32
    public static let maxHits = 64
    public static let maxHitBytes = 128
    public static let maxDetailBytes = 512
}

public struct JobLimits: Equatable, Sendable {
    public var maxBytes: UInt64
    public var maxPixels: UInt64
    public var deadlineMs: UInt32
    public var decode: Bool

    public init(maxBytes: UInt64, maxPixels: UInt64, deadlineMs: UInt32, decode: Bool) {
        self.maxBytes = maxBytes
        self.maxPixels = maxPixels
        self.deadlineMs = deadlineMs
        self.decode = decode
    }

    public var value: Value {
        .dict([
            "max_bytes": .uint(maxBytes), "max_pixels": .uint(maxPixels),
            "deadline_ms": .uint(UInt64(deadlineMs)), "decode": .bool(decode),
        ])
    }

    public init(_ v: Value) throws {
        let f = try Fields(v, required: ["max_bytes", "max_pixels", "deadline_ms", "decode"])
        maxBytes = try f.uint("max_bytes")
        maxPixels = try f.uint("max_pixels")
        deadlineMs = UInt32(try f.uint("deadline_ms", max: 60_000))
        guard case .bool(let d)? = f.d["decode"] else { throw ProtocolError("decode: bad bool") }
        decode = d
    }
}

public struct Stage1Reply: Equatable, Sendable {
    public var jobID: UInt64
    public var outcome: Outcome
    public var hits: [String]
    public var detail: String
    public var offset: UInt64
    public var fuel: UInt64
    public var format: String?

    public init(jobID: UInt64, outcome: Outcome, hits: [String], detail: String, offset: UInt64, fuel: UInt64,
                format: String?) {
        self.jobID = jobID; self.outcome = outcome; self.hits = hits; self.detail = detail
        self.offset = offset; self.fuel = fuel; self.format = format
    }

    public var value: Value {
        var d: [String: Value] = [
            "type": .string("stage1"), "job_id": .uint(jobID), "outcome": .uint(UInt64(outcome.rawValue)),
            "hits": .array(hits.map { .string($0) }), "detail": .string(detail), "offset": .uint(offset),
            "fuel": .uint(fuel),
        ]
        if let format { d["format"] = .string(format) }
        return .dict(d)
    }
}

public struct Stage2Reply: Equatable, Sendable {
    public var jobID: UInt64
    public var outcome: Outcome
    public var width: UInt64
    public var height: UInt64
    public var frames: UInt64
    public var detail: String

    public init(jobID: UInt64, outcome: Outcome, width: UInt64, height: UInt64, frames: UInt64, detail: String) {
        self.jobID = jobID; self.outcome = outcome; self.width = width; self.height = height
        self.frames = frames; self.detail = detail
    }

    public var value: Value {
        .dict([
            "type": .string("stage2"), "job_id": .uint(jobID), "outcome": .uint(UInt64(outcome.rawValue)),
            "width": .uint(width), "height": .uint(height), "frames": .uint(frames), "detail": .string(detail),
        ])
    }
}

public enum InspectorMessage: Equatable, Sendable {
    case hello(nonce: [UInt8])
    case ready
    case stage1(Stage1Reply)
    case stage2(Stage2Reply)

    /// Outcomes an inspector may report itself. TIMEOUT, CRASH and
    /// PROTOCOL_VIOLATION are decided by the sensor only.
    static let reportable: Set<Outcome> = [.clean, .staticMatch, .schemaViolation, .decodeError, .resourceExceeded]

    public static func parse(_ v: Value) throws -> InspectorMessage {
        guard let type = v.dict?["type"]?.string else { throw ProtocolError("missing type") }
        func outcome(_ f: Fields) throws -> Outcome {
            guard let o = Outcome(rawValue: UInt32(try f.uint("outcome", max: UInt64(UInt32.max)))),
                  reportable.contains(o)
            else { throw ProtocolError("outcome not reportable") }
            return o
        }
        let p = InspectorProtocol.self
        switch type {
        case "hello":
            let f = try Fields(v, required: ["type", "nonce"])
            return .hello(nonce: try f.data("nonce", count: p.nonceLength))
        case "ready":
            _ = try Fields(v, required: ["type"])
            return .ready
        case "stage1":
            let f = try Fields(v, required: ["type", "job_id", "outcome", "hits", "detail", "offset", "fuel"],
                               optional: ["format"])
            return .stage1(Stage1Reply(
                jobID: try f.uint("job_id"), outcome: try outcome(f),
                hits: try f.strings("hits", maxCount: p.maxHits, maxBytes: p.maxHitBytes),
                detail: try f.string("detail", maxBytes: p.maxDetailBytes), offset: try f.uint("offset"),
                fuel: try f.uint("fuel"), format: try f.optionalString("format", maxBytes: 32)))
        case "stage2":
            let f = try Fields(v, required: ["type", "job_id", "outcome", "width", "height", "frames", "detail"])
            return .stage2(Stage2Reply(
                jobID: try f.uint("job_id"), outcome: try outcome(f), width: try f.uint("width"),
                height: try f.uint("height"), frames: try f.uint("frames"),
                detail: try f.string("detail", maxBytes: p.maxDetailBytes)))
        default:
            throw ProtocolError("unknown type")
        }
    }
}

/// Sensor-side state machine for one inspector session. Feed every message;
/// any error ends the session as PROTOCOL_VIOLATION.
public struct InspectorSession {
    public enum State: Equatable { case awaitingHello, awaitingReady, ready, awaitingStage1, awaitingStage2, done }

    public let nonce: [UInt8]
    public private(set) var state: State = .awaitingHello
    public private(set) var jobID: UInt64?
    public private(set) var decode = false
    public private(set) var stage1: Stage1Reply?
    public private(set) var stage2: Stage2Reply?

    public init(nonce: [UInt8]) {
        precondition(nonce.count == InspectorProtocol.nonceLength)
        self.nonce = nonce
    }

    /// Constant-time comparison of the presented nonce.
    static func equal(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        return zip(a, b).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }

    public mutating func receive(_ msg: InspectorMessage) throws {
        switch (state, msg) {
        case (.awaitingHello, .hello(let n)):
            guard Self.equal(n, nonce) else { throw ProtocolError("nonce mismatch") }
            state = .awaitingReady
        case (.awaitingReady, .ready):
            state = .ready
        case (.awaitingStage1, .stage1(let r)) where r.jobID == jobID:
            stage1 = r
            state = decode && r.outcome == .clean ? .awaitingStage2 : .done
        case (.awaitingStage2, .stage2(let r)) where r.jobID == jobID:
            stage2 = r
            state = .done
        default:
            throw ProtocolError("unexpected message in state \(state)")
        }
    }

    /// Record that the job was sent.
    public mutating func sentJob(id: UInt64, decode: Bool) throws {
        guard state == .ready else { throw ProtocolError("job sent before ready") }
        jobID = id
        self.decode = decode
        state = .awaitingStage1
    }
}
