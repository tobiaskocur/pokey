/// Messages edr-netd may send to the sensor. Bundle bytes are passed through
/// unparsed; the sensor verifies them (signature before manifest).
public enum NetdMessage: Equatable, Sendable {
    case bundle([UInt8])
    case telemetryPull(max: Int)
    case telemetryAck(upTo: Int64)

    public static let maxBundleBytes = 32 << 20
    public static let maxPull = 500

    public static func parse(_ v: Value) throws -> NetdMessage {
        guard let type = v.dict?["type"]?.string else { throw ProtocolError("missing type") }
        switch type {
        case "bundle":
            let f = try Fields(v, required: ["type", "data"])
            return .bundle(try f.bytes("data", maxCount: maxBundleBytes))
        case "telemetry_pull":
            let f = try Fields(v, required: ["type", "max"])
            let n = try f.uint("max", max: UInt64(maxPull))
            guard n > 0 else { throw ProtocolError("max: must be positive") }
            return .telemetryPull(max: Int(n))
        case "telemetry_ack":
            let f = try Fields(v, required: ["type", "up_to"])
            return .telemetryAck(upTo: Int64(try f.uint("up_to", max: UInt64(Int64.max))))
        default:
            throw ProtocolError("unknown type")
        }
    }

    public var value: Value {
        switch self {
        case .bundle(let b): return .dict(["type": .string("bundle"), "data": .data(b)])
        case .telemetryPull(let n): return .dict(["type": .string("telemetry_pull"), "max": .uint(UInt64(n))])
        case .telemetryAck(let id): return .dict(["type": .string("telemetry_ack"), "up_to": .uint(UInt64(id))])
        }
    }
}

/// One telemetry record: hashes and metadata only (no path, no content).
/// `whereFroms` (base64 of the raw `kMDItemWhereFroms` xattr, never parsed by
/// the sensor) is included only when the local policy option is on.
public struct TelemetryRecord: Codable, Equatable, Sendable {
    public var time: Int64
    public var sha256: String
    public var size: UInt64
    public var format: String
    public var outcome: String
    public var severity: UInt8
    public var bundleVersion: UInt64
    public var quarantineAgent: String
    public var whereFroms: String?
    public var hits: [String]

    public init(time: Int64, sha256: String, size: UInt64, format: String, outcome: Outcome, severity: UInt8,
                bundleVersion: UInt64, quarantineAgent: String, whereFroms: String?, hits: [String]) {
        self.time = time; self.sha256 = sha256; self.size = size; self.format = format; self.outcome = outcome.name
        self.severity = severity; self.bundleVersion = bundleVersion; self.quarantineAgent = quarantineAgent
        self.whereFroms = whereFroms; self.hits = hits
    }
}
