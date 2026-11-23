import CEDRCore
import EDRCore
import Foundation

/// Error from the Rust core: an `EDR_ERR_*` code and its message.
public struct CoreError: Error, Equatable, CustomStringConvertible {
    public var code: Int32
    public var message: String
    public var description: String { "edr-core error \(code): \(message)" }
}

private func call(_ body: (UnsafeMutablePointer<CChar>, Int) -> Int32) throws {
    var buf = [CChar](repeating: 0, count: 512)
    let rc = buf.withUnsafeMutableBufferPointer { body($0.baseAddress!, $0.count) }
    guard rc == EDR_OK else {
        let msg = buf.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        throw CoreError(code: rc, message: msg)
    }
}

public enum Channel: UInt8, Sendable { case stable = 1, canary = 2 }
public enum Severity: UInt8, Sendable { case none = 0, low, medium, high, critical }
public enum Action: UInt8, Sendable { case allow = 0, log, alert, quarantine }

public struct BundleInfo: Equatable, Sendable {
    public var version: UInt64
    public var created: Int64
    public var expires: Int64
    public var channel: Channel?
    public var expired: Bool
    public var memoryLimitMB: UInt32
    public var selfTests: UInt32
}

public struct FormatPolicy: Equatable, Sendable {
    public var decode: Bool
    public var maxBytes: UInt64
    public var maxPixels: UInt64
    public var deadlineMs: UInt32

    public var jobLimits: JobLimits {
        JobLimits(maxBytes: maxBytes, maxPixels: maxPixels, deadlineMs: deadlineMs, decode: decode)
    }
}

/// Pinned root keys and signature threshold.
public struct TrustAnchors: Sendable {
    public var roots: [[UInt8]]
    public var threshold: Int

    public init(roots: [[UInt8]], threshold: Int) {
        self.roots = roots
        self.threshold = threshold
    }

    /// Hex keys, one per line, `#` comments (same format as `edr-rulec --roots`).
    public init(text: String, threshold: Int) throws {
        var roots: [[UInt8]] = []
        for line in text.split(whereSeparator: \.isNewline) {
            let hex = line.split(separator: "#", omittingEmptySubsequences: false)[0]
                .trimmingCharacters(in: .whitespaces)
            if hex.isEmpty { continue }
            guard hex.utf8.count == 64 else { throw CoreError(code: EDR_ERR_ARGUMENT, message: "bad root key") }
            var key: [UInt8] = []
            var it = hex.utf8.makeIterator()
            while let h = it.next(), let l = it.next() {
                guard let b = UInt8(String(decoding: [h, l], as: UTF8.self), radix: 16) else {
                    throw CoreError(code: EDR_ERR_ARGUMENT, message: "bad root key")
                }
                key.append(b)
            }
            roots.append(key)
        }
        self.init(roots: roots, threshold: threshold)
    }
}

/// A verified rule bundle. Construction verifies signatures before anything
/// in the manifest is parsed (done in Rust).
public final class RuleBundle: @unchecked Sendable {
    public enum Mode: Sendable {
        /// New bundle from netd: certificate window, expiry, version > current.
        case activation(currentVersion: UInt64?)
        /// Reload of an already activated bundle (expired keeps scanning).
        case load
    }

    let handle: OpaquePointer
    public let info: BundleInfo

    public init(bytes: [UInt8], anchors: TrustAnchors, now: Int64, mode: Mode) throws {
        guard anchors.roots.allSatisfy({ $0.count == 32 }) else {
            throw CoreError(code: EDR_ERR_ARGUMENT, message: "root keys must be 32 bytes")
        }
        let flat = anchors.roots.flatMap { $0 }
        var out: OpaquePointer?
        let (modeRaw, current): (UInt32, UInt64?) = switch mode {
        case .activation(let v): (UInt32(EDR_MODE_ACTIVATION), v)
        case .load: (UInt32(EDR_MODE_LOAD), nil)
        }
        try call { err, cap in
            bytes.withUnsafeBufferPointer { b in
                flat.withUnsafeBufferPointer { r in
                    withOptionalPointer(current) { cur in
                        edr_bundle_open(b.baseAddress, b.count, r.baseAddress, anchors.roots.count,
                                        anchors.threshold, now, modeRaw, cur, &out, err, cap)
                    }
                }
            }
        }
        handle = out!
        var i = EdrBundleInfo()
        guard edr_bundle_info(handle, &i) == EDR_OK else {
            edr_bundle_free(handle)
            throw CoreError(code: EDR_ERR_BUNDLE, message: "bundle info")
        }
        info = BundleInfo(version: i.version, created: i.created, expires: i.expires, channel: Channel(rawValue: i.channel),
                          expired: i.expired, memoryLimitMB: i.memory_limit_mb, selfTests: i.self_tests)
    }

    deinit { edr_bundle_free(handle) }

    /// Policy format name for a file extension, or "other".
    public func format(forExtension ext: String) -> String {
        var name = [CChar](repeating: 0, count: 64)
        let rc = name.withUnsafeMutableBufferPointer { edr_bundle_format_for_extension(handle, ext.lowercased(), $0.baseAddress, $0.count) }
        return rc == EDR_OK ? String(cString: name) : "other"
    }

    public func policy(format: String?) -> FormatPolicy {
        var p = EdrFormatPolicy()
        let rc = format.map { edr_bundle_format_policy(handle, $0, &p) } ?? edr_bundle_format_policy(handle, nil, &p)
        precondition(rc == EDR_OK, "format policy for a verified bundle")
        return FormatPolicy(decode: p.decode, maxBytes: p.max_bytes, maxPixels: p.max_pixels, deadlineMs: p.deadline_ms)
    }

    public func action(for outcome: Outcome) -> (severity: Severity, action: Action) {
        var a = EdrAction()
        precondition(edr_bundle_action(handle, outcome.rawValue, &a) == EDR_OK, "action for a valid outcome")
        // Unknown codes from a newer core fail closed to the strictest value.
        return (Severity(rawValue: a.severity) ?? .critical, Action(rawValue: a.action) ?? .quarantine)
    }
}

private func withOptionalPointer<T, R>(_ v: T?, _ body: (UnsafePointer<T>?) -> R) -> R {
    guard var v else { return body(nil) }
    return withUnsafePointer(to: &v) { body($0) }
}

public struct ScanReport: Equatable, Sendable {
    public var outcome: Outcome
    public var offset: UInt64
    public var fuelUsed: UInt64
    public var format: String?
    public var detail: String
    public var hits: [String]

    /// Bounded reply for the sensor (inspector side).
    public func stage1(jobID: UInt64) -> Stage1Reply {
        let p = InspectorProtocol.self
        return Stage1Reply(jobID: jobID, outcome: outcome,
                           hits: hits.prefix(p.maxHits).map { truncate($0, p.maxHitBytes) },
                           detail: truncate(detail, p.maxDetailBytes), offset: offset, fuel: fuelUsed,
                           format: format.map { truncate($0, 32) })
    }
}

/// Truncate to at most `n` UTF-8 bytes on a character boundary.
func truncate(_ s: String, _ n: Int) -> String {
    if s.utf8.count <= n { return s }
    var out = ""
    for c in s where out.utf8.count + c.utf8.count <= n { out.append(c) }
    return out
}

/// Compiled YARA-X rules and schema programs. Compile inside the sandboxed
/// inspector only (YARA compilation is untrusted-adjacent work).
public final class ScanEngine: @unchecked Sendable {
    let handle: OpaquePointer

    public init(bundle: RuleBundle) throws {
        var out: OpaquePointer?
        try call { err, cap in edr_engine_new(bundle.handle, &out, err, cap) }
        handle = out!
    }

    deinit { edr_engine_free(handle) }

    public static var coreVersion: UInt32 { edr_engine_version() }

    /// Runs the bundle's self-test vectors; returns how many passed.
    @discardableResult
    public func selfTest(bundle: RuleBundle) throws -> UInt32 {
        var passed: UInt32 = 0
        try call { err, cap in edr_engine_self_test(handle, bundle.handle, &passed, err, cap) }
        return passed
    }

    /// Stage 1 scan. A NULL report (internal panic) is CRASH.
    public func scan(_ data: UnsafeRawBufferPointer, hint: String?) -> ScanReport {
        let base = data.baseAddress?.assumingMemoryBound(to: UInt8.self)
        // Empty input still needs a valid pointer.
        var empty: UInt8 = 0
        let r: OpaquePointer? = withUnsafeMutablePointer(to: &empty) { e in
            let p = base ?? UnsafePointer(e)
            return hint.map { edr_engine_scan(handle, p, data.count, $0) } ?? edr_engine_scan(handle, p, data.count, nil)
        }
        guard let r else {
            return ScanReport(outcome: .crash, offset: 0, fuelUsed: 0, format: nil, detail: "core returned no report", hits: [])
        }
        defer { edr_report_free(r) }
        let hits = (0..<edr_report_hit_count(r)).compactMap { edr_report_hit(r, $0).map { String(cString: $0) } }
        return ScanReport(
            outcome: Outcome(rawValue: edr_report_outcome(r)) ?? .crash,
            offset: edr_report_offset(r), fuelUsed: edr_report_fuel_used(r),
            format: edr_report_format(r).map { String(cString: $0) },
            detail: edr_report_detail(r).map { String(cString: $0) } ?? "", hits: hits)
    }

    public func scan(_ data: [UInt8], hint: String?) -> ScanReport {
        data.withUnsafeBytes { scan($0, hint: hint) }
    }
}
