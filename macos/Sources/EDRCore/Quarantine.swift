import Foundation

/// Parsed `com.apple.quarantine` extended attribute:
/// `flags;hex-time;agent;UUID` (agent and UUID may be empty or absent).
public struct QuarantineInfo: Equatable, Sendable {
    public var flags: UInt32
    public var timestamp: Date
    public var agent: String
    public var eventID: UUID?

    public static let maxLength = 1024

    /// Returns nil for anything that is not a well-formed quarantine value.
    /// The value comes from the file system, so it is bounded and strict.
    public init?(xattr raw: [UInt8]) {
        guard !raw.isEmpty, raw.count <= Self.maxLength else { return nil }
        var bytes = raw
        if bytes.last == 0 { bytes.removeLast() }
        guard let text = String(bytes: bytes, encoding: .utf8) else { return nil }
        let parts = text.split(separator: ";", maxSplits: 3, omittingEmptySubsequences: false)
        guard parts.count >= 2,
              parts[0].count == 4, let flags = UInt32(parts[0], radix: 16),
              (1...16).contains(parts[1].count), let t = UInt64(parts[1], radix: 16), t <= UInt64(Int32.max)
        else { return nil }
        self.flags = flags
        self.timestamp = Date(timeIntervalSince1970: TimeInterval(t))
        self.agent = parts.count > 2 ? String(parts[2]).filter { !$0.isNewline } : ""
        if parts.count > 3, !parts[3].isEmpty {
            guard let id = UUID(uuidString: String(parts[3])) else { return nil }
            self.eventID = id
        } else {
            self.eventID = nil
        }
    }
}
