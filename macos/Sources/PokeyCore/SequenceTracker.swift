/// Counts Endpoint Security messages lost between client and kernel using
/// `global_seq_num` (one counter across all event types delivered to a client).
public struct SequenceTracker: Sendable {
    public private(set) var lastGlobal: UInt64?
    public private(set) var lost: UInt64 = 0

    public init() {}

    /// Returns the number of messages missing before this one.
    @discardableResult
    public mutating func observe(global: UInt64) -> UInt64 {
        defer { lastGlobal = max(lastGlobal ?? global, global) }
        guard let last = lastGlobal, global > last &+ 1 else { return 0 }
        let gap = global - last - 1
        lost &+= gap
        return gap
    }
}
