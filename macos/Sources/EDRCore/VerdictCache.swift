/// Verdicts keyed by (content hash, bundle version): a new bundle version
/// invalidates every entry implicitly. Bounded LRU.
public struct VerdictCache {
    public struct Key: Hashable, Sendable {
        public var sha256: [UInt8]
        public var bundleVersion: UInt64
        public init(sha256: [UInt8], bundleVersion: UInt64) {
            self.sha256 = sha256
            self.bundleVersion = bundleVersion
        }
    }

    public let capacity: Int
    private var entries: [Key: (outcome: Outcome, tick: UInt64)] = [:]
    private var tick: UInt64 = 0

    public init(capacity: Int = 50_000) {
        precondition(capacity > 0)
        self.capacity = capacity
    }

    public var count: Int { entries.count }

    public mutating func get(_ key: Key) -> Outcome? {
        guard let e = entries[key] else { return nil }
        tick += 1
        entries[key] = (e.outcome, tick)
        return e.outcome
    }

    public mutating func put(_ key: Key, _ outcome: Outcome) {
        tick += 1
        if entries[key] == nil, entries.count >= capacity {
            // O(n) eviction; capacity is fixed and puts are rare (cache misses
            // that went through a full inspection).
            if let oldest = entries.min(by: { $0.value.tick < $1.value.tick })?.key {
                entries[oldest] = nil
            }
        }
        entries[key] = (outcome, tick)
    }
}
