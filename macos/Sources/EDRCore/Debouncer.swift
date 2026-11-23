/// File identity on one volume.
public struct FileKey: Hashable, Sendable {
    public var dev: UInt64
    public var ino: UInt64
    public init(dev: UInt64, ino: UInt64) { self.dev = dev; self.ino = ino }
}

/// Trailing-edge debounce per file: a key becomes due once no new event has
/// arrived for `quietMs`. Bounded; overflow is counted, never blocks.
public struct Debouncer<Payload> {
    public let quietMs: UInt64
    public let capacity: Int
    public private(set) var dropped: UInt64 = 0
    private var pending: [FileKey: (lastMs: UInt64, payload: Payload)] = [:]

    public init(quietMs: UInt64 = 500, capacity: Int = 10_000) {
        self.quietMs = quietMs
        self.capacity = capacity
    }

    public var count: Int { pending.count }

    /// Record an event; the newest payload (e.g. latest path) wins.
    public mutating func offer(_ key: FileKey, payload: Payload, nowMs: UInt64) {
        if pending[key] == nil, pending.count >= capacity {
            dropped += 1
            return
        }
        pending[key] = (nowMs, payload)
    }

    /// Remove and return keys that have been quiet long enough, oldest first.
    public mutating func takeDue(nowMs: UInt64) -> [(FileKey, Payload)] {
        let due = pending.filter { nowMs >= $0.value.lastMs &+ quietMs }
            .sorted { $0.value.lastMs < $1.value.lastMs }
        for (k, _) in due { pending[k] = nil }
        return due.map { ($0.key, $0.value.payload) }
    }

    /// Milliseconds until the next key is due, or nil when nothing is pending.
    public func nextDeadline(nowMs: UInt64) -> UInt64? {
        pending.values.map { $0.lastMs &+ quietMs }.min().map { $0 > nowMs ? $0 - nowMs : 0 }
    }
}
