/// Local health gate after a new bundle is activated: the first inspections
/// under the new version decide whether it becomes known-good or is rolled
/// back. Only inspector failures (CRASH, PROTOCOL_VIOLATION) count against it;
/// detections are not failures.
public struct HealthGate: Sendable {
    public enum Decision: Equatable, Sendable { case healthy, rollback }

    public let version: UInt64
    public let requiredSuccesses: Int
    public let maxFailures: Int
    public private(set) var successes = 0
    public private(set) var failures = 0
    public private(set) var decision: Decision?

    public init(version: UInt64, requiredSuccesses: Int = 20, maxFailures: Int = 3) {
        self.version = version
        self.requiredSuccesses = requiredSuccesses
        self.maxFailures = maxFailures
    }

    /// Record an inspection done with `bundleVersion`; returns a decision once.
    public mutating func record(_ outcome: Outcome, bundleVersion: UInt64) -> Decision? {
        guard decision == nil, bundleVersion == version else { return nil }
        if outcome == .crash || outcome == .protocolViolation {
            failures += 1
        } else {
            successes += 1
        }
        if failures >= maxFailures {
            decision = .rollback
        } else if successes >= requiredSuccesses {
            decision = .healthy
        }
        return decision
    }
}
