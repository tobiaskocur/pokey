/// Inspection outcome. Raw values equal the `POKEY_OUTCOME_*` codes in
/// core/pokey-ffi/include/pokey_core.h (checked by PokeyRulesTests).
public enum Outcome: UInt32, CaseIterable, Sendable, Codable {
    case clean = 0
    case staticMatch = 1
    case schemaViolation = 2
    case decodeError = 3
    case timeout = 4
    case resourceExceeded = 5
    case crash = 6
    case protocolViolation = 7

    public var name: String {
        switch self {
        case .clean: return "CLEAN"
        case .staticMatch: return "STATIC_MATCH"
        case .schemaViolation: return "SCHEMA_VIOLATION"
        case .decodeError: return "DECODE_ERROR"
        case .timeout: return "TIMEOUT"
        case .resourceExceeded: return "RESOURCE_EXCEEDED"
        case .crash: return "CRASH"
        case .protocolViolation: return "PROTOCOL_VIOLATION"
        }
    }

    /// Precedence when stages disagree; same order as the Rust engine.
    public var rank: Int {
        switch self {
        case .clean: return 0
        case .resourceExceeded, .timeout: return 1
        case .decodeError: return 2
        case .schemaViolation: return 3
        case .staticMatch: return 4
        case .crash, .protocolViolation: return 5
        }
    }

    /// The more severe of two outcomes (first wins ties).
    public func combined(with other: Outcome) -> Outcome {
        other.rank > rank ? other : self
    }
}
