/// Commands pokey-ui may send to the sensor. Anything else is rejected.
public enum UICommand: Equatable, Sendable {
    case status
    case listAlerts(limit: Int)
    case ackAlert(id: UInt64)

    /// Fits one reply array (MessageLimits.maxArray).
    public static let maxAlerts = 50

    public static func parse(_ v: Value) throws -> UICommand {
        guard let cmd = v.dict?["cmd"]?.string else { throw ProtocolError("missing cmd") }
        switch cmd {
        case "status":
            _ = try Fields(v, required: ["cmd"])
            return .status
        case "list_alerts":
            let f = try Fields(v, required: ["cmd", "limit"])
            let limit = try f.uint("limit", max: UInt64(maxAlerts))
            guard limit > 0 else { throw ProtocolError("limit: must be positive") }
            return .listAlerts(limit: Int(limit))
        case "ack_alert":
            let f = try Fields(v, required: ["cmd", "id"])
            return .ackAlert(id: try f.uint("id"))
        default:
            throw ProtocolError("command not allowed")
        }
    }

    public var value: Value {
        switch self {
        case .status: return .dict(["cmd": .string("status")])
        case .listAlerts(let n): return .dict(["cmd": .string("list_alerts"), "limit": .uint(UInt64(n))])
        case .ackAlert(let id): return .dict(["cmd": .string("ack_alert"), "id": .uint(id)])
        }
    }
}
