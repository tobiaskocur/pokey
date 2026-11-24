import PokeyCore
import Foundation
import XPC

/// Client side of the sensor's Mach service for pokey-netd and pokey-ui. The
/// connection is pinned to the sensor's code signature, and every reply is
/// decoded through the bounded `XPCValue.decode` before use.
public final class SensorClient: @unchecked Sendable { // state confined to `queue`
    private let config: PokeyConfig
    private let queue = DispatchQueue(label: "pokey.sensor-client")
    private var conn: xpc_connection_t?
    private let log = logger("sensor-client")

    public init(config: PokeyConfig) {
        self.config = config
    }

    /// Sends `message` and waits for the reply. Call from any queue except
    /// the client's own. A broken connection is recreated on the next call.
    public func request(_ message: Value, maxReplyData: Int = MessageLimits.maxData) throws -> Value {
        let c = try connection()
        let reply = xpc_connection_send_message_with_reply_sync(c, XPCValue.encode(message))
        guard xpc_get_type(reply) == XPC_TYPE_DICTIONARY else {
            if reply === XPC_ERROR_CONNECTION_INVALID {
                queue.sync { if conn === c { conn = nil } }
            }
            throw ProtocolError("sensor unavailable")
        }
        return try XPCValue.decode(reply, maxData: maxReplyData)
    }

    private func connection() throws -> xpc_connection_t {
        try queue.sync {
            if let conn { return conn }
            // The sensor is a system extension: its service lives in the
            // privileged (system) bootstrap namespace.
            let c = xpc_connection_create_mach_service(config.sensorMachService, queue,
                                                       UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
            guard xpc_connection_set_peer_code_signing_requirement(c, config.requirement(.sensor)) == 0 else {
                throw ConfigError("cannot pin the sensor's code signature")
            }
            xpc_connection_set_event_handler(c) { [weak self] event in
                guard let self, xpc_get_type(event) == XPC_TYPE_ERROR else { return }
                if event === XPC_ERROR_CONNECTION_INVALID, self.conn === c {
                    self.log.notice("sensor connection invalidated")
                    self.conn = nil
                }
            }
            xpc_connection_activate(c)
            conn = c
            return c
        }
    }
}
