import EDRCore
import EDRPlatform
import Foundation
import XPC

/// The sensor's single Mach service (NSEndpointSecurityMachServiceName).
/// Every peer connection is pinned to "one of our signed clients" before it is
/// activated, so XPC drops messages from any other signer. The exact role
/// (inspector, netd, ui) is fixed by the first message's signature and never
/// changes for the connection; each role has its own protocol.
final class XPCServer {
    typealias Handler = (EDRConfig.Role, xpc_connection_t, xpc_object_t) -> Void

    static let clientRoles: [EDRConfig.Role] = [.inspector, .netd, .ui]

    private let config: EDRConfig
    private let queue: DispatchQueue
    private let log = logger("xpc")
    private var listener: xpc_connection_t?
    /// First message from a new connection; return false to drop the peer.
    var attach: (EDRConfig.Role, xpc_connection_t) -> Bool = { _, _ in false }
    var handle: Handler = { _, _, _ in }
    var disconnected: (EDRConfig.Role, xpc_connection_t) -> Void = { _, _ in }

    init(config: EDRConfig, queue: DispatchQueue) {
        self.config = config
        self.queue = queue
    }

    func start() {
        let l = xpc_connection_create_mach_service(config.sensorMachService, queue,
                                                   UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER))
        xpc_connection_set_event_handler(l) { [weak self] peer in
            guard let self, xpc_get_type(peer) == XPC_TYPE_CONNECTION else { return }
            self.accept(peer)
        }
        xpc_connection_activate(l)
        listener = l
        log.info("listening on \(self.config.sensorMachService, privacy: .public)")
    }

    private func accept(_ peer: xpc_connection_t) {
        guard PeerIdentity.pin(peer, to: Self.clientRoles, config: config) else {
            log.error("cannot set peer requirement; dropping connection")
            xpc_connection_cancel(peer)
            return
        }
        var role: EDRConfig.Role?
        xpc_connection_set_target_queue(peer, queue)
        xpc_connection_set_event_handler(peer) { [weak self] msg in
            guard let self else { return }
            if xpc_get_type(msg) == XPC_TYPE_ERROR {
                if let role { self.disconnected(role, peer) }
                return
            }
            guard xpc_get_type(msg) == XPC_TYPE_DICTIONARY else {
                xpc_connection_cancel(peer)
                return
            }
            if role == nil {
                guard let r = PeerIdentity.role(of: msg, config: self.config, among: Self.clientRoles),
                      self.attach(r, peer)
                else {
                    self.log.error("rejected peer pid \(xpc_connection_get_pid(peer))")
                    xpc_connection_cancel(peer)
                    return
                }
                role = r
            }
            self.handle(role!, peer, msg)
        }
        xpc_connection_activate(peer)
    }
}
