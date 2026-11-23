import Foundation
import Security
import SystemConfiguration
import XPC

/// Identifies the sender of an XPC message by its code signature, using the
/// audit token carried by the message itself (no PID reuse race).
public enum PeerIdentity {
    /// Returns the first role whose requirement the sender satisfies.
    public static func role(of message: xpc_object_t, config: EDRConfig,
                            among roles: [EDRConfig.Role]) -> EDRConfig.Role? {
        var code: SecCode?
        guard SecCodeCreateWithXPCMessage(message, SecCSFlags(), &code) == errSecSuccess, let code else { return nil }
        for role in roles {
            var req: SecRequirement?
            guard SecRequirementCreateWithString(config.requirement(role) as CFString, SecCSFlags(), &req) == errSecSuccess,
                  let req
            else { continue }
            if SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), req) == errSecSuccess {
                return role
            }
        }
        return nil
    }

    /// Enforce the requirement on every later message of the connection.
    public static func pin(_ connection: xpc_connection_t, to role: EDRConfig.Role, config: EDRConfig) -> Bool {
        xpc_connection_set_peer_code_signing_requirement(connection, config.requirement(role)) == 0
    }

    /// UID of the user at the console (nil at the login window).
    public static func consoleUID() -> uid_t? {
        var uid: uid_t = 0
        guard let user = SCDynamicStoreCopyConsoleUser(nil, &uid, nil) as String?, user != "loginwindow" else {
            return nil
        }
        return uid
    }
}

