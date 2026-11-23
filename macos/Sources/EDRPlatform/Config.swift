import Foundation
import os

/// Deployment identity, read at runtime from the Info.plist keys that the
/// Xcode build fills in from EDR_TEAM_ID and EDR_BUNDLE_PREFIX (see
/// macos/Config/Identity.xcconfig). Nothing identity-related is hard-coded.
public struct EDRConfig: Sendable {
    public let teamID: String
    public let prefix: String

    public init(info: [String: Any]) throws {
        guard let team = info["EDRTeamID"] as? String, team.count == 10, team.allSatisfy(\.isASCII),
              let prefix = info["EDRBundlePrefix"] as? String, !prefix.isEmpty, !prefix.hasPrefix("$(")
        else { throw ConfigError("EDRTeamID/EDRBundlePrefix missing from Info.plist") }
        teamID = team
        self.prefix = prefix
    }

    public static func main() throws -> EDRConfig { try EDRConfig(info: Bundle.main.infoDictionary ?? [:]) }

    public func identifier(_ role: Role) -> String { "\(prefix).\(role.rawValue)" }

    /// The sensor's Mach service (NSEndpointSecurityMachServiceName must be
    /// prefixed with the Team ID).
    public var sensorMachService: String { "\(teamID).\(prefix).sensor.xpc" }

    /// Code-signing requirement for one of our binaries.
    public func requirement(_ role: Role) -> String { requirement(anyOf: [role]) }

    /// Requirement satisfied by any of `roles` (Developer ID or Apple-issued
    /// certificate of our team, exact identifier).
    public func requirement(anyOf roles: [Role]) -> String {
        precondition(!roles.isEmpty)
        let ids = roles.map { "identifier \"\(identifier($0))\"" }.joined(separator: " or ")
        return "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\" and (\(ids))"
    }

    /// Root-owned state of the sensor.
    public var stateDirectory: URL {
        URL(fileURLWithPath: "/Library/Application Support").appendingPathComponent(prefix, isDirectory: true)
    }

    public enum Role: String, CaseIterable, Sendable {
        case host, sensor, inspector, netd, ui
    }
}

public struct ConfigError: Error, CustomStringConvertible {
    public var description: String
    public init(_ d: String) { description = d }
}

public func logger(_ category: String) -> Logger {
    Logger(subsystem: Bundle.main.bundleIdentifier ?? "edr", category: category)
}

/// Info.plist values filled from build settings arrive as strings
/// (`$(EDR_ROOT_THRESHOLD)`); accept both native and string forms.
public func plistInt(_ info: [String: Any], _ key: String) -> Int? {
    if let n = info[key] as? Int { return n }
    return (info[key] as? String).flatMap { Int($0) }
}

public func plistBool(_ info: [String: Any], _ key: String) -> Bool {
    if let b = info[key] as? Bool { return b }
    return ["YES", "yes", "true", "1"].contains(info[key] as? String ?? "")
}
