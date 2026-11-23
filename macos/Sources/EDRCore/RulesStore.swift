import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// On-disk rule bundles: `<root>/<version>/bundle` (read-only), an atomic
/// `<root>/current` symlink and `<root>/state.json`.
///
/// Activation order (sensor): verify bytes (EDR_MODE_ACTIVATION, version >
/// `highWater`) -> `install` -> self-test in a fresh inspector -> `activate`
/// -> health gate -> `markKnownGood` or `rollback`. `highWater` never goes
/// down, so a remote party cannot push an older bundle again; only the local
/// rollback may return to the last known-good version. At most two versions
/// (current and known-good) are kept.
public final class RulesStore {
    public struct State: Codable, Equatable, Sendable {
        public var highWater: UInt64 = 0
        public var current: UInt64?
        public var knownGood: UInt64?
        public init() {}
    }

    public enum StoreError: Error, Equatable {
        case notNewer(version: UInt64, highWater: UInt64)
        case notInstalled(UInt64)
        case noKnownGood
        case io(String)
    }

    public let root: URL
    public private(set) var state: State

    public init(root: URL) throws {
        self.root = root
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        let stateURL = root.appendingPathComponent("state.json")
        if let data = try? Data(contentsOf: stateURL) {
            state = try JSONDecoder().decode(State.self, from: data)
        } else {
            state = State()
        }
    }

    public func bundleURL(_ version: UInt64) -> URL {
        root.appendingPathComponent(String(version)).appendingPathComponent("bundle")
    }

    /// Bytes of the active bundle, if any (verify again with EDR_MODE_LOAD).
    public func currentBundle() throws -> (version: UInt64, bytes: Data)? {
        guard let v = state.current else { return nil }
        return (v, try Data(contentsOf: bundleURL(v)))
    }

    /// Write a verified bundle read-only. Requires version > highWater.
    public func install(version: UInt64, bytes: Data) throws {
        guard version > state.highWater else {
            throw StoreError.notNewer(version: version, highWater: state.highWater)
        }
        let dir = root.appendingPathComponent(String(version))
        let fm = FileManager.default
        if fm.fileExists(atPath: dir.path) { try fm.removeItem(at: dir) }
        try fm.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
        let tmp = dir.appendingPathComponent("bundle.tmp")
        try bytes.write(to: tmp)
        try fm.setAttributes([.posixPermissions: 0o444], ofItemAtPath: tmp.path)
        try Self.rename(tmp, bundleURL(version))
    }

    /// Point `current` at an installed version and raise the high-water mark.
    public func activate(version: UInt64) throws {
        guard version > state.highWater else {
            throw StoreError.notNewer(version: version, highWater: state.highWater)
        }
        try point(to: version)
        state.highWater = version
        try save()
        try prune()
    }

    /// The health gate passed for the current version.
    public func markKnownGood() throws {
        guard let v = state.current else { throw StoreError.noKnownGood }
        state.knownGood = v
        try save()
        try prune()
    }

    /// Return to the last known-good version (high-water stays).
    @discardableResult
    public func rollback() throws -> UInt64 {
        guard let good = state.knownGood else { throw StoreError.noKnownGood }
        try point(to: good)
        try save()
        try prune()
        return good
    }

    private func point(to version: UInt64) throws {
        guard FileManager.default.fileExists(atPath: bundleURL(version).path) else {
            throw StoreError.notInstalled(version)
        }
        let link = root.appendingPathComponent("current")
        let tmp = root.appendingPathComponent("current.tmp")
        try? FileManager.default.removeItem(at: tmp)
        try FileManager.default.createSymbolicLink(atPath: tmp.path, withDestinationPath: String(version))
        try Self.rename(tmp, link)
        state.current = version
    }

    private func save() throws {
        let enc = JSONEncoder()
        enc.outputFormatting = .sortedKeys
        let tmp = root.appendingPathComponent("state.json.tmp")
        try enc.encode(state).write(to: tmp)
        try Self.rename(tmp, root.appendingPathComponent("state.json"))
    }

    /// Remove version directories other than current and known-good.
    private func prune() throws {
        let keep = Set([state.current, state.knownGood].compactMap { $0 })
        let fm = FileManager.default
        for name in try fm.contentsOfDirectory(atPath: root.path) {
            guard let v = UInt64(name), !keep.contains(v) else { continue }
            let dir = root.appendingPathComponent(name)
            try? fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: dir.appendingPathComponent("bundle").path)
            try fm.removeItem(at: dir)
        }
    }

    /// rename(2): atomic replace, also for symlinks.
    private static func rename(_ from: URL, _ to: URL) throws {
        guard from.withUnsafeFileSystemRepresentation({ f in
            to.withUnsafeFileSystemRepresentation { t in
                #if canImport(Darwin)
                Darwin.rename(f!, t!) == 0
                #else
                Glibc.rename(f!, t!) == 0
                #endif
            }
        }) else { throw StoreError.io("rename \(from.lastPathComponent): errno \(errno)") }
    }
}
