/// Transport-neutral view of an IPC message. The macOS XPC adapter converts
/// `xpc_object_t` into this (bounded) and back, so validation is testable
/// without XPC. File descriptors are carried out of band by the adapter.
public indirect enum Value: Equatable, Sendable {
    case bool(Bool)
    case int(Int64)
    case uint(UInt64)
    case string(String)
    case data([UInt8])
    case array([Value])
    case dict([String: Value])
    /// Placeholder for an xpc fd object; the adapter keeps the descriptor.
    case fd

    public var uint: UInt64? {
        switch self {
        case .uint(let v): return v
        case .int(let v) where v >= 0: return UInt64(v)
        default: return nil
        }
    }

    public var string: String? { if case .string(let s) = self { return s } else { return nil } }
    public var data: [UInt8]? { if case .data(let d) = self { return d } else { return nil } }
    public var array: [Value]? { if case .array(let a) = self { return a } else { return nil } }
    public var dict: [String: Value]? { if case .dict(let d) = self { return d } else { return nil } }
}

/// Limits applied by the adapter while converting untrusted XPC objects.
public enum MessageLimits {
    public static let maxDepth = 4
    public static let maxKeys = 32
    public static let maxArray = 64
    public static let maxString = 1024
    public static let maxData = 64
}

public struct ProtocolError: Error, Equatable, CustomStringConvertible {
    public var description: String
    public init(_ d: String) { description = d }
}

/// Strict field access: the dictionary must contain exactly `allowed` keys
/// (`required` must be present).
public struct Fields {
    let d: [String: Value]

    public init(_ v: Value, required: Set<String>, optional: Set<String> = []) throws {
        guard let d = v.dict else { throw ProtocolError("not a dictionary") }
        let keys = Set(d.keys)
        guard required.isSubset(of: keys) else {
            throw ProtocolError("missing \(required.subtracting(keys).sorted())")
        }
        guard keys.isSubset(of: required.union(optional)) else {
            throw ProtocolError("unexpected \(keys.subtracting(required.union(optional)).sorted())")
        }
        self.d = d
    }

    public func has(_ k: String) -> Bool { d[k] != nil }

    public func uint(_ k: String, max: UInt64 = .max) throws -> UInt64 {
        guard let v = d[k]?.uint, v <= max else { throw ProtocolError("\(k): bad unsigned") }
        return v
    }

    public func string(_ k: String, maxBytes: Int = MessageLimits.maxString) throws -> String {
        guard let s = d[k]?.string, s.utf8.count <= maxBytes else { throw ProtocolError("\(k): bad string") }
        return s
    }

    public func optionalString(_ k: String, maxBytes: Int = MessageLimits.maxString) throws -> String? {
        d[k] == nil ? nil : try string(k, maxBytes: maxBytes)
    }

    public func data(_ k: String, count: Int) throws -> [UInt8] {
        guard let b = d[k]?.data, b.count == count else { throw ProtocolError("\(k): bad data") }
        return b
    }

    public func strings(_ k: String, maxCount: Int, maxBytes: Int) throws -> [String] {
        guard let a = d[k]?.array, a.count <= maxCount else { throw ProtocolError("\(k): bad array") }
        return try a.map {
            guard let s = $0.string, s.utf8.count <= maxBytes else { throw ProtocolError("\(k): bad element") }
            return s
        }
    }

    public func isFD(_ k: String) throws {
        guard d[k] == .fd else { throw ProtocolError("\(k): not a file descriptor") }
    }
}
