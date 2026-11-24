import PokeyCore
import Foundation
import XPC

/// Bounded conversion between XPC objects and `Value`. Every untrusted XPC
/// message goes through `decode` before any field is read.
public enum XPCValue {
    public static func decode(_ o: xpc_object_t, maxData: Int = MessageLimits.maxData, depth: Int = 0) throws -> Value {
        guard depth <= MessageLimits.maxDepth else { throw ProtocolError("too deep") }
        let t = xpc_get_type(o)
        switch t {
        case XPC_TYPE_BOOL:
            return .bool(xpc_bool_get_value(o))
        case XPC_TYPE_INT64:
            return .int(xpc_int64_get_value(o))
        case XPC_TYPE_UINT64:
            return .uint(xpc_uint64_get_value(o))
        case XPC_TYPE_STRING:
            let n = xpc_string_get_length(o)
            guard n <= MessageLimits.maxString, let p = xpc_string_get_string_ptr(o) else {
                throw ProtocolError("string too long")
            }
            let bytes = UnsafeRawBufferPointer(start: p, count: n)
            guard let s = String(bytes: bytes, encoding: .utf8) else { throw ProtocolError("invalid UTF-8") }
            return .string(s)
        case XPC_TYPE_DATA:
            let n = xpc_data_get_length(o)
            guard n <= maxData else { throw ProtocolError("data too long") }
            guard n > 0, let p = xpc_data_get_bytes_ptr(o) else { return .data([]) }
            return .data(Array(UnsafeRawBufferPointer(start: p, count: n)))
        case XPC_TYPE_FD:
            return .fd
        case XPC_TYPE_ARRAY:
            let n = xpc_array_get_count(o)
            guard n <= MessageLimits.maxArray else { throw ProtocolError("array too long") }
            return .array(try (0..<n).map { try decode(xpc_array_get_value(o, $0), maxData: maxData, depth: depth + 1) })
        case XPC_TYPE_DICTIONARY:
            guard xpc_dictionary_get_count(o) <= MessageLimits.maxKeys else { throw ProtocolError("too many keys") }
            var out: [String: Value] = [:]
            var failure: Error?
            xpc_dictionary_apply(o) { key, value in
                do {
                    let k = String(cString: key)
                    guard k.utf8.count <= 64 else { throw ProtocolError("key too long") }
                    out[k] = try decode(value, maxData: maxData, depth: depth + 1)
                    return true
                } catch {
                    failure = error
                    return false
                }
            }
            if let failure { throw failure }
            return .dict(out)
        default:
            throw ProtocolError("unsupported XPC type")
        }
    }

    /// `.fd` cannot be encoded here; set descriptors with `xpc_dictionary_set_fd`.
    public static func encode(_ v: Value) -> xpc_object_t {
        switch v {
        case .bool(let b): return xpc_bool_create(b)
        case .int(let i): return xpc_int64_create(i)
        case .uint(let u): return xpc_uint64_create(u)
        case .string(let s): return xpc_string_create(s)
        case .data(let d): return d.withUnsafeBytes { xpc_data_create($0.baseAddress, $0.count) }
        case .array(let a):
            let o = xpc_array_create(nil, 0)
            for e in a { xpc_array_append_value(o, encode(e)) }
            return o
        case .dict(let d):
            let o = xpc_dictionary_create(nil, nil, 0)
            for (k, e) in d { xpc_dictionary_set_value(o, k, encode(e)) }
            return o
        case .fd:
            preconditionFailure("encode file descriptors with xpc_dictionary_set_fd")
        }
    }

    /// Reply to `message` carrying `fields` (nil if the sender expects none).
    public static func reply(to message: xpc_object_t, _ fields: [String: Value]) -> xpc_object_t? {
        guard let r = xpc_dictionary_create_reply(message) else { return nil }
        for (k, v) in fields { xpc_dictionary_set_value(r, k, encode(v)) }
        return r
    }
}
