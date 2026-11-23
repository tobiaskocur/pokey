import EDRCore
import EDRPlatform
import EndpointSecurity
import Foundation
import os

/// What the ES callback copies out of a message. Nothing else is kept and the
/// callback never blocks.
struct FileEvent: Sendable {
    enum Kind: Sendable { case closeModified, quarantineSet, rename }
    var kind: Kind
    var key: FileKey
    var path: String
}

/// Endpoint Security client: NOTIFY_CLOSE, NOTIFY_SETEXTATTR (quarantine),
/// NOTIFY_RENAME, NOTIFY_EXIT. Events go to `sink` through a bounded hand-off;
/// overflow and sequence gaps are counted.
final class ESClient {
    static let queueCapacity = 4096
    static let mutedPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/", "/private/var/db/", "/Library/Caches/",
                                "/private/var/folders/", "/dev/"]

    private var client: OpaquePointer?
    private let log = logger("es")
    private let sink: (FileEvent) -> Void
    private let onExit: (pid_t) -> Void
    private let sinkQueue: DispatchQueue
    private let counters = OSAllocatedUnfairLock(initialState: Counters())

    struct Counters { var inFlight = 0; var dropped: UInt64 = 0; var seq = SequenceTracker() }

    init(queue: DispatchQueue, sink: @escaping (FileEvent) -> Void, onExit: @escaping (pid_t) -> Void) {
        sinkQueue = queue
        self.sink = sink
        self.onExit = onExit
    }

    var stats: (dropped: UInt64, lost: UInt64) {
        counters.withLock { ($0.dropped, $0.seq.lost) }
    }

    func start() throws {
        let res = es_new_client(&client) { [weak self] _, msg in self?.handle(msg) }
        guard res == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
            throw ConfigError("es_new_client failed: \(res.rawValue) (entitlement, TCC Full Disk Access, root?)")
        }
        // Our own process (and its reads) are not interesting.
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        if kr == KERN_SUCCESS { es_mute_process(client, &token) }
        for p in Self.mutedPrefixes {
            es_mute_path(client, p, ES_MUTE_PATH_TYPE_TARGET_PREFIX)
        }
        _ = es_clear_cache(client)
        var events = [ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_SETEXTATTR, ES_EVENT_TYPE_NOTIFY_RENAME,
                      ES_EVENT_TYPE_NOTIFY_EXIT]
        guard es_subscribe(client, &events, UInt32(events.count)) == ES_RETURN_SUCCESS else {
            throw ConfigError("es_subscribe failed")
        }
        log.info("endpoint security client subscribed")
    }

    func stop() {
        if let client { es_delete_client(client) }
        client = nil
    }

    private func handle(_ msg: UnsafePointer<es_message_t>) {
        let m = msg.pointee
        if m.version >= 4 {
            let gap = counters.withLock { $0.seq.observe(global: m.global_seq_num) }
            if gap > 0 { log.error("endpoint security dropped \(gap) message(s)") }
        }
        let event: FileEvent?
        switch m.event_type {
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            let c = m.event.close
            let writable = m.version >= 6 && c.was_mapped_writable
            event = (c.modified || writable) ? Self.fileEvent(.closeModified, c.target) : nil
        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            let s = m.event.setextattr
            event = Self.string(s.extattr) == "com.apple.quarantine" ? Self.fileEvent(.quarantineSet, s.target) : nil
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            let r = m.event.rename
            let src = r.source.pointee
            let key = FileKey(dev: UInt64(UInt32(bitPattern: src.stat.st_dev)), ino: src.stat.st_ino)
            if r.destination_type == ES_DESTINATION_TYPE_NEW_PATH {
                let dir = Self.string(r.destination.new_path.dir.pointee.path)
                let name = Self.string(r.destination.new_path.filename)
                event = FileEvent(kind: .rename, key: key, path: dir.hasSuffix("/") ? dir + name : dir + "/" + name)
            } else {
                event = FileEvent(kind: .rename, key: key, path: Self.string(r.destination.existing_file.pointee.path))
            }
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            onExit(audit_token_to_pid(m.process.pointee.audit_token))
            event = nil
        default:
            event = nil
        }
        guard let event else { return }
        let admitted = counters.withLock { c -> Bool in
            guard c.inFlight < Self.queueCapacity else { c.dropped += 1; return false }
            c.inFlight += 1
            return true
        }
        guard admitted else { return }
        sinkQueue.async { [self] in
            counters.withLock { $0.inFlight -= 1 }
            sink(event)
        }
    }

    private static func fileEvent(_ kind: FileEvent.Kind, _ f: UnsafeMutablePointer<es_file_t>) -> FileEvent {
        let file = f.pointee
        return FileEvent(kind: kind, key: FileKey(dev: UInt64(UInt32(bitPattern: file.stat.st_dev)), ino: file.stat.st_ino),
                         path: string(file.path))
    }

    private static func string(_ t: es_string_token_t) -> String {
        guard t.length > 0, let p = t.data else { return "" }
        return String(decoding: UnsafeRawBufferPointer(start: p, count: t.length), as: UTF8.self)
    }
}
