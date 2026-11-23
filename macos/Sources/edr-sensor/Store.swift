import EDRCore
import Foundation
import SQLite3

/// Root-owned SQLite database: job journal (restart recovery), event store
/// (alerts for edr-ui) and durable telemetry spool (pulled and acked by netd).
/// Used from the sensor's serial pipeline queue only.
final class Store {
    private var db: OpaquePointer?
    static let maxSpool = 100_000

    init(path: String) throws {
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil)
            == SQLITE_OK
        else { throw StoreError("open \(path)") }
        chmod(path, 0o600)
        try exec("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS journal(
                id INTEGER PRIMARY KEY, dev INTEGER NOT NULL, ino INTEGER NOT NULL, path TEXT NOT NULL,
                created INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY, time INTEGER NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL,
                outcome TEXT NOT NULL, severity INTEGER NOT NULL, action INTEGER NOT NULL,
                bundle_version INTEGER NOT NULL, detail TEXT NOT NULL, hits TEXT NOT NULL,
                quarantine_agent TEXT NOT NULL, acked INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS events_open ON events(action, acked);
            CREATE TABLE IF NOT EXISTS telemetry(id INTEGER PRIMARY KEY, record TEXT NOT NULL);
            """)
    }

    deinit { sqlite3_close_v2(db) }

    // MARK: journal

    func journalAdd(dev: UInt64, ino: UInt64, path: String) throws -> Int64 {
        try run("INSERT INTO journal(dev, ino, path, created) VALUES(?,?,?,?)",
                [.int(Int64(bitPattern: dev)), .int(Int64(bitPattern: ino)), .text(path), .int(now())])
        return sqlite3_last_insert_rowid(db)
    }

    func journalRemove(_ id: Int64) throws { try run("DELETE FROM journal WHERE id=?", [.int(id)]) }

    func journalPending() throws -> [(id: Int64, dev: UInt64, ino: UInt64, path: String)] {
        try query("SELECT id, dev, ino, path FROM journal ORDER BY id") {
            ($0.int(0), UInt64(bitPattern: $0.int(1)), UInt64(bitPattern: $0.int(2)), $0.text(3))
        }
    }

    // MARK: events

    struct Event {
        var path: String
        var sha256: String
        var outcome: Outcome
        var severity: UInt8
        var action: UInt8
        var bundleVersion: UInt64
        var detail: String
        var hits: [String]
        var quarantineAgent: String
    }

    @discardableResult
    func addEvent(_ e: Event) throws -> Int64 {
        try run("""
            INSERT INTO events(time, path, sha256, outcome, severity, action, bundle_version, detail, hits,
                               quarantine_agent) VALUES(?,?,?,?,?,?,?,?,?,?)
            """, [.int(now()), .text(e.path), .text(e.sha256), .text(e.outcome.name), .int(Int64(e.severity)),
                  .int(Int64(e.action)), .int(Int64(bitPattern: e.bundleVersion)), .text(e.detail),
                  .text(e.hits.joined(separator: ",")), .text(e.quarantineAgent)])
        return sqlite3_last_insert_rowid(db)
    }

    /// Unacknowledged alerts (action >= alert), newest first, for edr-ui.
    func openAlerts(limit: Int) throws -> [Value] {
        try query("""
            SELECT id, time, path, outcome, severity, detail FROM events
            WHERE action >= 2 AND acked = 0 ORDER BY id DESC LIMIT ?
            """, [.int(Int64(limit))]) {
            Value.dict(["id": .uint(UInt64($0.int(0))), "time": .int($0.int(1)), "path": .string(String($0.text(2).prefix(512))),
                        "outcome": .string($0.text(3)), "severity": .uint(UInt64($0.int(4))),
                        "detail": .string(String($0.text(5).prefix(256)))])
        }
    }

    func ack(_ id: UInt64) throws {
        try run("UPDATE events SET acked = 1 WHERE id = ?", [.int(Int64(bitPattern: id))])
    }

    // MARK: telemetry spool

    func spool(_ r: TelemetryRecord) throws {
        let json = String(decoding: try JSONEncoder().encode(r), as: UTF8.self)
        try run("INSERT INTO telemetry(record) VALUES(?)", [.text(json)])
        try run("DELETE FROM telemetry WHERE id <= (SELECT MAX(id) FROM telemetry) - ?", [.int(Int64(Self.maxSpool))])
    }

    func telemetry(max: Int) throws -> [(id: Int64, record: String)] {
        try query("SELECT id, record FROM telemetry ORDER BY id LIMIT ?", [.int(Int64(max))]) { ($0.int(0), $0.text(1)) }
    }

    func telemetryAck(upTo id: Int64) throws { try run("DELETE FROM telemetry WHERE id <= ?", [.int(id)]) }

    // MARK: SQLite plumbing

    enum Bind { case int(Int64), text(String) }

    struct Row {
        let stmt: OpaquePointer
        func int(_ i: Int32) -> Int64 { sqlite3_column_int64(stmt, i) }
        func text(_ i: Int32) -> String { sqlite3_column_text(stmt, i).map { String(cString: $0) } ?? "" }
    }

    private func exec(_ sql: String) throws {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw StoreError(lastError) }
    }

    private func prepare(_ sql: String, _ binds: [Bind]) throws -> OpaquePointer {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else { throw StoreError(lastError) }
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        for (i, b) in binds.enumerated() {
            switch b {
            case .int(let v): sqlite3_bind_int64(stmt, Int32(i + 1), v)
            case .text(let s): sqlite3_bind_text(stmt, Int32(i + 1), s, -1, transient)
            }
        }
        return stmt
    }

    private func run(_ sql: String, _ binds: [Bind]) throws {
        let stmt = try prepare(sql, binds)
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_DONE else { throw StoreError(lastError) }
    }

    private func query<T>(_ sql: String, _ binds: [Bind] = [], _ row: (Row) -> T) throws -> [T] {
        let stmt = try prepare(sql, binds)
        defer { sqlite3_finalize(stmt) }
        var out: [T] = []
        while true {
            switch sqlite3_step(stmt) {
            case SQLITE_ROW: out.append(row(Row(stmt: stmt)))
            case SQLITE_DONE: return out
            default: throw StoreError(lastError)
            }
        }
    }

    private var lastError: String { String(cString: sqlite3_errmsg(db)) }
    private func now() -> Int64 { Int64(Date().timeIntervalSince1970) }
}

struct StoreError: Error, CustomStringConvertible {
    var description: String
    init(_ d: String) { description = d }
}
