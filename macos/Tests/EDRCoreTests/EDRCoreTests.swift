import Foundation
import XCTest
@testable import EDRCore

final class OutcomeTests: XCTestCase {
    func testCombinedPrefersMoreSevere() {
        XCTAssertEqual(Outcome.clean.combined(with: .decodeError), .decodeError)
        XCTAssertEqual(Outcome.staticMatch.combined(with: .crash), .crash)
        XCTAssertEqual(Outcome.staticMatch.combined(with: .schemaViolation), .staticMatch)
        XCTAssertEqual(Outcome.timeout.combined(with: .resourceExceeded), .timeout, "ties keep the first")
    }
}

final class QuarantineTests: XCTestCase {
    func testParsesSafariValue() {
        let raw = Array("0083;6564f2a1;Safari;6B3B2E7A-1C2D-4E5F-8A9B-0C1D2E3F4A5B\0".utf8)
        let q = QuarantineInfo(xattr: raw)
        XCTAssertEqual(q?.flags, 0x83)
        XCTAssertEqual(q?.timestamp, Date(timeIntervalSince1970: 0x6564f2a1))
        XCTAssertEqual(q?.agent, "Safari")
        XCTAssertEqual(q?.eventID, UUID(uuidString: "6B3B2E7A-1C2D-4E5F-8A9B-0C1D2E3F4A5B"))
    }

    func testOptionalFields() {
        XCTAssertEqual(QuarantineInfo(xattr: Array("0081;6564f2a1".utf8))?.agent, "")
        XCTAssertNil(QuarantineInfo(xattr: Array("0081;6564f2a1;curl;".utf8))?.eventID)
    }

    func testRejectsMalformed() {
        for s in ["", "83;6564f2a1", "zzzz;1", "0081", "0081;", "0081;fffffffffffffffff", "0081;1;a;not-a-uuid"] {
            XCTAssertNil(QuarantineInfo(xattr: Array(s.utf8)), s)
        }
        XCTAssertNil(QuarantineInfo(xattr: [UInt8](repeating: 0x41, count: 2000)))
        XCTAssertNil(QuarantineInfo(xattr: [0x30, 0x30, 0x38, 0x31, 0x3b, 0xff]))
    }
}

final class DebouncerTests: XCTestCase {
    func testTrailingEdgeAndLatestPayload() {
        var d = Debouncer<String>(quietMs: 500, capacity: 2)
        let a = FileKey(dev: 1, ino: 10), b = FileKey(dev: 1, ino: 11)
        d.offer(a, payload: "/a1", nowMs: 0)
        d.offer(b, payload: "/b", nowMs: 100)
        d.offer(a, payload: "/a2", nowMs: 400)
        XCTAssertEqual(d.nextDeadline(nowMs: 400), 200)
        XCTAssertTrue(d.takeDue(nowMs: 599).isEmpty)
        let due = d.takeDue(nowMs: 900)
        XCTAssertEqual(due.map(\.0), [b, a])
        XCTAssertEqual(due.map(\.1), ["/b", "/a2"])
        XCTAssertNil(d.nextDeadline(nowMs: 900))
    }

    func testOverflowIsCountedNotBlocking() {
        var d = Debouncer<Int>(quietMs: 1, capacity: 1)
        d.offer(FileKey(dev: 1, ino: 1), payload: 1, nowMs: 0)
        d.offer(FileKey(dev: 1, ino: 2), payload: 2, nowMs: 0)
        d.offer(FileKey(dev: 1, ino: 1), payload: 3, nowMs: 0)
        XCTAssertEqual(d.count, 1)
        XCTAssertEqual(d.dropped, 1)
    }
}

final class VerdictCacheTests: XCTestCase {
    func testLRUEvictionAndVersionKey() {
        var c = VerdictCache(capacity: 2)
        let h1 = [UInt8](repeating: 1, count: 32), h2 = [UInt8](repeating: 2, count: 32)
        let k1 = VerdictCache.Key(sha256: h1, bundleVersion: 7)
        let k2 = VerdictCache.Key(sha256: h2, bundleVersion: 7)
        c.put(k1, .clean)
        c.put(k2, .staticMatch)
        XCTAssertEqual(c.get(k1), .clean) // k1 now most recent
        c.put(VerdictCache.Key(sha256: h1, bundleVersion: 8), .clean)
        XCTAssertNil(c.get(k2), "least recently used evicted")
        XCTAssertEqual(c.get(k1), .clean)
        XCTAssertEqual(c.count, 2)
    }
}

final class SequenceTrackerTests: XCTestCase {
    func testCountsGapsIgnoresReorder() {
        var s = SequenceTracker()
        XCTAssertEqual(s.observe(global: 10), 0)
        XCTAssertEqual(s.observe(global: 11), 0)
        XCTAssertEqual(s.observe(global: 15), 3)
        XCTAssertEqual(s.observe(global: 14), 0)
        XCTAssertEqual(s.lost, 3)
        XCTAssertEqual(s.lastGlobal, 15)
    }
}

final class InspectorProtocolTests: XCTestCase {
    let nonce = [UInt8](repeating: 7, count: 32)

    func stage1(_ outcome: UInt64 = 0, job: UInt64 = 1, extra: [String: Value] = [:]) -> Value {
        var d: [String: Value] = ["type": .string("stage1"), "job_id": .uint(job), "outcome": .uint(outcome),
                                  "hits": .array([]), "detail": .string(""), "offset": .uint(0), "fuel": .uint(5)]
        d.merge(extra) { $1 }
        return .dict(d)
    }

    func testRoundTripReplies() throws {
        let r = Stage1Reply(jobID: 3, outcome: .staticMatch, hits: ["x"], detail: "d", offset: 9, fuel: 1, format: "png")
        XCTAssertEqual(try InspectorMessage.parse(r.value), .stage1(r))
        let r2 = Stage2Reply(jobID: 3, outcome: .decodeError, width: 1, height: 2, frames: 1, detail: "")
        XCTAssertEqual(try InspectorMessage.parse(r2.value), .stage2(r2))
        let l = JobLimits(maxBytes: 1, maxPixels: 2, deadlineMs: 3, decode: true)
        XCTAssertEqual(try JobLimits(l.value), l)
    }

    func testStrictValidation() {
        let bad: [Value] = [
            .string("x"),
            .dict(["type": .string("shell")]),
            .dict(["type": .string("ready"), "extra": .bool(true)]),
            .dict(["type": .string("hello"), "nonce": .data([1, 2])]),
            stage1(extra: ["unexpected": .uint(1)]),
            stage1(4), // TIMEOUT is decided by the sensor
            stage1(6), // CRASH likewise
            stage1(99),
            stage1(extra: ["hits": .array(Array(repeating: .string("a"), count: 65))]),
            stage1(extra: ["hits": .array([.uint(1)])]),
            stage1(extra: ["detail": .string(String(repeating: "a", count: 513))]),
            stage1(extra: ["job_id": .int(-1)]),
        ]
        for v in bad { XCTAssertThrowsError(try InspectorMessage.parse(v), "\(v)") }
    }

    func testSessionHappyPathWithDecode() throws {
        var s = InspectorSession(nonce: nonce)
        try s.receive(.hello(nonce: nonce))
        try s.receive(.ready)
        try s.sentJob(id: 1, decode: true)
        try s.receive(InspectorMessage.parse(stage1()))
        XCTAssertEqual(s.state, .awaitingStage2)
        try s.receive(.stage2(Stage2Reply(jobID: 1, outcome: .clean, width: 1, height: 1, frames: 1, detail: "")))
        XCTAssertEqual(s.state, .done)
    }

    func testStage1MatchSkipsDecode() throws {
        var s = InspectorSession(nonce: nonce)
        try s.receive(.hello(nonce: nonce))
        try s.receive(.ready)
        try s.sentJob(id: 1, decode: true)
        try s.receive(InspectorMessage.parse(stage1(1)))
        XCTAssertEqual(s.state, .done)
        XCTAssertThrowsError(try s.receive(.stage2(Stage2Reply(jobID: 1, outcome: .clean, width: 0, height: 0,
                                                                 frames: 0, detail: ""))))
    }

    func testSessionRejectsOutOfOrderAndWrongNonce() throws {
        var s = InspectorSession(nonce: nonce)
        XCTAssertThrowsError(try s.receive(.ready))
        XCTAssertThrowsError(try s.receive(.hello(nonce: [UInt8](repeating: 8, count: 32))))
        try s.receive(.hello(nonce: nonce))
        XCTAssertThrowsError(try s.sentJob(id: 1, decode: false))
        try s.receive(.ready)
        try s.sentJob(id: 1, decode: false)
        XCTAssertThrowsError(try s.receive(InspectorMessage.parse(stage1(job: 2))), "wrong job id")
    }
}

final class WatchdogTests: XCTestCase {
    func testKillReasonsFireOnce() {
        var w = Watchdog(startMs: 1000, deadlineMs: 100, maxFootprint: 512)
        XCTAssertNil(w.check(nowMs: 1050, footprint: 100))
        XCTAssertEqual(w.check(nowMs: 1060, footprint: 600), .footprint)
        XCTAssertNil(w.check(nowMs: 2000, footprint: 600))
        var d = Watchdog(startMs: 1000, deadlineMs: 100, maxFootprint: 512)
        XCTAssertEqual(d.check(nowMs: 1100, footprint: 0), .deadline)
    }

    func finished(_ o: Outcome, decode: Bool = false) throws -> InspectorSession {
        let n = [UInt8](repeating: 1, count: 32)
        var s = InspectorSession(nonce: n)
        try s.receive(.hello(nonce: n))
        try s.receive(.ready)
        try s.sentJob(id: 1, decode: decode)
        try s.receive(.stage1(Stage1Reply(jobID: 1, outcome: o, hits: [], detail: "", offset: 0, fuel: 0, format: nil)))
        return s
    }

    func testVerdictResolution() throws {
        let clean = try finished(.clean)
        XCTAssertEqual(Verdict.resolve(session: clean, protocolError: false, killReason: nil, exit: .exited(0)), .clean)
        XCTAssertEqual(Verdict.resolve(session: clean, protocolError: true, killReason: nil, exit: .exited(0)),
                       .protocolViolation)
        // Decoder killed after a clean stage 1.
        let pending = try finished(.clean, decode: true)
        XCTAssertEqual(Verdict.resolve(session: pending, protocolError: false, killReason: .deadline,
                                       exit: .signaled(9)), .timeout)
        XCTAssertEqual(Verdict.resolve(session: pending, protocolError: false, killReason: .footprint,
                                       exit: .signaled(9)), .resourceExceeded)
        XCTAssertEqual(Verdict.resolve(session: pending, protocolError: false, killReason: nil, exit: .signaled(11)),
                       .crash)
        XCTAssertEqual(Verdict.resolve(session: pending, protocolError: false, killReason: nil, exit: .exited(0)),
                       .protocolViolation, "exit without stage 2")
        // A static match is not downgraded by a later timeout.
        let match = try finished(.staticMatch)
        XCTAssertEqual(Verdict.resolve(session: match, protocolError: false, killReason: .deadline,
                                       exit: .signaled(9)), .staticMatch)
        // Nothing reported at all.
        let fresh = InspectorSession(nonce: [UInt8](repeating: 1, count: 32))
        XCTAssertEqual(Verdict.resolve(session: fresh, protocolError: false, killReason: nil, exit: .exited(0)),
                       .protocolViolation)
        XCTAssertEqual(Verdict.resolve(session: fresh, protocolError: false, killReason: nil, exit: .signaled(6)),
                       .crash)
    }
}

final class UICommandTests: XCTestCase {
    func testAllowlist() throws {
        for c in [UICommand.status, .listAlerts(limit: 100), .ackAlert(id: 5)] {
            XCTAssertEqual(try UICommand.parse(c.value), c)
        }
        let bad: [Value] = [
            .dict(["cmd": .string("uninstall")]),
            .dict(["cmd": .string("status"), "path": .string("/etc")]),
            .dict(["cmd": .string("list_alerts"), "limit": .uint(101)]),
            .dict(["cmd": .string("list_alerts"), "limit": .uint(0)]),
            .dict(["cmd": .string("ack_alert")]),
            .array([]),
        ]
        for v in bad { XCTAssertThrowsError(try UICommand.parse(v), "\(v)") }
    }
}

final class RulesStoreTests: XCTestCase {
    var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("edr-rules-\(UUID().uuidString)")
    }

    override func tearDownWithError() throws {
        // Bundles are read-only files in writable dirs; removal works.
        try? FileManager.default.removeItem(at: dir)
    }

    func versions() throws -> Set<String> {
        Set(try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { UInt64($0) != nil })
    }

    func testActivationRollbackAndRetention() throws {
        let s = try RulesStore(root: dir)
        XCTAssertNil(try s.currentBundle())
        try s.install(version: 1, bytes: Data([1]))
        try s.activate(version: 1)
        try s.markKnownGood()
        try s.install(version: 2, bytes: Data([2]))
        try s.activate(version: 2)
        XCTAssertEqual(try s.currentBundle()?.bytes, Data([2]))
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: dir.appendingPathComponent("current").path), "2")
        let attrs = try FileManager.default.attributesOfItem(atPath: s.bundleURL(2).path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o444)

        // Health gate fails: back to 1; 2 can never be activated again.
        XCTAssertEqual(try s.rollback(), 1)
        XCTAssertEqual(try s.currentBundle()?.version, 1)
        XCTAssertThrowsError(try s.install(version: 2, bytes: Data([2])))
        XCTAssertThrowsError(try s.activate(version: 2))

        try s.install(version: 3, bytes: Data([3]))
        try s.activate(version: 3)
        try s.markKnownGood()
        try s.install(version: 4, bytes: Data([4]))
        try s.activate(version: 4)
        XCTAssertEqual(try versions(), ["3", "4"], "keep current and known-good only")

        // State survives a restart.
        let again = try RulesStore(root: dir)
        XCTAssertEqual(again.state.current, 4)
        XCTAssertEqual(again.state.knownGood, 3)
        XCTAssertEqual(again.state.highWater, 4)
    }

    func testRemoteCannotPushOlder() throws {
        let s = try RulesStore(root: dir)
        try s.install(version: 5, bytes: Data([5]))
        try s.activate(version: 5)
        XCTAssertThrowsError(try s.install(version: 4, bytes: Data([4]))) {
            XCTAssertEqual($0 as? RulesStore.StoreError, .notNewer(version: 4, highWater: 5))
        }
        XCTAssertThrowsError(try s.rollback()) { XCTAssertEqual($0 as? RulesStore.StoreError, .noKnownGood) }
        XCTAssertThrowsError(try s.activate(version: 9)) { XCTAssertEqual($0 as? RulesStore.StoreError, .notInstalled(9)) }
    }
}
