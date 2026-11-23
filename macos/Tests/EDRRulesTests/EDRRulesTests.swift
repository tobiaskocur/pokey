import CEDRCore
import EDRCore
import Foundation
import XCTest
@testable import EDRRules

/// Needs `make test` (builds the Rust library and a signed test bundle into
/// core/target/swift).
final class EDRRulesTests: XCTestCase {
    static let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    static let testData = repo.appendingPathComponent("core/target/swift/testdata")

    var bytes: [UInt8] = []
    var anchors: TrustAnchors!
    let now = Int64(Date().timeIntervalSince1970)

    override func setUpWithError() throws {
        bytes = Array(try Data(contentsOf: Self.testData.appendingPathComponent("rules.bundle")))
        let roots = try String(contentsOf: Self.testData.appendingPathComponent("roots.txt"), encoding: .utf8)
        anchors = try TrustAnchors(text: "# pinned\n" + roots, threshold: 1)
    }

    func fixture(_ name: String) throws -> [UInt8] {
        Array(try Data(contentsOf: Self.repo.appendingPathComponent("rules/fixtures/\(name)")))
    }

    func testOutcomeCodesMatchHeader() {
        let header: [Outcome: Int32] = [
            .clean: EDR_OUTCOME_CLEAN, .staticMatch: EDR_OUTCOME_STATIC_MATCH,
            .schemaViolation: EDR_OUTCOME_SCHEMA_VIOLATION, .decodeError: EDR_OUTCOME_DECODE_ERROR,
            .timeout: EDR_OUTCOME_TIMEOUT, .resourceExceeded: EDR_OUTCOME_RESOURCE_EXCEEDED,
            .crash: EDR_OUTCOME_CRASH, .protocolViolation: EDR_OUTCOME_PROTOCOL_VIOLATION,
        ]
        XCTAssertEqual(header.count, Outcome.allCases.count)
        for (o, c) in header { XCTAssertEqual(Int32(o.rawValue), c, o.name) }
    }

    func testOpenPolicyAndScan() throws {
        let b = try RuleBundle(bytes: bytes, anchors: anchors, now: now, mode: .activation(currentVersion: 6))
        XCTAssertEqual(b.info.version, 7)
        XCTAssertEqual(b.info.channel, .stable)
        XCTAssertFalse(b.info.expired)
        XCTAssertEqual(b.format(forExtension: "HEIC"), "isobmff")
        XCTAssertEqual(b.format(forExtension: "exe"), "other")
        XCTAssertEqual(b.policy(format: "png").jobLimits,
                       JobLimits(maxBytes: 268_435_456, maxPixels: 100_000_000, deadlineMs: 5000, decode: true))
        XCTAssertFalse(b.policy(format: nil).decode)
        XCTAssertTrue(b.action(for: .protocolViolation) == (.critical, .alert))

        let e = try ScanEngine(bundle: b)
        XCTAssertEqual(try e.selfTest(bundle: b), b.info.selfTests)
        XCTAssertEqual(e.scan(try fixture("png_valid.png"), hint: "png").outcome, .clean)
        let m = e.scan(try fixture("png_trailing_macho.png"), hint: "png")
        XCTAssertEqual(m.outcome, .staticMatch)
        XCTAssertTrue(m.hits.contains("image_with_embedded_macho"), "\(m.hits)")
        XCTAssertEqual(e.scan(try fixture("tiff_ifd_loop.tif"), hint: nil).outcome, .schemaViolation)
        XCTAssertEqual(e.scan([], hint: nil).outcome, .clean)
        let reply = m.stage1(jobID: 4)
        XCTAssertEqual(try InspectorMessage.parse(reply.value), .stage1(reply))
    }

    func testRejections() throws {
        XCTAssertThrowsError(try RuleBundle(bytes: bytes, anchors: anchors, now: now, mode: .activation(currentVersion: 7)))
        _ = try RuleBundle(bytes: bytes, anchors: anchors, now: now, mode: .load)
        var tampered = bytes
        tampered[tampered.count - 3] ^= 1
        XCTAssertThrowsError(try RuleBundle(bytes: tampered, anchors: anchors, now: now, mode: .load))
        let other = TrustAnchors(roots: [[UInt8](repeating: 9, count: 32)], threshold: 1)
        XCTAssertThrowsError(try RuleBundle(bytes: bytes, anchors: other, now: now, mode: .load)) {
            XCTAssertEqual(($0 as? CoreError)?.code, EDR_ERR_BUNDLE)
        }
        XCTAssertThrowsError(try RuleBundle(bytes: Array(bytes.prefix(40)), anchors: anchors, now: now, mode: .load))
        XCTAssertThrowsError(try TrustAnchors(text: "abcd", threshold: 1))
    }

    func testTruncateOnCharacterBoundary() {
        XCTAssertEqual(truncate("ééé", 5), "éé")
        XCTAssertEqual(truncate("abc", 3), "abc")
    }
}
