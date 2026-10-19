import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import NativeContract

final class ContractTests: XCTestCase {
    func testGoldenTranscript() throws {
        let work = try SyntheticWork(token: 9, epoch: 7, operation: .sign, fixture: 1,
            expiresUnixMs: 1_700_000_000_000, nonce: Data(repeating: 0x11, count: 32), keyID: Data(repeating: 0x22, count: 32))
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        let expected = try String(contentsOf: root.appendingPathComponent("fixtures/transcript-v1.hex"), encoding: .utf8)
        XCTAssertEqual(work.transcript().map { String(format: "%02x", $0) }.joined(), expected.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    func testBoundedSyntheticContract() {
        for id in [UInt32(0), 3, UInt32.max] {
            XCTAssertThrowsError(try SyntheticWork(token: 1, epoch: 0, operation: .sign, fixture: id,
                expiresUnixMs: 1, nonce: Data(repeating: 0, count: 32), keyID: Data(repeating: 0, count: 32)))
        }
        XCTAssertThrowsError(try SyntheticWork(token: 1, epoch: 0, operation: .sign, fixture: 1,
            expiresUnixMs: 1, nonce: Data(), keyID: Data()))
    }

    func testOnlySpecificInteractionErrorsPassNegativeGate() {
        for (domain, code) in [(NSOSStatusErrorDomain, -25308), (LAError.errorDomain, -1004)] {
            XCTAssertEqual(NativeTestKey.classify(.noInteraction, domain: domain, code: code).outcome, .interactionRequired)
            XCTAssertEqual(NativeTestKey.classify(.sign, domain: domain, code: code).outcome, .failed)
        }
        for code in [-25293, -25300, -50, -1, 0] {
            XCTAssertEqual(NativeTestKey.classify(.noInteraction, domain: NSOSStatusErrorDomain, code: code).outcome, .failed)
        }
    }

    func testFreshContextPolicyWithoutAnyPromptOrKeyMutation() {
        let first = NativeTestKey.context(for: .sign)
        let second = NativeTestKey.context(for: .sign)
        defer { first.invalidate(); second.invalidate() }
        XCTAssertFalse(first === second)
        XCTAssertEqual(first.touchIDAuthenticationAllowableReuseDuration, 0)
        XCTAssertEqual(first.localizedFallbackTitle, "")
        XCTAssertFalse(first.interactionNotAllowed)
        let silent = NativeTestKey.context(for: .noInteraction)
        defer { silent.invalidate() }
        XCTAssertTrue(silent.interactionNotAllowed)
        XCTAssertEqual(NativeTestKey.tag, Data("dev.vaultwarden.companionSlice.test-key.v1".utf8))
    }
}
