import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import NativeContract

final class ContractTests: XCTestCase {
    func testGoldenTranscript() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        for (fixture, file) in [(UInt32(1), "transcript-v1.hex"), (2, "transcript-v1-fixture-two.hex")] {
            let work = try SyntheticWork(token: 9, epoch: 7, operation: .sign, fixture: fixture,
                expiresUnixMs: 1_700_000_000_000, nonce: Data(repeating: 0x11, count: 32), keyID: Data(repeating: 0x22, count: 32))
            let expected = try String(contentsOf: root.appendingPathComponent("fixtures/\(file)"), encoding: .utf8)
            XCTAssertEqual(work.transcript().map { String(format: "%02x", $0) }.joined(), expected.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    func testExplicitDeletionTreatsConfirmedAbsenceAsRetired() {
        XCTAssertEqual(NativeTestKey.deletionOutcome(errSecSuccess), .deleted)
        XCTAssertEqual(NativeTestKey.deletionOutcome(errSecItemNotFound), .deleted)
        for status in [errSecAuthFailed, errSecInteractionNotAllowed, errSecUserCanceled] {
            XCTAssertEqual(NativeTestKey.deletionOutcome(status), .failed)
        }
        XCTAssertEqual(NativeTestKey.classify(.noInteraction, domain: NSOSStatusErrorDomain,
                                             code: Int(errSecItemNotFound)).outcome, .failed)
    }

    func testWorkerSlotCancellationAndStaleCompletions() throws {
        var slot = NativeAttemptSlot()
        var cancellations = 0
        let first = try work(token: 1)
        XCTAssertTrue(slot.begin(first, cancel: { cancellations += 1 }))
        XCTAssertFalse(slot.begin(try work(token: 2), cancel: {}))
        slot.invalidate(token: 99)
        XCTAssertEqual(cancellations, 0)
        slot.invalidate(token: 1)
        XCTAssertEqual(cancellations, 1)
        XCTAssertTrue(slot.isBusy)
        XCTAssertFalse(slot.begin(try work(token: 2), cancel: {}))
        let proof = SignerReply(outcome: .verified, signature: Data([1]))
        XCTAssertNil(slot.finish(token: 2, epoch: first.epoch, reply: proof))
        XCTAssertNil(slot.finish(token: 1, epoch: first.epoch + 1, reply: proof))
        XCTAssertTrue(slot.isBusy)
        let cancelled = slot.finish(token: 1, epoch: first.epoch, reply: proof)
        XCTAssertEqual(cancelled?.outcome, .cancelled)
        XCTAssertEqual(cancelled?.signature, Data())
        XCTAssertFalse(slot.isBusy)
        XCTAssertNil(slot.finish(token: 1, epoch: first.epoch, reply: proof))
        XCTAssertFalse(slot.begin(first, cancel: {}))
        let second = try work(token: 2)
        XCTAssertTrue(slot.begin(second, cancel: {}))
        XCTAssertNil(slot.finish(token: 1, epoch: first.epoch, reply: proof))
        XCTAssertTrue(slot.isBusy)
        XCTAssertEqual(slot.finish(token: 2, epoch: second.epoch, reply: proof)?.outcome, .verified)
    }

    func testWorkerSlotKeepsMutationsAndUnsafeEvidenceAfterInvalidation() throws {
        for (operation, outcome) in [(TestOperation.create, TestOutcome.created),
                                     (.delete, .deleted), (.noInteraction, .unsafe)] {
            var slot = NativeAttemptSlot()
            let request = try work(token: 1, operation: operation)
            XCTAssertTrue(slot.begin(request, cancel: {}))
            slot.invalidate()
            let reply = SignerReply(outcome: outcome, publicKey: Data([4]), signature: Data([1]))
            let accepted = slot.finish(token: request.token, epoch: request.epoch, reply: reply)
            XCTAssertEqual(accepted?.outcome, outcome)
            XCTAssertEqual(accepted?.publicKey, reply.publicKey)
            XCTAssertEqual(accepted?.signature, reply.signature)
            XCTAssertFalse(slot.isBusy)
        }
    }

    private func work(token: UInt32, operation: TestOperation = .sign) throws -> SyntheticWork {
        try SyntheticWork(token: token, epoch: 3, operation: operation, fixture: 1,
                          expiresUnixMs: 1, nonce: Data(repeating: 0, count: 32), keyID: Data(repeating: 0, count: 32))
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
