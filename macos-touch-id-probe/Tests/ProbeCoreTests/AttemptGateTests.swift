import XCTest
@testable import ProbeCore

final class AttemptGateTests: XCTestCase {
    func testOneWorkerEvenAfterCancellation() {
        var gate = AttemptGate()
        let first = gate.begin(.sign)!
        XCTAssertNil(gate.begin(.delete))
        gate.cancel()
        XCTAssertNil(gate.begin(.sign))
        XCTAssertEqual(gate.finish(first, outcome: .signatureVerified), .cancelled)
        XCTAssertEqual(gate.verifiedSignatures, 0)
        XCTAssertNotNil(gate.begin(.sign))
    }

    func testStaleCompletionCannotFinishNewAttempt() {
        var gate = AttemptGate()
        let first = gate.begin(.sign)!
        XCTAssertEqual(gate.finish(first, outcome: .signatureVerified), .signatureVerified)
        let second = gate.begin(.sign)!
        XCTAssertNil(gate.finish(first, outcome: .signatureVerified))
        XCTAssertEqual(gate.active, second)
        XCTAssertEqual(gate.finish(second, outcome: .signatureVerified), .signatureVerified)
        XCTAssertEqual(gate.verifiedSignatures, 2)
    }

    func testCancelledNegativeDoesNotCount() {
        var gate = AttemptGate()
        let token = gate.begin(.noInteraction)!
        gate.cancel()
        XCTAssertEqual(gate.finish(token, outcome: .interactionRequired), .cancelled)
        XCTAssertEqual(gate.blockedWithoutInteraction, 0)
    }

    func testNegativeRequiresCorrectOperationAndOutcome() {
        for outcome in [ProbeOutcome.missingKey, .unavailable, .failed, .unsafe, .cancelled] {
            var gate = AttemptGate()
            let token = gate.begin(.noInteraction)!
            XCTAssertEqual(gate.finish(token, outcome: outcome), outcome)
            XCTAssertEqual(gate.blockedWithoutInteraction, 0)
        }
        var gate = AttemptGate()
        XCTAssertEqual(gate.blockedWithoutInteraction, 0)
        let sign = gate.begin(.sign)!
        _ = gate.finish(sign, outcome: .interactionRequired)
        XCTAssertEqual(gate.blockedWithoutInteraction, 0)
        let negative = gate.begin(.noInteraction)!
        _ = gate.finish(negative, outcome: .interactionRequired)
        XCTAssertEqual(gate.blockedWithoutInteraction, 1)
    }

    func testUnsafeLatchSurvivesCleanupAndBlocksFurtherSigning() {
        var gate = AttemptGate()
        let token = gate.begin(.noInteraction)!
        gate.cancel()
        XCTAssertEqual(gate.finish(token, outcome: .unsafe), .unsafe)
        for (operation, outcome) in [(ProbeOperation.delete, ProbeOutcome.deleted),
                                     (.create, .created), (.reopen, .reopened)] {
            XCTAssertTrue(gate.unsafeObserved)
            XCTAssertNil(gate.begin(.sign))
            XCTAssertNil(gate.begin(.noInteraction))
            let mutation = gate.begin(operation)!
            gate.cancel()
            _ = gate.finish(mutation, outcome: outcome)
            XCTAssertTrue(gate.unsafeObserved)
        }
        XCTAssertFalse(AttemptGate().unsafeObserved)
    }

    func testOnlyExplicitSignCountsAndKeyChangesResetEvidence() {
        var gate = AttemptGate()
        let negative = gate.begin(.noInteraction)!
        _ = gate.finish(negative, outcome: .signatureVerified)
        XCTAssertEqual(gate.verifiedSignatures, 0)
        let sign = gate.begin(.sign)!
        _ = gate.finish(sign, outcome: .signatureVerified)
        XCTAssertEqual(gate.verifiedSignatures, 1)
        let reopen = gate.begin(.reopen)!
        _ = gate.finish(reopen, outcome: .reopened)
        XCTAssertEqual(gate.verifiedSignatures, 1)
        let delete = gate.begin(.delete)!
        _ = gate.finish(delete, outcome: .deleted)
        XCTAssertEqual(gate.verifiedSignatures, 0)
    }

    func testNoActiveCompletionIsIgnored() {
        var gate = AttemptGate()
        gate.cancel()
        XCTAssertNil(gate.finish(UUID(), outcome: .signatureVerified))
        XCTAssertEqual(gate.verifiedSignatures, 0)
    }

    func testCancellationCannotHideUnsafeResult() {
        for operation in ProbeOperation.allCases {
            var gate = AttemptGate()
            let token = gate.begin(operation)!
            gate.cancel()
            XCTAssertEqual(gate.finish(token, outcome: .unsafe), .unsafe)
            XCTAssertEqual(gate.verifiedSignatures, 0)
            XCTAssertEqual(gate.blockedWithoutInteraction, 0)
            XCTAssertNil(gate.active)
        }
    }

    func testCompletedKeyMutationSurvivesCancellation() {
        for (operation, outcome) in [(ProbeOperation.create, ProbeOutcome.created),
                                     (.delete, .deleted)] {
            var gate = AttemptGate()
            let sign = gate.begin(.sign)!
            _ = gate.finish(sign, outcome: .signatureVerified)
            let negative = gate.begin(.noInteraction)!
            _ = gate.finish(negative, outcome: .interactionRequired)
            let mutation = gate.begin(operation)!
            gate.cancel()
            XCTAssertEqual(gate.finish(mutation, outcome: outcome), outcome)
            XCTAssertEqual(gate.verifiedSignatures, 0)
            XCTAssertEqual(gate.blockedWithoutInteraction, 0)
            XCTAssertNil(gate.active)
        }
    }

    func testFailedKeyMutationPreservesEvidence() {
        var gate = AttemptGate()
        let sign = gate.begin(.sign)!
        _ = gate.finish(sign, outcome: .signatureVerified)
        let negative = gate.begin(.noInteraction)!
        _ = gate.finish(negative, outcome: .interactionRequired)
        for operation in [ProbeOperation.create, .delete] {
            let token = gate.begin(operation)!
            XCTAssertEqual(gate.finish(token, outcome: .failed), .failed)
            XCTAssertEqual(gate.verifiedSignatures, 1)
            XCTAssertEqual(gate.blockedWithoutInteraction, 1)
        }
    }

    func testOnlyKnownInteractionErrorsPassNegative() {
        XCTAssertTrue(isInteractionRequired(domain: "NSOSStatusErrorDomain", code: -25308))
        XCTAssertTrue(isInteractionRequired(domain: "com.apple.LocalAuthentication", code: -1004))
        for code in [-25300, -25293, -128, -1, 0] {
            XCTAssertFalse(isInteractionRequired(domain: "NSOSStatusErrorDomain", code: code))
        }
        XCTAssertFalse(isInteractionRequired(domain: "unexpected", code: -25308))
        XCTAssertFalse(isInteractionRequired(domain: "com.apple.LocalAuthentication", code: -2))
    }
}
