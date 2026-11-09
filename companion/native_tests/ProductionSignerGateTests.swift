import XCTest
@testable import NativeContract

/// The production signer channel's admission rules (`ProductionSigner`
/// delegates to `ProductionSignerGate`; the Flutter and LocalAuthentication
/// plumbing around it needs a signed app and is checked by hand).
final class ProductionSignerGateTests: XCTestCase {
    private let first = String(repeating: "a", count: 32), second = String(repeating: "b", count: 32)

    func testOneSignatureAtATimeAndTokensIncreaseWithinASession() {
        let gate = ProductionSignerGate()
        XCTAssertTrue(gate.idle)
        XCTAssertTrue(gate.begin(session: first, token: 1) {})
        XCTAssertFalse(gate.idle)
        XCTAssertFalse(gate.begin(session: first, token: 2) {}, "overlap")
        XCTAssertFalse(gate.begin(session: second, token: 1) {}, "overlap from another session")
        gate.finish(session: first, token: 2)
        XCTAssertFalse(gate.idle, "finish of another token keeps the open one")
        gate.finish(session: first, token: 1)
        XCTAssertTrue(gate.idle)
        XCTAssertFalse(gate.begin(session: first, token: 1) {}, "replayed token")
        XCTAssertFalse(gate.begin(session: first, token: 0) {})
        XCTAssertTrue(gate.begin(session: first, token: 5) {})
    }

    func testANewSessionStartsItsOwnNumbering() {
        // A Dart hot restart keeps the native gate but restarts Dart's counter.
        let gate = ProductionSignerGate()
        XCTAssertTrue(gate.begin(session: first, token: 7) {})
        gate.finish(session: first, token: 7)
        XCTAssertTrue(gate.begin(session: second, token: 1) {})
        gate.finish(session: second, token: 1)
        XCTAssertFalse(gate.begin(session: second, token: 1) {})
    }

    func testMalformedSessionsAreRefused() {
        let gate = ProductionSignerGate()
        for bad in ["", String(repeating: "A", count: 32), String(repeating: "a", count: 31),
                    String(repeating: "g", count: 32), String(repeating: "a", count: 33)] {
            XCTAssertFalse(gate.begin(session: bad, token: 1) {}, bad)
        }
        XCTAssertTrue(gate.idle)
    }

    func testCancelReachesOnlyTheOpenSignatureOfTheSameSessionAndToken() {
        let gate = ProductionSignerGate()
        var cancels = 0
        XCTAssertTrue(gate.begin(session: first, token: 3) { cancels += 1 })
        gate.cancel(session: first, token: 2)
        gate.cancel(session: second, token: 3)
        XCTAssertEqual(cancels, 0)
        gate.cancel(session: first, token: 3)
        XCTAssertEqual(cancels, 1)
        gate.cancelActive()
        XCTAssertEqual(cancels, 2)
        gate.finish(session: first, token: 3)
        gate.cancelActive()
        gate.cancel(session: first, token: 3)
        XCTAssertEqual(cancels, 2, "nothing open, nothing cancelled")
    }

    func testAFingerprintChangeMarksTheKeyInvalidated() {
        // `.biometryCurrentSet` makes the key unusable once the finger set
        // changes; the key records the biometry state it was created under.
        let created = Data(repeating: 1, count: 32), changed = Data(repeating: 2, count: 32)
        let label = ProductionApprovalKey.stateLabel(created)
        XCTAssertTrue(label.hasPrefix("biometry-state:"))
        XCTAssertFalse(ProductionApprovalKey.invalidated(label: label, currentState: created))
        XCTAssertTrue(ProductionApprovalKey.invalidated(label: label, currentState: changed))
        // Unknown evidence never claims invalidation: a key without a label,
        // or no readable state (locked out, no sensor).
        XCTAssertFalse(ProductionApprovalKey.invalidated(label: nil, currentState: changed))
        XCTAssertFalse(ProductionApprovalKey.invalidated(label: "", currentState: changed))
        XCTAssertFalse(ProductionApprovalKey.invalidated(label: label, currentState: nil))
        XCTAssertEqual(ProductionOutcome(rawValue: "invalidated"), .invalidated)
        XCTAssertNil(ProductionOutcome(rawValue: "missingKey"))
    }
}
