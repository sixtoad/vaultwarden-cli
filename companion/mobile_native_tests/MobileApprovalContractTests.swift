import CryptoKit
import Foundation
import XCTest
@testable import MobileContract

/// iOS approval-client rules that do not need UIKit (#60 phase 2). They run
/// on the macOS host with `swift test`; `ios/RunnerTests` repeats them, plus
/// the UIKit names and the shared key attributes, on an iOS simulator in CI.
final class MobileApprovalContractTests: XCTestCase {
    private var golden: [String: Any] = [:]
    private var publicKey = Data()

    override func setUpWithError() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("tests/fixtures/approval-v2-golden.json"))
        golden = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        publicKey = try XCTUnwrap(Self.base64url(golden["public_key"] as? String))
    }

    static func base64url(_ text: String?) -> Data? {
        guard var text else { return nil }
        text = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while text.count % 4 != 0 { text += "=" }
        return Data(base64Encoded: text)
    }

    static func hex(_ text: String) -> Data? {
        guard text.count % 2 == 0 else { return nil }
        var bytes = [UInt8](), index = text.startIndex
        while index < text.endIndex {
            let next = text.index(index, offsetBy: 2)
            guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
            bytes.append(byte); index = next
        }
        return Data(bytes)
    }

    private func section(_ name: String) throws -> (transcript: Data, signature: Data) {
        let value = try XCTUnwrap(golden[name] as? [String: Any])
        return (try XCTUnwrap(Self.hex(try XCTUnwrap(value["transcript_hex"] as? String))),
                try XCTUnwrap(Self.base64url(value["signature"] as? String)))
    }

    func testOnlyADERSignatureThatVerifiesOverTheExactTranscriptIsReturned() throws {
        for name in ["approval", "enroll"] {
            let (transcript, signature) = try section(name)
            let kept = MobileApproval.checked(outcome: "signed", publicKey: publicKey, signature: signature, transcript: transcript)
            XCTAssertEqual(kept.outcome, "signed", name)
            XCTAssertEqual(kept.signature, signature)
            XCTAssertEqual(kept.publicKey, publicKey)

            // One flipped transcript byte: the signature no longer verifies.
            var altered = transcript
            altered[altered.count - 1] ^= 0x01
            let refused = MobileApproval.checked(outcome: "signed", publicKey: publicKey, signature: signature, transcript: altered)
            XCTAssertEqual(refused.outcome, "failed")
            XCTAssertTrue(refused.signature.isEmpty)
            XCTAssertTrue(refused.publicKey.isEmpty)
        }
        let (transcript, signature) = try section("approval")
        // Raw r||s (not DER), truncated DER, empty and over-long bytes fail closed.
        let raw = try P256.Signing.ECDSASignature(derRepresentation: signature).rawRepresentation
        for bad in [raw, Data(signature.dropLast()), Data(), signature + Data([0])] {
            XCTAssertEqual(MobileApproval.checked(outcome: "signed", publicKey: publicKey, signature: bad,
                                                  transcript: transcript).outcome, "failed")
        }
        let other = P256.Signing.PrivateKey().publicKey.x963Representation
        XCTAssertEqual(MobileApproval.checked(outcome: "signed", publicKey: other, signature: signature,
                                              transcript: transcript).outcome, "failed")
    }

    func testCancelAndErrorsNeverCarryASignature() throws {
        let (transcript, signature) = try section("approval")
        for outcome in ["cancelled", "unavailable", "refused", "failed", "unsafe", "invalidated", "absent", "present"] {
            // Even if a native path wrongly attached bytes, a non-signed reply loses them.
            let reply = MobileApproval.checked(outcome: outcome, publicKey: publicKey, signature: signature, transcript: transcript)
            XCTAssertEqual(reply.outcome, outcome)
            XCTAssertTrue(reply.signature.isEmpty, outcome)
        }
    }

    func testAvailabilityNamesAndPromptReasons() {
        XCTAssertEqual(MobileApproval.availabilityName("faceID"), "faceID")
        XCTAssertEqual(MobileApproval.availabilityName("touchID"), "touchID")
        XCTAssertEqual(MobileApproval.availabilityName(nil), "unavailable")
        XCTAssertEqual(MobileApproval.availabilityName("opticID"), "unavailable")
        XCTAssertEqual(MobileApproval.reason(purpose: "approve", biometry: "faceID"), "Approve one provider request")
        XCTAssertEqual(MobileApproval.reason(purpose: "enroll", biometry: "faceID"), "Enroll this device's Face ID approval key")
        XCTAssertEqual(MobileApproval.reason(purpose: "enroll", biometry: "touchID"), "Enroll this device's Touch ID approval key")
    }

    func testTheBiometricSheetDoesNotCancelItsOwnPrompt() {
        // Presenting Face ID / Touch ID resigns the app active on iOS. A
        // trigger on resign-active would cancel every prompt it opened.
        XCTAssertFalse(MobileLifecycle.signerCancelTriggers.contains(MobileLifecycle.willResignActive))
        XCTAssertEqual(Set(MobileLifecycle.signerCancelTriggers),
                       [MobileLifecycle.didEnterBackground, MobileLifecycle.protectedDataWillBecomeUnavailable,
                        MobileLifecycle.willTerminate])
    }

    func testLeavingTheForegroundOrLockingInvalidatesProviderState() {
        // docs/mobile-clients.md: the provider `invalidate` argument is `inactive` or `close`.
        XCTAssertEqual(MobileLifecycle.providerInvalidations.map(\.reason), ["inactive", "inactive", "close"])
        XCTAssertEqual(MobileLifecycle.providerInvalidations.map(\.name),
                       [MobileLifecycle.didEnterBackground, MobileLifecycle.protectedDataWillBecomeUnavailable,
                        MobileLifecycle.willTerminate])
        // Administrative tickets are also dropped on resign-active, as on macOS.
        XCTAssertEqual(Set(MobileLifecycle.managementInvalidations),
                       Set(MobileLifecycle.providerInvalidations.map(\.name) + [MobileLifecycle.willResignActive]))
    }

    func testDeviceLockIsSignalledOnTheLifecycleChannel() {
        // `.../lifecycle` `signal`: iOS reports `locked` only. Interruptions
        // (calls, app switcher) already reach Flutter as `inactive`.
        XCTAssertEqual(MobileLifecycle.deviceSignals.map(\.name), [MobileLifecycle.protectedDataWillBecomeUnavailable])
        XCTAssertEqual(MobileLifecycle.deviceSignals.map(\.signal), ["locked"])
    }

    func testUIKitNotificationNamesAreSpelledOut() {
        XCTAssertEqual(MobileLifecycle.willResignActive, "UIApplicationWillResignActiveNotification")
        XCTAssertEqual(MobileLifecycle.didEnterBackground, "UIApplicationDidEnterBackgroundNotification")
        XCTAssertEqual(MobileLifecycle.protectedDataWillBecomeUnavailable, "UIApplicationProtectedDataWillBecomeUnavailable")
        XCTAssertEqual(MobileLifecycle.willTerminate, "UIApplicationWillTerminateNotification")
    }
}
