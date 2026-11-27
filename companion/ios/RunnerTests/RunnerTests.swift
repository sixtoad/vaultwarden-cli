import LocalAuthentication
import Security
import UIKit
import UserNotifications
import XCTest
@testable import Runner

/// iOS-simulator checks of the approval client (#60 phase 2), run in CI by
/// `xcodebuild test`. A simulator has no Secure Enclave or enrolled Face ID,
/// so these check the shared contract and key attributes as compiled for
/// iOS, never a real signature; hardware evidence is
/// scripts/ios-approval-hardware-evidence.sh on a physical iPhone.
final class RunnerTests: XCTestCase {
    private var golden: [String: Any] = [:]
    private var publicKey = Data()

    override func setUpWithError() throws {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "approval-v2-golden", withExtension: "json"))
        golden = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        publicKey = try XCTUnwrap(Self.base64url(golden["public_key"] as? String))
    }

    private static func base64url(_ text: String?) -> Data? {
        guard var text else { return nil }
        text = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while text.count % 4 != 0 { text += "=" }
        return Data(base64Encoded: text)
    }

    private func section(_ name: String) throws -> (transcript: Data, signature: Data) {
        let value = try XCTUnwrap(golden[name] as? [String: Any])
        return (try XCTUnwrap(Data(lowerHex: try XCTUnwrap(value["transcript_hex"] as? String))),
                try XCTUnwrap(Self.base64url(value["signature"] as? String)))
    }

    private func binding() throws -> ProductionBinding {
        let approval = try XCTUnwrap(golden["approval"] as? [String: Any])
        return try ProductionBinding(providerHex: try XCTUnwrap(approval["provider_identity"] as? String),
                                     clientHex: try XCTUnwrap(approval["approval_client"] as? String))
    }

    func testGoldenTranscriptsAreAdmittedOnlyForTheirPurposeOnIOS() throws {
        let approval = try section("approval").transcript, enroll = try section("enroll").transcript
        let binding = try binding()
        XCTAssertTrue(ProductionTranscript.admits(approval, purpose: .approve, binding: binding, publicKey: publicKey))
        XCTAssertTrue(ProductionTranscript.admits(enroll, purpose: .enroll, binding: binding, publicKey: publicKey))
        XCTAssertFalse(ProductionTranscript.admits(approval, purpose: .enroll, binding: binding, publicKey: publicKey))
        XCTAssertFalse(ProductionTranscript.admits(enroll, purpose: .approve, binding: binding, publicKey: publicKey))
    }

    func testKeyAttributesAsCompiledForIOS() throws {
        XCTAssertEqual(ProductionApprovalKey.accessFlags(), [.privateKeyUsage, .biometryCurrentSet])
        XCTAssertFalse(ProductionApprovalKey.accessFlags().contains(.devicePasscode))
        XCTAssertFalse(ProductionApprovalKey.accessFlags().contains(.userPresence))
        let context = ProductionApprovalKey.context()
        defer { context.invalidate() }
        XCTAssertEqual(context.touchIDAuthenticationAllowableReuseDuration, 0)
        XCTAssertEqual(context.localizedFallbackTitle, "")
        XCTAssertTrue(context.interactionNotAllowed)
        let query = ProductionApprovalKey.query(try binding(), context)
        XCTAssertTrue((query[kSecAttrApplicationTag as String] as? Data)?.starts(with: Data(ProductionBinding.tagPrefix.utf8)) ?? false)
    }

    func testIOSAdmitsFaceIDAndTouchIDOnly() {
        XCTAssertEqual(ProductionBiometry.admitted(.faceID), .faceID)
        XCTAssertEqual(ProductionBiometry.admitted(.touchID), .touchID)
        XCTAssertNil(ProductionBiometry.admitted(.none))
        if #available(iOS 17, *) { XCTAssertNil(ProductionBiometry.admitted(.opticID)) }
    }

    func testErrorsClassifyAsNeverApproving() {
        let cancelled = [LAError.userCancel, .appCancel, .systemCancel, .invalidContext, .userFallback]
        for code in cancelled {
            XCTAssertEqual(ProductionApprovalKey.classify(domain: LAError.errorDomain, code: code.rawValue).outcome, .cancelled)
        }
        for code in [LAError.biometryNotAvailable, .biometryNotEnrolled, .biometryLockout, .passcodeNotSet] {
            XCTAssertEqual(ProductionApprovalKey.classify(domain: LAError.errorDomain, code: code.rawValue).outcome, .unavailable)
        }
        XCTAssertEqual(ProductionApprovalKey.classify(domain: NSOSStatusErrorDomain, code: Int(errSecUserCanceled)).outcome, .cancelled)
        XCTAssertEqual(ProductionApprovalKey.classify(domain: "other", code: 1).outcome, .failed)
        for outcome in [ProductionOutcome.cancelled, .unavailable, .failed] {
            XCTAssertTrue(ProductionReply(outcome: outcome).signature.isEmpty)
        }
    }

    func testLifecycleNamesMatchUIKit() {
        XCTAssertEqual(MobileLifecycle.willResignActive, UIApplication.willResignActiveNotification.rawValue)
        XCTAssertEqual(MobileLifecycle.didEnterBackground, UIApplication.didEnterBackgroundNotification.rawValue)
        XCTAssertEqual(MobileLifecycle.protectedDataWillBecomeUnavailable,
                       UIApplication.protectedDataWillBecomeUnavailableNotification.rawValue)
        XCTAssertEqual(MobileLifecycle.willTerminate, UIApplication.willTerminateNotification.rawValue)
    }

    func testNotificationsCarryOnlyGenericCopyAndNoActions() {
        XCTAssertEqual(ReviewNotificationContract.title, "Approval companion")
        XCTAssertEqual(ReviewNotificationContract.body, "A request needs your review.")
        XCTAssertTrue(ReviewNotificationContract.opens(actionIdentifier: UNNotificationDefaultActionIdentifier,
                                                       defaultAction: UNNotificationDefaultActionIdentifier))
        XCTAssertFalse(ReviewNotificationContract.opens(actionIdentifier: UNNotificationDismissActionIdentifier,
                                                        defaultAction: UNNotificationDefaultActionIdentifier))
        XCTAssertNil(ReviewNotificationContract.token(fromPost: ["token": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"]))
    }
}
