import Foundation
import XCTest
@testable import MobileContract

/// iOS approval-client rules that do not need UIKit (#60 phase 2). They run
/// on the macOS host with `swift test`; `ios/RunnerTests` repeats them, plus
/// the UIKit names and the shared key attributes, on an iOS simulator in CI.
/// The signature check that used to live here is Rust's
/// (shared-approval-checks-spec S-3, `companion/rust/src/provider/proof_check.rs`).
final class MobileApprovalContractTests: XCTestCase {
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
