import UserNotifications
import XCTest
@testable import NativeContract

/// Review-request notifications (#61): fixed generic copy, opaque tokens only.
final class ReviewNotificationContractTests: XCTestCase {
    func testCopyIsGeneric() {
        XCTAssertEqual(ReviewNotificationContract.body, "A request needs your review.")
        XCTAssertEqual(ReviewNotificationContract.title, "Approval companion")
    }

    func testOnlyAnOpaqueTokenIsAccepted() {
        let token = "abcdefghijklmnopqrstu_"
        XCTAssertEqual(ReviewNotificationContract.token(fromPost: ["token": token]), token)
        // A request id (43 characters) is never a token.
        XCTAssertNil(ReviewNotificationContract.token(fromPost: ["token": String(repeating: "A", count: 43)]))
        // No extra fields (title, body, labels) are accepted alongside it.
        XCTAssertNil(ReviewNotificationContract.token(fromPost: ["token": token, "body": "Synthetic login"]))
        XCTAssertNil(ReviewNotificationContract.token(fromPost: ["token": "abcdefghijklmnopqrst u"]))
        XCTAssertNil(ReviewNotificationContract.token(fromPost: token))
        XCTAssertNil(ReviewNotificationContract.token(fromPost: nil))
    }

    func testOnlyTheDefaultActionOpens() {
        let open = UNNotificationDefaultActionIdentifier
        XCTAssertTrue(ReviewNotificationContract.opens(actionIdentifier: open, defaultAction: open))
        XCTAssertFalse(ReviewNotificationContract.opens(actionIdentifier: UNNotificationDismissActionIdentifier, defaultAction: open))
        XCTAssertFalse(ReviewNotificationContract.opens(actionIdentifier: "approve", defaultAction: open))
    }

    func testStatusNames() {
        XCTAssertEqual(ReviewNotificationContract.statusName(rawValue: 0), "notDetermined")
        XCTAssertEqual(ReviewNotificationContract.statusName(rawValue: 1), "denied")
        XCTAssertEqual(ReviewNotificationContract.statusName(rawValue: UNAuthorizationStatus.notDetermined.rawValue), "notDetermined")
        XCTAssertEqual(ReviewNotificationContract.statusName(rawValue: UNAuthorizationStatus.denied.rawValue), "denied")
        XCTAssertEqual(ReviewNotificationContract.statusName(rawValue: UNAuthorizationStatus.authorized.rawValue), "authorized")
        XCTAssertEqual(ReviewNotificationContract.statusName(rawValue: UNAuthorizationStatus.provisional.rawValue), "authorized")
        XCTAssertEqual(ReviewNotificationContract.statusName(rawValue: 99), "unavailable")
    }

    /// Shown while the app is frontmost too: a request first seen then (the
    /// review route not current) is marked announced, so it must be visible.
    func testForegroundPresentationIsVisible() {
        let options = ReviewNotificationContract.foregroundPresentation
        XCTAssertTrue(options.contains(.banner))
        XCTAssertTrue(options.contains(.list))
        XCTAssertNotEqual(options, [])
    }

    func testWithdrawAcceptsOnlyTokens() {
        let token = "abcdefghijklmnopqrstu_"
        XCTAssertEqual(ReviewNotificationContract.tokens(fromWithdraw: ["tokens": [token, token]]), [token, token])
        XCTAssertNil(ReviewNotificationContract.tokens(fromWithdraw: ["tokens": [token, String(repeating: "A", count: 43)]]))
        XCTAssertNil(ReviewNotificationContract.tokens(fromWithdraw: ["tokens": [String]()]))
        XCTAssertNil(ReviewNotificationContract.tokens(fromWithdraw: ["tokens": [token], "extra": 1]))
        XCTAssertNil(ReviewNotificationContract.tokens(fromWithdraw: ["tokens": Array(repeating: token, count: 257)]))
        XCTAssertNil(ReviewNotificationContract.tokens(fromWithdraw: [token]))
    }

    func testClicksBeforeFlutterListensAreQueued() {
        var queue = ReviewNotificationContract.PendingOpens()
        queue.enqueue("aaaaaaaaaaaaaaaaaaaaaa")
        queue.enqueue("bbbbbbbbbbbbbbbbbbbbbb")
        queue.enqueue("aaaaaaaaaaaaaaaaaaaaaa") // clicked again: moves to the end
        queue.enqueue("not a token")
        XCTAssertEqual(queue.drain(), ["bbbbbbbbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaaaaaaaa"])
        XCTAssertEqual(queue.drain(), [])
        for index in 0..<20 { queue.enqueue(String(repeating: "x", count: 20) + String(format: "%02d", index)) }
        let kept = queue.drain()
        XCTAssertEqual(kept.count, ReviewNotificationContract.PendingOpens.limit)
        XCTAssertEqual(kept.last, String(repeating: "x", count: 20) + "19", "the newest click is kept")
    }

    func testAuthorizationRequiresAFreshArmWhileActive() {
        var gate = ReviewNotificationContract.AuthorizationGate()
        let now = Date(timeIntervalSince1970: 1_000)
        XCTAssertFalse(gate.consume(now: now, appActive: true), "never armed: refused")
        gate.arm(now: now)
        XCTAssertTrue(gate.consume(now: now.addingTimeInterval(1), appActive: true))
        XCTAssertFalse(gate.consume(now: now.addingTimeInterval(2), appActive: true), "one-shot")
        gate.arm(now: now)
        XCTAssertFalse(gate.consume(now: now, appActive: false), "app not in front")
        XCTAssertFalse(gate.consume(now: now, appActive: true), "a refusal disarms too")
        gate.arm(now: now)
        XCTAssertFalse(gate.consume(now: now.addingTimeInterval(ReviewNotificationContract.AuthorizationGate.window + 1),
                                    appActive: true), "stale arm")
    }

    func testWatchActivityIsHeldOnceAndReleased() {
        var begun = 0, ended = 0
        let activity = ReviewNotificationContract.WatchActivity(begin: { begun += 1; return NSObject() },
                                                                end: { _ in ended += 1 })
        activity.set(true)
        activity.set(true)
        XCTAssertEqual(begun, 1)
        XCTAssertTrue(activity.held)
        activity.set(false)
        activity.set(false)
        XCTAssertEqual(ended, 1)
        XCTAssertFalse(activity.held)
        // Prevents App Nap, never keeps the Mac awake.
        let options = ReviewNotificationContract.watchActivityOptions
        XCTAssertEqual(options, .userInitiatedAllowingIdleSystemSleep)
        XCTAssertFalse(options.contains(.idleSystemSleepDisabled))
    }
}
