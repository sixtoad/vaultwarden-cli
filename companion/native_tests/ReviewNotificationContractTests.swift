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
}
