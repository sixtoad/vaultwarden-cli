import Foundation

/// Review-request notifications (#61). The only text a notification shows is
/// fixed here, natively, so Flutter can never put request content (labels,
/// targets, agents, request ids, values) on the lock screen. The single
/// argument Flutter supplies is an opaque per-process token that maps to the
/// request in Flutter memory only.
enum ReviewNotificationContract {
    static let title = "Approval companion"
    static let body = "A request needs your review."
    static let threadIdentifier = "review-requests"

    /// 22 base64url characters (16 random bytes). Request ids are 43, so a
    /// request id is never accepted as a token.
    static func validToken(_ value: String) -> Bool {
        value.utf8.count == 22 && value.utf8.allSatisfy { byte in
            (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
                || (byte >= 0x30 && byte <= 0x39) || byte == 0x2D || byte == 0x5F
        }
    }

    /// The `post` arguments: exactly `{"token": <valid token>}`.
    static func token(fromPost arguments: Any?) -> String? {
        guard let map = arguments as? [String: Any], map.count == 1,
              let token = map["token"] as? String, validToken(token) else { return nil }
        return token
    }

    /// Only the default action (a click on the notification body) opens a
    /// review. No categories or actions are registered, so there is no
    /// approve or deny button; anything else (dismiss) is ignored.
    static func opens(actionIdentifier: String, defaultAction: String) -> Bool {
        actionIdentifier == defaultAction
    }

    /// Authorization status names shared with Flutter.
    static func statusName(rawValue: Int) -> String {
        switch rawValue {
        case 0: return "notDetermined"
        case 1: return "denied"
        case 2, 3, 4: return "authorized" // authorized, provisional, ephemeral
        default: return "unavailable"
        }
    }
}
