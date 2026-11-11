import Foundation
import UserNotifications

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

    /// Presentation while the app is frontmost (D7). Flutter posts only when
    /// the review route is not current, so a request first seen then is not
    /// on screen; it is shown rather than marked announced and suppressed.
    static let foregroundPresentation: UNNotificationPresentationOptions = [.banner, .list]

    /// The `withdraw` arguments: exactly `{"tokens": [<valid token>, ...]}`,
    /// one to 256 tokens (the number Flutter remembers).
    static func tokens(fromWithdraw arguments: Any?) -> [String]? {
        guard let map = arguments as? [String: Any], map.count == 1,
              let tokens = map["tokens"] as? [String], (1...256).contains(tokens.count),
              tokens.allSatisfy(validToken) else { return nil }
        return tokens
    }

    /// Clicks that arrived before Flutter listened, oldest first. A token
    /// clicked again moves to the end; past `limit` the oldest is dropped.
    struct PendingOpens {
        static let limit = 8
        private var tokens: [String] = []
        mutating func enqueue(_ token: String) {
            guard ReviewNotificationContract.validToken(token) else { return }
            tokens.removeAll { $0 == token }
            tokens.append(token)
            if tokens.count > Self.limit { tokens.removeFirst(tokens.count - Self.limit) }
        }
        mutating func drain() -> [String] {
            defer { tokens = [] }
            return tokens
        }
    }

    /// The permission prompt runs only right after the Settings toggle armed
    /// it (D8): one-shot, within `window` seconds, with the app in front. A
    /// refusal disarms too, so a stray request cannot use a later arm.
    struct AuthorizationGate {
        static let window: TimeInterval = 10
        private var armedAt: Date?
        mutating func arm(now: Date) { armedAt = now }
        mutating func consume(now: Date, appActive: Bool) -> Bool {
            defer { armedAt = nil }
            guard let armedAt, appActive else { return false }
            let age = now.timeIntervalSince(armedAt)
            return age >= 0 && age <= Self.window
        }
    }

    /// The background watch's system activity (D6): it keeps App Nap from
    /// throttling the 15 s timer while the window is hidden, and still lets
    /// the Mac sleep when idle.
    static let watchActivityOptions: ProcessInfo.ActivityOptions = .userInitiatedAllowingIdleSystemSleep
    static let watchActivityReason = "Watching for review requests"

    /// Holds at most one activity; `set(false)` releases it.
    final class WatchActivity {
        private let begin: () -> NSObjectProtocol
        private let end: (NSObjectProtocol) -> Void
        private var token: NSObjectProtocol?
        init(begin: @escaping () -> NSObjectProtocol, end: @escaping (NSObjectProtocol) -> Void) {
            self.begin = begin
            self.end = end
        }
        var held: Bool { token != nil }
        func set(_ on: Bool) {
            if on, token == nil { token = begin() }
            if !on, let current = token { token = nil; end(current) }
        }
    }
}
