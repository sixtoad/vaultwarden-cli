import Cocoa
import FlutterMacOS
import UserNotifications

/// Native side of review-request notifications (#61). Posts only the fixed
/// generic text of `ReviewNotificationContract`, with an opaque token as the
/// identifier and no user info, categories or actions. A click brings the app
/// forward and hands Flutter the token; Flutter loads a fresh review itself.
@MainActor final class ReviewNotificationAdapter: NSObject, UNUserNotificationCenterDelegate {
    static let shared = ReviewNotificationAdapter()
    private static let enabledKey = "reviewNotificationsEnabled"
    private var channel: FlutterMethodChannel?
    /// Clicks that arrived before Flutter listened (launch from a notification).
    private var pendingOpens = ReviewNotificationContract.PendingOpens()
    private var listening = false
    private var authorization = ReviewNotificationContract.AuthorizationGate()
    /// Keeps App Nap off the background watch's timer while it runs.
    private let watchActivity = ReviewNotificationContract.WatchActivity(
        begin: {
            ProcessInfo.processInfo.beginActivity(options: ReviewNotificationContract.watchActivityOptions,
                                                  reason: ReviewNotificationContract.watchActivityReason)
        },
        end: { ProcessInfo.processInfo.endActivity($0) })

    /// Set the delegate before launch finishes so a launch click is delivered.
    func install() { UNUserNotificationCenter.current().delegate = self }

    func attach(messenger: FlutterBinaryMessenger) {
        let channel = FlutterMethodChannel(name: "dev.vaultwarden.companionSlice/notifications", binaryMessenger: messenger)
        self.channel = channel
        listening = false
        watchActivity.set(false)
        channel.setMethodCallHandler { [weak self] call, result in
            guard let self else { result(FlutterError(code: "unavailable", message: nil, details: nil)); return }
            MainActor.assumeIsolated { self.handle(call, result: result) }
        }
    }

    private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let center = UNUserNotificationCenter.current()
        switch call.method {
        case "status":
            center.getNotificationSettings { settings in
                let name = ReviewNotificationContract.statusName(rawValue: settings.authorizationStatus.rawValue)
                DispatchQueue.main.async { result(name) }
            }
        case "armAuthorization":
            // Called only by the Settings toggle, right before it asks.
            authorization.arm(now: Date())
            result(nil)
        case "requestAuthorization":
            // Refused unless the toggle armed it just now with the app in front.
            guard authorization.consume(now: Date(), appActive: NSApp.isActive) else {
                result(FlutterError(code: "not_armed", message: nil, details: nil)); return
            }
            center.requestAuthorization(options: [.alert, .sound]) { _, _ in
                UNUserNotificationCenter.current().getNotificationSettings { settings in
                    let name = ReviewNotificationContract.statusName(rawValue: settings.authorizationStatus.rawValue)
                    DispatchQueue.main.async { result(name) }
                }
            }
        case "enabled":
            result(UserDefaults.standard.bool(forKey: Self.enabledKey))
        case "setEnabled":
            guard let value = call.arguments as? Bool else { result(FlutterError(code: "invalid", message: nil, details: nil)); return }
            UserDefaults.standard.set(value, forKey: Self.enabledKey)
            if !value { center.removeAllDeliveredNotifications(); center.removeAllPendingNotificationRequests() }
            result(nil)
        case "post":
            guard let token = ReviewNotificationContract.token(fromPost: call.arguments) else {
                result(FlutterError(code: "invalid", message: nil, details: nil)); return
            }
            let content = UNMutableNotificationContent()
            content.title = ReviewNotificationContract.title
            content.body = ReviewNotificationContract.body
            content.threadIdentifier = ReviewNotificationContract.threadIdentifier
            content.sound = .default
            center.add(UNNotificationRequest(identifier: token, content: content, trigger: nil)) { error in
                DispatchQueue.main.async {
                    if error == nil { result(nil) } else { result(FlutterError(code: "post_failed", message: nil, details: nil)) }
                }
            }
        case "withdraw":
            // The request was decided or expired: its banner goes too.
            guard let tokens = ReviewNotificationContract.tokens(fromWithdraw: call.arguments) else {
                result(FlutterError(code: "invalid", message: nil, details: nil)); return
            }
            center.removeDeliveredNotifications(withIdentifiers: tokens)
            center.removePendingNotificationRequests(withIdentifiers: tokens)
            result(nil)
        case "watching":
            guard let value = call.arguments as? Bool else { result(FlutterError(code: "invalid", message: nil, details: nil)); return }
            watchActivity.set(value)
            result(nil)
        case "listen":
            // Flutter is ready for clicks; return those that arrived before.
            listening = true
            result(pendingOpens.drain())
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        // Frontmost, Flutter posts only when the review route is not current,
        // so the request is not on screen: show it (D7).
        completionHandler(ReviewNotificationContract.foregroundPresentation)
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                            withCompletionHandler completionHandler: @escaping () -> Void) {
        let token = response.notification.request.identifier
        let opens = ReviewNotificationContract.opens(actionIdentifier: response.actionIdentifier,
                                                     defaultAction: UNNotificationDefaultActionIdentifier)
        DispatchQueue.main.async {
            MainActor.assumeIsolated {
                if opens, ReviewNotificationContract.validToken(token) { self.open(token) }
                completionHandler()
            }
        }
    }

    private func open(_ token: String) {
        NSApp.unhide(nil)
        if let window = NSApp.windows.first(where: { $0 is MainFlutterWindow }) {
            if window.isMiniaturized { window.deminiaturize(nil) }
            window.makeKeyAndOrderFront(nil)
        }
        NSApp.activate(ignoringOtherApps: true)
        if listening, let channel { channel.invokeMethod("open", arguments: token) } else { pendingOpens.enqueue(token) }
    }
}
