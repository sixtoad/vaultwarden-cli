import Flutter
import UIKit
import UserNotifications

/// iOS side of review-request notifications (#61 rules, #60 phase 2). The
/// same channel and contract as macOS: only the fixed generic text of
/// `ReviewNotificationContract`, an opaque token as the identifier, no user
/// info, categories or actions (so no approve or deny button, on the lock
/// screen or anywhere). A tap opens the app and hands Flutter the token;
/// Flutter loads a fresh review of that exact request itself. A notification
/// never approves, denies or submits anything.
///
/// iOS suspends a backgrounded app, so `watching` holds no activity here:
/// notifications are posted while the app runs. Remote push is out of scope.
@MainActor final class MobileReviewNotificationAdapter: NSObject, UNUserNotificationCenterDelegate {
    static let shared = MobileReviewNotificationAdapter()
    private static let enabledKey = "reviewNotificationsEnabled"
    private var channel: FlutterMethodChannel?
    private var pendingOpens = ReviewNotificationContract.PendingOpens()
    private var listening = false
    private var authorization = ReviewNotificationContract.AuthorizationGate()

    /// Set the delegate before launch finishes so a launch tap is delivered.
    func install() { UNUserNotificationCenter.current().delegate = self }

    func attach(messenger: FlutterBinaryMessenger) {
        let channel = FlutterMethodChannel(name: "dev.vaultwarden.companionSlice/notifications", binaryMessenger: messenger)
        self.channel = channel
        listening = false
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
            authorization.arm(now: Date())
            result(nil)
        case "requestAuthorization":
            guard authorization.consume(now: Date(), appActive: UIApplication.shared.applicationState == .active) else {
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
            guard let tokens = ReviewNotificationContract.tokens(fromWithdraw: call.arguments) else {
                result(FlutterError(code: "invalid", message: nil, details: nil)); return
            }
            center.removeDeliveredNotifications(withIdentifiers: tokens)
            center.removePendingNotificationRequests(withIdentifiers: tokens)
            result(nil)
        case "watching":
            guard call.arguments is Bool else { result(FlutterError(code: "invalid", message: nil, details: nil)); return }
            result(nil)
        case "listen":
            listening = true
            result(pendingOpens.drain())
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler(ReviewNotificationContract.foregroundPresentation)
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                            withCompletionHandler completionHandler: @escaping () -> Void) {
        let token = response.notification.request.identifier
        let opens = ReviewNotificationContract.opens(actionIdentifier: response.actionIdentifier,
                                                     defaultAction: UNNotificationDefaultActionIdentifier)
        DispatchQueue.main.async {
            MainActor.assumeIsolated {
                if opens, ReviewNotificationContract.validToken(token) {
                    if self.listening, let channel = self.channel { channel.invokeMethod("open", arguments: token) }
                    else { self.pendingOpens.enqueue(token) }
                }
                completionHandler()
            }
        }
    }
}
