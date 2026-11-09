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
    /// A click that arrived before Flutter attached (launch from a notification).
    private var pendingOpen: String?
    private var listening = false

    /// Set the delegate before launch finishes so a launch click is delivered.
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
        case "requestAuthorization":
            // Only ever called from the Settings toggle (explicit user action).
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
        case "listen":
            // Flutter is ready for clicks; return one that launched the app.
            listening = true
            let token = pendingOpen
            pendingOpen = nil
            result(token)
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        // The app is frontmost: the request list is already on screen.
        completionHandler([])
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
        if listening, let channel { channel.invokeMethod("open", arguments: token) } else { pendingOpen = token }
    }
}
