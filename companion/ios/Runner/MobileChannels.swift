import Flutter
import UIKit

/// Registers the iOS approval client's native channels on the implicit
/// Flutter engine (#60 phase 2): the production approval key, the provider
/// transport, review notifications and device lock signals. Mobile has no installation channel
/// (phones never install a desktop CLI) and no synthetic signer.
@MainActor final class MobileChannels {
    static let shared = MobileChannels()
    private var approvalKey: MobileApprovalKeyChannel?
    private var provider: MobileProviderAdapter?
    private var lifecycle: FlutterMethodChannel?
    private var observers: [NSObjectProtocol] = []

    func attach(_ registry: FlutterPluginRegistry) {
        guard let messenger = registry.registrar(forPlugin: "CompanionMobileChannels")?.messenger() else { return }
        approvalKey = MobileApprovalKeyChannel(messenger: messenger)
        provider = MobileProviderAdapter(messenger: messenger)
        MobileReviewNotificationAdapter.shared.attach(messenger: messenger)
        let lifecycle = FlutterMethodChannel(name: "dev.vaultwarden.companionSlice/lifecycle", binaryMessenger: messenger)
        self.lifecycle = lifecycle
        observers.forEach(NotificationCenter.default.removeObserver)
        observers = MobileLifecycle.deviceSignals.map { name, signal in
            NotificationCenter.default.addObserver(forName: Notification.Name(name), object: nil, queue: .main) { _ in
                lifecycle.invokeMethod("signal", arguments: signal)
            }
        }
    }
}
