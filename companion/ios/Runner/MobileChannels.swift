import Flutter
import UIKit

/// Registers the iOS approval client's native channels on the implicit
/// Flutter engine (#60 phase 2): the production approval key, the provider
/// transport and review notifications. Mobile has no installation channel
/// (phones never install a desktop CLI) and no synthetic signer.
@MainActor final class MobileChannels {
    static let shared = MobileChannels()
    private var approvalKey: MobileApprovalKeyChannel?
    private var provider: MobileProviderAdapter?

    func attach(_ registry: FlutterPluginRegistry) {
        guard let messenger = registry.registrar(forPlugin: "CompanionMobileChannels")?.messenger() else { return }
        approvalKey = MobileApprovalKeyChannel(messenger: messenger)
        provider = MobileProviderAdapter(messenger: messenger)
        MobileReviewNotificationAdapter.shared.attach(messenger: messenger)
    }
}
