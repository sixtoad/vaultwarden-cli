import Flutter
import Security
import UIKit
import UniformTypeIdentifiers

/// iOS provider transport (#60 phase 2): the macOS `ProviderAdapter` contract
/// on UIKit. Presentation and protocol state live in Flutter/Rust; this
/// adapter owns only explicit file selection, the client identity, durable
/// recovery and TLS. The client identity is imported into this app's Keychain
/// (`...WhenUnlockedThisDeviceOnly`, never exported or migrated); the
/// provider leaf is pinned by `PinnedTransport` exactly as on macOS: the
/// enrolled private CA only, hostname, validity, then the SHA-256 leaf pin.
/// There is no system-trust fallback.
@MainActor final class MobileProviderAdapter {
    private let channel: FlutterMethodChannel
    private let settings: ProviderSettings
    private var active = false
    private let managementGate = ManagementTransportGate()
    private var observers: [NSObjectProtocol] = []
    private let picker = DocumentPicker()

    init(messenger: FlutterBinaryMessenger) {
        channel = FlutterMethodChannel(name: "dev.vaultwarden.companionSlice/provider", binaryMessenger: messenger)
        settings = ProviderSettings()
        channel.setMethodCallHandler { [weak self] call, result in
            guard let self else { result(FlutterError(code: "unavailable", message: nil, details: nil)); return }
            Task { @MainActor in await self.handle(call, result: result) }
        }
        for (name, reason) in MobileLifecycle.providerInvalidations {
            observers.append(NotificationCenter.default.addObserver(forName: Notification.Name(name), object: nil,
                                                                    queue: .main) { [weak self] _ in
                MainActor.assumeIsolated {
                    self?.managementGate.invalidate()
                    self?.channel.invokeMethod("invalidate", arguments: reason)
                }
            })
        }
        // Resign-active (app switcher, notification shade, the biometric
        // sheet) drops only a prepared administrative ticket, natively.
        observers.append(NotificationCenter.default.addObserver(forName: Notification.Name(MobileLifecycle.willResignActive),
                                                                object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.managementGate.invalidate() }
        })
    }

    deinit { observers.forEach(NotificationCenter.default.removeObserver) }

    private var foreground: Bool { UIApplication.shared.applicationState == .active }

    private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) async {
        do {
            switch call.method {
            case "configuration": result(try settings.metadata())
            case "setup":
                guard !active, foreground, try !settings.hasPending(),
                      let args = call.arguments as? [String: Any], Set(args.keys) == ["endpoint", "pin", "passphrase"],
                      let endpoint = args["endpoint"] as? String, endpoint.utf8.count <= 2048,
                      let pin = args["pin"] as? String, validHex(pin, count: 64),
                      let passphrase = args["passphrase"] as? String, passphrase.utf8.count <= 4096,
                      let url = URL(string: endpoint) else { throw CompanionError.configuration }
                active = true
                defer { active = false }
                // Native file selection keeps the PKCS#12/private key out of Dart/Rust.
                let ca = try await picker.select(maximum: 65_536)
                let identity = try await picker.select(maximum: 1_048_576)
                try settings.install(endpoint: url, ca: ca, pin: pin, pkcs12: identity, passphrase: passphrase)
                result(try settings.metadata())
            case "send":
                guard !active, let bytes = call.arguments as? FlutterStandardTypedData,
                      bytes.data.count <= 16_384 else { throw CompanionError.configuration }
                let managementEpoch = try managementGate.begin(bytes.data, foreground: foreground)
                let configuration = try settings.configuration()
                let transport = try PinnedTransport(configuration: configuration)
                // Persist before send. Even a suspension or termination remains uncertain.
                try settings.beforeSend(bytes.data)
                active = true
                defer { active = false }
                let response = try await transport.send(bytes.data)
                try managementGate.finish(bytes.data, response: response, started: managementEpoch, foreground: foreground)
                result(FlutterStandardTypedData(bytes: response))
            case "settle":
                guard let id = call.arguments as? String, validRequestID(id) else { throw CompanionError.configuration }
                try settings.settle(id)
                result(nil)
            default: result(FlutterMethodNotImplemented)
            }
        } catch let error as ProviderSettingsError {
            result(FlutterError(code: error.code, message: "Provider setup, trust or transport unavailable.", details: nil))
        } catch {
            // Never return NSError descriptions, keychain paths, request bodies or passwords.
            result(FlutterError(code: "provider_unavailable", message: "Provider setup, trust or transport unavailable.", details: nil))
        }
    }
}

/// One document at a time from the Files picker, copied into the app's
/// sandbox by the system (`asCopy`) and read with a size bound.
@MainActor final class DocumentPicker: NSObject, UIDocumentPickerDelegate {
    private var continuation: CheckedContinuation<URL?, Never>?

    func select(maximum: Int) async throws -> Data {
        guard continuation == nil, let presenter = Self.presenter() else { throw CompanionError.configuration }
        let controller = UIDocumentPickerViewController(forOpeningContentTypes: [.data], asCopy: true)
        controller.allowsMultipleSelection = false
        controller.delegate = self
        let url = await withCheckedContinuation { continuation in
            self.continuation = continuation
            presenter.present(controller, animated: true)
        }
        guard let url else { throw CompanionError.configuration }
        defer { try? FileManager.default.removeItem(at: url) } // the sandbox copy
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let bytes = try handle.read(upToCount: maximum + 1) ?? Data()
        guard !bytes.isEmpty, bytes.count <= maximum else { throw CompanionError.oversized }
        return bytes
    }

    nonisolated func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        MainActor.assumeIsolated { finish(urls.count == 1 ? urls[0] : nil) }
    }

    nonisolated func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        MainActor.assumeIsolated { finish(nil) }
    }

    private func finish(_ url: URL?) {
        let pending = continuation
        continuation = nil
        pending?.resume(returning: url)
    }

    private static func presenter() -> UIViewController? {
        let scene = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive }
        var top = scene?.keyWindow?.rootViewController
        while let next = top?.presentedViewController { top = next }
        return top
    }
}
