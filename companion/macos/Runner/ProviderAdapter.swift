import Cocoa
import FlutterMacOS
import Security

/// Presentation and protocol state live in Flutter/Rust. This adapter owns only
/// explicit file selection, the development identity, durable recovery and TLS.
@MainActor final class ProviderAdapter {
    private let channel: FlutterMethodChannel
    private let settings: ProviderSettings
    private var active = false
    private var observers: [NSObjectProtocol] = []

    init(messenger: FlutterBinaryMessenger) {
        channel = FlutterMethodChannel(name: "dev.vaultwarden.companionSlice/provider", binaryMessenger: messenger)
        settings = ProviderSettings()
        channel.setMethodCallHandler { [weak self] call, result in
            guard let self else { result(FlutterError(code: "unavailable", message: nil, details: nil)); return }
            Task { @MainActor in await self.handle(call, result: result) }
        }
        observers.append(NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.channel.invokeMethod("invalidate", arguments: "sleep") }
        })
        observers.append(NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: nil, queue: .main) { [weak self] notification in
            guard notification.object is MainFlutterWindow else { return }
            Task { @MainActor in self?.channel.invokeMethod("invalidate", arguments: "close") }
        })
    }
    deinit {
        for observer in observers {
            NotificationCenter.default.removeObserver(observer)
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
    }
    private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) async {
        do {
            switch call.method {
            case "configuration": result(try settings.metadata())
            case "setup":
                guard !active, try settings.pendingID() == nil,
                      let args = call.arguments as? [String: Any], Set(args.keys) == ["endpoint", "pin", "passphrase"],
                      let endpoint = args["endpoint"] as? String, endpoint.utf8.count <= 2048,
                      let pin = args["pin"] as? String, validHex(pin, count: 64),
                      let passphrase = args["passphrase"] as? String, passphrase.utf8.count <= 4096,
                      let url = URL(string: endpoint) else { throw CompanionError.configuration }
                // Native file selection keeps the PKCS#12/private key out of Dart/Rust.
                let ca = try selectFile(title: "Select the development provider CA certificate (DER)", maximum: 65_536)
                let identity = try selectFile(title: "Select a dedicated Flutter development client identity (PKCS#12)", maximum: 1_048_576)
                try settings.install(endpoint: url, ca: ca, pin: pin, pkcs12: identity, passphrase: passphrase)
                result(try settings.metadata())
            case "send":
                guard !active, let bytes = call.arguments as? FlutterStandardTypedData,
                      bytes.data.count <= 16_384 else { throw CompanionError.configuration }
                let configuration = try settings.configuration()
                let transport = try PinnedTransport(configuration: configuration)
                // Persist before send. Even a process/window close remains uncertain.
                try settings.beforeSend(bytes.data)
                active = true
                defer { active = false }
                let response = try await transport.send(bytes.data)
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
    private func selectFile(title: String, maximum: Int) throws -> Data {
        let panel = NSOpenPanel()
        panel.title = title
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { throw CompanionError.configuration }
        let granted = url.startAccessingSecurityScopedResource()
        defer { if granted { url.stopAccessingSecurityScopedResource() } }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let bytes = try handle.read(upToCount: maximum + 1) ?? Data()
        guard !bytes.isEmpty, bytes.count <= maximum else { throw CompanionError.oversized }
        return bytes
    }
}
