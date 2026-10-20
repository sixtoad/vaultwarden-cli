import Cocoa
import FlutterMacOS
import LocalAuthentication

/// Platform plumbing only. Rust owns review, expiry, admission and verification.
final class ApprovalSigner {
    private let channel: FlutterMethodChannel
    private let worker = DispatchQueue(label: "dev.vaultwarden.companionSlice.signer")
    private var attempts = NativeAttemptSlot()
    private var observers: [NSObjectProtocol] = []

    init(messenger: FlutterBinaryMessenger) {
        channel = FlutterMethodChannel(name: "dev.vaultwarden.companionSlice/signer", binaryMessenger: messenger)
        channel.setMethodCallHandler { [weak self] call, result in self?.handle(call, result: result) }
        observers.append(NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in self?.invalidate("sleep") })
        observers.append(NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification, object: nil, queue: .main) { [weak self] _ in self?.invalidate("close") })
        observers.append(NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification, object: nil, queue: .main) { [weak self] _ in self?.invalidate("close") })
    }

    private func invalidate(_ reason: String) {
        attempts.invalidate()
        channel.invokeMethod("invalidate", arguments: reason)
    }

    private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        if call.method == "availability" { result(NativeTestKey.availability() ? "touchID" : "unavailable"); return }
        if call.method == "cancel" {
            // Retain the active slot until the worker has returned.
            if let token = number(call.arguments, max: UInt64(UInt32.max)) {
                attempts.invalidate(token: UInt32(token))
            }
            result(nil); return
        }
        guard call.method == "perform" else { result(FlutterMethodNotImplemented); return }
        guard !attempts.isBusy, let args = call.arguments as? [String: Any],
              Set(args.keys) == Set(["token", "epoch", "operation", "fixture", "expiresUnixMs", "nonce", "keyId"]),
              let token = number(args["token"], max: UInt64(UInt32.max)), token > 0,
              let epoch = number(args["epoch"], max: UInt64(UInt32.max)),
              let fixture = number(args["fixture"], max: 2),
              let expires = number(args["expiresUnixMs"], max: UInt64(Int64.max)),
              let rawOperation = args["operation"] as? String, let operation = TestOperation(rawValue: rawOperation),
              let nonce = args["nonce"] as? FlutterStandardTypedData,
              let keyID = args["keyId"] as? FlutterStandardTypedData,
              let work = try? SyntheticWork(token: UInt32(token), epoch: UInt32(epoch), operation: operation,
                                            fixture: UInt32(fixture), expiresUnixMs: expires, nonce: nonce.data, keyID: keyID.data)
        else { result(FlutterError(code: "invalid_request", message: "Invalid or overlapping synthetic operation", details: nil)); return }
        let context = NativeTestKey.context(for: operation)
        guard attempts.begin(work, cancel: { context.invalidate() }) else {
            context.invalidate()
            result(FlutterError(code: "invalid_request", message: "Stale synthetic operation", details: nil))
            return
        }
        worker.async { [weak self] in
            let reply = NativeTestKey.perform(work, context: context)
            DispatchQueue.main.async {
                guard let self,
                      let accepted = self.attempts.finish(token: work.token, epoch: work.epoch, reply: reply) else { return }
                result(["outcome": accepted.outcome.rawValue,
                        "publicKey": FlutterStandardTypedData(bytes: accepted.publicKey),
                        "signature": FlutterStandardTypedData(bytes: accepted.signature)])
            }
        }
    }

    private func number(_ value: Any?, max: UInt64) -> UInt64? {
        guard let value = value as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(),
              value.doubleValue.isFinite, value.doubleValue <= Double(max),
              value.doubleValue >= 0, value.doubleValue.rounded() == value.doubleValue,
              value.uint64Value <= max else { return nil }
        return value.uint64Value
    }
}
