import Flutter
import LocalAuthentication
import UIKit

/// iOS plumbing for the production approval key (#60 phase 2). The same
/// channel name and method contract as the macOS `ProductionSigner`: Rust
/// builds and checks every transcript and the provider verifies every proof;
/// this channel only creates, reads, deletes and signs with the Secure
/// Enclave key bound to the pinned provider and client identities
/// (`ProductionApprovalKey`, shared with macOS). Face ID or Touch ID on the
/// current enrollment, a fresh `LAContext` per operation, no reuse window and
/// no passcode fallback. A cancelled or failed prompt returns its outcome and
/// nothing else; this channel never approves and never sends anything.
final class MobileApprovalKeyChannel {
    private let channel: FlutterMethodChannel
    private let worker = DispatchQueue(label: "dev.vaultwarden.companionSlice.mobile-approval-key")
    private let gate = ProductionSignerGate()
    private var observers: [NSObjectProtocol] = []

    init(messenger: FlutterBinaryMessenger) {
        channel = FlutterMethodChannel(name: "dev.vaultwarden.companionSlice/approvalKey", binaryMessenger: messenger)
        channel.setMethodCallHandler { [weak self] call, result in self?.handle(call, result: result) }
        // Background, device lock and termination cancel an open prompt.
        // Not resign-active: iOS resigns the app to show the biometric sheet.
        for name in MobileLifecycle.signerCancelTriggers {
            observers.append(NotificationCenter.default.addObserver(forName: Notification.Name(name), object: nil,
                                                                    queue: .main) { [weak self] _ in
                self?.gate.cancelActive()
            })
        }
    }

    deinit { observers.forEach(NotificationCenter.default.removeObserver) }

    private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "availability":
            result(MobileApproval.availabilityName(ProductionApprovalKey.biometry()?.rawValue))
        case "cancel":
            if let args = call.arguments as? [String: Any], args.count == 2,
               let session = args["session"] as? String, let token = args["token"] as? NSNumber {
                gate.cancel(session: session, token: token.uint32Value)
            }
            result(nil)
        case "read", "create", "delete":
            guard gate.idle, let binding = binding(call.arguments, keys: []) else {
                result(FlutterError(code: "invalid_request", message: "Invalid or overlapping key operation", details: nil)); return
            }
            let method = call.method
            worker.async {
                let reply = method == "read" ? ProductionApprovalKey.read(binding)
                    : method == "create" ? ProductionApprovalKey.create(binding) : ProductionApprovalKey.delete(binding)
                DispatchQueue.main.async { result(Self.encode(reply)) }
            }
        case "sign":
            guard gate.idle, UIApplication.shared.applicationState != .background,
                  let args = call.arguments as? [String: Any],
                  let binding = binding(args, keys: ["session", "token", "purpose", "transcript"]),
                  let session = args["session"] as? String,
                  let token = (args["token"] as? NSNumber)?.uint32Value,
                  let purpose = (args["purpose"] as? String).flatMap(ProductionPurpose.init(rawValue:)),
                  let transcript = (args["transcript"] as? FlutterStandardTypedData)?.data,
                  transcript.count <= 4096, let biometry = ProductionApprovalKey.biometry() else {
                result(FlutterError(code: "invalid_request", message: "Invalid or overlapping signature", details: nil)); return
            }
            let context = ProductionApprovalKey.context()
            guard gate.begin(session: session, token: token, cancel: { context.invalidate() }) else {
                context.invalidate()
                result(FlutterError(code: "invalid_request", message: "Invalid or overlapping signature", details: nil)); return
            }
            let reason = MobileApproval.reason(purpose: purpose.rawValue, biometry: biometry.rawValue)
            let queue = worker
            worker.async {
                // Rust checks and verifies the signature before any proof is
                // sent (shared-approval-checks-spec S-3); this channel only signs.
                ProductionApprovalKey.sign(binding, purpose: purpose, transcript: transcript, reason: reason,
                                           context: context, worker: queue) { reply in
                    DispatchQueue.main.async {
                        self.gate.finish(session: session, token: token)
                        result(Self.encode(reply))
                    }
                }
            }
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func binding(_ arguments: Any?, keys: Set<String>) -> ProductionBinding? {
        guard let args = arguments as? [String: Any],
              Set(args.keys) == keys.union(["providerIdentity", "approvalClient"]),
              let provider = args["providerIdentity"] as? String, let client = args["approvalClient"] as? String else {
            return nil
        }
        return try? ProductionBinding(providerHex: provider, clientHex: client)
    }

    private static func encode(_ reply: ProductionReply) -> [String: Any] {
        ["outcome": reply.outcome.rawValue,
         "publicKey": FlutterStandardTypedData(bytes: reply.publicKey),
         "signature": FlutterStandardTypedData(bytes: reply.signature)]
    }
}
