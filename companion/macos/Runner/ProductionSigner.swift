import Cocoa
import FlutterMacOS
import LocalAuthentication

/// Platform plumbing for the production approval key. Rust builds and checks
/// every transcript and the provider verifies every proof; this channel only
/// creates, reads, deletes and signs with the key bound to the pinned
/// provider and client identities. It never accepts synthetic work.
final class ProductionSigner {
    private let channel: FlutterMethodChannel
    private let worker = DispatchQueue(label: "dev.vaultwarden.companionSlice.production-signer")
    private let gate = ProductionSignerGate()
    private var observers: [NSObjectProtocol] = []

    init(messenger: FlutterBinaryMessenger) {
        channel = FlutterMethodChannel(name: "dev.vaultwarden.companionSlice/approvalKey", binaryMessenger: messenger)
        channel.setMethodCallHandler { [weak self] call, result in self?.handle(call, result: result) }
        // Sleep, display sleep, fast user switching (session resigned), window
        // close and quit cancel an open prompt; it never outlives the session.
        let workspace = NSWorkspace.shared.notificationCenter
        for (center, name) in [(workspace, NSWorkspace.willSleepNotification),
                               (workspace, NSWorkspace.screensDidSleepNotification),
                               (workspace, NSWorkspace.sessionDidResignActiveNotification),
                               (NotificationCenter.default, NSWindow.willCloseNotification),
                               (NotificationCenter.default, NSApplication.willTerminateNotification)] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                self?.gate.cancelActive()
            })
        }
    }

    private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "availability":
            result(ProductionApprovalKey.availability() ? "touchID" : "unavailable")
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
                DispatchQueue.main.async { result(self.encode(reply)) }
            }
        case "sign":
            guard gate.idle, let args = call.arguments as? [String: Any],
                  let binding = binding(args, keys: ["session", "token", "purpose", "transcript"]),
                  let session = args["session"] as? String,
                  let token = (args["token"] as? NSNumber)?.uint32Value,
                  let purpose = (args["purpose"] as? String).flatMap(ProductionPurpose.init(rawValue:)),
                  let transcript = (args["transcript"] as? FlutterStandardTypedData)?.data,
                  transcript.count <= 4096 else {
                result(FlutterError(code: "invalid_request", message: "Invalid or overlapping signature", details: nil)); return
            }
            let context = ProductionApprovalKey.context()
            guard gate.begin(session: session, token: token, cancel: { context.invalidate() }) else {
                context.invalidate()
                result(FlutterError(code: "invalid_request", message: "Invalid or overlapping signature", details: nil)); return
            }
            let reason = purpose == .approve ? "approve one provider request" : "enroll this Mac's Touch ID approval key"
            let queue = worker
            worker.async {
                ProductionApprovalKey.sign(binding, purpose: purpose, transcript: transcript, reason: reason,
                                           context: context, worker: queue) { reply in
                    DispatchQueue.main.async {
                        self.gate.finish(session: session, token: token)
                        result(self.encode(reply))
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

    private func encode(_ reply: ProductionReply) -> [String: Any] {
        ["outcome": reply.outcome.rawValue,
         "publicKey": FlutterStandardTypedData(bytes: reply.publicKey),
         "signature": FlutterStandardTypedData(bytes: reply.signature)]
    }
}
