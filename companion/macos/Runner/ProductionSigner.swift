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
    private var active: (token: UInt32, context: LAContext)?
    private var lastToken: UInt32 = 0
    private var observers: [NSObjectProtocol] = []

    init(messenger: FlutterBinaryMessenger) {
        channel = FlutterMethodChannel(name: "dev.vaultwarden.companionSlice/approvalKey", binaryMessenger: messenger)
        channel.setMethodCallHandler { [weak self] call, result in self?.handle(call, result: result) }
        for (center, name) in [(NSWorkspace.shared.notificationCenter, NSWorkspace.willSleepNotification),
                               (NotificationCenter.default, NSWindow.willCloseNotification),
                               (NotificationCenter.default, NSApplication.willTerminateNotification)] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                self?.active?.context.invalidate()
            })
        }
    }

    private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "availability":
            result(ProductionApprovalKey.availability() ? "touchID" : "unavailable")
        case "cancel":
            if let token = call.arguments as? NSNumber, active?.token == token.uint32Value {
                active?.context.invalidate()
            }
            result(nil)
        case "read", "create", "delete":
            guard active == nil, let binding = binding(call.arguments, keys: []) else {
                result(FlutterError(code: "invalid_request", message: "Invalid or overlapping key operation", details: nil)); return
            }
            let method = call.method
            worker.async {
                let reply = method == "read" ? ProductionApprovalKey.read(binding)
                    : method == "create" ? ProductionApprovalKey.create(binding) : ProductionApprovalKey.delete(binding)
                DispatchQueue.main.async { result(self.encode(reply)) }
            }
        case "sign":
            guard active == nil, let args = call.arguments as? [String: Any],
                  let binding = binding(args, keys: ["token", "purpose", "transcript"]),
                  let token = args["token"] as? NSNumber, token.uint32Value > lastToken,
                  let purpose = (args["purpose"] as? String).flatMap(ProductionPurpose.init(rawValue:)),
                  let transcript = (args["transcript"] as? FlutterStandardTypedData)?.data,
                  transcript.count <= 4096 else {
                result(FlutterError(code: "invalid_request", message: "Invalid or overlapping signature", details: nil)); return
            }
            let context = ProductionApprovalKey.context()
            lastToken = token.uint32Value
            active = (token.uint32Value, context)
            let reason = purpose == .approve ? "approve one provider request" : "enroll this Mac's Touch ID approval key"
            let queue = worker
            worker.async {
                ProductionApprovalKey.sign(binding, purpose: purpose, transcript: transcript, reason: reason,
                                           context: context, worker: queue) { reply in
                    DispatchQueue.main.async {
                        if self.active?.token == token.uint32Value { self.active = nil }
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
