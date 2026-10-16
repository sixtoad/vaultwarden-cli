import AppKit
// The Objective-C framework predates Sendable annotations. Each context belongs
// to one worker; the main actor only invokes its cancellation API (invalidate).
@preconcurrency import LocalAuthentication
import ProbeCore
import SwiftUI

@MainActor final class ProbeModel: ObservableObject {
    @Published private(set) var gate = AttemptGate()
    @Published private(set) var result = "Not run. No key is created until you choose Create test key."
    @Published private(set) var fingerprint = "Not read"
    private var context: LAContext?

    func run(_ operation: ProbeOperation) {
        guard let token = gate.begin(operation) else { return }
        let authentication = LAContext()
        authentication.touchIDAuthenticationAllowableReuseDuration = 0
        authentication.localizedFallbackTitle = ""
        authentication.localizedReason = "Sign one synthetic Touch ID feasibility message"
        authentication.interactionNotAllowed = operation != .sign
        context = authentication
        result = "Running \(operation.rawValue)…"
        DispatchQueue.global(qos: .userInitiated).async {
            let observation = NativeKey.perform(operation, context: authentication)
            Task { @MainActor in
                guard let accepted = self.gate.finish(token, outcome: observation.outcome) else { return }
                self.context = nil
                self.result = "\(operation.rawValue): \(accepted.rawValue)"
                if accepted != .cancelled, let publicFingerprint = observation.fingerprint {
                    self.fingerprint = publicFingerprint
                }
                if accepted == .created || accepted == .deleted { self.fingerprint = "Not read" }
            }
        }
    }

    func cancel() {
        guard gate.active != nil else { return }
        gate.cancel()
        context?.invalidate()
        result = "Cancellation requested; waiting for the native worker. Completed key changes and unsafe results will still be reported."
    }
}

@main struct TouchIDProbeApp: App {
    @StateObject private var model = ProbeModel()

    var body: some Scene {
        WindowGroup("Touch ID feasibility — synthetic data only") {
            VStack(alignment: .leading, spacing: 14) {
                Text("Touch ID signing probe").font(.title)
                Text("Not connected to your vault or Linux provider. This app cannot approve a real operation.")
                Text("1. Create a test key, then Reopen. Record the public fingerprint.\n2. Run No-interaction check: expect interactionRequired, never unsafe.\n3. Sign once and touch the sensor; immediately run No-interaction check again. Repeat Sign once with a separate touch and repeat the negative check.\n4. Try Sign once and cancel the system prompt.\n5. Quit/reopen this app, then Reopen and repeat the checks.\n6. Delete the test key when finished.")
                HStack {
                    Button("Create test key") { model.run(.create) }
                    Button("Reopen test key") { model.run(.reopen) }
                    Button("No-interaction check") { model.run(.noInteraction) }
                }.disabled(model.gate.active != nil)
                HStack {
                    Button("Sign once with Touch ID") { model.run(.sign) }
                        .disabled(model.gate.active != nil)
                    Button("Cancel attempt") { model.cancel() }
                        .disabled(model.gate.active == nil)
                    Button("Delete this probe's test key", role: .destructive) { model.run(.delete) }
                        .disabled(model.gate.active != nil)
                }
                Divider()
                Text(model.result).textSelection(.enabled)
                Text("Verified signatures this session: \(model.gate.verifiedSignatures); blocked no-interaction checks: \(model.gate.blockedWithoutInteraction)")
                Text("Public test-key SHA-256: \(model.fingerprint)").font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                Text("These are API observations, not automatic proof of a fresh fingerprint. Report whether every Sign once required a new touch. Any unsafe result stops acceptance; do not use this for real credentials.")
                    .foregroundStyle(.secondary)
                Text(ProcessInfo.processInfo.operatingSystemVersionString).font(.caption)
            }
            .padding(24).frame(width: 780)
            .onDisappear { model.cancel() }
            .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.willSleepNotification)) { _ in
                model.cancel()
            }
        }
    }
}
