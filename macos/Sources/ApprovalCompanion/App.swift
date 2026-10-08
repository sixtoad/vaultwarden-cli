import AppKit
import CompanionCore
import ServiceManagement
import SwiftUI
import UniformTypeIdentifiers
import UserNotifications

enum InboxTab: Hashable { case approvals, setup }

@MainActor final class AppModel: ObservableObject {
    @Published var selectedTab: InboxTab = .approvals
    @Published var controller: DecisionController?
    @Published var pending: [String] = []
    @Published var sessionState = "unavailable"
    @Published var connection = "Complete trusted setup."
    @Published var configuration: ProviderConfiguration?
    @Published var unlockBusy = false
    @Published var unlockPassword = ""
    private var client: (any CompanionServing)?
    private var pollTask: Task<Void, Never>?
    private var generation: UInt64?
    private var lifecycle: UInt64 = 0
    private var seen = Set<String>()
    private let automaticallyPoll: Bool
    private let preferencesKey = "providerConfiguration.v1"
    private var workspaceObservers: [NSObjectProtocol] = []
    init() {
        automaticallyPoll = true
        // Observe lifecycle independently of the inbox window's lifetime.
        let center = NSWorkspace.shared.notificationCenter
        workspaceObservers.append(center.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.sleeping() }
        })
        workspaceObservers.append(center.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.start() }
        })
        if let data = UserDefaults.standard.data(forKey: preferencesKey),
           let saved = try? JSONDecoder().decode(ProviderConfiguration.self, from: data),
           let valid = try? saved.validated() { configure(valid) }
    }
    // Tests drive the same pollOnce path without timers, preferences or notifications.
    init(client: any CompanionServing) {
        automaticallyPoll = false
        replaceClient(client)
    }
    func configure(_ configuration: ProviderConfiguration) {
        unlockPassword = ""
        do {
            let transport = try PinnedTransport(configuration: configuration)
            let newClient = CompanionClient(transport: transport)
            UserDefaults.standard.set(try JSONEncoder().encode(configuration), forKey: preferencesKey)
            self.configuration = configuration
            replaceClient(newClient)
        } catch { connection = "Setup invalid. Check endpoint, CA, pin and Keychain identity." }
    }
    func replaceClient(_ newClient: any CompanionServing) {
        invalidateContext()
        client = newClient; controller = DecisionController(client: newClient)
        generation = nil; seen = []; pending = []; sessionState = "unavailable"
        start()
    }
    private func invalidateContext() {
        lifecycle &+= 1
        controller?.invalidate()
        unlockPassword = ""; unlockBusy = false
    }
    func start() {
        pollTask?.cancel()
        invalidateContext()
        guard client != nil, automaticallyPoll else { return }
        pollTask = Task { [weak self] in
            var backoff: UInt64 = 5
            while !Task.isCancelled {
                guard let connected = await self?.pollOnce() else { return }
                backoff = connected ? 5 : min(backoff * 2, 60)
                do { try await Task.sleep(nanoseconds: backoff * 1_000_000_000) }
                catch { return }
            }
        }
    }
    @discardableResult func pollOnce() async -> Bool {
        guard let client else { return false }
        let epoch = lifecycle
        do {
            let state = try await client.session()
            guard epoch == lifecycle, !Task.isCancelled else { return false }
            let ids = state.state == "unlocked" ? try await client.list() : []
            guard epoch == lifecycle, !Task.isCancelled else { return false }
            apply(state, ids: ids)
            let newIDs = Set(ids).subtracting(seen)
            seen = Set(ids)
            if !newIDs.isEmpty, automaticallyPoll { notify() }
            if let controller, controller.uncertain { await controller.refreshUncertainStatus() }
            return true
        } catch {
            guard epoch == lifecycle, !Task.isCancelled else { return false }
            invalidateContext()
            sessionState = "unavailable"; pending = []
            connection = "Disconnected. Retrying reads only."
            return false
        }
    }
    private func apply(_ state: SessionResponse, ids: [String]) {
        if generation != state.generation || sessionState != state.state {
            invalidateContext()
        } else if state.state != "unlocked" {
            controller?.invalidate()
        }
        if let id = controller?.review?.review.id, !ids.contains(id) { controller?.invalidate() }
        generation = state.generation; sessionState = state.state
        pending = ids; connection = "Connected"
    }
    var inboxCapacityExplanation: String? {
        pending.count == 256 ? "Showing up to 256 pending requests. Later requests appear as slots become available." : nil
    }
    func selectApprovals() { selectedTab = .approvals }
    func openNotificationReview() async {
        guard let client, let controller else { return }
        invalidateContext()
        let epoch = lifecycle
        do {
            let state = try await client.session()
            guard epoch == lifecycle else { return }
            let ids = state.state == "unlocked" ? try await client.list() : []
            guard epoch == lifecycle else { return }
            apply(state, ids: ids)
            // load also captures the controller's review epoch: sleep/refresh while
            // this final request is in flight cannot restore a visible ticket.
            if let id = ids.first { await controller.load(id) }
        } catch {
            guard epoch == lifecycle else { return }
            connection = "Review unavailable. Refresh the inbox when connected."
        }
    }
    func sleeping() {
        pollTask?.cancel(); invalidateContext(); pending = []; sessionState = "unavailable"
        connection = "Sleeping. Inbox refreshes after wake."
    }
    func unlock(_ password: String) async {
        guard !unlockBusy, let client else { return }
        unlockPassword = ""; unlockBusy = true; controller?.invalidate()
        let epoch = lifecycle
        defer { if epoch == lifecycle { unlockBusy = false } }
        do {
            _ = try await client.unlock(password)
            guard epoch == lifecycle else { return }
            connection = "Unlocked. Ask the agent to submit a fresh request."
            sessionState = "unlocked"; start()
        } catch {
            guard epoch == lifecycle else { return }
            connection = "Unlock failed or its outcome is unknown. Refresh session before an explicit new attempt."
            // No unlock retry. Only the polling task may refresh the session.
        }
    }
    private func notify() {
        let content = UNMutableNotificationContent()
        content.title = "Approval requested"
        content.body = "Open Approval Companion to review pending work."
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "pending-inbox", content: content, trigger: nil))
    }
}

final class ApplicationDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    var openInbox: (() -> Void)?
    func applicationDidFinishLaunching(_ notification: Notification) {
        UNUserNotificationCenter.current().delegate = self
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        DispatchQueue.main.async { self.openInbox?(); completionHandler() }
    }
}

@main struct ApprovalCompanionApp: App {
    @NSApplicationDelegateAdaptor(ApplicationDelegate.self) var appDelegate
    @StateObject private var model = AppModel()
    var body: some Scene {
        MenuBarExtra {
            MenuContents(model: model)
        } label: {
            MenuLabel(appDelegate: appDelegate, model: model)
        }
        Window("Approval Companion", id: "inbox") {
            InboxView(model: model)
                .frame(minWidth: 760, minHeight: 650)
        }
    }
}
private struct MenuLabel: View {
    @Environment(\.openWindow) private var openWindow
    let appDelegate: ApplicationDelegate
    @ObservedObject var model: AppModel
    var body: some View {
        Image(systemName: "checkmark.shield")
            .onAppear {
                appDelegate.openInbox = {
                    model.selectApprovals()
                    openWindow(id: "inbox"); NSApp.activate(ignoringOtherApps: true)
                    Task { await model.openNotificationReview() }
                }
            }
    }
}
private struct MenuContents: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Text(model.connection)
        Button("Open approvals (\(model.pending.count))") {
            model.selectApprovals()
            openWindow(id: "inbox"); NSApp.activate(ignoringOtherApps: true)
        }
        Button("Refresh inbox") { model.start() }
        Divider()
        Button("Quit") { NSApp.terminate(nil) }
    }
}
private struct InboxView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        TabView(selection: $model.selectedTab) {
            VStack(alignment: .leading, spacing: 12) {
                Text("\(model.connection) · Provider: \(model.sessionState)").font(.headline)
                if model.sessionState == "locked" {
                    Text("Unlock is separate from approval. After unlock, the agent must submit a fresh request.")
                    SecureField("Provider password for unlock", text: $model.unlockPassword)
                    Button("Unlock provider") {
                        let password = model.unlockPassword; model.unlockPassword = ""
                        Task { await model.unlock(password) }
                    }.disabled(model.unlockPassword.isEmpty || model.unlockBusy)
                }
                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading) {
                        Text("Pending inbox").font(.headline)
                        if let explanation = model.inboxCapacityExplanation { Text(explanation).font(.caption) }
                        if model.pending.isEmpty { Text("No pending requests.") }
                        ScrollView {
                            ForEach(model.pending, id: \.self) { id in
                                Button { Task { await model.controller?.load(id) } } label: {
                                    Text(id).font(.system(.caption, design: .monospaced)).lineLimit(2)
                                }.disabled(model.controller?.busy == true)
                            }
                        }
                        Button("Refresh inbox") { model.start() }
                    }.frame(width: 180)
                    Divider()
                    if let controller = model.controller {
                        ReviewView(controller: controller).id(ObjectIdentifier(controller))
                    } else { Text("Configure a trusted provider in Setup.") }
                }
            }.padding().tabItem { Text("Approvals") }.tag(InboxTab.approvals)
            SetupView(model: model).padding().tabItem { Text("Setup") }.tag(InboxTab.setup)
        }.onDisappear { model.unlockPassword = "" }
    }
}
private struct ReviewView: View {
    @ObservedObject var controller: DecisionController
    @State private var password = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(controller.message).textSelection(.enabled)
            if let response = controller.review {
                let review = response.review
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        field("Request", review.id)
                        field("Requester", review.requester)
                        field("Operation", review.operation)
                        field("Effect", review.effect)
                        field("Target", review.target)
                        Text("Arguments (\(review.arguments.count))").bold()
                        ForEach(Array(review.arguments.enumerated()), id: \.offset) { index, argument in
                            field("Argument \(index)", argument)
                        }
                        Text("Credentials (\(review.credentials.count))").bold()
                        ForEach(Array(review.credentials.enumerated()), id: \.offset) { index, credential in
                            field("Credential \(index) label", credential.label)
                            field("Credential \(index) use", credential.useType)
                        }
                        field("Executable SHA256", review.executableDigest)
                        field("Policy SHA256", review.policyDigest)
                        field("Arguments SHA256", review.argumentsDigest)
                        field("Expires (Unix seconds)", String(review.expiresAtUnixSeconds))
                        field("Expires (local time)", Date(timeIntervalSince1970: Double(review.expiresAtUnixSeconds)).formatted())
                        field("One-time authorization", review.oneTime)
                        field("Status", review.status.summary)
                        field("Authority generation", String(response.generation))
                    }.frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                }
                SecureField("Fresh provider password for this approval", text: $password)
                TimelineView(.periodic(from: .now, by: 1)) { _ in
                    HStack {
                        Button("Approve once") {
                            let fresh = password; password = ""
                            Task { await controller.decide(approve: true, password: fresh) }
                        }.disabled(password.isEmpty || !controller.canDecide)
                        Button("Deny", role: .destructive) {
                            password = ""
                            Task { await controller.decide(approve: false, password: nil) }
                        }.disabled(!controller.canDecide)
                    }
                }
                Text("Review tickets last at most 60 seconds. Select the request again if the controls expire.").font(.caption)
            }
            if controller.uncertain {
                Button("Check outcome (read only)") { Task { await controller.refreshUncertainStatus() } }
            }
        }
        .onChange(of: controller.review?.review.id) { _ in password = "" }
        .onChange(of: controller.review?.ticket) { _ in password = "" }
        .onDisappear { password = "" }
    }
    private func field(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading) { Text(label).font(.caption).foregroundColor(.secondary); Text(visibleReviewText(value)).font(.system(.body, design: .monospaced)).fixedSize(horizontal: false, vertical: true) }
    }
}

private struct SetupView: View {
    @ObservedObject var model: AppModel
    @State private var endpoint = "https://provider.example:8443"
    @State private var pin = ""
    @State private var ca: Data?
    @State private var identityReference: Data?
    @State private var packagePassword = ""
    @State private var feedback = ""
    var body: some View {
        Form {
            Text("Trusted LAN/VPN setup").font(.title2)
            Text("Obtain the HTTPS address, CA certificate (DER), exact server leaf SHA256, and a client PKCS#12 identity through a trusted provisioning channel. Compare the server fingerprint with the Linux console.")
            TextField("HTTPS endpoint", text: $endpoint)
            TextField("Server leaf SHA256 (64 lowercase hex)", text: $pin)
            Button(ca == nil ? "Choose trusted CA (.der)" : "Replace trusted CA (.der)") {
                if let data = chooseFile() { ca = data }
            }
            SecureField("PKCS#12 import passphrase", text: $packagePassword)
            Button("Import client PKCS#12 into Keychain") {
                defer { packagePassword = "" }
                guard let data = chooseFile() else { return }
                do {
                    let reference = try KeychainIdentity.importPKCS12(data, passphrase: packagePassword)
                    identityReference = reference
                    feedback = "Client certificate SHA256: \(try KeychainIdentity.fingerprint(reference)). Enroll this exact certificate on Linux."
                } catch { feedback = "Identity import failed. Check the package, passphrase and Keychain access." }
            }
            Button("Save trusted setup and connect") {
                guard let url = URL(string: endpoint), let ca, let identityReference else { feedback = "Provide endpoint, CA, leaf fingerprint and identity."; return }
                do {
                    let config = try ProviderConfiguration(endpoint: url, trustedCA: ca, leafSHA256: pin, identityReference: identityReference)
                    model.configure(config); feedback = "Setup saved. Connecting with mutual TLS."
                } catch { feedback = "Invalid setup. Use HTTPS, a DER CA, and an exact lowercase leaf fingerprint." }
            }
            Divider()
            Button("Enable approval notifications") {
                UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, error in
                    DispatchQueue.main.async {
                        if let error = error as NSError? {
                            feedback = "Notification setup failed: \(error.localizedDescription) (\(error.domain), \(error.code)). The inbox remains available."
                        } else if granted {
                            feedback = "Notifications enabled."
                        } else {
                            feedback = "Notifications are disabled. Enable Approval Companion in System Settings → Notifications. The inbox remains available."
                        }
                    }
                }
            }
            HStack {
                Button("Start at login") {
                    do {
                        try SMAppService.mainApp.register()
                        feedback = SMAppService.mainApp.status == .enabled ? "Login startup enabled." : "Approve startup in System Settings → General → Login Items."
                    } catch { feedback = "Login registration failed. Install and run the .app bundle from Applications." }
                }
                Button("Disable login startup") {
                    Task {
                        do { try await SMAppService.mainApp.unregister(); feedback = "Login startup disabled." }
                        catch { feedback = "Could not unregister login startup. Check System Settings → General → Login Items." }
                    }
                }
            }
            Text(feedback).font(.callout).textSelection(.enabled)
        }
        .onAppear {
            if let config = model.configuration {
                endpoint = config.endpoint.absoluteString; pin = config.leafSHA256
                ca = config.trustedCA; identityReference = config.identityReference
            }
        }
        .onDisappear { packagePassword = "" }
    }
    private func chooseFile() -> Data? {
        let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url,
              let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 1_048_576 else { return nil }
        return try? Data(contentsOf: url)
    }
}
