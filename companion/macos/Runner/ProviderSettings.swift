import Foundation
import Security

/// Closed operational categories; never retain underlying errors or file contents.
enum ProviderSettingsError: Error, Equatable {
    case unreadable, invalid, identityUnavailable
    var code: String {
        switch self {
        case .unreadable: return "provider_configuration_unreadable"
        case .invalid: return "provider_configuration_invalid"
        case .identityUnavailable: return "provider_identity_unavailable"
        }
    }
}

/// Stored in this sandbox's Application Support, never the Swift app's defaults.
/// The durable marker has no password/ticket/review; it binds recovery to the
/// exact saved configuration by forbidding replacement while unresolved.
final class ProviderSettings {
    private struct Saved: Codable {
        let configuration: ProviderConfiguration
        var pendingID: String?
        var management: ManagementRecovery?
    }
    private let file: URL
    init(directory: URL? = nil) {
        let base = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("dev.vaultwarden.companionSlice.provider", isDirectory: true)
        file = base.appendingPathComponent("configuration-v1.json")
    }
    private func load() throws -> Saved {
        let data: Data
        do { data = try Data(contentsOf: file) }
        catch { throw ProviderSettingsError.unreadable }
        do {
            guard data.count <= 131_072 else { throw ProviderSettingsError.invalid }
            let saved = try JSONDecoder().decode(Saved.self, from: data)
            _ = try saved.configuration.validated()
            if let id = saved.pendingID, !validRequestID(id) { throw ProviderSettingsError.invalid }
            if let management = saved.management {
                guard management.valid, saved.pendingID == nil else { throw ProviderSettingsError.invalid }
            }
            return saved
        } catch { throw ProviderSettingsError.invalid }
    }
    private func save(_ value: Saved) throws {
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(value).write(to: file, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }
    func configuration() throws -> ProviderConfiguration { try load().configuration }
    func pendingID() throws -> String? {
        guard FileManager.default.fileExists(atPath: file.path) else { return nil }
        return try load().pendingID
    }
    func hasPending() throws -> Bool {
        guard FileManager.default.fileExists(atPath: file.path) else { return false }
        let saved = try load()
        return saved.pendingID != nil || saved.management != nil
    }
    func metadata() throws -> [String: Any] {
        guard FileManager.default.fileExists(atPath: file.path) else { return ["configured": false] }
        let saved = try load()
        let fingerprint: String
        do { fingerprint = try KeychainIdentity.fingerprint(saved.configuration.identityReference) }
        catch { throw ProviderSettingsError.identityUnavailable }
        return ["configured": true, "endpoint": saved.configuration.endpoint.absoluteString,
                "pin": saved.configuration.leafSHA256,
                "fingerprint": fingerprint,
                "uncertainId": saved.pendingID ?? "",
                "managementRecovery": try saved.management.map { String(decoding: try JSONEncoder().encode($0), as: UTF8.self) } ?? ""]
    }
    func install(endpoint: URL, ca: Data, pin: String, pkcs12: Data, passphrase: String,
                 expectedFingerprint: String? = nil) throws {
        guard try !hasPending() else { throw CompanionError.configuration }
        // Validate routing/trust before importing anything. No lookup or adoption
        // of an installed companion identity or configuration occurs.
        _ = try ProviderConfiguration(endpoint: endpoint, trustedCA: ca, leafSHA256: pin, identityReference: Data([1]))
        let reference = try KeychainIdentity.importPKCS12(pkcs12, passphrase: passphrase)
        if let expectedFingerprint {
            guard try KeychainIdentity.fingerprint(reference) == expectedFingerprint else { throw CompanionError.configuration }
        }
        let configuration = try ProviderConfiguration(endpoint: endpoint, trustedCA: ca, leafSHA256: pin, identityReference: reference)
        try save(Saved(configuration: configuration, pendingID: nil))
    }
    #if COMPANION_DISPOSABLE_PILOT
    /// No file chooser, network call, trust-store change or unlock. This entry
    /// exists only in the explicitly opted-in disposable test executable.
    func installPilot(_ arguments: Any?) throws {
        guard try !hasPending() else { throw CompanionError.configuration }
        let bundle = try DisposablePilotBundle(arguments)
        // Validate the actual CA/routing before backup or Keychain side effects.
        _ = try ProviderConfiguration(endpoint: bundle.endpoint, trustedCA: bundle.ca,
                                      leafSHA256: bundle.pin, identityReference: Data([1]))
        if FileManager.default.fileExists(atPath: file.path) {
            _ = try load()
            let backup = file.deletingLastPathComponent().appendingPathComponent("configuration-before-pilot-\(UUID().uuidString).json")
            let bytes = try Data(contentsOf: file)
            guard FileManager.default.createFile(atPath: backup.path, contents: bytes,
                                                attributes: [.posixPermissions: 0o600]) else { throw CompanionError.configuration }
        }
        try install(endpoint: bundle.endpoint, ca: bundle.ca, pin: bundle.pin,
                    pkcs12: bundle.identity, passphrase: bundle.passphrase, expectedFingerprint: bundle.fingerprint)
    }
    #endif
    func beforeSend(_ bytes: Data) throws {
        guard let body = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let command = body["command"] as? String else { throw CompanionError.configuration }
        var saved = try load()
        if let pending = saved.pendingID {
            guard command == "status", body["request_id"] as? String == pending else { throw CompanionError.configuration }
        }
        if let pending = saved.management {
            guard command == "identity_status", body["version"] as? Int == 2,
                  Set(body.keys) == ["version", "command", "target", "action_id"],
                  let target = body["target"] as? [String: Any],
                  Set(target.keys) == ["kind", "id"],
                  target["kind"] as? String == pending.target.kind,
                  target["id"] as? String == pending.target.id,
                  body["action_id"] as? String == pending.actionID else { throw CompanionError.configuration }
        }
        if command == "identity_revoke" {
            guard saved.pendingID == nil, saved.management == nil,
                  Set(body.keys) == ["version", "command", "target", "action_id", "ticket", "password"],
                  let version = body["version"] as? NSNumber, CFGetTypeID(version) != CFBooleanGetTypeID(), version == 2,
                  let target = body["target"] as? [String: Any], Set(target.keys) == ["kind", "id"],
                  let kind = target["kind"] as? String, let id = target["id"] as? String,
                  let actionID = body["action_id"] as? String,
                  let ticket = body["ticket"] as? String, validHex(ticket, count: 64),
                  let password = body["password"] as? String, !password.isEmpty, password.utf8.count <= 4096 else { throw CompanionError.configuration }
            let marker = ManagementRecovery(target: .init(kind: kind, id: id), actionID: actionID)
            guard marker.valid else { throw CompanionError.configuration }
            saved.management = marker
            try save(saved)
        }
        if command == "decision" {
            guard let id = body["request_id"] as? String, validRequestID(id) else { throw CompanionError.configuration }
            saved.pendingID = id
            try save(saved)
        }
    }
    func settle(_ id: String) throws {
        var saved = try load()
        if let management = saved.management {
            guard management.actionID == id, saved.pendingID == nil else { throw CompanionError.configuration }
            saved.management = nil
        } else {
            guard saved.pendingID == id else { throw CompanionError.configuration }
            saved.pendingID = nil
        }
        try save(saved)
    }
}

#if COMPANION_DISPOSABLE_PILOT
struct DisposablePilotBundle {
    let endpoint: URL
    let ca: Data
    let identity: Data
    let pin: String
    let fingerprint: String
    let passphrase: String

    init(_ arguments: Any?) throws {
        guard let values = arguments as? [String: Any],
              Set(values.keys) == ["version", "kind", "endpoint", "leaf_sha256", "client_sha256", "ca_der", "pkcs12", "import_passphrase"],
              let version = values["version"] as? NSNumber,
              CFGetTypeID(version) != CFBooleanGetTypeID(), version == 1,
              !["f", "d"].contains(String(cString: version.objCType)),
              values["kind"] as? String == "disposable-companion-pilot",
              let endpointText = values["endpoint"] as? String, endpointText.utf8.count <= 2048,
              !endpointText.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) || $0 == "\\" }),
              let url = URL(string: endpointText), url.scheme == "https",
              let host = url.host, !host.isEmpty,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              ["", "/", "/v1/companion"].contains(url.path),
              url.port == nil || (1...65535).contains(url.port!),
              let pin = values["leaf_sha256"] as? String, validHex(pin, count: 64),
              let fingerprint = values["client_sha256"] as? String, validHex(fingerprint, count: 64),
              let passphrase = values["import_passphrase"] as? String,
              !passphrase.isEmpty, passphrase.utf8.count <= 4096 else { throw CompanionError.configuration }
        func decode(_ key: String, maximum: Int) throws -> Data {
            guard let encoded = values[key] as? String, encoded.utf8.count <= ((maximum + 2) / 3) * 4,
                  let decoded = Data(base64Encoded: encoded), !decoded.isEmpty, decoded.count <= maximum,
                  decoded.base64EncodedString() == encoded else { throw CompanionError.configuration }
            return decoded
        }
        endpoint = url
        ca = try decode("ca_der", maximum: 65_536)
        identity = try decode("pkcs12", maximum: 1_048_576)
        self.pin = pin; self.fingerprint = fingerprint; self.passphrase = passphrase
    }
}
#endif

/// Original action/target only; no password, ticket, label or diagnostics persist.
private struct ManagementRecovery: Codable {
    struct Target: Codable {
        let kind: String; let id: String
        enum CodingKeys: String, CodingKey { case kind, id }
        init(kind: String, id: String) { self.kind = kind; self.id = id }
        init(from decoder: Decoder) throws {
            try managementKeys(decoder, ["kind", "id"])
            let c = try decoder.container(keyedBy: CodingKeys.self)
            kind = try c.decode(String.self, forKey: .kind); id = try c.decode(String.self, forKey: .id)
        }
    }
    let target: Target
    let actionID: String
    enum CodingKeys: String, CodingKey { case target; case actionID = "action_id" }
    var valid: Bool {
        validRequestID(actionID) && ((target.kind == "approval_client" && validHex(target.id, count: 64)) ||
            (target.kind == "requester_agent" && validRequestID(target.id)))
    }
    init(target: Target, actionID: String) { self.target = target; self.actionID = actionID }
    init(from decoder: Decoder) throws {
        try managementKeys(decoder, ["target", "action_id"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        target = try c.decode(Target.self, forKey: .target)
        actionID = try c.decode(String.self, forKey: .actionID)
        guard valid else { throw CompanionError.configuration }
    }
}

private func managementKeys(_ decoder: Decoder, _ expected: Set<String>) throws {
    struct Key: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
    let container = try decoder.container(keyedBy: Key.self)
    guard Set(container.allKeys.map(\.stringValue)) == expected else { throw CompanionError.configuration }
}

/// Native lifecycle binding for administrative tickets. A queued Dart send after
/// native sleep/close cannot revive a prepared ticket before Dart handles events.
final class ManagementTransportGate {
    private var epoch: UInt64 = 0
    private var prepared: [String: String]?
    private var deadline: TimeInterval = 0
    func invalidate() { epoch &+= 1; prepared = nil; deadline = 0 }
    func begin(_ bytes: Data, foreground: Bool) throws -> UInt64 {
        guard let body = try JSONSerialization.jsonObject(with: bytes) as? [String: Any], let command = body["command"] as? String else { throw CompanionError.configuration }
        if command == "identity_prepare" {
            invalidate()
            guard foreground else { throw CompanionError.configuration }
            deadline = ProcessInfo.processInfo.systemUptime + 55
        } else if command == "identity_revoke" {
            let expected = prepared
            let expires = deadline
            invalidate() // one send attempt, including native storage failure
            guard foreground, ProcessInfo.processInfo.systemUptime < expires,
                  let expected, let supplied = binding(body), supplied == expected else { throw CompanionError.configuration }
        } else if ["identity_list", "identity_detail"].contains(command) { invalidate() }
        return epoch
    }
    func finish(_ request: Data, response: Data, started: UInt64, foreground: Bool) throws {
        guard let body = try JSONSerialization.jsonObject(with: request) as? [String: Any], body["command"] as? String == "identity_prepare" else { return }
        guard foreground, started == epoch, ProcessInfo.processInfo.systemUptime < deadline else { throw CompanionError.configuration }
        guard let reply = try JSONSerialization.jsonObject(with: response) as? [String: Any], reply["version"] as? Int == 2,
              let identity = reply["identity"] as? [String: Any], let target = body["target"] as? [String: Any],
              identity["kind"] as? String == target["kind"] as? String, identity["id"] as? String == target["id"] as? String else { return }
        var bound = reply
        bound["target"] = target
        prepared = binding(bound)
    }
    private func binding(_ value: [String: Any]) -> [String: String]? {
        guard let target = value["target"] as? [String: Any], let kind = target["kind"] as? String,
              let id = target["id"] as? String, let action = value["action_id"] as? String, validRequestID(action),
              let ticket = value["ticket"] as? String, validHex(ticket, count: 64),
              (kind == "approval_client" && validHex(id, count: 64)) || (kind == "requester_agent" && validRequestID(id)) else { return nil }
        return ["kind":kind,"id":id,"action_id":action,"ticket":ticket]
    }
}
