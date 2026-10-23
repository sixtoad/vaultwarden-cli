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
    func metadata() throws -> [String: Any] {
        guard FileManager.default.fileExists(atPath: file.path) else { return ["configured": false] }
        let saved = try load()
        let fingerprint: String
        do { fingerprint = try KeychainIdentity.fingerprint(saved.configuration.identityReference) }
        catch { throw ProviderSettingsError.identityUnavailable }
        return ["configured": true, "endpoint": saved.configuration.endpoint.absoluteString,
                "pin": saved.configuration.leafSHA256,
                "fingerprint": fingerprint,
                "uncertainId": saved.pendingID ?? ""]
    }
    func install(endpoint: URL, ca: Data, pin: String, pkcs12: Data, passphrase: String,
                 expectedFingerprint: String? = nil) throws {
        guard try pendingID() == nil else { throw CompanionError.configuration }
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
        guard try pendingID() == nil else { throw CompanionError.configuration }
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
        if command == "decision" {
            guard let id = body["request_id"] as? String, validRequestID(id) else { throw CompanionError.configuration }
            saved.pendingID = id
            try save(saved)
        }
    }
    func settle(_ id: String) throws {
        var saved = try load()
        guard saved.pendingID == id else { throw CompanionError.configuration }
        saved.pendingID = nil
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
