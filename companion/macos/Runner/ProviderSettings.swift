import Foundation
import Security

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
        let data = try Data(contentsOf: file)
        guard data.count <= 131_072 else { throw CompanionError.configuration }
        let saved = try JSONDecoder().decode(Saved.self, from: data)
        _ = try saved.configuration.validated()
        if let id = saved.pendingID, !validRequestID(id) { throw CompanionError.configuration }
        return saved
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
        return ["configured": true, "endpoint": saved.configuration.endpoint.absoluteString,
                "pin": saved.configuration.leafSHA256,
                "fingerprint": try KeychainIdentity.fingerprint(saved.configuration.identityReference),
                "uncertainId": saved.pendingID ?? ""]
    }
    func install(endpoint: URL, ca: Data, pin: String, pkcs12: Data, passphrase: String) throws {
        guard try pendingID() == nil else { throw CompanionError.configuration }
        // Validate routing/trust before importing anything. No lookup or adoption
        // of an installed companion identity or configuration occurs.
        _ = try ProviderConfiguration(endpoint: endpoint, trustedCA: ca, leafSHA256: pin, identityReference: Data([1]))
        let reference = try KeychainIdentity.importPKCS12(pkcs12, passphrase: passphrase)
        let configuration = try ProviderConfiguration(endpoint: endpoint, trustedCA: ca, leafSHA256: pin, identityReference: reference)
        try save(Saved(configuration: configuration, pendingID: nil))
    }
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
