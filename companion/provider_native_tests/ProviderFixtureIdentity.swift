// External CI fixture tool, never linked into the application.
import Foundation
import Security

@main struct ProviderFixtureIdentity {
    // CI-only diagnostics. Never emit errors, Keychain references or file contents.
    enum Phase: String {
        case input, openKeychain, readCertificate, findIdentity, persistentReference
        case saveConfiguration, savedConfiguration, savedIdentity, savedFingerprint, savedMetadata
    }
    static var phase = Phase.input
    static func main() {
        do {
            try provision()
            print("COMPANION_PROVIDER_PROVISION_OK")
        } catch {
            print("COMPANION_PROVIDER_PROVISION_FAILED:\(phase.rawValue)")
            exit(1)
        }
    }
    static func provision() throws {
        guard ProcessInfo.processInfo.environment["CI"] == "true", CommandLine.arguments.count == 8 else { throw CompanionError.configuration }
        let args = CommandLine.arguments
        let fixture = URL(fileURLWithPath: args[1], isDirectory: true)
        let destination = URL(fileURLWithPath: args[2])
        guard ["client", "foreign", "revoked"].contains(args[3]),
              ["ca", "other-ca"].contains(args[4]),
              let endpoint = URL(string: args[5]), endpoint.host == "127.0.0.1" else { throw CompanionError.configuration }
        var keychain: SecKeychain?
        phase = .openKeychain
        guard SecKeychainOpen(args[7], &keychain) == errSecSuccess, let keychain else { throw CompanionError.configuration }
        phase = .readCertificate
        let certificate = try Data(contentsOf: fixture.appendingPathComponent("\(args[3]).der"))
        var result: CFTypeRef?
        phase = .findIdentity
        guard SecItemCopyMatching([kSecClass as String: kSecClassIdentity,
                                   kSecMatchSearchList as String: [keychain],
                                   kSecMatchLimit as String: kSecMatchLimitAll,
                                   kSecReturnRef as String: true] as CFDictionary, &result) == errSecSuccess,
              let identities = result as? [SecIdentity] else { throw CompanionError.configuration }
        var reference: Data?
        for identity in identities {
            var candidate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &candidate) == errSecSuccess, let candidate,
                  SecCertificateCopyData(candidate) as Data == certificate else { continue }
            var persistent: CFTypeRef?
            phase = .persistentReference
            guard SecItemCopyMatching([kSecClass as String: kSecClassIdentity,
                                       kSecMatchSearchList as String: [keychain],
                                       kSecMatchItemList as String: [identity],
                                       kSecReturnPersistentRef as String: true] as CFDictionary, &persistent) == errSecSuccess,
                  let data = persistent as? Data else { throw CompanionError.configuration }
            reference = data
        }
        guard let reference else { throw CompanionError.configuration }
        phase = .saveConfiguration
        let configuration = try ProviderConfiguration(endpoint: endpoint,
            trustedCA: Data(contentsOf: fixture.appendingPathComponent("\(args[4]).der")),
            leafSHA256: args[6], identityReference: reference)
        struct Saved: Encodable { let configuration: ProviderConfiguration }
        try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(Saved(configuration: configuration)).write(to: destination, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
        // Exercise the app's actual loading and implicit-search reference lookup,
        // not just the explicit-keychain search used above. This is still an
        // external helper: success alone does not prove sandboxed app access.
        let settings = ProviderSettings(directory: destination.deletingLastPathComponent())
        phase = .savedConfiguration
        let loaded = try settings.configuration()
        guard loaded.endpoint == configuration.endpoint,
              loaded.trustedCA == configuration.trustedCA,
              loaded.leafSHA256 == configuration.leafSHA256,
              loaded.identityReference == reference,
              try settings.pendingID() == nil else { throw CompanionError.configuration }
        phase = .savedIdentity
        _ = try KeychainIdentity.resolve(loaded.identityReference)
        phase = .savedFingerprint
        let expectedFingerprint = KeychainIdentity.fingerprintDER(certificate)
        guard try KeychainIdentity.fingerprint(loaded.identityReference) == expectedFingerprint else { throw CompanionError.configuration }
        phase = .savedMetadata
        let metadata = try settings.metadata()
        guard metadata["configured"] as? Bool == true,
              metadata["fingerprint"] as? String == expectedFingerprint,
              metadata["uncertainId"] as? String == "" else { throw CompanionError.configuration }
    }
}
