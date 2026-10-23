// External disposable CI audit; never linked into the application. Emits no
// certificates, persistent references, paths, passwords or Security errors.
import Foundation
import Security

@main struct PilotFixtureIdentityAudit {
    enum Invalid: Error { case fixture }
    static func identities(_ keychain: SecKeychain? = nil) throws -> [SecIdentity] {
        var query: [String: Any] = [kSecClass as String: kSecClassIdentity,
            kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnRef as String: true]
        if let keychain { query[kSecMatchSearchList as String] = [keychain] }
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let result = value as? [SecIdentity] else { throw Invalid.fixture }
        return result
    }
    static func certificate(_ identity: SecIdentity) throws -> Data {
        var value: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &value) == errSecSuccess, let value else { throw Invalid.fixture }
        return SecCertificateCopyData(value) as Data
    }
    static func main() {
        do {
            guard ProcessInfo.processInfo.environment["CI"] == "true",
                  CommandLine.arguments.count == 5 else { throw Invalid.fixture }
            let args = CommandLine.arguments
            let expected = try Data(contentsOf: URL(fileURLWithPath: args[4]))
            if args[1] == "absent" {
                for identity in try identities() {
                    guard try certificate(identity) != expected else { throw Invalid.fixture }
                }
            } else {
                let raw = try Data(contentsOf: URL(fileURLWithPath: args[2]))
                guard let saved = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
                      let config = saved["configuration"] as? [String: Any],
                      let encoded = config["identityReference"] as? String,
                      let reference = Data(base64Encoded: encoded) else { throw Invalid.fixture }
                var resolved: CFTypeRef?
                let result = SecItemCopyMatching([kSecValuePersistentRef as String: reference,
                    kSecReturnRef as String: true] as CFDictionary, &resolved)
                if args[1] == "removed" {
                    guard result == errSecItemNotFound else { throw Invalid.fixture }
                    for identity in try identities() {
                        guard try certificate(identity) != expected else { throw Invalid.fixture }
                    }
                } else {
                    guard args[1] == "present", result == errSecSuccess else { throw Invalid.fixture }
                    var keychain: SecKeychain?
                    guard SecKeychainOpen(args[3], &keychain) == errSecSuccess, let keychain else { throw Invalid.fixture }
                    var matched = false
                    for identity in try identities(keychain) {
                        guard try certificate(identity) == expected else { continue }
                        var persistent: CFTypeRef?
                        guard SecItemCopyMatching([kSecClass as String: kSecClassIdentity,
                            kSecMatchSearchList as String: [keychain],
                            kSecMatchItemList as String: [identity],
                            kSecReturnPersistentRef as String: true] as CFDictionary, &persistent) == errSecSuccess,
                            let data = persistent as? Data, data == reference else { throw Invalid.fixture }
                        matched = true
                    }
                    guard matched else { throw Invalid.fixture }
                }
            }
            print("COMPANION_PILOT_IDENTITY_AUDIT_OK")
        } catch { exit(1) }
    }
}
