// Synthetic-only .app regression probe, compiled with production CompanionCore.
import Foundation
import Security

@main struct BundleProbe {
    static func main() async {
        guard CommandLine.arguments.count == 2 else { exit(2) }
        let setup: [String: String]
        do { setup = try JSONDecoder().decode([String: String].self, from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))) }
        catch { exit(2) }
        // The probe is restricted to the synthetic loopback fixture.
        guard let endpoint = URL(string: setup["endpoint"] ?? ""), endpoint.host == "companion.localhost" else { exit(2) }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("companion-bundle-keychain-\(UUID().uuidString)")
        var keychain: SecKeychain?
        var originalSearchList: CFArray?
        var output: [String: Any] = ["bundled": Bundle.main.bundleURL.pathExtension == "app", "ats": Bundle.main.object(forInfoDictionaryKey: "NSAppTransportSecurity") ?? [:]]
        do {
            guard Bundle.main.bundleURL.pathExtension == "app" else { throw CompanionError.configuration }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let password = "synthetic-bundle-keychain-only"
            let created = directory.appendingPathComponent("test.keychain-db").path.withCString { path in
                password.withCString { bytes in SecKeychainCreate(path, UInt32(password.utf8.count), bytes, false, nil, &keychain) }
            }
            guard created == errSecSuccess, let keychain else { throw CompanionError.configuration }
            guard SecKeychainCopySearchList(&originalSearchList) == errSecSuccess else { throw CompanionError.configuration }
            let existing = (originalSearchList as? [SecKeychain]) ?? []
            guard SecKeychainSetSearchList((existing + [keychain]) as CFArray) == errSecSuccess else { throw CompanionError.configuration }
            let reference = try KeychainIdentity.importPKCS12(Data(contentsOf: URL(fileURLWithPath: setup["identity"]!)), passphrase: "synthetic-only", keychain: keychain)
            let configuration = try ProviderConfiguration(endpoint: endpoint, trustedCA: Data(contentsOf: URL(fileURLWithPath: setup["ca"]!)), leafSHA256: setup["pin"]!, identityReference: reference)
            let client = CompanionClient(transport: try PinnedTransport(configuration: configuration))
            if setup["command"] == "authentication-unlock" {
                _ = try await client.unlock("synthetic-wrong")
            } else if setup["command"] == "authentication" {
                let review = try JSONDecoder().decode(ReviewResponse.self, from: Data(contentsOf: URL(fileURLWithPath: setup["review"]!)))
                _ = try await client.decide(review, approve: true, password: "synthetic-wrong")
            } else if setup["command"] == "drop" {
                let review = try JSONDecoder().decode(ReviewResponse.self, from: Data(contentsOf: URL(fileURLWithPath: setup["review"]!)))
                var lostReply = false
                do { _ = try await client.decide(review, approve: true, password: "synthetic-only") }
                catch { lostReply = true }
                let status = try await client.status(review.review.id)
                output["lost_reply"] = lostReply; output["status"] = status.status
            } else { output["state"] = try await client.session().state }
            output["success"] = true
        } catch {
            output["success"] = false
            if let companionError = error as? CompanionError, case .rejected(let code) = companionError { output["rejection"] = code }
            output["configuration_rejected"] = (error as? CompanionError) == .configuration
            output["error"] = (error as? CompanionError)?.errorDescription ?? "Probe failed."
        }
        var cleanup: [String] = []
        if let originalSearchList {
            if SecKeychainSetSearchList(originalSearchList) != errSecSuccess { cleanup.append("restore failed") }
            var restored: CFArray?
            if SecKeychainCopySearchList(&restored) != errSecSuccess || restored == nil || !CFEqual(restored, originalSearchList) { cleanup.append("restore verification failed") }
        }
        if let keychain, SecKeychainDelete(keychain) != errSecSuccess { cleanup.append("delete failed") }
        if FileManager.default.fileExists(atPath: directory.path) {
            do { try FileManager.default.removeItem(at: directory) } catch { cleanup.append("directory cleanup failed") }
        }
        output["cleanup_verified"] = cleanup.isEmpty
        if !cleanup.isEmpty { output["cleanup_failures"] = cleanup }
        if let data = try? JSONSerialization.data(withJSONObject: output, options: [.sortedKeys]) { print(String(decoding: data, as: UTF8.self)) }
        else { exit(2) }
    }
}
