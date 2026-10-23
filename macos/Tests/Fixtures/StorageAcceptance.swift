// Synthetic-only acceptance driver, compiled with the production CompanionCore.
// Configuration, passwords and client identity are read from an owner-only file.
import Foundation
import Security

struct StorageAcceptanceConfiguration: Decodable {
    let syntheticOnly: Bool
    let endpoint: URL
    let identity: String
    let identityPassword: String
    let ca: String
    let pin: String
    let command: String
    let password: String?
    let operation: String?
    let requestID: String?
    let expectedCreate: CreateEffect?
    enum CodingKeys: String, CodingKey {
        case syntheticOnly = "synthetic_only", endpoint, identity, identityPassword = "identity_password"
        case ca, pin, command, password, operation, requestID = "request_id", expectedCreate = "expected_create"
    }
    static func decode(_ data: Data) throws -> Self {
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.syntheticOnly, value.endpoint.scheme == "https",
              ["192.168.1.235", "pop-os.int.cantolla.casa", "127.0.0.1"].contains(value.endpoint.host ?? ""),
              value.endpoint.user == nil, value.endpoint.password == nil,
              value.endpoint.query == nil, value.endpoint.fragment == nil,
              ["", "/", "/v1/companion"].contains(value.endpoint.path),
              value.identity.hasPrefix("/"), value.ca.hasPrefix("/"), !value.identityPassword.isEmpty,
              validHex(value.pin, count: 64),
              ["session", "unlock", "approve", "deny", "status"].contains(value.command)
        else { throw CompanionError.configuration }
        if ["unlock", "approve"].contains(value.command) {
            guard let password = value.password, !password.isEmpty, password.utf8.count <= 4096 else { throw CompanionError.configuration }
        }
        if value.command == "status" {
            guard let id = value.requestID, validRequestID(id) else { throw CompanionError.configuration }
        }
        if ["approve", "deny"].contains(value.command) {
            guard let operation = value.operation,
                  ["storage-create", "storage-consume", "storage-deny", "storage-interrupt"].contains(operation)
            else { throw CompanionError.configuration }
            if operation != "storage-consume" {
                guard let create = value.expectedCreate,
                      create.destination.folder == "storage-acceptance",
                      create.destination.reference == "storage-acceptance/" + String(operation.dropFirst("storage-".count)),
                      create.fields == ["password"], create.eligibilityMarker == "storage-consume"
                else { throw CompanionError.configuration }
            }
        }
        return value
    }
}

@MainActor final class StorageAcceptanceMetrics {
    private let began = ProcessInfo.processInfo.systemUptime
    private(set) var attempted: [String: Int] = [:]
    private(set) var completed: [String: Int] = [:]
    private(set) var elapsed: [String: Double] = [:]
    func request<T>(_ name: String, _ action: () async throws -> T) async throws -> T {
        attempted[name, default: 0] += 1
        let started = ProcessInfo.processInfo.systemUptime
        defer { elapsed[name, default: 0] += ProcessInfo.processInfo.systemUptime - started }
        let value = try await action()
        completed[name, default: 0] += 1
        return value
    }
    func append(to output: inout [String: Any]) {
        output["native_request_counts"] = completed
        output["native_request_attempted_counts"] = attempted
        output["native_request_completed_counts"] = completed
        output["native_request_elapsed_seconds"] = elapsed
        output["operation_elapsed_seconds"] = ProcessInfo.processInfo.systemUptime - began
    }
}

@MainActor struct StorageAcceptance {
    static func requireOutcome(_ status: DirectStatus, command: String, operation: String) throws {
        if command == "deny" {
            guard status.status == "denied" else { throw CompanionError.invalidResponse }
        } else if operation == "storage-interrupt" {
            guard status.status == "failed", status.reason == "execution_unavailable" else { throw CompanionError.invalidResponse }
        } else {
            guard ["storage-create", "storage-consume"].contains(operation), status.status == "completed", status.exitCode == 0 else { throw CompanionError.invalidResponse }
        }
    }
    static func finishDecision(_ initial: DirectStatus, requestID: String, client: any CompanionServing,
                               command: String, operation: String, metrics: StorageAcceptanceMetrics,
                               output: inout [String: Any], polls: Int = 180, delay: UInt64 = 500_000_000) async throws {
        var status = initial
        for _ in 0..<polls {
            if ["completed", "failed", "denied", "expired"].contains(status.status) { break }
            try await Task.sleep(nanoseconds: delay)
            status = try await metrics.request("status") { try await client.status(requestID) }
        }
        output["status"] = status.status
        if let code = status.exitCode { output["exit_code"] = code }
        if let reason = status.reason { output["reason"] = reason }
        try requireOutcome(status, command: command, operation: operation)
    }
    static func cleanupKeychain(_ keychain: SecKeychain?, original: CFArray?) -> [String] {
        var failures: [String] = []
        if let keychain, SecKeychainDelete(keychain) != errSecSuccess { failures.append("delete failed") }
        if let original {
            if SecKeychainSetSearchList(original) != errSecSuccess { failures.append("restore failed") }
            var restored: CFArray?
            if SecKeychainCopySearchList(&restored) != errSecSuccess || restored == nil || !CFEqual(restored, original) { failures.append("restore verification failed") }
        }
        return failures
    }
    static func main() async {
        guard CommandLine.arguments.count == 2 else { exit(2) }
        var output: [String: Any] = ["approval_mode": "automated_native_client"]
        let metrics = StorageAcceptanceMetrics()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("storage-acceptance-keychain-\(UUID().uuidString)")
        var keychain: SecKeychain?
        var originalSearchList: CFArray?
        do {
            let file = URL(fileURLWithPath: CommandLine.arguments[1])
            let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
            guard (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600,
                  (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid() else { throw CompanionError.configuration }
            // Decode and validate every command-dependent field before mutating Keychain.
            let setup = try StorageAcceptanceConfiguration.decode(Data(contentsOf: file))
            let command = setup.command
            let identityData = try Data(contentsOf: URL(fileURLWithPath: setup.identity))
            let caData = try Data(contentsOf: URL(fileURLWithPath: setup.ca))
            _ = try ProviderConfiguration(endpoint: setup.endpoint, trustedCA: caData, leafSHA256: setup.pin, identityReference: Data([1]))
            guard SecKeychainCopySearchList(&originalSearchList) == errSecSuccess, originalSearchList != nil else { throw CompanionError.configuration }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let keychainPassword = UUID().uuidString
            let created = directory.appendingPathComponent("test.keychain-db").path.withCString { path in
                keychainPassword.withCString { bytes in SecKeychainCreate(path, UInt32(keychainPassword.utf8.count), bytes, false, nil, &keychain) }
            }
            guard created == errSecSuccess, let keychain else { throw CompanionError.configuration }
            let existing = (originalSearchList as? [SecKeychain]) ?? []
            guard SecKeychainSetSearchList((existing + [keychain]) as CFArray) == errSecSuccess else { throw CompanionError.configuration }
            let reference = try KeychainIdentity.importPKCS12(identityData, passphrase: setup.identityPassword, keychain: keychain)
            let configuration = try ProviderConfiguration(endpoint: setup.endpoint, trustedCA: caData, leafSHA256: setup.pin, identityReference: reference)
            let client = CompanionClient(transport: try PinnedTransport(configuration: configuration))
            let session = try await metrics.request("session") { try await client.session() }
            output["initial_session"] = session.state
            if command == "unlock" {
                let unlocked = try await metrics.request("unlock") { try await client.unlock(setup.password ?? "") }
                output["session"] = unlocked.state
                guard unlocked.state == "unlocked" else { throw CompanionError.invalidResponse }
            } else if command == "status" {
                let status = try await metrics.request("status") { try await client.status(setup.requestID ?? "") }
                output["status"] = status.status
            } else if command == "approve" || command == "deny" {
                guard session.state == "unlocked" else { throw CompanionError.configuration }
                var ids: [String] = []
                for _ in 0..<120 {
                    ids = try await metrics.request("list") { try await client.list() }
                    if !ids.isEmpty { break }
                    try await Task.sleep(nanoseconds: 500_000_000)
                }
                guard ids.count == 1 else { throw CompanionError.invalidResponse }
                let review = try await metrics.request("review") { try await client.review(ids[0]) }
                let expectedOperation = setup.operation ?? ""
                guard review.review.operation == expectedOperation,
                      review.review.status.status == "pending",
                      review.ticket != nil else { throw CompanionError.invalidResponse }
                if expectedOperation == "storage-consume" {
                    guard review.review.create == nil,
                          review.review.target == "storage.invalid",
                          review.review.arguments == ["storage.invalid"],
                          review.review.credentials.count == 1,
                          review.review.credentials[0].label == "Synthetic created login",
                          review.review.credentials[0].useType == "login" else { throw CompanionError.invalidResponse }
                } else {
                    guard ["storage-create", "storage-deny", "storage-interrupt"].contains(expectedOperation) else { throw CompanionError.configuration }
                    guard let expected = setup.expectedCreate else { throw CompanionError.configuration }
                    guard let create = review.review.create, create == expected,
                          create.destination.folder == "storage-acceptance",
                          create.fields == ["password"], create.eligibilityMarker == "storage-consume",
                          review.review.arguments.isEmpty, review.review.credentials.count == 1,
                          review.review.credentials[0].label == create.destination.reference,
                          review.review.credentials[0].useType == "login",
                          review.review.target == create.destination.reference,
                          review.review.effect == "CREATE personal vault item (no update)" else { throw CompanionError.invalidResponse }
                    output["complete_create_effect_validated"] = true
                }
                output["request_id"] = review.review.id
                output["operation"] = expectedOperation
                let status = try await metrics.request("decision") {
                    try await client.decide(review, approve: command == "approve", password: command == "approve" ? setup.password : nil)
                }
                try await finishDecision(status, requestID: review.review.id, client: client, command: command,
                                         operation: expectedOperation, metrics: metrics, output: &output)
            }
            output["success"] = true
        } catch {
            output["success"] = false
            output["error"] = (error as? CompanionError)?.errorDescription ?? "Synthetic acceptance failed."
        }
        metrics.append(to: &output)
        var cleanup = cleanupKeychain(keychain, original: originalSearchList)
        if FileManager.default.fileExists(atPath: directory.path) {
            do { try FileManager.default.removeItem(at: directory) } catch { cleanup.append("directory cleanup failed") }
        }
        output["cleanup_verified"] = cleanup.isEmpty
        if !cleanup.isEmpty { output["cleanup_failures"] = cleanup }
        guard let data = try? JSONSerialization.data(withJSONObject: output, options: [.sortedKeys]) else { exit(2) }
        print(String(decoding: data, as: UTF8.self))
        if output["success"] as? Bool != true || !cleanup.isEmpty { exit(1) }
    }
}

#if !STORAGE_ACCEPTANCE_TESTS
@main struct StorageAcceptanceMain {
    static func main() async { await StorageAcceptance.main() }
}
#endif
