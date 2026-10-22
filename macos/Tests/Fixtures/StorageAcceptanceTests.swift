// Compile production CompanionCore + StorageAcceptance.swift + this file with
// swiftc -D STORAGE_ACCEPTANCE_TESTS -parse-as-library ... -o storage-acceptance-tests
import Foundation
import Security

private struct Reply: CompanionTransport {
    let status: String
    let fail: Bool
    func send(_ body: Data) async throws -> Data {
        if fail { throw CompanionError.transport }
        return Data("{\"version\":1,\"status\":\(status)}".utf8)
    }
}

@main struct StorageAcceptanceTests {
    @MainActor static func main() async throws {
        func require(_ condition: @autoclosure () -> Bool, _ label: String) throws {
            guard condition() else { throw NSError(domain: "StorageAcceptanceTests", code: 1, userInfo: [NSLocalizedDescriptionKey: label]) }
        }
        func status(_ json: String) throws -> DirectStatus { try JSONDecoder().decode(DirectStatus.self, from: Data(json.utf8)) }
        func rejects(_ action: () throws -> Void) -> Bool {
            do { try action(); return false } catch { return true }
        }
        let base: [String: Any] = ["synthetic_only": true, "endpoint": "https://127.0.0.1:443", "identity": "/private/identity.p12", "identity_password": "synthetic-only", "ca": "/private/ca.der", "pin": String(repeating: "a", count: 64), "command": "session"]
        func decode(_ value: [String: Any]) throws -> StorageAcceptanceConfiguration { try StorageAcceptanceConfiguration.decode(JSONSerialization.data(withJSONObject: value)) }
        _ = try decode(base)
        try require(rejects { _ = try StorageAcceptanceConfiguration.decode(Data("[]".utf8)) }, "non-object config rejected")
        for field in ["identity", "identity_password", "ca", "pin", "command"] {
            var value = base; value.removeValue(forKey: field)
            try require(rejects { _ = try decode(value) }, "missing common config rejected")
            value = base; value[field] = 12
            try require(rejects { _ = try decode(value) }, "wrong config type rejected")
        }
        var unlock = base; unlock["command"] = "unlock"
        try require(rejects { _ = try decode(unlock) }, "missing unlock password rejected")
        unlock["password"] = ""; try require(rejects { _ = try decode(unlock) }, "empty password rejected")
        unlock["password"] = "synthetic-only"; _ = try decode(unlock)
        var query = base; query["command"] = "status"
        try require(rejects { _ = try decode(query) }, "missing status ID rejected")
        query["request_id"] = "invalid"; try require(rejects { _ = try decode(query) }, "invalid status ID rejected")
        var approve = unlock; approve["command"] = "approve"
        try require(rejects { _ = try decode(approve) }, "missing operation rejected")
        approve["operation"] = "storage-create"
        try require(rejects { _ = try decode(approve) }, "missing create effect rejected")
        approve["expected_create"] = ["server": "https://127.0.0.1:443", "destination": ["account_id": "11111111-1111-1111-1111-111111111111", "folder": "storage-acceptance", "folder_id": "22222222-2222-2222-2222-222222222222", "reference": "storage-acceptance/create"], "fields": ["password"], "eligibility_marker": "storage-consume"]
        _ = try decode(approve)
        var denied = approve; denied["command"] = "deny"; denied.removeValue(forKey: "password"); _ = try decode(denied)
        approve["expected_create"] = ["fields": ["password"]]
        try require(rejects { _ = try decode(approve) }, "malformed create effect rejected before mutation")

        let completed = try status("{\"status\":\"completed\",\"exit_code\":0}")
        let deniedStatus = try status("{\"status\":\"denied\"}")
        let failed = try status("{\"status\":\"failed\",\"reason\":\"execution_unavailable\"}")
        try StorageAcceptance.requireOutcome(completed, command: "approve", operation: "storage-create")
        try StorageAcceptance.requireOutcome(completed, command: "approve", operation: "storage-consume")
        try StorageAcceptance.requireOutcome(deniedStatus, command: "deny", operation: "storage-deny")
        try StorageAcceptance.requireOutcome(failed, command: "approve", operation: "storage-interrupt")
        for json in ["{\"status\":\"pending\"}", "{\"status\":\"running\"}", "{\"status\":\"expired\"}", "{\"status\":\"completed\",\"exit_code\":1}", "{\"status\":\"denied\"}", "{\"status\":\"failed\",\"reason\":\"execution_unavailable\"}"] {
            let wrong = try status(json)
            try require(rejects { try StorageAcceptance.requireOutcome(wrong, command: "approve", operation: "storage-create") }, "wrong create result rejected")
        }
        try require(rejects { try StorageAcceptance.requireOutcome(completed, command: "deny", operation: "storage-deny") }, "wrong deny result rejected")
        try require(rejects { try StorageAcceptance.requireOutcome(completed, command: "approve", operation: "storage-interrupt") }, "wrong interrupted result rejected")
        let wrongFailure = try status("{\"status\":\"failed\",\"reason\":\"execution_rejected\"}")
        try require(rejects { try StorageAcceptance.requireOutcome(wrongFailure, command: "approve", operation: "storage-interrupt") }, "wrong interruption reason rejected")

        for fail in [false, true] {
            let client = CompanionClient(transport: Reply(status: "{\"status\":\"running\"}", fail: fail))
            let metrics = StorageAcceptanceMetrics()
            var output: [String: Any] = [:]
            var rejected = false
            do {
                try await StorageAcceptance.finishDecision(try status("{\"status\":\"running\"}"), requestID: String(repeating: "A", count: 43), client: client, command: "approve", operation: "storage-create", metrics: metrics, output: &output, polls: 2, delay: 0)
            } catch { rejected = true }
            metrics.append(to: &output)
            try require(rejected, "poll exhaustion or transport error must fail")
            try require(metrics.attempted["status"] == (fail ? 1 : 2), "attempted requests retained")
            try require(metrics.completed["status", default: 0] == (fail ? 0 : 2), "completed requests distinct from attempts")
            try require(metrics.elapsed["status"] != nil, "failed request timing retained")
            try require((output["operation_elapsed_seconds"] as? Double) != nil, "operation timing retained")
            try require(output["native_request_attempted_counts"] != nil && output["native_request_completed_counts"] != nil, "catch output keeps counters")
            if !fail { try require(output["status"] as? String == "running", "last nonterminal status retained") }
        }

        // Exercise the same cleanup function with a real disposable Keychain.
        var original: CFArray?
        try require(SecKeychainCopySearchList(&original) == errSecSuccess && original != nil, "capture original search list")
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("storage-acceptance-regression-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var keychain: SecKeychain?
        defer { _ = StorageAcceptance.cleanupKeychain(keychain, original: original); try? FileManager.default.removeItem(at: directory) }
        let password = UUID().uuidString
        let created = directory.appendingPathComponent("test.keychain-db").path.withCString { path in
            password.withCString { bytes in SecKeychainCreate(path, UInt32(password.utf8.count), bytes, false, nil, &keychain) }
        }
        try require(created == errSecSuccess, "create disposable keychain")
        if let keychain, let existing = original as? [SecKeychain] {
            try require(SecKeychainSetSearchList((existing + [keychain]) as CFArray) == errSecSuccess, "add disposable keychain")
        } else { throw CompanionError.configuration }
        let cleanup = StorageAcceptance.cleanupKeychain(keychain, original: original)
        keychain = nil
        try require(cleanup.isEmpty, "delete then restore and verify original search list")
        var restored: CFArray?
        try require(SecKeychainCopySearchList(&restored) == errSecSuccess && restored != nil && CFEqual(restored, original), "independent restoration check")
        print("PASS: config validation, scenario outcomes, poll exhaustion, failure counters/timing, keychain restoration")
    }
}
