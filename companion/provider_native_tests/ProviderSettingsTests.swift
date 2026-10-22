import Foundation
import Security
import XCTest
@testable import CompanionCore

final class ProviderSettingsTests: XCTestCase {
    func testProductionInstallReloadAndBoundedFailuresInDisposableDefaultKeychain() throws {
        guard ProcessInfo.processInfo.environment["CI"] == "true" else {
            throw XCTSkip("Disposable default-Keychain installation test is CI-only")
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("flutter-install-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        var originalDefault: SecKeychain?
        var originalSearch: CFArray?
        guard SecKeychainCopyDefault(&originalDefault) == errSecSuccess, let originalDefault,
              SecKeychainCopySearchList(&originalSearch) == errSecSuccess, let originalSearch else {
            throw CompanionError.configuration
        }
        var disposable: SecKeychain?
        let password = "synthetic-keychain-only"
        let path = directory.appendingPathComponent("install.keychain-db").path
        let created = path.withCString { path in
            password.withCString { bytes in SecKeychainCreate(path, UInt32(password.utf8.count), bytes, false, nil, &disposable) }
        }
        guard created == errSecSuccess, let disposable else { throw CompanionError.configuration }
        defer {
            XCTAssertEqual(SecKeychainSetDefault(originalDefault), errSecSuccess)
            XCTAssertEqual(SecKeychainSetSearchList(originalSearch), errSecSuccess)
            var actualDefault: SecKeychain?
            var actualSearch: CFArray?
            XCTAssertEqual(SecKeychainCopyDefault(&actualDefault), errSecSuccess)
            XCTAssertEqual(SecKeychainCopySearchList(&actualSearch), errSecSuccess)
            XCTAssertTrue(actualDefault.map { CFEqual($0, originalDefault) } ?? false)
            XCTAssertTrue(actualSearch.map { CFEqual($0, originalSearch) } ?? false)
            XCTAssertEqual(SecKeychainDelete(disposable), errSecSuccess)
        }
        guard SecKeychainSetSearchList(((originalSearch as? [SecKeychain] ?? []) + [disposable]) as CFArray) == errSecSuccess,
              SecKeychainSetDefault(disposable) == errSecSuccess else { throw CompanionError.configuration }
        var selected: SecKeychain?
        guard SecKeychainCopyDefault(&selected) == errSecSuccess, let selected,
              CFEqual(selected, disposable) else { throw CompanionError.configuration }
        // The real install method imports into the verified disposable default.
        // No production injection, login-keychain import or trust modification.
        let fixture = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Fixtures/tls_fixture.py")
        let process = Process()
        let exited = DispatchGroup()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", fixture.path, "provision", directory.path]
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        exited.enter()
        process.terminationHandler = { _ in exited.leave() }
        do { try process.run() } catch { exited.leave(); throw error }
        guard exited.wait(timeout: .now() + 30) == .success else {
            process.terminate()
            _ = exited.wait(timeout: .now() + 5)
            XCTFail("Synthetic certificate provisioning exceeded deadline")
            throw CompanionError.configuration
        }
        guard process.terminationStatus == 0 else { throw CompanionError.configuration }
        let ca = try Data(contentsOf: directory.appendingPathComponent("ca.der"))
        let package = try Data(contentsOf: directory.appendingPathComponent("client.p12"))
        let fingerprint = KeychainIdentity.fingerprintDER(try Data(contentsOf: directory.appendingPathComponent("client.der")))
        let settingsDirectory = directory.appendingPathComponent("settings")
        let settings = ProviderSettings(directory: settingsDirectory)
        let endpoint = URL(string: "https://localhost:8443/v1/companion")!
        let pin = String(repeating: "a", count: 64)
        XCTAssertThrowsError(try settings.install(endpoint: endpoint, ca: ca, pin: pin, pkcs12: package, passphrase: "wrong"))
        XCTAssertEqual(try settings.metadata()["configured"] as? Bool, false)
        XCTAssertThrowsError(try settings.install(endpoint: URL(string: "http://localhost")!, ca: ca, pin: pin, pkcs12: package, passphrase: "synthetic-only"))
        XCTAssertThrowsError(try settings.install(endpoint: endpoint, ca: Data(), pin: pin, pkcs12: package, passphrase: "synthetic-only"))
        XCTAssertThrowsError(try settings.install(endpoint: endpoint, ca: ca, pin: "invalid", pkcs12: package, passphrase: "synthetic-only"))
        XCTAssertEqual(try settings.metadata()["configured"] as? Bool, false)
        try settings.install(endpoint: endpoint, ca: ca, pin: pin, pkcs12: package, passphrase: "synthetic-only")
        let reloaded = ProviderSettings(directory: settingsDirectory)
        let configuration = try reloaded.configuration()
        XCTAssertEqual(configuration.endpoint, endpoint)
        XCTAssertEqual(configuration.trustedCA, ca)
        XCTAssertEqual(configuration.leafSHA256, pin)
        XCTAssertEqual(try reloaded.metadata()["fingerprint"] as? String, fingerprint)
        XCTAssertEqual(try KeychainIdentity.fingerprint(configuration.identityReference), fingerprint)
        let blocker = directory.appendingPathComponent("not-a-directory")
        try Data([1]).write(to: blocker)
        let cannotSave = ProviderSettings(directory: blocker)
        XCTAssertThrowsError(try cannotSave.install(endpoint: endpoint, ca: ca, pin: pin, pkcs12: package, passphrase: "synthetic-only"))
        XCTAssertThrowsError(try cannotSave.configuration())
        XCTAssertEqual(try cannotSave.metadata()["configured"] as? Bool, false)
    }
    func testDurableMarkerSurvivesRelaunchAndBindsOriginalRequest() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("flutter-provider-settings-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let fixture = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Fixtures/tls_fixture.py")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", fixture.path, "provision", directory.path]
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        let ca = try Data(contentsOf: directory.appendingPathComponent("ca.der"))
        let configuration = try ProviderConfiguration(endpoint: URL(string: "https://localhost:8443")!, trustedCA: ca,
                                                      leafSHA256: String(repeating: "a", count: 64), identityReference: Data([1]))
        let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(configuration))
        let file = directory.appendingPathComponent("configuration-v1.json")
        try JSONSerialization.data(withJSONObject: ["configuration": object]).write(to: file)
        let settings = ProviderSettings(directory: directory)
        // Valid saved configuration with a deliberately nonexistent opaque ref.
        XCTAssertNoThrow(try settings.configuration())
        XCTAssertThrowsError(try settings.metadata()) { error in
            XCTAssertEqual(error as? ProviderSettingsError, .identityUnavailable)
        }
        let id = String(repeating: "A", count: 43)
        try settings.beforeSend(Data(#"{"version":1,"command":"session"}"#.utf8))
        XCTAssertNil(try settings.pendingID())
        try settings.beforeSend(Data("{\"version\":1,\"command\":\"decision\",\"request_id\":\"\(id)\"}".utf8))
        let relaunched = ProviderSettings(directory: directory)
        XCTAssertEqual(try relaunched.pendingID(), id)
        for command in ["session", "unlock", "review", "decision"] {
            XCTAssertThrowsError(try relaunched.beforeSend(Data("{\"command\":\"\(command)\",\"request_id\":\"\(id)\"}".utf8)))
        }
        XCTAssertThrowsError(try relaunched.beforeSend(Data("{\"command\":\"status\",\"request_id\":\"\(String(repeating: "B", count: 43))\"}".utf8)))
        try relaunched.beforeSend(Data("{\"command\":\"status\",\"request_id\":\"\(id)\"}".utf8))
        XCTAssertThrowsError(try relaunched.settle(String(repeating: "B", count: 43)))
        try relaunched.settle(id)
        XCTAssertNil(try ProviderSettings(directory: directory).pendingID())
        let saved = try String(contentsOf: file)
        XCTAssertFalse(saved.contains("password")); XCTAssertFalse(saved.contains("ticket"))
        XCTAssertFalse(saved.contains("PRIVATE KEY"))
        let mode = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode?.intValue, 0o600)
    }
    func testFreshDevelopmentSettingsDoNotAdoptAnotherApplication() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("flutter-empty-\(UUID().uuidString)")
        let settings = ProviderSettings(directory: directory)
        XCTAssertEqual(try settings.metadata()["configured"] as? Bool, false)
        XCTAssertNil(try settings.pendingID())
        XCTAssertThrowsError(try settings.configuration()) { error in
            XCTAssertEqual(error as? ProviderSettingsError, .unreadable)
        }
    }
    func testInvalidSavedConfigurationHasClosedNonSecretError() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("flutter-invalid-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("configuration-v1.json")
        let settings = ProviderSettings(directory: directory)
        for bytes in [Data("private-path password identity-reference".utf8),
                      Data(#"{"configuration":{"identityReference":"secret"}}"#.utf8),
                      Data(repeating: 65, count: 131_073)] {
            try bytes.write(to: file)
            XCTAssertThrowsError(try settings.metadata()) { error in
                XCTAssertEqual(error as? ProviderSettingsError, .invalid)
                XCTAssertEqual((error as? ProviderSettingsError)?.code, "provider_configuration_invalid")
            }
        }
    }
    func testSettingsErrorVocabularyIsClosed() {
        XCTAssertEqual(ProviderSettingsError.unreadable.code, "provider_configuration_unreadable")
        XCTAssertEqual(ProviderSettingsError.invalid.code, "provider_configuration_invalid")
        XCTAssertEqual(ProviderSettingsError.identityUnavailable.code, "provider_identity_unavailable")
    }
}
