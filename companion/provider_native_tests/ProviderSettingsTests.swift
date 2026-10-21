import Foundation
import XCTest
@testable import CompanionCore

final class ProviderSettingsTests: XCTestCase {
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
