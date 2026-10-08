import CryptoKit
import Foundation
import Security
import XCTest
@testable import CompanionCore

/// These tests use real URLSession, Security.framework, Keychain, and a localhost
/// TLS server requiring a client certificate. They are mandatory, not skipped.
final class TLSTests: XCTestCase {
    func testSameSubjectRenewalReturnsExactImportedIdentity() throws {
        let fixture = try TLSFixture()
        defer { XCTAssertEqual(fixture.close(), [], "Temporary Keychain cleanup must succeed") }
        let oldReference = try XCTUnwrap(fixture.references["client"])
        let oldFingerprint = try KeychainIdentity.fingerprint(oldReference)
        let renewed = try fixture.renewedClient(collision: false)
        XCTAssertNotEqual(renewed.fingerprint, oldFingerprint)
        let reference = try KeychainIdentity.importPKCS12(renewed.package, passphrase: "synthetic-only", keychain: fixture.keychain)
        XCTAssertEqual(try KeychainIdentity.fingerprint(reference), renewed.fingerprint)
        XCTAssertEqual(try KeychainIdentity.fingerprint(oldReference), oldFingerprint, "Renewal must preserve the original identity")
        let repeated = try KeychainIdentity.importPKCS12(renewed.package, passphrase: "synthetic-only", keychain: fixture.keychain)
        XCTAssertEqual(try KeychainIdentity.fingerprint(repeated), renewed.fingerprint)
    }

    func testIssuerSerialCollisionNeverSubstitutesExistingIdentity() throws {
        let fixture = try TLSFixture()
        defer { XCTAssertEqual(fixture.close(), [], "Temporary Keychain cleanup must succeed") }
        let oldReference = try XCTUnwrap(fixture.references["client"])
        let oldFingerprint = try KeychainIdentity.fingerprint(oldReference)
        let renewed = try fixture.renewedClient(collision: true)
        XCTAssertNotEqual(renewed.fingerprint, oldFingerprint)
        do {
            let reference = try KeychainIdentity.importPKCS12(renewed.package, passphrase: "synthetic-only", keychain: fixture.keychain)
            XCTAssertEqual(try KeychainIdentity.fingerprint(reference), renewed.fingerprint, "A colliding import must never substitute the older identity")
        } catch {
            XCTAssertEqual(error as? CompanionError, .configuration, "A Keychain issuer/serial collision must fail closed")
        }
        XCTAssertEqual(try KeychainIdentity.fingerprint(oldReference), oldFingerprint)
    }

    func testRealURLSessionRejectsHTTPBodyStatusMismatch() async throws {
        let fixture = try TLSFixture()
        defer { XCTAssertEqual(fixture.close(), [], "Temporary Keychain cleanup must succeed") }
        for mode in ["success503", "error200", "mismatched-error422", "unknown-error422", "extra-error422"] {
            try fixture.start(mode: mode)
            do {
                _ = try await fixture.client().session()
                XCTFail("Accepted HTTP/body mismatch: \(mode)")
            } catch {
                XCTAssertEqual(error as? CompanionError, .invalidResponse, mode)
            }
            XCTAssertEqual(try fixture.commands(), ["session"], "Mismatches must not trigger replay")
        }
        try fixture.start(mode: "valid-error422")
        do {
            _ = try await fixture.client().session()
            XCTFail("Accepted authentication rejection as success")
        } catch {
            XCTAssertEqual(error as? CompanionError, .rejected("authentication_failed"))
        }
        XCTAssertEqual(try fixture.commands(), ["session"])
    }

    func testRealURLSessionAuthenticationAndSingleTransmission() async throws {
        let fixture = try TLSFixture()
        defer { XCTAssertEqual(fixture.close(), [], "Temporary Keychain and search list cleanup must succeed") }
        try fixture.start()
        let valid = try fixture.client()
        let session = try await valid.session()
        XCTAssertEqual(session.state, "unlocked")
        XCTAssertEqual(try fixture.commands(), ["session"])

        for variant in ["pin", "ca", "foreign", "revoked"] {
            try fixture.start()
            let client = try fixture.client(variant: variant)
            do { _ = try await client.session(); XCTFail("Accepted \(variant)") } catch {}
            XCTAssertEqual(try fixture.commands(), variant == "revoked" ? ["session"] : [], "An untrusted server or client must not exchange an API body")
        }
        try fixture.start(mode: "wrong-host")
        do { _ = try await fixture.client(serverCertificate: "wrong-host").session(); XCTFail("Accepted wrong hostname with matching CA and pin") } catch {}
        XCTAssertEqual(try fixture.commands(), [])

        try fixture.start(mode: "redirect")
        do { _ = try await fixture.client().session(); XCTFail("Followed redirect") } catch {}
        XCTAssertEqual(try fixture.commands(), ["session"])

        try fixture.start(mode: "oversized")
        // Assert at the transport boundary: closed JSON decoding must not mask
        // a regression that buffers and returns an oversized valid JSON body.
        do {
            _ = try await fixture.transport().send(Data(#"{"version":1,"command":"session"}"#.utf8))
            XCTFail("Accepted oversized response")
        } catch {
            XCTAssertTrue([CompanionError.invalidResponse, .oversized].contains(error as? CompanionError ?? .transport))
        }

        try fixture.start(mode: "drop")
        let dropped = try fixture.client()
        do { _ = try await dropped.decide(fixtureReview(), approve: true, password: "synthetic-only"); XCTFail("Expected lost decision response") } catch {}
        let status = try await dropped.status(fixtureReview().review.id)
        XCTAssertEqual(status.status, "pending")
        // Counts bodies received by the real server, catching implicit URLSession
        // POST replay as well as retries in our own transport/client.
        XCTAssertEqual(try fixture.commands(), ["decision", "status"])
    }
}

private final class TLSFixture {
    let directory: URL
    let script: URL
    var keychain: SecKeychain?
    var originalSearchList: CFArray?
    var server: Process?
    var port = 0
    var references: [String: Data] = [:]
    init() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("companion-tls-\(UUID().uuidString)", isDirectory: true)
        script = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Fixtures/tls_fixture.py")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        do {
            let setup = Process(); setup.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            setup.arguments = ["python3", script.path, "provision", directory.path]
            setup.standardOutput = FileHandle.nullDevice
            setup.standardError = FileHandle.nullDevice
            try setup.run(); setup.waitUntilExit()
            guard setup.terminationStatus == 0 else { throw CompanionError.configuration }
            let password = "synthetic-keychain-only"
            let result = directory.appendingPathComponent("test.keychain-db").path.withCString { path in
                password.withCString { bytes in SecKeychainCreate(path, UInt32(password.utf8.count), bytes, false, nil, &keychain) }
            }
            guard result == errSecSuccess, let keychain else { throw CompanionError.configuration }
            guard SecKeychainCopySearchList(&originalSearchList) == errSecSuccess else { throw CompanionError.configuration }
            let existing = (originalSearchList as? [SecKeychain]) ?? []
            guard SecKeychainSetSearchList((existing + [keychain]) as CFArray) == errSecSuccess else { throw CompanionError.configuration }
            for name in ["client", "revoked", "foreign"] {
                references[name] = try KeychainIdentity.importPKCS12(Data(contentsOf: directory.appendingPathComponent("\(name).p12")), passphrase: "synthetic-only", keychain: keychain)
            }
        } catch { _ = close(); throw error }
    }
    func start(mode: String = "normal") throws {
        stopServer()
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", script.path, "serve", directory.path, "--mode", mode]
        let output = Pipe(); process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run(); server = process
        var line = Data()
        while line.count < 16, let byte = try output.fileHandleForReading.read(upToCount: 1), !byte.isEmpty {
            if byte == Data([10]) { break }; line.append(byte)
        }
        guard let value = String(data: line, encoding: .utf8), let port = Int(value) else { throw CompanionError.configuration }
        self.port = port
    }
    func renewedClient(collision: Bool) throws -> (package: Data, fingerprint: String) {
        // Same subjects and default PKCS12 labels, but fresh CA/client keys.
        // Unlike ordinary TLS fixtures, both generations coexist in one Keychain.
        let renewed = directory.appendingPathComponent("renewal", isDirectory: true)
        func run(_ arguments: [String], at workingDirectory: URL) throws -> String {
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = arguments; process.currentDirectoryURL = workingDirectory
            let output = Pipe(); process.standardOutput = output; process.standardError = FileHandle.nullDevice
            try process.run(); let data = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw CompanionError.configuration }
            return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        _ = try run(["python3", script.path, "provision", renewed.path], at: directory)
        let openssl = ProcessInfo.processInfo.environment["OPENSSL"] ?? "openssl"
        let originalSerial = try run([openssl, "x509", "-in", "client.pem", "-noout", "-serial"], at: directory)
        let prefix = "serial="
        guard originalSerial.hasPrefix(prefix) else { throw CompanionError.configuration }
        let serial = String(originalSerial.dropFirst(prefix.count))
        guard !serial.isEmpty, serial.allSatisfy({ $0.isHexDigit }) else { throw CompanionError.configuration }
        if collision {
            _ = try run([openssl, "x509", "-req", "-in", "client.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-set_serial", "0x" + serial, "-days", "2", "-extfile", "client.ext", "-out", "client.pem"], at: renewed)
            _ = try run([openssl, "x509", "-in", "client.pem", "-outform", "DER", "-out", "client.der"], at: renewed)
            _ = try run([openssl, "pkcs12", "-export", "-inkey", "client.key", "-in", "client.pem", "-certfile", "ca.pem", "-passout", "pass:synthetic-only", "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1", "-out", "client.p12"], at: renewed)
        }
        let renewedSerial = try run([openssl, "x509", "-in", "client.pem", "-noout", "-serial"], at: renewed)
        guard (renewedSerial == originalSerial) == collision else { throw CompanionError.configuration }
        let originalSubject = try run([openssl, "x509", "-in", "client.pem", "-noout", "-subject", "-issuer"], at: directory)
        let renewedSubject = try run([openssl, "x509", "-in", "client.pem", "-noout", "-subject", "-issuer"], at: renewed)
        guard originalSubject == renewedSubject else { throw CompanionError.configuration }
        let der = try Data(contentsOf: renewed.appendingPathComponent("client.der"))
        return (try Data(contentsOf: renewed.appendingPathComponent("client.p12")), KeychainIdentity.fingerprintDER(der))
    }
    func client(variant: String = "valid", serverCertificate: String = "server") throws -> CompanionClient {
        CompanionClient(transport: try transport(variant: variant, serverCertificate: serverCertificate))
    }
    func transport(variant: String = "valid", serverCertificate: String = "server") throws -> PinnedTransport {
        let ca = try Data(contentsOf: directory.appendingPathComponent(variant == "ca" ? "other-ca.der" : "ca.der"))
        let leaf = try Data(contentsOf: directory.appendingPathComponent("\(serverCertificate).der"))
        let fingerprint = variant == "pin" ? String(repeating: "0", count: 64) : SHA256.hash(data: leaf).map { String(format: "%02x", $0) }.joined()
        let reference = references[["foreign", "revoked"].contains(variant) ? variant : "client"]!
        let config = try ProviderConfiguration(endpoint: URL(string: "https://127.0.0.1:\(port)")!, trustedCA: ca, leafSHA256: fingerprint, identityReference: reference)
        return try PinnedTransport(configuration: config)
    }
    func commands() throws -> [String] {
        let data = try String(contentsOf: directory.appendingPathComponent("requests.jsonl"), encoding: .utf8)
        return try data.split(separator: "\n").map {
            let object = try JSONSerialization.jsonObject(with: Data($0.utf8)) as! [String: String]
            return object["command"]!
        }
    }
    func stopServer() {
        if let server, server.isRunning { server.terminate(); server.waitUntilExit() }
        server = nil
    }
    @discardableResult func close() -> [String] {
        stopServer()
        var failures: [String] = []
        let hadKeychain = keychain != nil
        if let originalSearchList {
            let status = SecKeychainSetSearchList(originalSearchList)
            if status != errSecSuccess { failures.append("search-list restore: \(status)") }
            var actual: CFArray?
            let readStatus = SecKeychainCopySearchList(&actual)
            if readStatus != errSecSuccess || actual == nil || !CFEqual(actual, originalSearchList) {
                failures.append("search-list restoration verification failed")
            }
            self.originalSearchList = nil
        }
        if let keychain {
            let status = SecKeychainDelete(keychain)
            if status != errSecSuccess { failures.append("temporary Keychain delete: \(status)") }
            self.keychain = nil
        }
        if FileManager.default.fileExists(atPath: directory.path) {
            do { try FileManager.default.removeItem(at: directory) }
            catch { failures.append("temporary fixture directory removal failed") }
        }
        if hadKeychain && failures.isEmpty {
            print("TLS fixture cleanup verified: original Keychain search list restored; temporary Keychain and certificates deleted.")
        }
        return failures
    }
    deinit { close() }
}
