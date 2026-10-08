// Public-certificate diagnostic only. Reimports the approved synthetic package into existing login Keychain.
// No preference writes, deletions, trust/ACL/search-list changes, UI or network calls.
import Foundation
import CoreFoundation
import CryptoKit
import Security
import Darwin
import CompanionCore

struct Failure: Error { let message: String }
struct Input: Decodable {
    let endpoint: String
    let caPath: String
    let pkcs12Path: String
    let pkcs12Passphrase: String
    let expectedPKCS12SHA256: String
    let serverLeafSHA256: String
    let expectedClientSHA256: String
}
let manager = FileManager.default
func require(_ value: Bool, _ message: String) throws {
    if !value { throw Failure(message: message) }
}
func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
func hex(_ value: String) -> Bool {
    value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
func path(_ value: String) throws -> URL {
    try require(value.hasPrefix("/") && !value.split(separator: "/").contains(".."), "Expected absolute path without traversal.")
    return URL(fileURLWithPath: value)
}
func privateDirectory(_ url: URL) throws {
    var info = stat()
    try require(url.path.withCString { lstat($0, &info) } == 0 && info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) && info.st_uid == getuid() && info.st_mode & 0o777 == 0o700, "Directory must be private, owned and not a symlink.")
}
func readPrivate(_ url: URL) throws -> Data {
    try privateDirectory(url.deletingLastPathComponent())
    let fd = url.path.withCString { open($0, O_RDONLY | O_NOFOLLOW) }
    try require(fd >= 0, "Cannot open private input or backup.")
    defer { close(fd) }
    var info = stat()
    try require(fstat(fd, &info) == 0 && info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) && info.st_uid == getuid() && info.st_mode & 0o777 == 0o600 && info.st_nlink == 1 && info.st_size <= 1_048_576, "Input or backup ownership, permissions, type or size is unsafe.")
    let data = FileHandle(fileDescriptor: fd, closeOnDealloc: false).readDataToEndOfFile()
    try require(data.count <= 1_048_576, "Input or backup is oversized.")
    return data
}

func certificateHash(_ identity: SecIdentity) throws -> String {
    var certificate: SecCertificate?
    try require(SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess && certificate != nil, "Cannot inspect imported public certificate.")
    return hash(SecCertificateCopyData(certificate!) as Data)
}
func persistent(_ identity: SecIdentity, exact: Bool) -> (OSStatus, Data?) {
    var query: [String: Any] = [kSecClass as String: kSecClassIdentity, kSecReturnPersistentRef as String: true]
    if exact { query[kSecMatchItemList as String] = [identity] }
    else { query[kSecValueRef as String] = identity }
    var value: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &value)
    return (status, value as? Data)
}
func inspect(_ reference: Data?, exact: Bool) -> [String: Any] {
    guard let reference else { return ["reference_returned": false] }
    do {
        let identity: SecIdentity
        if exact {
            var value: CFTypeRef?
            let status = SecItemCopyMatching([kSecClass as String: kSecClassIdentity,
                kSecMatchItemList as String: [reference], kSecReturnRef as String: true] as CFDictionary, &value)
            guard status == errSecSuccess, let value, CFGetTypeID(value) == SecIdentityGetTypeID() else {
                return ["reference_returned": true, "resolve_status": status, "resolved_identity": false]
            }
            identity = value as! SecIdentity
        } else { identity = try KeychainIdentity.resolve(reference) }
        return ["reference_returned": true, "resolved_identity": true, "certificate_sha256": try certificateHash(identity)]
    } catch { return ["reference_returned": true, "resolved_identity": false] }
}
do {
    umask(0o077)
    try require(CommandLine.arguments.count == 2, "Expected absolute private input JSON path.")
    let input = try JSONDecoder().decode(Input.self, from: readPrivate(path(CommandLine.arguments[1])))
    let package = try readPrivate(path(input.pkcs12Path))
    try require(hex(input.expectedPKCS12SHA256) && hex(input.expectedClientSHA256) && hash(package) == input.expectedPKCS12SHA256, "Approved package hash mismatch.")
    let login = manager.homeDirectoryForCurrentUser.appendingPathComponent("Library/Keychains/login.keychain-db")
    var keychain: SecKeychain?
    try require(SecKeychainOpen(login.path, &keychain) == errSecSuccess && keychain != nil, "Cannot open existing login Keychain.")
    var state: SecKeychainStatus = 0
    try require(SecKeychainGetStatus(keychain!, &state) == errSecSuccess && state & UInt32(kSecUnlockStateStatus) != 0, "Run locally with the login Keychain already unlocked.")
    var items: CFArray?
    let status = SecPKCS12Import(package as CFData,
        [kSecImportExportPassphrase as String: input.pkcs12Passphrase,
         kSecImportExportKeychain as String: keychain!] as CFDictionary, &items)
    guard status == errSecSuccess,
          let first = (items as? [[String: Any]])?.first,
          let value = first[kSecImportItemIdentity as String] else {
        throw Failure(message: "PKCS12 import did not return an identity.")
    }
    let identity = value as! SecIdentity
    let direct = try certificateHash(identity)
    let legacy = persistent(identity, exact: false)
    let exact = persistent(identity, exact: true)
    let report: [String: Any] = [
        "expected_client_sha256": input.expectedClientSHA256,
        "direct_imported_certificate_sha256": direct,
        "direct_matches_expected": direct == input.expectedClientSHA256,
        "legacy_query_status": legacy.0,
        "legacy_query_production_resolve": inspect(legacy.1, exact: false),
        "legacy_query_exact_resolve": inspect(legacy.1, exact: true),
        "exact_query_status": exact.0,
        "exact_query_production_resolve": inspect(exact.1, exact: false),
        "exact_query_exact_resolve": inspect(exact.1, exact: true),
        "queries_return_same_reference": legacy.1 != nil && legacy.1 == exact.1,
        "preferences_written": false,
        "keychain_deletions_or_acl_changes": false
    ]
    print(String(decoding: try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]), as: UTF8.self))
} catch let failure as Failure { fputs("Identity diagnostic failed: \(failure.message)\n", stderr); exit(2) }
catch { fputs("Identity diagnostic failed: local file, Keychain or decoding operation.\n", stderr); exit(2) }
