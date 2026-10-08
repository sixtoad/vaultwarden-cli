#!/usr/bin/swift
// Acceptance-only helper. No Keychain, UI, process-lifecycle or network APIs.
// Usage: swift companion-preference-check.swift backup|break-identity|restore|check /absolute/private-backup-directory
import Foundation
import CoreFoundation
import CryptoKit
import Darwin

struct Failure: Error { let message: String }
struct Manifest: Codable {
    let version: Int
    let originalSHA256: String
    let identityReferenceSHA256: String
}
let domain = "dev.vaultwarden.ApprovalCompanion"
let key = "providerConfiguration.v1"
let manager = FileManager.default
func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw Failure(message: message) }
}
func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
func exists(_ url: URL) -> Bool {
    var info = stat()
    return url.path.withCString { lstat($0, &info) } == 0
}
func privateItem(_ url: URL, directory: Bool) throws {
    var info = stat()
    try require(url.path.withCString { lstat($0, &info) } == 0, "Required private backup item is missing.")
    let expected = mode_t(directory ? S_IFDIR : S_IFREG)
    try require((info.st_mode & mode_t(S_IFMT)) == expected, "Backup item has an unsafe file type.")
    try require(info.st_uid == getuid(), "Backup item is not owned by this user.")
    try require((info.st_mode & 0o777) == (directory ? 0o700 : 0o600), "Backup item permissions are unsafe.")
    if !directory { try require(info.st_nlink == 1, "Backup item has unexpected hard links.") }
}
func appStopped() throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/ps")
    process.arguments = ["-axww", "-o", "pid=,comm="]
    let output = Pipe(); process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    try process.run()
    let bytes = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    try require(process.terminationStatus == 0, "Cannot establish whether the companion is stopped.")
    for line in String(decoding: bytes, as: UTF8.self).split(separator: "\n") {
        let fields = line.split(maxSplits: 1, omittingEmptySubsequences: true, whereSeparator: { $0.isWhitespace })
        if fields.count == 2 {
            let command = String(fields[1]).trimmingCharacters(in: .whitespaces)
            try require(URL(fileURLWithPath: command).lastPathComponent != "ApprovalCompanion", "Quit every Approval Companion process before this mode.")
        }
    }
}
func readPreference() throws -> Data {
    try require(CFPreferencesAppSynchronize(domain as CFString), "Preference synchronization failed.")
    guard let data = CFPreferencesCopyAppValue(key as CFString, domain as CFString) as? Data else {
        throw Failure(message: "The saved provider configuration is absent or is not Data.")
    }
    return data
}
func writePreference(_ data: Data) throws {
    try appStopped() // Recheck immediately before touching the single preference.
    CFPreferencesSetAppValue(key as CFString, data as CFData, domain as CFString)
    try require(CFPreferencesAppSynchronize(domain as CFString), "Preference write synchronization failed.")
    try require(try readPreference() == data, "Preference write did not preserve exact bytes.")
}
func configuration(_ data: Data) throws -> [String: String] {
    let value = try JSONDecoder().decode([String: String].self, from: data)
    try require(Set(value.keys) == Set(["endpoint", "trustedCA", "leafSHA256", "identityReference"]), "Unexpected provider configuration schema.")
    try require(value["endpoint"]?.hasPrefix("https://") == true, "Saved endpoint is not HTTPS.")
    guard let reference = Data(base64Encoded: value["identityReference"]!), !reference.isEmpty else {
        throw Failure(message: "Saved identity reference is absent or invalid.")
    }
    return value
}
func privateWrite(_ data: Data, _ url: URL) throws {
    try require(!exists(url), "Refusing to overwrite an existing backup item.")
    try data.write(to: url, options: .atomic)
    try privateItem(url, directory: false)
}
func readPrivate(_ url: URL) throws -> Data {
    try privateItem(url, directory: false)
    return try Data(contentsOf: url)
}
func emit(_ value: [String: Any]) throws {
    let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    print(String(decoding: data, as: UTF8.self))
}

do {
    umask(0o077)
    try require(CommandLine.arguments.count == 3, "Expected mode and absolute private backup directory.")
    let mode = CommandLine.arguments[1]
    try require(["backup", "break-identity", "restore", "check"].contains(mode), "Unknown mode.")
    let path = CommandLine.arguments[2]
    try require(path.hasPrefix("/") && !path.split(separator: "/").contains(".."), "Backup directory must be an absolute path without parent traversal.")
    let directory = URL(fileURLWithPath: path, isDirectory: true)
    if mode != "check" { try appStopped() }
    if mode == "backup" {
        try require(!exists(directory), "Backup requires a new private directory.")
        // Parent must already exist; never create a broad directory tree.
        try manager.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
    try privateItem(directory, directory: true)
    let originalURL = directory.appendingPathComponent("original-configuration.bin")
    let invalidURL = directory.appendingPathComponent("invalid-configuration.bin")
    let manifestURL = directory.appendingPathComponent("manifest.json")
    if mode == "backup" {
        let original = try readPreference()
        let value = try configuration(original)
        let reference = Data(base64Encoded: value["identityReference"]!)!
        let manifest = Manifest(version: 1, originalSHA256: digest(original), identityReferenceSHA256: digest(reference))
        try privateWrite(original, originalURL)
        try privateWrite(try JSONEncoder().encode(manifest), manifestURL)
        try emit(["mode": mode, "app_stopped": true, "backup_sha256": manifest.originalSHA256, "backup_verified": try readPrivate(originalURL) == original])
    } else {
        let original = try readPrivate(originalURL)
        let manifest = try JSONDecoder().decode(Manifest.self, from: readPrivate(manifestURL))
        let originalValue = try configuration(original)
        try require(manifest.version == 1 && digest(original) == manifest.originalSHA256, "Backup hash verification failed.")
        try require(digest(Data(base64Encoded: originalValue["identityReference"]!)!) == manifest.identityReferenceSHA256, "Backup identity hash verification failed.")
        let current = try readPreference()
        let currentValue = try configuration(current)
        if mode == "break-identity" {
            try require(currentValue == originalValue, "Saved setup changed since backup; refusing substitution.")
            var invalid = originalValue
            let marker = Data(("synthetic-missing-companion-identity-" + UUID().uuidString).utf8)
            invalid["identityReference"] = marker.base64EncodedString()
            let invalidData = try JSONEncoder().encode(invalid)
            try privateWrite(invalidData, invalidURL)
            try writePreference(invalidData)
            try emit(["mode": mode, "app_stopped": true, "backup_sha256": manifest.originalSHA256, "current_sha256": digest(invalidData), "only_identity_reference_changed": invalid.filter { $0.key != "identityReference" } == originalValue.filter { $0.key != "identityReference" }])
        } else if mode == "restore" {
            var known = currentValue == originalValue
            if exists(invalidURL) {
                let invalidValue = try configuration(readPrivate(invalidURL))
                known = known || currentValue == invalidValue
            }
            try require(known, "Current setup is neither original nor the known test substitution; refusing overwrite.")
            try writePreference(original)
            try emit(["mode": mode, "app_stopped": true, "current_sha256": digest(try readPreference()), "exact_original_bytes": true, "semantic_original_configuration": true])
        } else {
            var invalidMatch = false
            if exists(invalidURL) { invalidMatch = currentValue == (try configuration(readPrivate(invalidURL))) }
            try emit(["mode": mode, "backup_sha256": manifest.originalSHA256, "current_sha256": digest(current), "exact_original_bytes": current == original, "semantic_original_configuration": currentValue == originalValue, "semantic_test_substitution": invalidMatch, "identity_reference_matches_original": currentValue["identityReference"] == originalValue["identityReference"]])
        }
    }
} catch let failure as Failure {
    fputs("Preference verification failed: \(failure.message)\n", stderr)
    exit(2)
} catch {
    // Never print arbitrary decoder/system errors containing saved data.
    fputs("Preference verification failed: unexpected local I/O or decoding error.\n", stderr)
    exit(2)
}
