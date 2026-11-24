// A headless service account does not get a login keychain from loginwindow.
// Configure only the dedicated CI user's preferences before running the native tests.
import Darwin
import Foundation
import Security

func fail(_ message: String) -> Never {
    fputs("\(message)\n", stderr)
    exit(1)
}

func check(_ status: OSStatus, _ operation: String) {
    if status != errSecSuccess { fail("\(operation): OSStatus \(status)") }
}

func path(of keychain: SecKeychain) -> String {
    var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
    var length = UInt32(buffer.count)
    check(SecKeychainGetPath(keychain, &length, &buffer), "Read keychain path")
    return String(cString: buffer)
}

func searchList(_ domain: SecPreferencesDomain) -> [SecKeychain] {
    var list: CFArray?
    check(SecKeychainCopyDomainSearchList(domain, &list), "Read keychain search list")
    guard let keys = list as? [SecKeychain] else { fail("Invalid keychain search list") }
    return keys
}

guard ProcessInfo.processInfo.environment["RUNNER_ENVIRONMENT"] == "self-hosted",
      NSUserName() == "vwci", NSHomeDirectory() == "/Users/vwci"
else { fail("Expected the dedicated self-hosted CI account") }
umask(0o077)
check(SecKeychainSetUserInteractionAllowed(false), "Disable interactive prompts")
var domain = SecPreferencesDomain.user
check(SecKeychainGetPreferenceDomain(&domain), "Read Keychain preference domain")
guard domain == .user else { fail("The runner requires a user security session") }

let files = FileManager.default
let directory = files.homeDirectoryForCurrentUser.appendingPathComponent("Library/Keychains")
try files.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
let login = directory.appendingPathComponent("login.keychain-db")
var keychain: SecKeychain?
let status = SecKeychainCopyDomainDefault(.user, &keychain)
let hasUserDefault = keychain.map {
    let name = path(of: $0)
    return name.hasPrefix(directory.path + "/") && files.fileExists(atPath: name)
} ?? false
if status != errSecSuccess || !hasUserDefault {
    if files.fileExists(atPath: login.path) {
        check(SecKeychainOpen(login.path, &keychain), "Open the runner login keychain")
    } else {
        let passwordFile = directory.appendingPathComponent(".vwci-keychain-key")
        let password: Data
        if files.fileExists(atPath: passwordFile.path) {
            password = try Data(contentsOf: passwordFile)
            guard password.count == 32 else { fail("Unexpected runner key file format") }
        } else {
            var bytes = [UInt8](repeating: 0, count: 32)
            check(SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes), "Generate keychain password")
            password = Data(bytes)
            try password.write(to: passwordFile, options: .withoutOverwriting)
        }
        check(password.withUnsafeBytes {
            SecKeychainCreate(login.path, UInt32($0.count), $0.baseAddress, false, nil, &keychain)
        }, "Create the runner login keychain")
    }
    guard let keychain else { fail("Missing login keychain") }
    check(SecKeychainSetDomainDefault(.user, keychain), "Set runner default keychain")
}
guard let keychain, path(of: keychain).hasPrefix(directory.path + "/") else {
    fail("Expected a default keychain in the CI account")
}
// Security.framework appends common-domain keys when reading the effective
// list. Keeping a second copy in the user domain prevents a clean round trip.
var seen = Set(searchList(.common).map(path(of:)))
let current = searchList(.user)
let desired = ([keychain] + current).filter { seen.insert(path(of: $0)).inserted }
if current.map(path(of:)) != desired.map(path(of:)) {
    check(SecKeychainSetDomainSearchList(.user, desired as CFArray), "Set runner search list")
}
print("Verified dedicated user Keychain baseline (\(desired.count) user entries)")
