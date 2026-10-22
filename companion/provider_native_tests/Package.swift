// swift-tools-version: 5.9
// Staged by scripts/test-provider-native.sh; no installed app or keychain adopted.
import PackageDescription
let package = Package(name: "FlutterProviderNative", platforms: [.macOS(.v13)], targets: [
    .target(name: "CompanionCore"),
    .testTarget(name: "CompanionCoreTests", dependencies: ["CompanionCore"])
])
