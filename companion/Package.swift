// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CompanionNativeContract",
    platforms: [.macOS(.v13)],
    products: [.library(name: "NativeContract", targets: ["NativeContract"])],
    targets: [
        .target(name: "NativeContract", path: "macos/Runner",
                // Flutter/Xcode owns these app sources and resources, including Base.lproj.
                exclude: ["AppDelegate.swift", "ApprovalSigner.swift", "MainFlutterWindow.swift", "ProviderAdapter.swift", "ProviderSettings.swift",
                          "Assets.xcassets", "Base.lproj", "Configs", "Info.plist",
                          "DebugProfile.entitlements", "Release.entitlements"],
                sources: ["ApprovalContract.swift", "NativeTestKey.swift"]),
        .testTarget(name: "NativeContractTests", dependencies: ["NativeContract"], path: "native_tests")
    ]
)
