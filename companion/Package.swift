// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CompanionNativeContract",
    platforms: [.macOS(.v13)],
    products: [.library(name: "NativeContract", targets: ["NativeContract"])],
    targets: [
        .target(name: "NativeContract", path: "macos/Runner",
                // Flutter/Xcode owns these app sources and resources, including Base.lproj.
                exclude: ["AppDelegate.swift", "ApprovalSigner.swift", "MainFlutterWindow.swift", "ProviderAdapter.swift", "ReviewNotificationAdapter.swift", "ProviderSettings.swift", "ProductionSigner.swift",
                          "Assets.xcassets", "Base.lproj", "Configs", "Info.plist",
                          "DebugProfile.entitlements", "Release.entitlements"],
                sources: ["ApprovalContract.swift", "NativeTestKey.swift",
                          "ProductionApprovalContract.swift", "ProductionApprovalKey.swift",
                          "ReviewNotificationContract.swift"]),
        .testTarget(name: "NativeContractTests", dependencies: ["NativeContract"], path: "native_tests"),
        // iOS approval-client rules free of UIKit and of the shared key code
        // (#60 phase 2). The iOS Runner compiles the same file.
        .target(name: "MobileContract", path: "ios/Runner",
                exclude: ["AppDelegate.swift", "SceneDelegate.swift", "MobileChannels.swift", "MobileApprovalKeyChannel.swift",
                          "MobileProviderAdapter.swift", "MobileReviewNotificationAdapter.swift",
                          "Runner-Bridging-Header.h", "GeneratedPluginRegistrant.h", "GeneratedPluginRegistrant.m",
                          "Assets.xcassets", "Base.lproj", "Info.plist", "Runner.entitlements"],
                sources: ["MobileApprovalContract.swift"]),
        .testTarget(name: "MobileContractTests", dependencies: ["MobileContract"], path: "mobile_native_tests")
    ]
)
