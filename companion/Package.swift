// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CompanionNativeContract",
    platforms: [.macOS(.v13)],
    products: [.library(name: "NativeContract", targets: ["NativeContract"])],
    targets: [
        .target(name: "NativeContract", path: "macos/Runner",
                sources: ["ApprovalContract.swift", "NativeTestKey.swift"]),
        .testTarget(name: "NativeContractTests", dependencies: ["NativeContract"], path: "native_tests")
    ]
)
