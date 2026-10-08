// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ApprovalCompanion",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "ApprovalCompanion", targets: ["ApprovalCompanion"])],
    targets: [
        .target(name: "CompanionCore"),
        .executableTarget(name: "ApprovalCompanion", dependencies: ["CompanionCore"]),
        .testTarget(name: "CompanionCoreTests", dependencies: ["CompanionCore"]),
        .testTarget(name: "ApprovalCompanionTests", dependencies: ["ApprovalCompanion", "CompanionCore"])
    ]
)
