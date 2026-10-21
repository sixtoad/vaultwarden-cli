// swift-tools-version: 5.9
import PackageDescription

var targets: [Target] = [
    .target(name: "ProbeCore"),
    .testTarget(name: "ProbeCoreTests", dependencies: ["ProbeCore"])
]
var products: [Product] = []
#if os(macOS)
targets.append(.executableTarget(name: "TouchIDProbe", dependencies: ["ProbeCore"]))
products.append(.executable(name: "TouchIDProbe", targets: ["TouchIDProbe"]))
#endif
let package = Package(name: "TouchIDProbe", platforms: [.macOS(.v13)],
                      products: products, targets: targets)
