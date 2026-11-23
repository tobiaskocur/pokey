// swift-tools-version:5.9
// Portable logic (EDRCore) and the Rust core wrapper (EDRRules) build and test
// on macOS and Linux. The processes that use Endpoint Security, XPC, ImageIO
// and ServiceManagement are macOS-only; the Xcode project (project.yml) packages
// them into signed bundles. Build the Rust static library first: `make core`.
import PackageDescription

var targets: [Target] = [
    .systemLibrary(name: "CEDRCore", path: "Sources/CEDRCore"),
    .target(name: "EDRCore"),
    .target(name: "EDRRules", dependencies: ["CEDRCore", "EDRCore"]),
    .testTarget(name: "EDRCoreTests", dependencies: ["EDRCore"]),
    .testTarget(name: "EDRRulesTests", dependencies: ["EDRRules"]),
]
var products: [Product] = [.library(name: "EDRCore", targets: ["EDRCore"])]

#if os(macOS)
targets += [
    .executableTarget(
        name: "edr-sensor", dependencies: ["EDRCore", "EDRRules"],
        linkerSettings: [.linkedLibrary("EndpointSecurity"), .linkedLibrary("bsm"), .linkedLibrary("sqlite3")]),
    .executableTarget(name: "edr-inspector", dependencies: ["EDRCore", "EDRRules"]),
    .executableTarget(name: "edr-netd", dependencies: ["EDRCore"]),
    .executableTarget(name: "edr-ui", dependencies: ["EDRCore"]),
    .executableTarget(name: "EDRHost", dependencies: ["EDRCore"]),
]
products += ["edr-sensor", "edr-inspector", "edr-netd", "edr-ui", "EDRHost"].map {
    .executable(name: $0, targets: [$0])
}
#endif

let package = Package(
    name: "EDRAgent",
    platforms: [.macOS(.v13)],
    products: products,
    targets: targets
)
