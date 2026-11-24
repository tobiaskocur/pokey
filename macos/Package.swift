// swift-tools-version:5.9
// Portable logic (PokeyCore) and the Rust core wrapper (PokeyRules) build and test
// on macOS and Linux. The processes that use Endpoint Security, XPC, ImageIO
// and ServiceManagement are macOS-only; the Xcode project (project.yml) packages
// them into signed bundles. Build the Rust static library first: `make core`.
import PackageDescription

var targets: [Target] = [
    .systemLibrary(name: "CPokeyCore", path: "Sources/CPokeyCore"),
    .target(name: "PokeyCore"),
    .target(name: "PokeyRules", dependencies: ["CPokeyCore", "PokeyCore"]),
    .testTarget(name: "PokeyCoreTests", dependencies: ["PokeyCore"]),
    .testTarget(name: "PokeyRulesTests", dependencies: ["PokeyRules"]),
]
var products: [Product] = [.library(name: "PokeyCore", targets: ["PokeyCore"])]

#if os(macOS)
targets += [
    .target(name: "PokeyPlatform", dependencies: ["PokeyCore"]),
    .executableTarget(
        name: "pokey-sensor", dependencies: ["PokeyCore", "PokeyRules", "PokeyPlatform"],
        linkerSettings: [.linkedLibrary("EndpointSecurity"), .linkedLibrary("bsm"), .linkedLibrary("sqlite3")]),
    .executableTarget(name: "pokey-inspector", dependencies: ["PokeyCore", "PokeyRules", "PokeyPlatform"]),
    .executableTarget(name: "pokey-netd", dependencies: ["PokeyCore", "PokeyPlatform"]),
    .executableTarget(name: "pokey-ui", dependencies: ["PokeyCore", "PokeyPlatform"]),
    .executableTarget(name: "PokeyHost", dependencies: ["PokeyCore", "PokeyPlatform"]),
]
products += ["pokey-sensor", "pokey-inspector", "pokey-netd", "pokey-ui", "PokeyHost"].map {
    .executable(name: $0, targets: [$0])
}
#endif

let package = Package(
    name: "Pokey",
    platforms: [.macOS(.v13)],
    products: products,
    targets: targets
)
