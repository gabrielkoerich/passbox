// swift-tools-version:5.10
import PackageDescription

// CryptoKit ships with Apple's platforms. Elsewhere swift-crypto has the same API, which is what
// lets `swift test` check the protocol on Linux, where the rest of CI runs
#if os(Linux)
    let packages: [Package.Dependency] = [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")
    ]
    let crypto: [Target.Dependency] = [.product(name: "Crypto", package: "swift-crypto")]
#else
    let packages: [Package.Dependency] = []
    let crypto: [Target.Dependency] = []
#endif

let package = Package(
    name: "PassboxCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "PassboxCore", targets: ["PassboxCore"])],
    dependencies: packages,
    targets: [
        // Everything the phone does that needs no screen, no Enclave and no network of its own
        .target(name: "PassboxCore", dependencies: crypto),
        .testTarget(name: "PassboxCoreTests", dependencies: ["PassboxCore"] + crypto),
    ]
)
