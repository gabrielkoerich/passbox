// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "PassboxApp",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "PassboxApp", dependencies: ["Search"]),
        // The filter has no AppKit in it, so `swift run SearchCheck` checks it without a GUI
        .target(name: "Search"),
        .executableTarget(name: "SearchCheck", dependencies: ["Search"]),
    ]
)
