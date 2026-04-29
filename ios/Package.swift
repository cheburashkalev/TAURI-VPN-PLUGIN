// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "VpnPlugin",
    platforms: [
        .iOS(.v15),
        .macOS(.v13)
    ],
    products: [
        .library(name: "VpnPlugin", targets: ["VpnPlugin"])
    ],
    dependencies: [
        .package(url: "https://github.com/tauri-apps/tauri", from: "2.0.0")
    ],
    targets: [
        .target(
            name: "VpnPlugin",
            dependencies: [
                .product(name: "Tauri", package: "tauri")
            ]
        )
    ]
)
