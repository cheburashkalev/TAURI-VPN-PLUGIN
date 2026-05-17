// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "tauri-plugin-vpn",
    platforms: [
        .iOS(.v15),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "tauri-plugin-vpn",
            type: .static,
            targets: ["tauri-plugin-vpn"]
        )
    ],
    dependencies: [
        .package(name: "Tauri", path: "../.tauri/tauri-api")
    ],
    targets: [
        .target(
            name: "tauri-plugin-vpn",
            dependencies: [
                .byName(name: "Tauri")
            ],
            path: "Sources/VpnPlugin"
        )
    ]
)
