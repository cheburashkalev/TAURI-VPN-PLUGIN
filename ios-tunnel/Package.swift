// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "KostraVpnTunnelPackage",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "KostraVpnTunnel",
            targets: ["KostraVpnTunnel"]
        )
    ],
    targets: [
        .target(
            name: "KostraVpnTunnel",
            dependencies: [
                .target(name: "Libbox")
            ],
            path: "Sources/KostraVpnTunnel"
        ),
        .binaryTarget(
            name: "Libbox",
            url: "https://github.com/proother/sing-box-lib/releases/download/v1.13.12/Libbox-ios.xcframework.zip",
            checksum: "d2f03f10cdfb9411655269a291cfeea1e61a799e77d2fdca07bc228674a11eef"
        )
    ]
)
