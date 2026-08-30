// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PrivacyShield",
    platforms: [
        .iOS(.v17),
        .macOS(.v13)
    ],
    products: [
        .library(name: "PrivacyShieldCore", targets: ["PrivacyShieldCore"]),
        .executable(name: "PrivacyShieldRunner", targets: ["PrivacyShieldRunner"])
    ],
    targets: [
        .target(name: "PrivacyShieldCore"),
        .executableTarget(name: "PrivacyShieldRunner", dependencies: ["PrivacyShieldCore"]),
        .testTarget(name: "PrivacyShieldCoreTests", dependencies: ["PrivacyShieldCore"])
    ]
)