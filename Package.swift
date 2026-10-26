// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "CorsoShield", platforms: [.macOS(.v13)], products: [.executable(name: "CorsoShield", targets: ["CorsoShield"])], dependencies: [.package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.1")], targets: [.executableTarget(name: "CorsoShield", dependencies: [.product(name: "Sparkle", package: "Sparkle")]), .testTarget(name: "CorsoShieldTests", dependencies: ["CorsoShield"])])
