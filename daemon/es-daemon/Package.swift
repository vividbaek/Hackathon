// swift-tools-version: 5.9
import PackageDescription

let package = Package(
  name: "es-daemon",
  platforms: [.macOS(.v13)],
  products: [
    .executable(name: "es-daemon", targets: ["ESDaemon"]),
    .library(name: "ESDaemonCore", targets: ["ESDaemonCore"])
  ],
  targets: [
    .executableTarget(name: "ESDaemon", dependencies: ["ESDaemonCore"]),
    .target(
      name: "ESDaemonCore",
      linkerSettings: [
        .linkedLibrary("EndpointSecurity"),
        .linkedLibrary("bsm")
      ]
    ),
    .testTarget(name: "ESDaemonCoreTests", dependencies: ["ESDaemonCore"])
  ]
)
