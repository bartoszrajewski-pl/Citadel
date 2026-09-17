// swift-tools-version:5.9
import PackageDescription

// Deliberately a separate package rather than a test target: it needs a live
// OpenSSH server, so it is not something `swift test` should pick up.
let package = Package(
    name: "CTRAcceptance",
    platforms: [.macOS(.v14)],
    dependencies: [.package(path: "..")],
    targets: [
        // the full acceptance list, end to end, once
        .executableTarget(name: "ctrtest", dependencies: [.product(name: "Citadel", package: "Citadel")]),
        // one connection, N checksummed reads, watchdog per read — for
        // measuring how often something stalls rather than whether it can
        .executableTarget(name: "rekeyprobe", dependencies: [.product(name: "Citadel", package: "Citadel")]),
    ]
)
