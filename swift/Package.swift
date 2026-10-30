// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "fasten",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "Fasten", targets: ["Fasten"]),
    ],
    targets: [
        // Linux system SQLite3 wrapper.  On Apple platforms the SDK-provided
        // SQLite3 module is used directly; this target is only active on Linux.
        .target(
            name: "CSQLite3",
            path: "Sources/CSQLite3",
            publicHeadersPath: "include",
            linkerSettings: [.linkedLibrary("sqlite3")]
        ),
        .target(
            name: "Fasten",
            dependencies: [
                .target(name: "CSQLite3", condition: .when(platforms: [.linux])),
            ],
            path: "Sources/Fasten"
        ),
        .testTarget(
            name: "FastenTests",
            dependencies: [
                "Fasten",
                .target(name: "CSQLite3", condition: .when(platforms: [.linux])),
            ],
            path: "Tests/FastenTests"
        ),
    ]
)
