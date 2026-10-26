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
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        // Links the system libsqlite3 on Linux. Apple platforms import the SDK's
        // SQLite3 module instead.
        .target(
            name: "CSQLite3",
            path: "Sources/CSQLite3",
            publicHeadersPath: "include",
            linkerSettings: [.linkedLibrary("sqlite3")]
        ),
        .target(
            name: "Fasten",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .target(name: "CSQLite3", condition: .when(platforms: [.linux])),
            ],
            path: "Sources/Fasten"
        ),
        .testTarget(
            name: "FastenTests",
            dependencies: ["Fasten"],
            path: "Tests/FastenTests"
        ),
    ]
)
