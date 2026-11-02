// swift-tools-version: 5.9
//
// Build the Rust library, then build and test against it (from the repo root):
//      cd fasten-core && cargo build --release --features all
//      cd bindings/swift
//      swift build -Xlinker -L../../target/release
//      swift test  -Xlinker -L../../target/release
//
// Pass a different -L to link a library built elsewhere.
//
// Cargo builds one architecture per --target. For a macOS universal binary:
//      cargo build --release --features all --target aarch64-apple-darwin
//      cargo build --release --features all --target x86_64-apple-darwin
//      lipo -create target/aarch64-apple-darwin/release/libfasten_core.dylib \
//                   target/x86_64-apple-darwin/release/libfasten_core.dylib \
//           -output libfasten_core.dylib

import PackageDescription

let package = Package(
    name: "FastenStore",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(name: "FastenStore", targets: ["FastenStore"]),
    ],
    targets: [
        // Exposes the C header in Sources/CFastenStoreCore/ as a Swift module.
        // The caller supplies -L<dir> for the native library at link time.
        .systemLibrary(
            name: "CFastenStoreCore",
            path: "Sources/CFastenStoreCore"
        ),

        .target(
            name: "FastenStore",
            dependencies: ["CFastenStoreCore"],
            path: "Sources/FastenStore"
        ),

        .testTarget(
            name: "FastenStoreTests",
            dependencies: ["FastenStore"],
            path: "Tests/FastenStoreTests"
        ),
    ]
)
