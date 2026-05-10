// swift-tools-version: 5.9
//
// Build instructions
// ------------------
// 1. Build the Rust library:
//      cd fasten/store-core
//      cargo build --release --features all
//
// 2. Build + test (macOS / Linux):
//      cd fasten/store-core/bindings/swift
//      swift build  -Xlinker -L../../../../target/release
//      swift test   -Xlinker -L../../../../target/release
//
//    Override the library directory:
//      FASTEN_STORE_CORE_LIB_DIR=/custom/path swift test \
//        -Xlinker -L$FASTEN_STORE_CORE_LIB_DIR
//
// Architecture support
// --------------------
// The Rust crate is built separately for each target; pass the appropriate
// --target flag to cargo (e.g. aarch64-apple-darwin, x86_64-unknown-linux-gnu).
// For a macOS universal binary:
//      cargo build --release --features all --target aarch64-apple-darwin
//      cargo build --release --features all --target x86_64-apple-darwin
//      lipo -create target/aarch64-apple-darwin/release/libfasten_store_core.dylib \
//                   target/x86_64-apple-darwin/release/libfasten_store_core.dylib \
//           -output libfasten_store_core.dylib

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
        // Wraps the C header in a Swift-importable module.
        // The module.modulemap + header live in Sources/CFastenStoreCore/.
        // At link time the caller must supply -L<dir containing libfasten_store_core>.
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
