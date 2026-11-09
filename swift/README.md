# fasten for Swift

Audit and correlation SDK for Swift apps and services. v1.0.0-beta.

The Swift SDK is pure Swift. It does not use `libfasten_core`, so there is
no Rust build step. It writes audit rows to SQLite but does not seal them:
rows have no hash chain, and the SDK logs `audit_chain_unavailable` at
start.

## Requirements

- Swift 5.10 or later. CI builds and tests with Swift 5.10 on Ubuntu 24.04.
- macOS 13+ or iOS 16+ on Apple platforms.
- On Linux, the SQLite headers (`libsqlite3-dev` on Debian/Ubuntu).

## Install

`Package.swift` lives in `swift/`, not at the repo root, so SwiftPM cannot
add the package by repo URL. Clone the repo and add it as a local package:

```bash
git clone https://github.com/nerdapplabs/fasten.git
```

In your `Package.swift`, with your package next to the clone:

```swift
dependencies: [
    .package(path: "../fasten/swift"),
],
targets: [
    .executableTarget(
        name: "myapp",
        dependencies: [.product(name: "Fasten", package: "swift")]
    ),
]
```

For a local package, SwiftPM names it after its directory, so the package
name here is `swift`.

## Quickstart

Verified to build and run as-is on macOS (Swift 6.3) and Linux (Swift 5.10):

```swift
import Fasten

Fasten.register("user", codes: [
    "USER_CREATED": Meta(id: "USER_CREATED", domain: "user",
                         category: "account", action: "create",
                         description: "New user", emitter: "auth-svc"),
])

let store = try SQLiteStore(path: "./fasten-audit.db")
try Fasten.configure(serviceID: "auth-svc", nodeID: "host-01", store: store)

try Fasten.withRequestID(Fasten.mintID()) {
    try Fasten.emit("USER_CREATED", target: "u-42", actor: "admin",
                    detail: ["email": "alice@example.com"])
    Fasten.log.info("signup_complete", fields: ["user_id": "u-42"])
}

Fasten.flush(timeout: 5.0)
Fasten.close()
```

The audit row and the log line go to stdout with the same `request_id`.
The audit row is also stored in the `audit_log` table of
`./fasten-audit.db`.

## Tests

The same steps CI runs (see
[`fasten-swift.yml`](../.github/workflows/fasten-swift.yml)):

```bash
cd swift
swift build
swift test
```

## Docs and design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/).
Design and cross-language design: [README.md](../README.md).
