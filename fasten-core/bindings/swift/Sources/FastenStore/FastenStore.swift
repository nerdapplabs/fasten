import Foundation
import CFastenStoreCore

/// Thread-safe audit store backed by libfasten_core.
///
/// Build the Rust library first, then link it:
/// ```sh
/// cd fasten/fasten-core
/// cargo build --release --features all
/// swift build -Xlinker -L./target/release
/// ```
///
/// Usage:
/// ```swift
/// let store = try FastenStore(backend: "sqlite", connstr: ":memory:")
/// defer { store.close() }
/// try store.insert(["id": "evt-001", ...])
/// ```
public final class FastenStore {

    private var handle: OpaquePointer

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /// Open an audit store.
    ///
    /// - Parameters:
    ///   - backend: `"sqlite"` or `"postgres"`
    ///   - connstr: SQLite path / `":memory:"` or PostgreSQL DSN
    ///   - table:   plain or schema-qualified table name (default `"audit_log"`)
    public init(backend: String, connstr: String, table: String = "audit_log") throws {
        var errPtr: UnsafeMutablePointer<CChar>? = nil
        let h = fasten_store_open(backend, connstr, table, &errPtr)
        guard let h else {
            let msg = errPtr.map { String(cString: $0) } ?? "unknown error"
            errPtr.map { fasten_store_free_str($0) }
            throw FastenStoreError(msg)
        }
        handle = h
    }

    deinit { fasten_store_close(handle) }

    /// Release resources immediately.  The store is unusable after this call.
    /// Calling `close()` makes subsequent operations throw.
    public func close() {
        fasten_store_close(handle)
        // Note: after close the handle is dangling; subsequent calls will crash.
        // Callers should discard the reference after close().
    }

    // ── Write path ────────────────────────────────────────────────────────────

    /// Insert one audit row.  Accepts any `Encodable` value.
    /// Duplicate IDs are silently ignored.
    public func insert(_ row: some Encodable) throws {
        let data = try JSONEncoder().encode(row)
        guard let json = String(data: data, encoding: .utf8) else {
            throw FastenStoreError("row could not be encoded as UTF-8 JSON")
        }
        try insertJSON(json)
    }

    /// Insert from a plain dictionary (useful in scripts / tests).
    public func insert(_ row: [String: Any]) throws {
        let data = try JSONSerialization.data(withJSONObject: row)
        guard let json = String(data: data, encoding: .utf8) else {
            throw FastenStoreError("row could not be encoded as UTF-8 JSON")
        }
        try insertJSON(json)
    }

    /// Insert from a pre-serialised JSON string.
    public func insertJSON(_ json: String) throws {
        var errPtr: UnsafeMutablePointer<CChar>? = nil
        let rc = fasten_store_insert(handle, json, &errPtr)
        guard rc == 0 else {
            let msg = errPtr.map { String(cString: $0) } ?? "insert failed"
            errPtr.map { fasten_store_free_str($0) }
            throw FastenStoreError(msg)
        }
    }

    // ── Health ────────────────────────────────────────────────────────────────

    /// Verify the backend is reachable (runs `SELECT 1`).
    public func ping() throws {
        var errPtr: UnsafeMutablePointer<CChar>? = nil
        let rc = fasten_store_ping(handle, &errPtr)
        guard rc == 0 else {
            let msg = errPtr.map { String(cString: $0) } ?? "ping failed"
            errPtr.map { fasten_store_free_str($0) }
            throw FastenStoreError(msg)
        }
    }

    // ── Metadata ──────────────────────────────────────────────────────────────

    /// Return the library version string, e.g. `"0.1.0"`.
    public static var version: String {
        String(cString: fasten_store_version())
    }
}
