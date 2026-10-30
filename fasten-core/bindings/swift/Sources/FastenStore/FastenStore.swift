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

    private var handle: OpaquePointer?
    private let lock = RWLock()
    // Set before close() waits for the write lock, so new calls fail at once
    // instead of queueing ahead of it (glibc's rwlock favours readers).
    private var closing = false
    private let closingLock = NSLock()

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

    deinit { close() }

    /// Release resources immediately.  The store is unusable after this call.
    /// Calling `close()` again is a no-op; other operations throw.
    /// Waits for calls already in progress, so a slow insert delays it.
    public func close() {
        closingLock.lock()
        closing = true
        closingLock.unlock()
        lock.writeLock()
        defer { lock.unlock() }
        if let h = handle {
            handle = nil
            fasten_store_close(h)
        }
    }

    // Calls share the read lock so they still run concurrently; close()
    // takes the write lock and waits for them to finish.
    private func withHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        closingLock.lock()
        let isClosing = closing
        closingLock.unlock()
        if isClosing { throw FastenStoreError("store is closed") }
        lock.readLock()
        defer { lock.unlock() }
        guard let h = handle else { throw FastenStoreError("store is closed") }
        return try body(h)
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
        let rc = try withHandle { fasten_store_insert($0, json, &errPtr) }
        guard rc == FASTEN_OK else {
            let msg = errPtr.map { String(cString: $0) } ?? "insert failed"
            errPtr.map { fasten_store_free_str($0) }
            throw FastenStoreError(msg)
        }
    }

    // ── Health ────────────────────────────────────────────────────────────────

    /// Verify the backend is reachable (runs `SELECT 1`).
    public func ping() throws {
        var errPtr: UnsafeMutablePointer<CChar>? = nil
        let rc = try withHandle { fasten_store_ping($0, &errPtr) }
        guard rc == FASTEN_OK else {
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

private final class RWLock {
    private let rw = UnsafeMutablePointer<pthread_rwlock_t>.allocate(capacity: 1)

    init() { check(pthread_rwlock_init(rw, nil)) }

    deinit {
        pthread_rwlock_destroy(rw)
        rw.deallocate()
    }

    func readLock() { check(pthread_rwlock_rdlock(rw)) }
    func writeLock() { check(pthread_rwlock_wrlock(rw)) }
    func unlock() { check(pthread_rwlock_unlock(rw)) }

    // Call first, then check, so the call still runs in -Ounchecked builds.
    private func check(_ rc: Int32) {
        precondition(rc == 0, "pthread_rwlock failed: \(rc)")
    }
}
