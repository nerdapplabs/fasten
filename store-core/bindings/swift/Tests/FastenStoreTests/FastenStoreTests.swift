import XCTest
@testable import FastenStore

// Helper — builds a minimal valid Row as a plain dictionary.
func makeRow(_ id: String, code: String = "TEST") -> [String: Any] {
    return [
        "wire_version":   "1",
        "id":             id,
        "origin_id":      id,
        "monotonic_seq":  1,
        "timestamp":      "2026-05-07T00:00:00.000Z",
        "code":           code,
        "action":         "test",
        "severity":       "info",
        "service_id":     "test-svc",
        "source_node_id": "node-1",
        "actor":          "tester",
        "actor_kind":     "user",
        "target":         "res-1",
        "category":       "test",
        "domain":         "test",
        "method":         "sdk",
        "request_id":     "req-001",
        "detail":         ["key": "value"],
        "prev_hash":      "genesis",
        "hash":           "",
    ]
}

// ── Version ───────────────────────────────────────────────────────────────────

final class VersionTests: XCTestCase {
    func testVersionIsNonEmpty() {
        let v = FastenStore.version
        XCTAssertFalse(v.isEmpty)
    }
}

// ── SQLite ────────────────────────────────────────────────────────────────────

final class SQLiteTests: XCTestCase {

    func testOpenMemoryAndPing() throws {
        let store = try FastenStore(backend: "sqlite", connstr: ":memory:")
        XCTAssertNoThrow(try store.ping())
    }

    func testInsertRow() throws {
        let store = try FastenStore(backend: "sqlite", connstr: ":memory:")
        XCTAssertNoThrow(try store.insert(makeRow("evt-swift-sqlite-001")))
    }

    func testInsertIdempotent() throws {
        let store = try FastenStore(backend: "sqlite", connstr: ":memory:")
        let row = makeRow("evt-swift-idem-001")
        try store.insert(row)
        XCTAssertNoThrow(try store.insert(row)) // INSERT OR IGNORE
    }

    func testInsertJSONString() throws {
        let store = try FastenStore(backend: "sqlite", connstr: ":memory:")
        let data = try JSONSerialization.data(withJSONObject: makeRow("evt-swift-json-001"))
        let json = String(data: data, encoding: .utf8)!
        XCTAssertNoThrow(try store.insertJSON(json))
    }

    func testNullableColumns() throws {
        let store = try FastenStore(backend: "sqlite", connstr: ":memory:")
        var row = makeRow("evt-swift-null-001")
        row["tenant_id"]  = "tenant-abc"
        row["shipped_at"] = "2026-05-07T01:00:00.000Z"
        XCTAssertNoThrow(try store.insert(row))
    }

    func testCustomTableName() throws {
        let store = try FastenStore(backend: "sqlite", connstr: ":memory:", table: "fasten_audit")
        XCTAssertNoThrow(try store.insert(makeRow("evt-swift-table-001")))
    }

    func testInvalidTableNameThrows() {
        XCTAssertThrowsError(
            try FastenStore(backend: "sqlite", connstr: ":memory:", table: "bad-name!")
        ) { error in
            XCTAssertTrue(error is FastenStoreError)
        }
    }

    func testUnknownBackendThrows() {
        XCTAssertThrowsError(
            try FastenStore(backend: "nope", connstr: ":memory:", table: "audit_log")
        ) { error in
            XCTAssertTrue(error is FastenStoreError)
        }
    }
}

// ── PostgreSQL ────────────────────────────────────────────────────────────────

final class PostgreSQLTests: XCTestCase {

    var pgDSN: String? { ProcessInfo.processInfo.environment["FASTEN_TEST_POSTGRES_DSN"] }

    func testOpenAndPing() throws {
        guard let dsn = pgDSN else { throw XCTSkip("FASTEN_TEST_POSTGRES_DSN not set") }
        let store = try FastenStore(backend: "postgres", connstr: dsn,
                                   table: "fasten_swift_sc_test")
        XCTAssertNoThrow(try store.ping())
    }

    func testInsertIdempotent() throws {
        guard let dsn = pgDSN else { throw XCTSkip("FASTEN_TEST_POSTGRES_DSN not set") }
        let store = try FastenStore(backend: "postgres", connstr: dsn,
                                   table: "fasten_swift_sc_test")
        let row = makeRow("evt-swift-pg-001")
        try store.insert(row)
        XCTAssertNoThrow(try store.insert(row)) // ON CONFLICT DO NOTHING
    }

    func testSchemaQualifiedTable() throws {
        guard let dsn = pgDSN else { throw XCTSkip("FASTEN_TEST_POSTGRES_DSN not set") }
        let store = try FastenStore(backend: "postgres", connstr: dsn,
                                   table: "fasten_swift_sc_schema.audit_rows")
        XCTAssertNoThrow(try store.insert(makeRow("evt-swift-schema-001")))
    }
}
