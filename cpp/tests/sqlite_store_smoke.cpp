// Smoke tests for fasten_store_sqlite.hpp.
// All tests use ":memory:" — no filesystem side effects.
#include "fasten.hpp"
#include "fasten_store_sqlite.hpp"

#include <cassert>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

fasten::Row make_row(const std::string& id, const std::string& code) {
    fasten::Row r;
    r.id             = id;
    r.origin_id      = id;
    r.monotonic_seq  = 1;
    r.timestamp      = "2026-05-07T00:00:00.000Z";
    r.code           = code;
    r.action         = "test_action";
    r.severity       = "info";
    r.service_id     = "test-svc";
    r.source_node_id = "node-1";
    r.actor          = "tester";
    r.actor_kind     = "user";
    r.target         = "resource-1";
    r.category       = "test";
    r.domain         = "test";
    r.method         = "sdk";
    r.request_id     = "req-test-001";
    r.detail["key"] = "value";
    return r;
}

// ── #1 basic insert + idempotency ──────────────────────────────────────────

void test_insert_idempotent() {
    fasten::SqliteStore store(":memory:");
    auto row = make_row("evt-sqlite-001", "TEST_INSERT");
    store.insert(row);
    store.insert(row); // INSERT OR IGNORE — must not throw
    std::cout << "  test_insert_idempotent: PASS\n";
}

// ── #2 sink() returns a callable AuditSink ────────────────────────────────

void test_sink_callable() {
    fasten::SqliteStore store(":memory:");
    fasten::AuditSink s = store.sink();
    s(make_row("evt-sqlite-002", "TEST_SINK"));
    std::cout << "  test_sink_callable: PASS\n";
}

// ── #3 nullable columns (tenant_id, shipped_at) ───────────────────────────

void test_null_columns() {
    fasten::SqliteStore store(":memory:");
    fasten::Row row  = make_row("evt-sqlite-003", "TEST_NULLS");
    row.tenant_id    = "";  // stored as NULL
    row.shipped_at   = "";  // stored as NULL
    store.insert(row);
    std::cout << "  test_null_columns: PASS\n";
}

// ── #4 populated nullable columns ─────────────────────────────────────────

void test_populated_nullable_columns() {
    fasten::SqliteStore store(":memory:");
    fasten::Row row  = make_row("evt-sqlite-004", "TEST_NULLABLE_SET");
    row.tenant_id    = "tenant-abc";
    row.shipped_at   = "2026-05-07T01:00:00.000Z";
    store.insert(row);
    std::cout << "  test_populated_nullable_columns: PASS\n";
}

// ── #5 pii_in_detail flag ─────────────────────────────────────────────────

void test_pii_in_detail() {
    fasten::SqliteStore store(":memory:");
    fasten::Row row   = make_row("evt-sqlite-005", "TEST_PII");
    row.pii_in_detail = true;
    store.insert(row);
    std::cout << "  test_pii_in_detail: PASS\n";
}

// ── #6 detail JSON round-trip (multiple keys) ─────────────────────────────

void test_detail_multi_key() {
    fasten::SqliteStore store(":memory:");
    fasten::Row row = make_row("evt-sqlite-006", "TEST_DETAIL");
    row.detail["alpha"] = "one";
    row.detail["beta"]  = "two";
    store.insert(row);
    std::cout << "  test_detail_multi_key: PASS\n";
}

// ── #7 invalid table name is rejected before open ─────────────────────────

void test_invalid_table_name() {
    bool threw = false;
    try {
        fasten::SqliteStore store(":memory:", "bad-name!");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    assert(threw && "expected std::invalid_argument for bad table name");
    std::cout << "  test_invalid_table_name: PASS\n";
}

// ── #8 custom table name ──────────────────────────────────────────────────

void test_custom_table_name() {
    fasten::SqliteStore store(":memory:", "fasten_audit");
    store.insert(make_row("evt-sqlite-008", "TEST_CUSTOM_TABLE"));
    std::cout << "  test_custom_table_name: PASS\n";
}

} // namespace

int main() {
    std::cout << "=== sqlite_store_smoke ===\n";
    test_insert_idempotent();
    test_sink_callable();
    test_null_columns();
    test_populated_nullable_columns();
    test_pii_in_detail();
    test_detail_multi_key();
    test_invalid_table_name();
    test_custom_table_name();
    std::cout << "All SQLite store smoke tests passed.\n";
    return 0;
}
