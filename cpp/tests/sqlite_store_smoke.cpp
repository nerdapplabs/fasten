// Smoke tests for fasten_store_sqlite.hpp.
// All tests use ":memory:" — no filesystem side effects.
#include "fasten.hpp"
#include "fasten_store_sqlite.hpp"

#include <cassert>
#include <cstdio>
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

// ── seq allocation (#138) ──────────────────────────────────────────────────

void test_seq_allocated_per_node() {
    const std::string path = "/tmp/fasten_seq_" + fasten::mint_id() + ".db";
    {
        fasten::SqliteStore store(path);
        for (int i = 0; i < 3; ++i) {
            auto row = make_row("evt-seq-a" + std::to_string(i), "TEST_SEQ");
            row.monotonic_seq = 0;
            store.insert(row);
        }
        auto other = make_row("evt-seq-b", "TEST_SEQ");
        other.monotonic_seq  = 0;
        other.source_node_id = "node-2";
        store.insert(other);
    }
    sqlite3* db = nullptr;
    sqlite3_open(path.c_str(), &db);
    sqlite3_stmt* q = nullptr;
    sqlite3_prepare_v2(db,
        "SELECT source_node_id, monotonic_seq FROM audit_log ORDER BY source_node_id, monotonic_seq",
        -1, &q, nullptr);
    std::string got;
    while (sqlite3_step(q) == SQLITE_ROW) {
        got += reinterpret_cast<const char*>(sqlite3_column_text(q, 0));
        got += ":" + std::to_string(sqlite3_column_int64(q, 1)) + " ";
    }
    sqlite3_finalize(q);
    sqlite3_close(db);
    std::remove(path.c_str());
    assert(got == "node-1:1 node-1:2 node-1:3 node-2:1 ");
    std::cout << "  test_seq_allocated_per_node: PASS\n";
}

// A COMMIT that fails (another connection holds a read lock, rollback
// journal) must not leave the connection inside the transaction.
void test_failed_commit_does_not_wedge_the_store() {
    const std::string path = "/tmp/fasten_commit_" + fasten::mint_id() + ".db";
    {
        fasten::SqliteStore store(path, "audit_log", false);
        auto first = make_row("evt-c0", "TEST_COMMIT");
        first.monotonic_seq = 0;
        store.insert(first);

        sqlite3* reader = nullptr;
        sqlite3_open(path.c_str(), &reader);
        sqlite3_exec(reader, "BEGIN; SELECT COUNT(*) FROM audit_log;", nullptr, nullptr, nullptr);
        auto blocked = make_row("evt-c1", "TEST_COMMIT");
        blocked.monotonic_seq = 0;
        bool threw = false;
        try { store.insert(blocked); } catch (const std::runtime_error&) { threw = true; }
        assert(threw);
        sqlite3_exec(reader, "COMMIT", nullptr, nullptr, nullptr);
        sqlite3_close(reader);

        auto after = make_row("evt-c2", "TEST_COMMIT");
        after.monotonic_seq = 0;
        store.insert(after);  // threw "cannot start a transaction within a transaction"
    }
    std::remove(path.c_str());
    std::cout << "  test_failed_commit_does_not_wedge_the_store: PASS\n";
}

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
    test_seq_allocated_per_node();
    test_failed_commit_does_not_wedge_the_store();
    std::cout << "All SQLite store smoke tests passed.\n";
    return 0;
}
