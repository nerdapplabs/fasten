// Smoke tests for fasten_store_postgres.hpp.
//
// Tests #1 and #2 (validation + connection error) run without a live database.
// Tests #3+ require FASTEN_TEST_POSTGRES_DSN to be set; they are silently
// skipped when the env var is absent so CI passes without a Postgres service.
#include "fasten.hpp"
#include "fasten_store_postgres.hpp"

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

const char* get_dsn() {
    return std::getenv("FASTEN_TEST_POSTGRES_DSN");
}

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

// ── No-DSN tests ──────────────────────────────────────────────────────────

void test_invalid_table_name() {
    bool threw = false;
    try {
        // Validation happens before connecting; no DSN required.
        fasten::PostgresStore store("host=localhost user=nobody", "bad-name!");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    assert(threw && "expected std::invalid_argument for bad table name");
    std::cout << "  test_invalid_table_name: PASS\n";
}

void test_connection_error() {
    bool threw = false;
    try {
        fasten::PostgresStore store(
            "host=127.0.0.1 port=1 user=nobody dbname=nobody connect_timeout=1",
            "audit"
        );
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw && "expected std::runtime_error for unreachable host");
    std::cout << "  test_connection_error: PASS\n";
}

// ── Live-database tests (require FASTEN_TEST_POSTGRES_DSN) ────────────────

void test_insert_idempotent(const std::string& dsn) {
    fasten::PostgresStore store(dsn, "fasten_cpp_pg_test");
    auto row = make_row("evt-cpp-pg-insert-001", "TEST_INSERT");
    store.insert(row);
    store.insert(row); // ON CONFLICT (id) DO NOTHING — must not throw
    std::cout << "  test_insert_idempotent: PASS\n";
}

void test_sink_callable(const std::string& dsn) {
    fasten::PostgresStore store(dsn, "fasten_cpp_pg_test");
    fasten::AuditSink s = store.sink();
    s(make_row("evt-cpp-pg-sink-001", "TEST_SINK"));
    std::cout << "  test_sink_callable: PASS\n";
}

void test_null_columns(const std::string& dsn) {
    fasten::PostgresStore store(dsn, "fasten_cpp_pg_test");
    fasten::Row row  = make_row("evt-cpp-pg-null-001", "TEST_NULLS");
    row.tenant_id    = "";  // stored as NULL
    row.shipped_at   = "";  // stored as NULL
    store.insert(row);
    std::cout << "  test_null_columns: PASS\n";
}

void test_populated_nullable_columns(const std::string& dsn) {
    fasten::PostgresStore store(dsn, "fasten_cpp_pg_test");
    fasten::Row row  = make_row("evt-cpp-pg-nullable-001", "TEST_NULLABLE_SET");
    row.tenant_id    = "tenant-abc";
    row.shipped_at   = "2026-05-07T01:00:00.000Z";
    store.insert(row);
    std::cout << "  test_populated_nullable_columns: PASS\n";
}

void test_pii_in_detail(const std::string& dsn) {
    fasten::PostgresStore store(dsn, "fasten_cpp_pg_test");
    fasten::Row row   = make_row("evt-cpp-pg-pii-001", "TEST_PII");
    row.pii_in_detail = true;
    store.insert(row);
    std::cout << "  test_pii_in_detail: PASS\n";
}

void test_schema_qualified_table(const std::string& dsn) {
    // Auto-creates the schema if absent.
    fasten::PostgresStore store(dsn, "fasten_cpp_test_schema.audit_rows");
    auto row = make_row("evt-cpp-schema-001", "TEST_SCHEMA");
    store.insert(row);
    std::cout << "  test_schema_qualified_table: PASS\n";
}

} // namespace

int main() {
    std::cout << "=== postgres_store_smoke ===\n";

    test_invalid_table_name();
    test_connection_error();

    const char* raw_dsn = get_dsn();
    if (!raw_dsn) {
        std::cout << "FASTEN_TEST_POSTGRES_DSN not set — skipping live tests.\n";
        std::cout << "All PostgreSQL store smoke tests passed.\n";
        return 0;
    }

    std::string dsn(raw_dsn);
    test_insert_idempotent(dsn);
    test_sink_callable(dsn);
    test_null_columns(dsn);
    test_populated_nullable_columns(dsn);
    test_pii_in_detail(dsn);
    test_schema_qualified_table(dsn);

    std::cout << "All PostgreSQL store smoke tests passed.\n";
    return 0;
}
