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
#include <thread>
#include <vector>

#include <libpq-fe.h>

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

// Two stores inserting seq-0 rows for one node at once get 1..N with no
// repeats (the advisory lock); another node starts at 1.
void test_seq_allocated_per_node(const std::string& dsn) {
    const std::string table = "fasten_cpp_seq_" + fasten::mint_id();
    {
        fasten::PostgresStore a(dsn, table);
        fasten::PostgresStore b(dsn, table);
        auto insert_many = [](fasten::PostgresStore& store, const std::string& prefix) {
            for (int i = 0; i < 10; ++i) {
                auto row = make_row(prefix + std::to_string(i), "TEST_SEQ");
                row.monotonic_seq = 0;
                store.insert(row);
            }
        };
        std::thread ta([&] { insert_many(a, "evt-seq-a"); });
        std::thread tb([&] { insert_many(b, "evt-seq-b"); });
        ta.join();
        tb.join();
        auto other = make_row("evt-seq-other", "TEST_SEQ");
        other.monotonic_seq  = 0;
        other.source_node_id = "node-2";
        a.insert(other);
    }
    PGconn* conn = PQconnectdb(dsn.c_str());
    assert(PQstatus(conn) == CONNECTION_OK);
    PGresult* res = PQexec(conn, ("SELECT source_node_id, monotonic_seq FROM " + table +
                                  " ORDER BY source_node_id, monotonic_seq").c_str());
    assert(PQresultStatus(res) == PGRES_TUPLES_OK);
    std::string got;
    for (int i = 0; i < PQntuples(res); ++i) {
        got += std::string(PQgetvalue(res, i, 0)) + ":" + PQgetvalue(res, i, 1) + " ";
    }
    PQclear(res);
    PQclear(PQexec(conn, ("DROP TABLE " + table).c_str()));
    PQfinish(conn);
    std::string want;
    for (int i = 1; i <= 20; ++i) want += "node-1:" + std::to_string(i) + " ";
    want += "node-2:1 ";
    assert(got == want);
    std::cout << "  test_seq_allocated_per_node: PASS\n";
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
    test_seq_allocated_per_node(dsn);

    std::cout << "All PostgreSQL store smoke tests passed.\n";
    return 0;
}
