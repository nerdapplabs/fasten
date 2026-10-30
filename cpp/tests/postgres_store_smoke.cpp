// Smoke tests for fasten_store_postgres.hpp.
//
// Tests #1 and #2 (validation + connection error) run without a live database.
// Tests #3+ require FASTEN_TEST_POSTGRES_DSN to be set; they are silently
// skipped when the env var is absent so CI passes without a Postgres service.
#include "fasten.hpp"
#include "fasten_store_postgres.hpp"

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

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

// Runs sql and returns the first column of each row.
std::vector<std::string> pg_col(const std::string& dsn, const std::string& sql) {
    PGconn* c = PQconnectdb(dsn.c_str());
    PGresult* r = PQexec(c, sql.c_str());
    assert(PQresultStatus(r) == PGRES_TUPLES_OK || PQresultStatus(r) == PGRES_COMMAND_OK);
    std::vector<std::string> out;
    if (PQresultStatus(r) == PGRES_TUPLES_OK)
        for (int i = 0; i < PQntuples(r); ++i) out.push_back(PQgetvalue(r, i, 0));
    PQclear(r);
    PQfinish(c);
    return out;
}

// #92: two stores on one table, one node, interleaved inserts.
void test_two_stores_one_node(const std::string& dsn) {
    const std::string table = "fasten_cpp_pg_two";
    pg_col(dsn, "DROP TABLE IF EXISTS " + table);
    const int per_store = 30;
    {
        fasten::PostgresStore a(dsn, table);
        fasten::PostgresStore b(dsn, table);
        auto run = [&](fasten::PostgresStore& s, const std::string& tag) {
            for (int i = 0; i < per_store; ++i) {
                auto row = make_row("evt-pg-two-" + tag + std::to_string(i), "TEST_TWO");
                row.monotonic_seq = 0;
                s.insert(row);
            }
        };
        std::thread ta(run, std::ref(a), "a");
        std::thread tb(run, std::ref(b), "b");
        ta.join();
        tb.join();
    }
    auto seqs = pg_col(dsn, "SELECT monotonic_seq FROM " + table + " ORDER BY monotonic_seq");
    assert(seqs.size() == static_cast<size_t>(2 * per_store));
    for (size_t i = 0; i < seqs.size(); ++i) assert(seqs[i] == std::to_string(i + 1));
    std::cout << "  test_two_stores_one_node: PASS\n";
}

void test_redaction(const std::string& dsn) {
    const std::string table = "fasten_cpp_pg_redact";
    pg_col(dsn, "DROP TABLE IF EXISTS " + table);
    // A table from before the chain columns.
    pg_col(dsn, "CREATE TABLE " + table + " (id TEXT PRIMARY KEY, origin_id TEXT NOT NULL,"
                " monotonic_seq BIGINT NOT NULL DEFAULT 0, timestamp TEXT NOT NULL,"
                " code TEXT NOT NULL, action TEXT NOT NULL DEFAULT '',"
                " severity TEXT NOT NULL DEFAULT 'info', service_id TEXT NOT NULL DEFAULT '',"
                " source_node_id TEXT NOT NULL DEFAULT '', tenant_id TEXT,"
                " actor TEXT NOT NULL DEFAULT '', actor_kind TEXT NOT NULL DEFAULT '',"
                " target TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '',"
                " domain TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT '',"
                " request_id TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '{}',"
                " pii_in_detail SMALLINT NOT NULL DEFAULT 0, shipped_at TEXT)");
    fasten::PostgresStore store(dsn, table);
    fasten::PostgresStore again(dsn, table);  // the migration runs twice

    auto old_row = [](const std::string& id, const std::string& code) {
        auto r = make_row(id, code);
        r.monotonic_seq = 0;
        r.timestamp = "2020-01-01T00:00:00.000000Z";
        return r;
    };
    store.insert(old_row("evt-pg-pii", "TEST_PII"));
    store.insert(old_row("evt-pg-plain", "TEST_PLAIN"));
    store.insert(old_row("evt-pg-form1", "TEST_PII"));
    pg_col(dsn, "UPDATE " + table + " SET hash = 'x', canonical_form_id = '1'"
                " WHERE id = 'evt-pg-form1'");

    const auto cutoff = std::chrono::system_clock::now();
    int64_t skipped = 0;
    auto c = store.list_redaction_candidates(cutoff, {"TEST_PII"}, &skipped);
    assert(c.size() == 1 && c[0].first == "evt-pg-pii" && c[0].second == 1);
    assert(skipped == 1);
    auto ids = store.redact_rows({"evt-pg-pii", "evt-pg-form1"});
    assert(ids.size() == 2);
    store.redact_rows({"evt-pg-pii"});

    auto detail = [&](const std::string& id) {
        return pg_col(dsn, "SELECT detail FROM " + table + " WHERE id = '" + id + "'").at(0);
    };
    assert(detail("evt-pg-pii") == "null");
    assert(detail("evt-pg-plain") != "null");
    assert(detail("evt-pg-form1") != "null");
    assert(store.list_redaction_candidates(cutoff, {"TEST_PII"}).empty());
    std::cout << "  test_redaction: PASS\n";
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
    test_two_stores_one_node(dsn);
    test_redaction(dsn);

    std::cout << "All PostgreSQL store smoke tests passed.\n";
    return 0;
}
