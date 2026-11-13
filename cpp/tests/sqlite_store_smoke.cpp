// Smoke tests for fasten_store_sqlite.hpp.
// Most tests use ":memory:"; the file mode tests use files under /tmp.
#include "fasten.hpp"
#include "fasten_store_sqlite.hpp"

#include <algorithm>
#include <cassert>
#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

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

// basic insert + idempotency

void test_insert_idempotent() {
    fasten::SqliteStore store(":memory:");
    auto row = make_row("evt-sqlite-001", "TEST_INSERT");
    store.insert(row);
    store.insert(row); // INSERT OR IGNORE: must not throw
    std::cout << "  test_insert_idempotent: PASS\n";
}

// sink() returns a callable AuditSink

void test_sink_callable() {
    fasten::SqliteStore store(":memory:");
    fasten::AuditSink s = store.sink();
    s(make_row("evt-sqlite-002", "TEST_SINK"));
    std::cout << "  test_sink_callable: PASS\n";
}

// nullable columns (tenant_id, shipped_at)

void test_null_columns() {
    fasten::SqliteStore store(":memory:");
    fasten::Row row  = make_row("evt-sqlite-003", "TEST_NULLS");
    row.tenant_id    = "";  // stored as NULL
    row.shipped_at   = "";  // stored as NULL
    store.insert(row);
    std::cout << "  test_null_columns: PASS\n";
}

// populated nullable columns

void test_populated_nullable_columns() {
    fasten::SqliteStore store(":memory:");
    fasten::Row row  = make_row("evt-sqlite-004", "TEST_NULLABLE_SET");
    row.tenant_id    = "tenant-abc";
    row.shipped_at   = "2026-05-07T01:00:00.000Z";
    store.insert(row);
    std::cout << "  test_populated_nullable_columns: PASS\n";
}

// pii_in_detail flag

void test_pii_in_detail() {
    fasten::SqliteStore store(":memory:");
    fasten::Row row   = make_row("evt-sqlite-005", "TEST_PII");
    row.pii_in_detail = true;
    store.insert(row);
    std::cout << "  test_pii_in_detail: PASS\n";
}

// detail JSON round-trip (multiple keys)

void test_detail_multi_key() {
    fasten::SqliteStore store(":memory:");
    fasten::Row row = make_row("evt-sqlite-006", "TEST_DETAIL");
    row.detail["alpha"] = "one";
    row.detail["beta"]  = "two";
    store.insert(row);
    std::cout << "  test_detail_multi_key: PASS\n";
}

// invalid table name is rejected before open

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

// custom table name

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

// Picking the next seq seeks the node's rows instead of scanning the table.
void test_next_seq_uses_index() {
    const std::string path = "/tmp/fasten_seqidx_" + fasten::mint_id() + ".db";
    { fasten::SqliteStore store(path); }
    sqlite3* db = nullptr;
    sqlite3_open(path.c_str(), &db);
    sqlite3_stmt* q = nullptr;
    sqlite3_prepare_v2(db,
        "EXPLAIN QUERY PLAN SELECT COALESCE(MAX(monotonic_seq), 0) + 1 FROM audit_log "
        "WHERE source_node_id = 'node-1'",
        -1, &q, nullptr);
    std::string plan;
    while (sqlite3_step(q) == SQLITE_ROW) {
        plan += reinterpret_cast<const char*>(sqlite3_column_text(q, 3));
        plan += "\n";
    }
    sqlite3_finalize(q);
    sqlite3_close(db);
    std::remove(path.c_str());
    assert(plan.find("idx_audit_log_node_seq") != std::string::npos);
    std::cout << "  test_next_seq_uses_index: PASS\n";
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

// #92: two stores (two engines) on one file, one node. Each insert must get
// the next seq from the table, not from its own store.
void test_two_stores_one_node_get_distinct_seqs() {
    const std::string path = "/tmp/fasten_two_" + fasten::mint_id() + ".db";
    const int per_store = 50;
    {
        fasten::SqliteStore a(path);
        fasten::SqliteStore b(path);
        auto run = [&](fasten::SqliteStore& s, const std::string& tag) {
            for (int i = 0; i < per_store; ++i) {
                auto row = make_row("evt-two-" + tag + std::to_string(i), "TEST_TWO");
                row.monotonic_seq = 0;
                s.insert(row);
            }
        };
        std::thread ta(run, std::ref(a), "a");
        std::thread tb(run, std::ref(b), "b");
        ta.join();
        tb.join();
    }
    sqlite3* db = nullptr;
    sqlite3_open(path.c_str(), &db);
    sqlite3_stmt* q = nullptr;
    sqlite3_prepare_v2(db,
        "SELECT monotonic_seq FROM audit_log WHERE source_node_id = 'node-1' ORDER BY monotonic_seq",
        -1, &q, nullptr);
    std::vector<int64_t> seqs;
    while (sqlite3_step(q) == SQLITE_ROW) seqs.push_back(sqlite3_column_int64(q, 0));
    sqlite3_finalize(q);
    sqlite3_close(db);
    std::remove(path.c_str());
    assert(seqs.size() == static_cast<size_t>(2 * per_store));
    for (size_t i = 0; i < seqs.size(); ++i) assert(seqs[i] == static_cast<int64_t>(i + 1));
    std::cout << "  test_two_stores_one_node_get_distinct_seqs: PASS\n";
}

int count_rows(const std::string& path) {
    sqlite3* db = nullptr;
    sqlite3_open(path.c_str(), &db);
    sqlite3_stmt* q = nullptr;
    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM audit_log", -1, &q, nullptr);
    int n = sqlite3_step(q) == SQLITE_ROW ? sqlite3_column_int(q, 0) : -1;
    sqlite3_finalize(q);
    sqlite3_close(db);
    return n;
}

// A different row with an id already stored is rejected, not dropped while
// the insert reports success. Both insert paths: a given seq and seq 0.
void test_id_held_by_a_different_row_is_rejected() {
    const std::string path = "/tmp/fasten_dupid_" + fasten::mint_id() + ".db";
    {
        fasten::SqliteStore store(path);
        auto first = make_row("evt-dup-1", "TEST_DUP");
        store.insert(first);
        for (int64_t seq : {int64_t(7), int64_t(0)}) {
            auto other = make_row("evt-dup-1", "TEST_DUP");
            other.request_id    = "req-other";
            other.monotonic_seq = seq;
            bool rejected = false;
            try {
                store.insert(other);
            } catch (const fasten::InsertRejected&) {
                rejected = true;
            }
            assert(rejected);
        }
        store.insert(first);  // the same row again is still fine
        auto next = make_row("evt-dup-2", "TEST_DUP");
        next.monotonic_seq = 0;
        store.insert(next);   // the rolled-back transaction left the store usable
    }
    assert(count_rows(path) == 2);
    std::remove(path.c_str());
    std::cout << "  test_id_held_by_a_different_row_is_rejected: PASS\n";
}

// A table with a unique (node, seq) index, as the Go store creates: a fresh
// id at a taken seq is refused by that index, and the error says so.
void test_taken_seq_is_named_in_the_error() {
    const std::string path = "/tmp/fasten_seqclash_" + fasten::mint_id() + ".db";
    {
        fasten::SqliteStore store(path);
        store.insert(make_row("evt-clash-1", "TEST_CLASH"));
    }
    sqlite3* db = nullptr;
    sqlite3_open(path.c_str(), &db);
    sqlite3_exec(db, "CREATE UNIQUE INDEX uq_audit_log_node_seq ON audit_log (source_node_id, monotonic_seq)",
                 nullptr, nullptr, nullptr);
    sqlite3_close(db);
    {
        fasten::SqliteStore store(path);
        std::string msg;
        try {
            store.insert(make_row("evt-clash-2", "TEST_CLASH"));  // seq 1 again
        } catch (const fasten::InsertRejected& e) {
            msg = e.what();
        }
        assert(msg.find("another unique index") != std::string::npos);
    }
    assert(count_rows(path) == 1);
    std::remove(path.c_str());
    std::cout << "  test_taken_seq_is_named_in_the_error: PASS\n";
}

void test_text_with_a_nul_byte_is_rejected() {
    fasten::SqliteStore store(":memory:");
    auto row = make_row("evt-nul-1", "TEST_NUL");
    row.target = std::string("a\0b", 3);
    bool rejected = false;
    try {
        store.insert(row);
    } catch (const fasten::InsertRejected& e) {
        rejected = std::string(e.what()).find("target") != std::string::npos;
    }
    assert(rejected);
    std::cout << "  test_text_with_a_nul_byte_is_rejected: PASS\n";
}

void test_minted_ids_do_not_repeat() {
    std::vector<std::string> ids;
    for (int i = 0; i < 20000; ++i) ids.push_back(fasten::detail_::mint_id_bytes(10));
    std::sort(ids.begin(), ids.end());
    assert(std::adjacent_find(ids.begin(), ids.end()) == ids.end());
    std::cout << "  test_minted_ids_do_not_repeat: PASS\n";
}

#ifndef _WIN32
// Under the usual 022 umask SQLite alone would create these 0644.
int file_mode(const std::string& path) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) return -1;
    return static_cast<int>(st.st_mode & 0777);
}

void remove_db(const std::string& path) {
    for (const char* ext : {"", "-wal", "-shm"}) std::remove((path + ext).c_str());
}

void test_new_file_and_wal_are_0600() {
    const std::string path = "/tmp/fasten_mode_" + fasten::mint_id() + ".db";
    {
        fasten::SqliteStore store(path);
        store.insert(make_row("evt-mode-1", "TEST_MODE"));
        assert(file_mode(path) == 0600);
        assert(file_mode(path + "-wal") == 0600);
    }
    remove_db(path);
    std::cout << "  test_new_file_and_wal_are_0600: PASS\n";
}

void test_existing_file_keeps_its_mode() {
    const std::string path = "/tmp/fasten_mode_" + fasten::mint_id() + ".db";
    std::FILE* f = std::fopen(path.c_str(), "w");
    std::fclose(f);
    chmod(path.c_str(), 0644);
    { fasten::SqliteStore store(path); }
    assert(file_mode(path) == 0644);
    remove_db(path);
    std::cout << "  test_existing_file_keeps_its_mode: PASS\n";
}

void test_file_uri_is_0600() {
    const std::string path = "/tmp/fasten mode " + fasten::mint_id() + ".db";
    std::string uri = "file://";
    for (char c : path) uri += c == ' ' ? std::string("%20") : std::string(1, c);
    { fasten::SqliteStore store(uri + "?cache=private"); }
    assert(file_mode(path) == 0600);
    remove_db(path);
    std::cout << "  test_file_uri_is_0600: PASS\n";
}

void test_read_only_file_uri_creates_nothing() {
    const std::string path = "/tmp/fasten_mode_" + fasten::mint_id() + ".db";
    bool threw = false;
    try { fasten::SqliteStore store("file:" + path + "?mode=ro"); }
    catch (const std::runtime_error&) { threw = true; }
    assert(threw);
    assert(file_mode(path) == -1);
    std::cout << "  test_read_only_file_uri_creates_nothing: PASS\n";
}

void test_file_uri_without_a_file_to_create_creates_nothing() {
    for (const char* param : {"immutable=1", "vfs=memdb"}) {
        const std::string path = "/tmp/fasten_mode_" + fasten::mint_id() + ".db";
        try { fasten::SqliteStore store("file:" + path + "?" + param); }
        catch (const std::runtime_error&) {}
        // Some SQLite versions create an empty file for immutable=1
        // themselves, with the umask; fasten must not create one 0600 first.
        const int mode = file_mode(path);
        assert(mode == -1 || (std::string(param) == "immutable=1" && mode == 0644));
        remove_db(path);
    }
    std::cout << "  test_file_uri_without_a_file_to_create_creates_nothing: PASS\n";
}

void test_file_uri_keeps_an_invalid_escape() {
    const std::string path = "/tmp/fasten_mode_" + fasten::mint_id() + "%zz.db";
    { fasten::SqliteStore store("file:" + path); }
    assert(file_mode(path) == 0600);
    remove_db(path);
    std::cout << "  test_file_uri_keeps_an_invalid_escape: PASS\n";
}

void test_file_uri_path_ends_at_nul() {
    const std::string path = "/tmp/fasten_mode_" + fasten::mint_id();
    { fasten::SqliteStore store("file:" + path + "%00x.db"); }
    assert(file_mode(path) == 0600);
    remove_db(path);
    std::cout << "  test_file_uri_path_ends_at_nul: PASS\n";
}

void test_file_uri_immutable_forms() {
    // A true form: fasten must not create the file 0600 (some SQLite
    // versions create an empty one themselves, with the umask).
    const std::string on = "/tmp/fasten_mode_" + fasten::mint_id() + ".db";
    try { fasten::SqliteStore store("file:" + on + "?immutable=Yes"); }
    catch (const std::runtime_error&) {}
    assert(file_mode(on) == -1 || file_mode(on) == 0644);
    remove_db(on);
    // A false form is not immutable.
    const std::string off = "/tmp/fasten_mode_" + fasten::mint_id() + ".db";
    { fasten::SqliteStore store("file:" + off + "?immutable=0"); }
    assert(file_mode(off) == 0600);
    remove_db(off);
    std::cout << "  test_file_uri_immutable_forms: PASS\n";
}

void test_dangling_symlink_target_is_0600() {
    const std::string target = "/tmp/fasten_mode_" + fasten::mint_id() + ".db";
    const std::string link = "/tmp/fasten_mode_" + fasten::mint_id() + ".db";
    const int rc = symlink(target.c_str(), link.c_str());
    assert(rc == 0);
    {
        fasten::SqliteStore store(link);
        store.insert(make_row("evt-mode-link", "TEST_MODE"));
    }
    assert(file_mode(target) == 0600);
    std::remove(link.c_str());
    remove_db(target);
    std::cout << "  test_dangling_symlink_target_is_0600: PASS\n";
}

// A SQLite built without URI support reads file: as a plain name unless the
// open passes SQLITE_OPEN_URI. Turn URI support off for this test only.
void test_file_uri_without_sqlite_uri_support() {
    const std::string path = "/tmp/fasten_mode_" + fasten::mint_id() + ".db";
    sqlite3_shutdown();
    sqlite3_config(SQLITE_CONFIG_URI, 0);
    sqlite3_initialize();
    bool opened = false;
    try {
        fasten::SqliteStore store("file:" + path);
        store.insert(make_row("evt-mode-uri", "TEST_MODE"));
        opened = true;
    } catch (const std::runtime_error&) {}
    sqlite3_shutdown();
    sqlite3_config(SQLITE_CONFIG_URI, 1);
    sqlite3_initialize();
    assert(opened);
    assert(file_mode(path) == 0600);
    remove_db(path);
    std::cout << "  test_file_uri_without_sqlite_uri_support: PASS\n";
}
#endif

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
    test_next_seq_uses_index();
    test_failed_commit_does_not_wedge_the_store();
    test_two_stores_one_node_get_distinct_seqs();
    test_id_held_by_a_different_row_is_rejected();
    test_taken_seq_is_named_in_the_error();
    test_text_with_a_nul_byte_is_rejected();
    test_minted_ids_do_not_repeat();
#ifndef _WIN32
    test_new_file_and_wal_are_0600();
    test_existing_file_keeps_its_mode();
    test_file_uri_is_0600();
    test_read_only_file_uri_creates_nothing();
    test_file_uri_without_a_file_to_create_creates_nothing();
    test_file_uri_keeps_an_invalid_escape();
    test_file_uri_path_ends_at_nul();
    test_file_uri_immutable_forms();
    test_dangling_symlink_target_is_0600();
    test_file_uri_without_sqlite_uri_support();
#endif
    std::cout << "All SQLite store smoke tests passed.\n";
    return 0;
}
