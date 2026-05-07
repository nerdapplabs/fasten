// fasten_store_sqlite.hpp — header-only SQLite audit store for fasten.hpp
//
// Requires: sqlite3 development headers + library
// CMake:    target_link_libraries(mytarget PRIVATE SQLite3::SQLite3)
//
// Usage:
//   #include "fasten.hpp"
//   #include "fasten_store_sqlite.hpp"
//
//   fasten::SqliteStore store("path/to/audit.db");
//   fasten::set_audit_sink(store.sink());
//   // store must outlive the engine

#pragma once
#ifndef FASTEN_STORE_SQLITE_HPP
#define FASTEN_STORE_SQLITE_HPP

#include <cctype>
#include <mutex>
#include <stdexcept>
#include <string>

#include <sqlite3.h>

#include "fasten.hpp"

namespace fasten {

class SqliteStore {
public:
    /// Open (or create) the SQLite database at `path`, bootstrap the audit
    /// table + indexes, and prepare the INSERT statement.
    ///
    /// `path`  — filesystem path, or ":memory:" for in-process databases.
    /// `table` — table name; must match [A-Za-z_][A-Za-z0-9_]*.
    /// `wal`   — if true (default) enables WAL journal mode for better
    ///           write concurrency. Ignored for ":memory:" databases.
    explicit SqliteStore(const std::string& path,
                         const std::string& table = "audit_log",
                         bool wal = true)
        : table_(table)
    {
        validate_table_name(table_);

        int rc = sqlite3_open(path.c_str(), &db_);
        if (rc != SQLITE_OK) {
            std::string msg = db_ ? sqlite3_errmsg(db_) : "sqlite3_open failed";
            sqlite3_close(db_);
            db_ = nullptr;
            throw std::runtime_error("fasten SqliteStore: " + msg);
        }

        if (wal && path != ":memory:") {
            sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
        }

        migrate();
        prepare_stmt();
    }

    ~SqliteStore() {
        if (stmt_) sqlite3_finalize(stmt_);
        if (db_)   sqlite3_close(db_);
    }

    SqliteStore(const SqliteStore&)            = delete;
    SqliteStore& operator=(const SqliteStore&) = delete;

    /// Insert one audit row. Thread-safe via internal mutex.
    void insert(const Row& row) {
        std::string detail_json = detail_::fields_to_json(row.detail);
        int         pii_int     = row.pii_in_detail ? 1 : 0;

        std::lock_guard<std::mutex> lk(mu_);

        int idx = 1;
        sqlite3_bind_text (stmt_, idx++, row.id.c_str(),             -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt_, idx++, row.origin_id.c_str(),      -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt_, idx++, row.monotonic_seq);
        sqlite3_bind_text (stmt_, idx++, row.timestamp.c_str(),      -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt_, idx++, row.code.c_str(),           -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt_, idx++, row.action.c_str(),         -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt_, idx++, row.severity.c_str(),       -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt_, idx++, row.service_id.c_str(),     -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt_, idx++, row.source_node_id.c_str(), -1, SQLITE_TRANSIENT);

        if (row.tenant_id.empty())
            sqlite3_bind_null(stmt_, idx++);
        else
            sqlite3_bind_text(stmt_, idx++, row.tenant_id.c_str(),   -1, SQLITE_TRANSIENT);

        sqlite3_bind_text(stmt_, idx++, row.actor.c_str(),      -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt_, idx++, row.actor_kind.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt_, idx++, row.target.c_str(),     -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt_, idx++, row.category.c_str(),   -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt_, idx++, row.domain.c_str(),     -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt_, idx++, row.method.c_str(),     -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt_, idx++, row.request_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt_, idx++, detail_json.c_str(),    -1, SQLITE_TRANSIENT);
        sqlite3_bind_int (stmt_, idx++, pii_int);

        if (row.shipped_at.empty())
            sqlite3_bind_null(stmt_, idx++);
        else
            sqlite3_bind_text(stmt_, idx++, row.shipped_at.c_str(),  -1, SQLITE_TRANSIENT);

        int step = sqlite3_step(stmt_);
        sqlite3_reset(stmt_);
        sqlite3_clear_bindings(stmt_);

        if (step != SQLITE_DONE && step != SQLITE_ROW) {
            throw std::runtime_error(
                std::string("fasten SqliteStore insert: ") + sqlite3_errmsg(db_));
        }
    }

    /// Returns an AuditSink that calls insert(). The SqliteStore must
    /// outlive the returned sink.
    AuditSink sink() {
        return [this](const Row& row) { insert(row); };
    }

private:
    static bool is_valid_identifier(const std::string& s) {
        if (s.empty()) return false;
        if (!std::isalpha(static_cast<unsigned char>(s[0])) && s[0] != '_')
            return false;
        for (size_t i = 1; i < s.size(); ++i) {
            if (!std::isalnum(static_cast<unsigned char>(s[i])) && s[i] != '_')
                return false;
        }
        return true;
    }

    static void validate_table_name(const std::string& table) {
        if (!is_valid_identifier(table))
            throw std::invalid_argument(
                "fasten SqliteStore: invalid table name '" + table + "'");
    }

    void migrate() {
        const std::string ddl =
            "CREATE TABLE IF NOT EXISTS " + table_ + " ("
            "  id              TEXT    PRIMARY KEY,"
            "  origin_id       TEXT    NOT NULL,"
            "  monotonic_seq   INTEGER NOT NULL DEFAULT 0,"
            "  timestamp       TEXT    NOT NULL,"
            "  code            TEXT    NOT NULL,"
            "  action          TEXT    NOT NULL DEFAULT '',"
            "  severity        TEXT    NOT NULL DEFAULT 'info',"
            "  service_id      TEXT    NOT NULL DEFAULT '',"
            "  source_node_id  TEXT    NOT NULL DEFAULT '',"
            "  tenant_id       TEXT,"
            "  actor           TEXT    NOT NULL DEFAULT '',"
            "  actor_kind      TEXT    NOT NULL DEFAULT '',"
            "  target          TEXT    NOT NULL DEFAULT '',"
            "  category        TEXT    NOT NULL DEFAULT '',"
            "  domain          TEXT    NOT NULL DEFAULT '',"
            "  method          TEXT    NOT NULL DEFAULT '',"
            "  request_id      TEXT    NOT NULL DEFAULT '',"
            "  detail          TEXT    NOT NULL DEFAULT '{}',"
            "  pii_in_detail   INTEGER NOT NULL DEFAULT 0,"
            "  shipped_at      TEXT"
            ")";

        char* errmsg = nullptr;
        int rc = sqlite3_exec(db_, ddl.c_str(), nullptr, nullptr, &errmsg);
        if (rc != SQLITE_OK) {
            std::string msg = errmsg ? errmsg : "DDL error";
            sqlite3_free(errmsg);
            throw std::runtime_error("fasten SqliteStore migrate: " + msg);
        }

        const std::string idx_sql =
            "CREATE INDEX IF NOT EXISTS idx_" + table_ + "_req  ON " + table_ + "(request_id);"
            "CREATE INDEX IF NOT EXISTS idx_" + table_ + "_code ON " + table_ + "(code);"
            "CREATE INDEX IF NOT EXISTS idx_" + table_ + "_ts   ON " + table_ + "(timestamp);"
            "CREATE INDEX IF NOT EXISTS idx_" + table_ + "_svc  ON " + table_ + "(service_id);";

        rc = sqlite3_exec(db_, idx_sql.c_str(), nullptr, nullptr, &errmsg);
        if (rc != SQLITE_OK) {
            std::string msg = errmsg ? errmsg : "index error";
            sqlite3_free(errmsg);
            throw std::runtime_error("fasten SqliteStore migrate (indexes): " + msg);
        }
    }

    void prepare_stmt() {
        const std::string sql =
            "INSERT OR IGNORE INTO " + table_ +
            " (id, origin_id, monotonic_seq, timestamp,"
            "  code, action, severity, service_id, source_node_id, tenant_id,"
            "  actor, actor_kind, target, category, domain, method,"
            "  request_id, detail, pii_in_detail, shipped_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt_, nullptr);
        if (rc != SQLITE_OK)
            throw std::runtime_error(
                std::string("fasten SqliteStore prepare: ") + sqlite3_errmsg(db_));
    }

    sqlite3*      db_   = nullptr;
    sqlite3_stmt* stmt_ = nullptr;
    std::string   table_;
    std::mutex    mu_;
};

} // namespace fasten

#endif // FASTEN_STORE_SQLITE_HPP
