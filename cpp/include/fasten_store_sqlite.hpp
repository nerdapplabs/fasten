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
#include <chrono>
#include <cstdint>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

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

        // Wait for a lock held by another connection instead of failing at
        // once with SQLITE_BUSY (the Go store waits 5 s too).
        sqlite3_busy_timeout(db_, 5000);

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
    ///
    /// A row with monotonic_seq 0 (what emit() returns) gets the node's next
    /// seq in the insert's transaction (spec §2.1). The row is not sealed.
    void insert(const Row& row) {
        std::string detail_json = detail_::fields_to_json(row.detail);
        int         pii_int     = row.pii_in_detail ? 1 : 0;

        std::lock_guard<std::mutex> lk(mu_);

        const bool allocate = row.monotonic_seq == 0;
        int64_t seq = row.monotonic_seq;
        if (allocate) {
            exec("BEGIN IMMEDIATE");
            try {
                seq = next_seq(row.source_node_id);
            } catch (...) {
                rollback();
                throw;
            }
        }

        int idx = 1;
        sqlite3_bind_text (stmt_, idx++, row.id.c_str(),             -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt_, idx++, row.origin_id.c_str(),      -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt_, idx++, seq);
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
            std::string msg = sqlite3_errmsg(db_);
            if (allocate) rollback();
            throw std::runtime_error("fasten SqliteStore insert: " + msg);
        }
        if (allocate) {
            try {
                exec("COMMIT");
            } catch (...) {
                rollback();  // else the connection stays in the transaction
                throw;
            }
        }
    }

    /// Returns an AuditSink that calls insert(). The SqliteStore must
    /// outlive the returned sink.
    AuditSink sink() {
        return [this](const Row& row) { insert(row); };
    }

    /// (id, monotonic_seq) of rows with a code in `codes`, older than
    /// `before`, that redact_rows() would redact (spec §7.1). A sealed row
    /// under form "1" is never one: its detail is in the hash. Their number
    /// goes to `skipped`.
    std::vector<std::pair<std::string, int64_t>> list_redaction_candidates(
        std::chrono::system_clock::time_point before,
        const std::vector<std::string>& codes,
        int64_t* skipped = nullptr)
    {
        std::vector<std::pair<std::string, int64_t>> out;
        if (skipped) *skipped = 0;
        if (codes.empty()) return out;
        const std::string cutoff = detail_::iso8601(before);
        const std::string where =
            " FROM " + table_ + " WHERE timestamp < ? AND code IN (" +
            placeholders(codes.size()) + ") AND detail <> 'null' AND ";

        std::lock_guard<std::mutex> lk(mu_);
        if (skipped) {
            Stmt q(db_, "SELECT COUNT(*)" + where + "NOT " + redactable());
            bind_window(q.s, cutoff, codes);
            if (sqlite3_step(q.s) == SQLITE_ROW) *skipped = sqlite3_column_int64(q.s, 0);
        }
        Stmt q(db_, "SELECT id, monotonic_seq" + where + redactable() +
                    " ORDER BY monotonic_seq");
        bind_window(q.s, cutoff, codes);
        int rc;
        while ((rc = sqlite3_step(q.s)) == SQLITE_ROW) {
            out.emplace_back(
                reinterpret_cast<const char*>(sqlite3_column_text(q.s, 0)),
                sqlite3_column_int64(q.s, 1));
        }
        if (rc != SQLITE_DONE)
            throw std::runtime_error(
                std::string("fasten SqliteStore list_redaction_candidates: ") +
                sqlite3_errmsg(db_));
        return out;
    }

    /// Sets detail to the JSON literal null and clears detail_salt on these
    /// ids (spec §7.1). Hash, prev_hash and seq are kept. A sealed form-"1"
    /// row is left alone. Safe to repeat; returns `ids`.
    std::vector<std::string> redact_rows(const std::vector<std::string>& ids) {
        if (ids.empty()) return ids;
        std::lock_guard<std::mutex> lk(mu_);
        Stmt q(db_, "UPDATE " + table_ +
                    " SET detail = 'null', detail_salt = '' WHERE id IN (" +
                    placeholders(ids.size()) + ") AND " + redactable());
        int i = 1;
        for (const auto& id : ids)
            sqlite3_bind_text(q.s, i++, id.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(q.s) != SQLITE_DONE)
            throw std::runtime_error(
                std::string("fasten SqliteStore redact_rows: ") + sqlite3_errmsg(db_));
        return ids;
    }

private:
    // Unsealed, or sealed under form "2" where the hash covers the detail
    // commitment and not the detail.
    static const char* redactable() {
        return "(hash = '' OR canonical_form_id = '2')";
    }

    struct Stmt {
        sqlite3_stmt* s = nullptr;
        Stmt(sqlite3* db, const std::string& sql) {
            if (sqlite3_prepare_v2(db, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
                throw std::runtime_error(
                    std::string("fasten SqliteStore prepare: ") + sqlite3_errmsg(db));
        }
        ~Stmt() { sqlite3_finalize(s); }
        Stmt(const Stmt&)            = delete;
        Stmt& operator=(const Stmt&) = delete;
    };

    static std::string placeholders(size_t n) {
        std::string out;
        for (size_t i = 0; i < n; ++i) out += i ? ",?" : "?";
        return out;
    }

    static void bind_window(sqlite3_stmt* q, const std::string& cutoff,
                            const std::vector<std::string>& codes) {
        sqlite3_bind_text(q, 1, cutoff.c_str(), -1, SQLITE_TRANSIENT);
        int i = 2;
        for (const auto& c : codes)
            sqlite3_bind_text(q, i++, c.c_str(), -1, SQLITE_TRANSIENT);
    }

    void exec(const char* sql) { exec_sql(sql); }

    void exec_sql(const std::string& sql) {
        char* errmsg = nullptr;
        if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errmsg) != SQLITE_OK) {
            std::string msg = errmsg ? errmsg : sqlite3_errmsg(db_);
            sqlite3_free(errmsg);
            throw std::runtime_error(std::string("fasten SqliteStore ") + sql + ": " + msg);
        }
    }

    // Ends an open transaction without throwing, so the original error is the
    // one reported. SQLite may have rolled back already.
    void rollback() noexcept {
        if (!sqlite3_get_autocommit(db_)) {
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        }
    }

    int64_t next_seq(const std::string& node) {
        const std::string sql = "SELECT COALESCE(MAX(monotonic_seq), 0) + 1 FROM " +
                                table_ + " WHERE source_node_id = ?";
        sqlite3_stmt* q = nullptr;
        if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &q, nullptr) != SQLITE_OK)
            throw std::runtime_error(
                std::string("fasten SqliteStore next seq: ") + sqlite3_errmsg(db_));
        sqlite3_bind_text(q, 1, node.c_str(), -1, SQLITE_TRANSIENT);
        int64_t seq = sqlite3_step(q) == SQLITE_ROW ? sqlite3_column_int64(q, 0) : 1;
        sqlite3_finalize(q);
        return seq;
    }

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
            "  shipped_at      TEXT,"
            "  prev_hash       TEXT    NOT NULL DEFAULT '',"
            "  hash            TEXT    NOT NULL DEFAULT '',"
            "  canonical_form_id TEXT  NOT NULL DEFAULT '1',"
            "  detail_salt     TEXT    NOT NULL DEFAULT '',"
            "  detail_commitment TEXT  NOT NULL DEFAULT ''"
            ")";

        char* errmsg = nullptr;
        int rc = sqlite3_exec(db_, ddl.c_str(), nullptr, nullptr, &errmsg);
        if (rc != SQLITE_OK) {
            std::string msg = errmsg ? errmsg : "DDL error";
            sqlite3_free(errmsg);
            throw std::runtime_error("fasten SqliteStore migrate: " + msg);
        }

        // Chain columns for a table created before they were added, with the
        // Go store's definitions so the table can be shared.
        std::set<std::string> have;
        {
            Stmt q(db_, "PRAGMA table_info(" + table_ + ")");
            while (sqlite3_step(q.s) == SQLITE_ROW)
                have.insert(reinterpret_cast<const char*>(sqlite3_column_text(q.s, 1)));
        }
        const char* const chain_cols[][2] = {
            {"prev_hash",         "TEXT NOT NULL DEFAULT ''"},
            {"hash",              "TEXT NOT NULL DEFAULT ''"},
            {"canonical_form_id", "TEXT NOT NULL DEFAULT '1'"},
            {"detail_salt",       "TEXT NOT NULL DEFAULT ''"},
            {"detail_commitment", "TEXT NOT NULL DEFAULT ''"},
        };
        for (const auto& col : chain_cols) {
            if (have.count(col[0])) continue;
            exec_sql("ALTER TABLE " + table_ + " ADD COLUMN " + col[0] + " " + col[1]);
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
            "  request_id, detail, pii_in_detail, shipped_at,"
            "  prev_hash, hash, canonical_form_id, detail_salt, detail_commitment)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'','','1','','')";

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
