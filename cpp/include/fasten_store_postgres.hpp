// fasten_store_postgres.hpp — header-only PostgreSQL audit store for fasten.hpp
//
// Requires: libpq (PostgreSQL C client library)
// CMake:    target_link_libraries(mytarget PRIVATE PostgreSQL::PostgreSQL)
//
// Usage:
//   #include "fasten.hpp"
//   #include "fasten_store_postgres.hpp"
//
//   fasten::PostgresStore store("host=localhost user=app dbname=audit");
//   fasten::set_audit_sink(store.sink());
//   // store must outlive the engine

#pragma once
#ifndef FASTEN_STORE_POSTGRES_HPP
#define FASTEN_STORE_POSTGRES_HPP

#include <cctype>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <libpq-fe.h>

#include "fasten.hpp"

namespace fasten {

class PostgresStore {
public:
    /// Connect to `conninfo`, bootstrap the schema/table/indexes, and
    /// return a ready-to-use store.
    ///
    /// `conninfo` — libpq connection string or URI
    ///              (e.g. "host=localhost user=app dbname=audit" or
    ///               "postgresql://app@localhost/audit").
    /// `table`    — plain name ("audit_log") or schema-qualified
    ///              ("audit.audit_log"). Both parts must match
    ///              [A-Za-z_][A-Za-z0-9_]*.
    explicit PostgresStore(const std::string& conninfo,
                           const std::string& table = "audit_log")
        : table_(table)
    {
        auto dot = table_.find('.');
        if (dot != std::string::npos) {
            schema_ = table_.substr(0, dot);
            bare_   = table_.substr(dot + 1);
        } else {
            bare_ = table_;
        }

        validate_table_name(table_);

        conn_ = PQconnectdb(conninfo.c_str());
        if (!conn_ || PQstatus(conn_) != CONNECTION_OK) {
            std::string msg = conn_ ? PQerrorMessage(conn_) : "PQconnectdb returned null";
            if (conn_) { PQfinish(conn_); conn_ = nullptr; }
            throw std::runtime_error("fasten PostgresStore: " + msg);
        }

        migrate();
    }

    ~PostgresStore() {
        if (conn_) PQfinish(conn_);
    }

    PostgresStore(const PostgresStore&)            = delete;
    PostgresStore& operator=(const PostgresStore&) = delete;

    /// Insert one audit row. Thread-safe via internal mutex.
    ///
    /// A row with monotonic_seq 0 (what emit() returns) gets the node's next
    /// seq in the insert's transaction, under the same per-node advisory lock
    /// as the Python, Go and JS stores (spec §2.1). The row is not sealed.
    void insert(const Row& row) {
        std::lock_guard<std::mutex> lk(mu_);
        if (row.monotonic_seq != 0) {
            insert_row(row, row.monotonic_seq);
            return;
        }
        exec("BEGIN");
        try {
            const char* node[1] = {row.source_node_id.c_str()};
            query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", 1, node);
            std::string seq = query(
                "SELECT COALESCE(MAX(monotonic_seq), 0) + 1 FROM " + table_ +
                " WHERE source_node_id = $1", 1, node);
            insert_row(row, std::stoll(seq));
            exec("COMMIT");
        } catch (...) {
            PQclear(PQexec(conn_, "ROLLBACK"));
            throw;
        }
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
        std::vector<const char*> params{cutoff.c_str()};
        for (const auto& c : codes) params.push_back(c.c_str());
        const std::string where =
            " FROM " + table_ + " WHERE timestamp < $1 AND code IN (" +
            placeholders(2, codes.size()) + ") AND detail <> 'null' AND ";

        std::lock_guard<std::mutex> lk(mu_);
        if (skipped) {
            *skipped = std::stoll(query("SELECT COUNT(*)" + where + "NOT " + redactable(),
                                        static_cast<int>(params.size()), params.data()));
        }
        Result res(conn_, "SELECT id, monotonic_seq" + where + redactable() +
                          " ORDER BY monotonic_seq",
                   static_cast<int>(params.size()), params.data());
        for (int i = 0; i < PQntuples(res.r); ++i)
            out.emplace_back(PQgetvalue(res.r, i, 0), std::stoll(PQgetvalue(res.r, i, 1)));
        return out;
    }

    /// Sets detail to the JSON literal null and clears detail_salt on these
    /// ids (spec §7.1). Hash, prev_hash and seq are kept. A sealed form-"1"
    /// row is left alone. Safe to repeat; returns `ids`.
    std::vector<std::string> redact_rows(const std::vector<std::string>& ids) {
        if (ids.empty()) return ids;
        std::vector<const char*> params;
        for (const auto& id : ids) params.push_back(id.c_str());
        std::lock_guard<std::mutex> lk(mu_);
        query("UPDATE " + table_ + " SET detail = 'null', detail_salt = ''"
              " WHERE id IN (" + placeholders(1, ids.size()) + ") AND " + redactable(),
              static_cast<int>(params.size()), params.data());
        return ids;
    }

private:
    // Unsealed, or sealed under form "2" where the hash covers the detail
    // commitment and not the detail.
    static const char* redactable() {
        return "(hash = '' OR canonical_form_id = '2')";
    }

    static std::string placeholders(size_t first, size_t n) {
        std::string out;
        for (size_t i = 0; i < n; ++i)
            out += (i ? ",$" : "$") + std::to_string(first + i);
        return out;
    }

    struct Result {
        PGresult* r;
        Result(PGconn* c, const std::string& sql, int n, const char* const* params)
            : r(PQexecParams(c, sql.c_str(), n, nullptr, params, nullptr, nullptr, 0)) {
            if (PQresultStatus(r) != PGRES_TUPLES_OK) {
                std::string msg = PQerrorMessage(c);
                PQclear(r);
                throw std::runtime_error("fasten PostgresStore: " + msg);
            }
        }
        ~Result() { PQclear(r); }
        Result(const Result&)            = delete;
        Result& operator=(const Result&) = delete;
    };

    void exec(const char* sql) { query(sql, 0, nullptr); }

    // Runs sql and returns the first column of the first row, or "".
    std::string query(const std::string& sql, int n, const char* const* params) {
        PGresult* res = PQexecParams(conn_, sql.c_str(), n, nullptr, params,
                                     nullptr, nullptr, 0);
        ExecStatusType status = PQresultStatus(res);
        if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
            std::string msg = PQerrorMessage(conn_);
            PQclear(res);
            throw std::runtime_error("fasten PostgresStore: " + msg);
        }
        std::string out = (status == PGRES_TUPLES_OK && PQntuples(res) > 0)
            ? PQgetvalue(res, 0, 0) : "";
        PQclear(res);
        return out;
    }

    void insert_row(const Row& row, int64_t seq) {
        std::string detail_json = detail_::fields_to_json(row.detail);
        std::string mono_str    = std::to_string(seq);
        const char* pii_str     = row.pii_in_detail ? "1" : "0";

        // nullptr → SQL NULL for nullable columns
        const char* tenant_ptr  = row.tenant_id.empty()  ? nullptr : row.tenant_id.c_str();
        const char* shipped_ptr = row.shipped_at.empty() ? nullptr : row.shipped_at.c_str();

        const char* params[20] = {
            row.id.c_str(),              // $1  id
            row.origin_id.c_str(),       // $2  origin_id
            mono_str.c_str(),            // $3  monotonic_seq
            row.timestamp.c_str(),       // $4  timestamp
            row.code.c_str(),            // $5  code
            row.action.c_str(),          // $6  action
            row.severity.c_str(),        // $7  severity
            row.service_id.c_str(),      // $8  service_id
            row.source_node_id.c_str(),  // $9  source_node_id
            tenant_ptr,                  // $10 tenant_id   (nullptr → NULL)
            row.actor.c_str(),           // $11 actor
            row.actor_kind.c_str(),      // $12 actor_kind
            row.target.c_str(),          // $13 target
            row.category.c_str(),        // $14 category
            row.domain.c_str(),          // $15 domain
            row.method.c_str(),          // $16 method
            row.request_id.c_str(),      // $17 request_id
            detail_json.c_str(),         // $18 detail
            pii_str,                     // $19 pii_in_detail
            shipped_ptr,                 // $20 shipped_at  (nullptr → NULL)
        };

        const std::string sql =
            "INSERT INTO " + table_ +
            " (id, origin_id, monotonic_seq, timestamp,"
            "  code, action, severity, service_id, source_node_id, tenant_id,"
            "  actor, actor_kind, target, category, domain, method,"
            "  request_id, detail, pii_in_detail, shipped_at,"
            "  prev_hash, hash, canonical_form_id, detail_salt, detail_commitment)"
            " VALUES"
            " ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,"
            "  '','','1','','')"
            " ON CONFLICT (id) DO NOTHING";

        PGresult* res = PQexecParams(
            conn_,
            sql.c_str(),
            20,
            nullptr,   // param types — infer from context
            params,
            nullptr,   // param lengths — text mode
            nullptr,   // param formats — text mode
            0          // result format: text
        );

        ExecStatusType status = PQresultStatus(res);
        if (status != PGRES_COMMAND_OK) {
            std::string msg = PQerrorMessage(conn_);
            PQclear(res);
            throw std::runtime_error("fasten PostgresStore insert: " + msg);
        }
        PQclear(res);
    }

public:
    /// Returns an AuditSink that calls insert(). The PostgresStore must
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
        auto dot = table.find('.');
        if (dot == std::string::npos) {
            if (!is_valid_identifier(table))
                throw std::invalid_argument(
                    "fasten PostgresStore: invalid table name '" + table + "'");
        } else {
            std::string schema = table.substr(0, dot);
            std::string bare   = table.substr(dot + 1);
            if (!is_valid_identifier(schema) || !is_valid_identifier(bare))
                throw std::invalid_argument(
                    "fasten PostgresStore: invalid table name '" + table + "'");
        }
    }

    void pg_exec(const std::string& sql) {
        PGresult* res = PQexec(conn_, sql.c_str());
        ExecStatusType status = PQresultStatus(res);
        if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
            std::string msg = PQerrorMessage(conn_);
            PQclear(res);
            throw std::runtime_error("fasten PostgresStore DDL: " + msg);
        }
        PQclear(res);
    }

    void migrate() {
        if (!schema_.empty())
            pg_exec("CREATE SCHEMA IF NOT EXISTS " + schema_);

        pg_exec(
            "CREATE TABLE IF NOT EXISTS " + table_ + " ("
            "  id              TEXT        NOT NULL,"
            "  origin_id       TEXT        NOT NULL,"
            "  monotonic_seq   BIGINT      NOT NULL DEFAULT 0,"
            "  timestamp       TEXT        NOT NULL,"
            "  code            TEXT        NOT NULL,"
            "  action          TEXT        NOT NULL DEFAULT '',"
            "  severity        TEXT        NOT NULL DEFAULT 'info',"
            "  service_id      TEXT        NOT NULL DEFAULT '',"
            "  source_node_id  TEXT        NOT NULL DEFAULT '',"
            "  tenant_id       TEXT,"
            "  actor           TEXT        NOT NULL DEFAULT '',"
            "  actor_kind      TEXT        NOT NULL DEFAULT '',"
            "  target          TEXT        NOT NULL DEFAULT '',"
            "  category        TEXT        NOT NULL DEFAULT '',"
            "  domain          TEXT        NOT NULL DEFAULT '',"
            "  method          TEXT        NOT NULL DEFAULT '',"
            "  request_id      TEXT        NOT NULL DEFAULT '',"
            "  detail          TEXT        NOT NULL DEFAULT '{}',"
            "  pii_in_detail   SMALLINT    NOT NULL DEFAULT 0,"
            "  shipped_at      TEXT,"
            "  prev_hash       TEXT        NOT NULL DEFAULT '',"
            "  hash            TEXT        NOT NULL DEFAULT '',"
            "  canonical_form_id TEXT      NOT NULL DEFAULT '1',"
            "  detail_salt     TEXT        NOT NULL DEFAULT '',"
            "  detail_commitment TEXT      NOT NULL DEFAULT '',"
            "  PRIMARY KEY (id)"
            ")"
        );

        // Chain columns for a table created before they were added, with the
        // Go store's definitions so the table can be shared.
        for (const char* col : {
                 "prev_hash TEXT NOT NULL DEFAULT ''",
                 "hash TEXT NOT NULL DEFAULT ''",
                 "canonical_form_id TEXT NOT NULL DEFAULT '1'",
                 "detail_salt TEXT NOT NULL DEFAULT ''",
                 "detail_commitment TEXT NOT NULL DEFAULT ''"}) {
            pg_exec("ALTER TABLE " + table_ + " ADD COLUMN IF NOT EXISTS " + col);
        }

        pg_exec("CREATE INDEX IF NOT EXISTS idx_" + bare_ + "_req  ON " + table_ + " (request_id)");
        pg_exec("CREATE INDEX IF NOT EXISTS idx_" + bare_ + "_code ON " + table_ + " (code)");
        pg_exec("CREATE INDEX IF NOT EXISTS idx_" + bare_ + "_ts   ON " + table_ + " (timestamp)");
        pg_exec("CREATE INDEX IF NOT EXISTS idx_" + bare_ + "_svc  ON " + table_ + " (service_id)");
    }

    PGconn*     conn_   = nullptr;
    std::string table_;
    std::string schema_;
    std::string bare_;
    std::mutex  mu_;
};

} // namespace fasten

#endif // FASTEN_STORE_POSTGRES_HPP
