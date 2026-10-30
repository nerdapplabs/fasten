// PII retention by redaction (spec §7, #124) on SqliteStore.
#include "fasten.hpp"
#include "fasten_store_sqlite.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

namespace {

using clock_type = std::chrono::system_clock;
using days       = std::chrono::duration<int64_t, std::ratio<86400>>;

std::string days_ago(int n) { return fasten::detail_::iso8601(clock_type::now() - days(n)); }

fasten::Row make_row(const std::string& id, const std::string& code, const std::string& ts) {
    fasten::Row r;
    r.id             = id;
    r.origin_id      = id;
    r.timestamp      = ts;
    r.code           = code;
    r.severity       = "info";
    r.service_id     = "svc";
    r.source_node_id = "node-1";
    r.request_id     = "req-1";
    r.detail["email"] = "a@example.com";
    return r;
}

struct Db {
    sqlite3* db = nullptr;
    explicit Db(const std::string& path) { sqlite3_open(path.c_str(), &db); }
    ~Db() { sqlite3_close(db); }

    std::string text(const std::string& sql) {
        sqlite3_stmt* q = nullptr;
        sqlite3_prepare_v2(db, sql.c_str(), -1, &q, nullptr);
        std::string out;
        if (sqlite3_step(q) == SQLITE_ROW && sqlite3_column_text(q, 0))
            out = reinterpret_cast<const char*>(sqlite3_column_text(q, 0));
        sqlite3_finalize(q);
        return out;
    }
    void exec(const std::string& sql) {
        int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
        assert(rc == SQLITE_OK);
        (void)rc;
    }
    std::string detail(const std::string& id) {
        return text("SELECT detail FROM audit_log WHERE id = '" + id + "'");
    }
};

void register_codes() {
    fasten::Meta pii;
    pii.domain        = "user";
    pii.category      = "profile";
    pii.action        = "seen";
    pii.description   = "Email seen";
    pii.emitter       = "svc";
    pii.pii_in_detail = true;
    fasten::Meta plain = pii;
    plain.pii_in_detail = false;
    plain.description   = "Login";
    fasten::register_codes("user", {{"USER_EMAIL_SEEN", pii}, {"USER_LOGIN", plain}});
}

void test_redacts_expired_pii_rows() {
    const std::string path = "/tmp/fasten_pii_" + fasten::mint_id() + ".db";
    {
        fasten::SqliteStore store(path);
        store.insert(make_row("evt-pii-old", "USER_EMAIL_SEEN", days_ago(40)));
        store.insert(make_row("evt-pii-new", "USER_EMAIL_SEEN", days_ago(5)));
        store.insert(make_row("evt-plain-old", "USER_LOGIN", days_ago(40)));
        store.insert(make_row("evt-form1", "USER_EMAIL_SEEN", days_ago(40)));
        store.insert(make_row("evt-form2", "USER_EMAIL_SEEN", days_ago(40)));

        Db db(path);
        db.exec("UPDATE audit_log SET hash = 'x', canonical_form_id = '1' WHERE id = 'evt-form1'");
        db.exec("UPDATE audit_log SET hash = 'y', canonical_form_id = '2' WHERE id = 'evt-form2'");
        const std::string kept = db.detail("evt-plain-old");

        auto ids = fasten::redact_expired(store, clock_type::now() - days(30));
        assert(ids.size() == 2);
        assert(ids[0] == "evt-pii-old" || ids[1] == "evt-pii-old");
        assert(ids[0] == "evt-form2" || ids[1] == "evt-form2");

        assert(db.detail("evt-pii-old") == "null");
        assert(db.detail("evt-form2") == "null");
        assert(db.detail("evt-pii-new") != "null");
        assert(db.detail("evt-plain-old") == kept);
        assert(db.detail("evt-form1") != "null");
        assert(db.text("SELECT hash FROM audit_log WHERE id = 'evt-form2'") == "y");
        assert(db.text("SELECT detail_salt FROM audit_log WHERE id = 'evt-pii-old'").empty());

        // Five rows plus one record per redacted row.
        assert(db.text("SELECT COUNT(*) FROM audit_log") == "7");
        assert(db.text("SELECT COUNT(*) FROM audit_log WHERE code = 'AUDIT_ROW_REDACTED'"
                       " AND target = 'evt-pii-old'") == "1");
        const std::string rec = db.text(
            "SELECT detail FROM audit_log WHERE code = 'AUDIT_ROW_REDACTED'"
            " AND target = 'evt-pii-old'");
        assert(rec.find("\"redacted_id\":\"evt-pii-old\"") != std::string::npos);
        assert(rec.find("\"reason\":\"retention\"") != std::string::npos);
        assert(rec.find("\"redacted_seq\":1") != std::string::npos);
        assert(db.text("SELECT monotonic_seq FROM audit_log WHERE code = 'AUDIT_ROW_REDACTED'"
                       " AND target = 'evt-pii-old'") != "0");

        bool reported = false;
        for (const auto& r : fasten::query_syslog(100, "warn")) {
            auto it = r.find("event");
            if (it != r.end() && it->second == "pii_redaction_skipped_legacy_form") {
                assert(r.at("rows") == "1");
                reported = true;
            }
        }
        assert(reported);

        // Again: nothing left to redact, no new records.
        assert(fasten::redact_expired(store, clock_type::now() - days(30)).empty());
        assert(db.text("SELECT COUNT(*) FROM audit_log") == "7");

        // redact_rows is idempotent and never touches a form-"1" row.
        auto again = store.redact_rows({"evt-pii-old", "evt-form1"});
        assert(again.size() == 2);
        assert(db.detail("evt-pii-old") == "null");
        assert(db.detail("evt-form1") != "null");
    }
    std::remove(path.c_str());
    std::cout << "  test_redacts_expired_pii_rows: PASS\n";
}

// A table made before the chain columns gets them, and its rows (unsealed)
// can be redacted.
void test_migrates_legacy_table() {
    const std::string path = "/tmp/fasten_pii_legacy_" + fasten::mint_id() + ".db";
    {
        Db db(path);
        db.exec("CREATE TABLE audit_log (id TEXT PRIMARY KEY, origin_id TEXT NOT NULL,"
                " monotonic_seq INTEGER NOT NULL DEFAULT 0, timestamp TEXT NOT NULL,"
                " code TEXT NOT NULL, action TEXT NOT NULL DEFAULT '',"
                " severity TEXT NOT NULL DEFAULT 'info', service_id TEXT NOT NULL DEFAULT '',"
                " source_node_id TEXT NOT NULL DEFAULT '', tenant_id TEXT,"
                " actor TEXT NOT NULL DEFAULT '', actor_kind TEXT NOT NULL DEFAULT '',"
                " target TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '',"
                " domain TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT '',"
                " request_id TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '{}',"
                " pii_in_detail INTEGER NOT NULL DEFAULT 0, shipped_at TEXT)");
        db.exec("INSERT INTO audit_log (id, origin_id, monotonic_seq, timestamp, code, detail)"
                " VALUES ('evt-legacy', 'evt-legacy', 1, '" + days_ago(40) +
                "', 'USER_EMAIL_SEEN', '{\"email\":\"a@example.com\"}')");
    }
    {
        fasten::SqliteStore store(path);
        fasten::SqliteStore reopened(path);  // the migration runs twice
        auto ids = fasten::redact_expired(reopened, clock_type::now() - days(30));
        assert(ids.size() == 1 && ids[0] == "evt-legacy");
        Db db(path);
        assert(db.detail("evt-legacy") == "null");
        assert(db.text("SELECT canonical_form_id FROM audit_log WHERE id = 'evt-legacy'") == "1");
    }
    std::remove(path.c_str());
    std::cout << "  test_migrates_legacy_table: PASS\n";
}

}  // namespace

int main() {
    std::cout << "=== pii_redaction_smoke ===\n";
    register_codes();
    fasten::init("svc", "node-1");
    test_redacts_expired_pii_rows();
    test_migrates_legacy_table();
    std::cout << "All PII redaction smoke tests passed.\n";
    return 0;
}
