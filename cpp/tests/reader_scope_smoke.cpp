// Reader tenant isolation (#138 point 3).
#include "fasten.hpp"
#include "fasten_reader.hpp"

#include <cassert>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

namespace reader = fasten::reader;

void init_tenant(const std::string& tenant) {
    fasten::Config c{"svc", "node", tenant};
    c.audit_store_failure_strategy = "raise";
    fasten::init(c);
}

bool has(const std::string& body, const std::string& s) {
    return body.find(s) != std::string::npos;
}

fasten::Row audit_row(const std::string& id, const std::string& tenant) {
    fasten::Row r;
    r.id = id;
    r.tenant_id = tenant;
    return r;
}

void sys_rows_are_scoped() {
    fasten::detail_::globals().reset_for_tests();
    init_tenant("tenant-a");
    fasten::log::info("marker-a");
    init_tenant("tenant-b");
    fasten::log::info("marker-b");

    auto r = reader::handle_sys({{"tenant_id", "tenant-b"}}, "tenant-a");
    assert(r.status == 200);
    assert(has(r.body, "marker-a"));
    assert(!has(r.body, "marker-b"));

    assert(reader::handle_sys({}, "").status == 401);
    auto all = reader::handle_sys({});
    assert(has(all.body, "marker-a") && has(all.body, "marker-b"));
    std::cout << "sys scoped: PASS\n";
}

// A log field cannot set shape, service_id or timestamp, or override the
// engine's tenant. A request_id field is used, and a tenant_id field is used
// when the engine has no tenant. Each key appears once.
void sys_fields_and_envelope_keys() {
    fasten::detail_::globals().reset_for_tests();
    init_tenant("tenant-a");
    std::ostringstream captured;
    auto* old = std::cout.rdbuf(captured.rdbuf());
    fasten::log::info("marker-fields", {{"tenant_id", "tenant-b"},
                                        {"shape", "audit"},
                                        {"service_id", "other"},
                                        {"timestamp", "yesterday"},
                                        {"request_id", "up-123"},
                                        {"note", "kept"}});
    std::cout.rdbuf(old);

    assert(!has(reader::handle_sys({}, "tenant-b").body, "marker-fields"));
    auto mine = reader::handle_sys({}, "tenant-a");
    assert(has(mine.body, "marker-fields") && has(mine.body, "kept"));

    const std::string line = captured.str();
    auto count = [&](const std::string& s) {
        int n = 0;
        for (auto at = line.find(s); at != std::string::npos; at = line.find(s, at + 1)) ++n;
        return n;
    };
    assert(count("\"shape\":") == 1 && has(line, "\"shape\":\"sys\""));
    assert(count("\"tenant_id\":") == 1 && has(line, "\"tenant_id\":\"tenant-a\""));
    assert(count("\"service_id\":") == 1 && has(line, "\"service_id\":\"svc\""));
    assert(count("\"timestamp\":") == 1 && !has(line, "yesterday"));
    // A request_id field is the line's request_id, as in the other SDKs.
    assert(count("\"request_id\":") == 1 && has(line, "\"request_id\":\"up-123\""));
    assert(has(line, "\"note\":\"kept\""));

    // The ring row has the SDK's service_id and timestamp, as the line does.
    auto ring = fasten::query_syslog(10);
    assert(!ring.empty());
    const auto& row = ring.front();
    assert(row.at("service_id") == "svc");
    assert(row.at("timestamp") != "yesterday" && !row.at("timestamp").empty());
    assert(row.at("request_id") == "up-123");
    assert(row.at("tenant_id") == "tenant-a");
    assert(!row.count("shape"));

    // With no engine tenant, the field's tenant scopes the row, as in Go
    // and Python.
    fasten::detail_::globals().reset_for_tests();
    init_tenant("");
    std::ostringstream untenanted;
    old = std::cout.rdbuf(untenanted.rdbuf());
    fasten::log::info("marker-untenanted", {{"tenant_id", "tenant-b"}});
    std::cout.rdbuf(old);
    assert(has(reader::handle_sys({}, "tenant-b").body, "marker-untenanted"));
    assert(!has(reader::handle_sys({}, "tenant-a").body, "marker-untenanted"));
    assert(has(untenanted.str(), "\"tenant_id\":\"tenant-b\""));
    std::cout << "sys envelope keys: PASS\n";
}

void enforced_isolation_refuses_unscoped_calls() {
    reader::enforce_tenant_isolation();
    assert(reader::handle_sys({}).status == 401);
    assert(reader::handle_api({}).status == 401);
    assert(reader::handle_audit({}).status == 401);
    assert(reader::handle_sys({}, "tenant-a").status == 200);
    reader::enforce_tenant_isolation(false);
    std::cout << "enforced isolation: PASS\n";
}

void audit_rows_are_scoped() {
    reader::set_audit_query([](const std::string&, const std::string&,
                               const std::string&, int) {
        return std::vector<fasten::Row>{audit_row("evt-a", "tenant-a"),
                                        audit_row("evt-b", "tenant-b")};
    });
    auto r = reader::handle_audit({}, "tenant-a");
    assert(has(r.body, "evt-a") && !has(r.body, "evt-b"));

    std::string seen;
    reader::set_scoped_audit_query([&](const std::string&, const std::string&,
                                       const std::string&, const std::string& tenant, int) {
        seen = tenant;
        return std::vector<fasten::Row>{audit_row("evt-a", "tenant-a")};
    });
    r = reader::handle_audit({{"tenant_id", "tenant-b"}}, "tenant-a");
    assert(seen == "tenant-a");
    assert(has(r.body, "evt-a"));
    reader::set_scoped_audit_query({});
    std::cout << "audit scoped: PASS\n";
}

void audit_errors_stay_out_of_the_response() {
    reader::set_audit_query([](const std::string&, const std::string&,
                               const std::string&, int) -> std::vector<fasten::Row> {
        throw std::runtime_error("connection to host=db.internal user=svc failed");
    });
    auto r = reader::handle_audit({});
    assert(r.status == 500);
    assert(!has(r.body, "db.internal"));
    std::cout << "audit 500 body: PASS\n";
}

}  // namespace

int main() {
    sys_rows_are_scoped();
    sys_fields_and_envelope_keys();
    enforced_isolation_refuses_unscoped_calls();
    audit_rows_are_scoped();
    audit_errors_stay_out_of_the_response();
    return 0;
}
