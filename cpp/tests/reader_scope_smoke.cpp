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

// A log field cannot set the row's tenant or the other keys the SDK sets.
void sys_fields_cannot_set_envelope_keys() {
    fasten::detail_::globals().reset_for_tests();
    init_tenant("tenant-a");
    std::ostringstream captured;
    auto* old = std::cout.rdbuf(captured.rdbuf());
    fasten::log::info("marker-fields", {{"tenant_id", "tenant-b"},
                                        {"shape", "audit"},
                                        {"service_id", "other"},
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
    assert(has(line, "\"note\":\"kept\""));

    // With no engine tenant, a field cannot give the row one.
    fasten::detail_::globals().reset_for_tests();
    init_tenant("");
    old = std::cout.rdbuf(captured.rdbuf());
    fasten::log::info("marker-untenanted", {{"tenant_id", "tenant-b"}});
    std::cout.rdbuf(old);
    assert(!has(reader::handle_sys({}, "tenant-b").body, "marker-untenanted"));
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
    sys_fields_cannot_set_envelope_keys();
    enforced_isolation_refuses_unscoped_calls();
    audit_rows_are_scoped();
    audit_errors_stay_out_of_the_response();
    return 0;
}
