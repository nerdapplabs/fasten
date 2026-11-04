// Queue mode stores the row's own columns, whatever keys detail holds (#147).
//
// The drainer hands rows to the sink as JSON. Columns used to be found by a
// substring search over that JSON, so a detail key named like a column could
// set it.
#include "fasten.hpp"

#include <cassert>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

namespace {

std::mutex          mu;
std::vector<fasten::Row> stored;

void reset_state() {
    fasten_registry_clear();
    auto& g = fasten::detail_::globals();
    g.registry.clear();
    std::lock_guard<std::mutex> lk(mu);
    stored.clear();
}

void register_code() {
    fasten::Meta m;
    m.domain      = "user";
    m.category    = "account";
    m.action      = "create";
    m.severity    = fasten::Sev::Info;
    m.description = "x";
    m.emitter     = "t";
    fasten::register_codes("user", { {"USER_CREATED", m} });
}

fasten::Row emit_and_store(const std::string& tenant, const std::string& strategy) {
    reset_state();
    register_code();
    fasten::set_audit_sink([](const fasten::Row& r) {
        std::lock_guard<std::mutex> lk(mu);
        stored.push_back(r);
    });
    fasten::Config cfg{"svc", "node", tenant};
    cfg.audit_store_failure_strategy = strategy;
    fasten::init(cfg);
    fasten::emit("USER_CREATED",
        fasten::target("u-1"),
        fasten::detail({
            {"tenant_id",     "acme"},
            {"shipped_at",    "2020-01-01T00:00:00.000000Z"},
            {"pii_in_detail", "true"},
            {"detail",        "inner"},
            {"expr",          "a}b"},
            {"other",         "ok"},
        }));
    assert(fasten::flush());
    std::lock_guard<std::mutex> lk(mu);
    assert(stored.size() == 1);
    return stored[0];
}

void check(const fasten::Row& r, const std::string& tenant) {
    assert(r.tenant_id == tenant);
    assert(r.shipped_at.empty());
    assert(!r.pii_in_detail);
    assert(r.target == "u-1");
    assert(r.detail.size() == 6);
    assert(r.detail.at("tenant_id") == "acme");
    assert(r.detail.at("shipped_at") == "2020-01-01T00:00:00.000000Z");
    assert(r.detail.at("detail") == "inner");
    assert(r.detail.at("expr") == "a}b");
    assert(r.detail.at("other") == "ok");
}

}  // namespace

int main() {
    check(emit_and_store("", "queue"), "");
    std::cout << "queue mode, no tenant: PASS\n";
    check(emit_and_store("t1", "queue"), "t1");
    std::cout << "queue mode, engine tenant: PASS\n";
    check(emit_and_store("", "raise"), "");
    std::cout << "raise mode, no tenant: PASS\n";
    return 0;
}
