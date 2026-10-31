// Row and sys-row fields (#138 point 3): sentinel request_ids, tenant_id on
// sys rows, canonical timestamps, seq left to the store, and JSON escapes.
#include "fasten.hpp"

#include <cassert>
#include <iostream>
#include <regex>
#include <string>

namespace {

void reset_state(const std::string& tenant = "") {
    fasten::detail_::globals().reset_for_tests();
    fasten_registry_clear();
    fasten::detail_::globals().registry.clear();
    fasten::Meta m;
    m.domain = "user"; m.category = "account"; m.action = "create";
    m.severity = fasten::Sev::Info; m.description = "x"; m.emitter = "t";
    fasten::register_codes("user", { {"USER_CREATED", m} });
    fasten::Config c{"svc", "node", tenant};
    c.audit_store_failure_strategy = "raise";
    fasten::init(c);
}

std::string last_sys_request_id() {
    return fasten::query_syslog(1)[0]["request_id"];
}

bool starts_with(const std::string& s, const std::string& p) {
    return s.compare(0, p.size(), p) == 0;
}

void sys_rows_get_boot_then_orphan_sentinels() {
    reset_state();
    fasten::log::info("starting");
    const auto boot = last_sys_request_id();
    assert(starts_with(boot, "boot-svc-"));
    fasten::log::info("still starting");
    assert(last_sys_request_id() == boot);
    {
        fasten::RequestScope scope("req-real-1");
        fasten::log::info("handling");
        assert(last_sys_request_id() == "req-real-1");
    }
    fasten::log::info("after the first request");
    const auto orphan = last_sys_request_id();
    assert(starts_with(orphan, "orphan-svc-"));
    fasten::log::info("again");
    assert(last_sys_request_id() != orphan);
    std::cout << "sentinels: PASS\n";
}

void sys_rows_carry_the_engine_tenant() {
    reset_state("tenant-a");
    fasten::log::info("x");
    assert(fasten::query_syslog(1)[0]["tenant_id"] == "tenant-a");
    std::cout << "tenant on sys rows: PASS\n";
}

void scheduler_mints_sched_ids() {
    reset_state();
    auto scope = fasten::scheduler::job_run();
    assert(starts_with(scope.id(), "sched-"));
    std::cout << "sched- prefix: PASS\n";
}

void emit_leaves_seq_to_the_store_and_stamps_canonical_time() {
    reset_state();
    fasten::Row stored;
    fasten::set_audit_sink([&](const fasten::Row& r) { stored = r; });
    auto row = fasten::emit("USER_CREATED", fasten::target("u-1"));
    assert(row.monotonic_seq == 0);
    static const std::regex canonical(R"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z)");
    assert(std::regex_match(row.timestamp, canonical));
    fasten::log::info("x");
    assert(std::regex_match(fasten::detail_::now_iso8601(), canonical));
    std::cout << "seq 0 + canonical timestamp: PASS\n";
}

void json_escapes_decode() {
    auto f = fasten::detail_::parse_flat_json_fields(
        R"({"a":"café","b":"😀","c":"x\/y\b\f","kA":"v"})");
    assert(f["a"] == "caf\xc3\xa9");
    assert(f["b"] == "\xf0\x9f\x98\x80");
    assert(f["c"] == "x/y\b\f");
    assert(f["kA"] == "v");
    auto r = fasten::detail_::row_from_json_(
        R"({"id":"evt-1","target":"\u0001x","detail":{}})");
    assert(r.target == std::string("\x01x"));
    std::cout << "JSON escapes: PASS\n";
}

}  // namespace

int main() {
    sys_rows_get_boot_then_orphan_sentinels();
    sys_rows_carry_the_engine_tenant();
    scheduler_mints_sched_ids();
    emit_leaves_seq_to_the_store_and_stamps_canonical_time();
    json_escapes_decode();
    return 0;
}
