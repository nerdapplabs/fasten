// P1-12 — Boost.Log → fasten syslog shim integration test.
//
// Requires Boost.Log headers (boost >= 1.54). Guarded in CMakeLists.txt
// via find_package(Boost COMPONENTS log) — skipped when Boost is absent.
//
// Tests:
//   1. consume() pushes a row with correct level and event fields
//   2. Level mapping (trivial severity → fasten level strings)
//   3. Recursion guard (no infinite re-entry)

#include "fasten.hpp"
#include "fasten/shim/boost_log.hpp"

#include <boost/log/record_view.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/core.hpp>
#include <cassert>
#include <iostream>

namespace {

void reset() {
    auto& g = fasten::detail_::globals();
    g.registry.clear();
    g.seq        = 0;
    g.service_id = "";
    g.node_id    = "";
    g.syslog_ring.clear();
}

// Build a trivial Boost.Log record and open a record_view from it.
// We drive the fasten backend via core::open_record + record_view.
void fire_via_core(boost::log::trivial::severity_level sev,
                   const std::string& msg)
{
    namespace bl = boost::log;
    auto core = bl::core::get();
    bl::attribute_set attrs;
    attrs.insert(bl::attribute_name("Severity"),
                 bl::attributes::make_constant(sev));
    auto rec = core->open_record(attrs);
    if (rec) {
        fasten::shim::boost_log::fasten_backend backend;
        backend.consume(rec.lock(), msg);
    }
}

void test_ring_receives_row() {
    reset();
    fasten::init({"svc", "node"});
    boost::log::add_common_attributes();

    fasten::shim::boost_log::fasten_backend backend;
    // Build a record_view with INFO severity.
    namespace bl = boost::log;
    auto core = bl::core::get();
    bl::attribute_set attrs;
    attrs.insert(bl::attribute_name("Severity"),
                 bl::attributes::make_constant(bl::trivial::info));
    auto rec = core->open_record(attrs);
    if (!rec) {
        std::cerr << "SKIP: Boost.Log core not accepting records\n";
        return;
    }
    backend.consume(rec.lock(), "session_started");
    auto rows = fasten::detail_::globals().syslog_ring.query(1);
    assert(rows.size() == 1);
    assert(rows[0]["event"] == "session_started");
    assert(rows[0]["level"] == "info");
    std::cout << "ok test_ring_receives_row\n";
}

void test_level_mapping() {
    reset();
    fasten::init({"svc", "node"});
    namespace bl  = boost::log;
    namespace blt = bl::trivial;
    fasten::shim::boost_log::fasten_backend backend;
    auto core = bl::core::get();
    struct Case { blt::severity_level in; std::string want; };
    for (auto& c : std::vector<Case>{
            {blt::debug,   "debug"},
            {blt::info,    "info"},
            {blt::warning, "warn"},
            {blt::error,   "error"},
            {blt::fatal,   "error"},
    }) {
        reset(); fasten::init({"svc", "node"});
        bl::attribute_set attrs;
        attrs.insert(bl::attribute_name("Severity"),
                     bl::attributes::make_constant(c.in));
        auto rec = core->open_record(attrs);
        if (!rec) continue;
        backend.consume(rec.lock(), "msg");
        auto rows = fasten::detail_::globals().syslog_ring.query(1);
        assert(rows.size() == 1 && rows[0]["level"] == c.want);
    }
    std::cout << "ok test_level_mapping\n";
}

void test_recursion_guard() {
    reset();
    fasten::init({"svc", "node"});
    fasten::shim::boost_log::detail_::sink_active = true;
    namespace bl = boost::log;
    auto core = bl::core::get();
    bl::attribute_set attrs;
    attrs.insert(bl::attribute_name("Severity"),
                 bl::attributes::make_constant(bl::trivial::info));
    auto rec = core->open_record(attrs);
    if (rec) {
        fasten::shim::boost_log::fasten_backend backend;
        backend.consume(rec.lock(), "should-not-land");
    }
    fasten::shim::boost_log::detail_::sink_active = false;
    assert(fasten::detail_::globals().syslog_ring.size() == 0);
    std::cout << "ok test_recursion_guard\n";
}

} // namespace

int main() {
    test_ring_receives_row();
    test_level_mapping();
    test_recursion_guard();
    std::cout << "\nALL P1-12 boost_log SHIM TESTS PASSED\n";
    return 0;
}
