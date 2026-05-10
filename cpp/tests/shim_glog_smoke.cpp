// P1-12 — glog → fasten syslog shim integration test.
//
// Compiled against the stub headers in tests/shim_stubs/ so no real glog
// install is required. Tests:
//   1. install() populates the ring when send() is called
//   2. Level mapping (INFO/WARNING/ERROR/FATAL → fasten level strings)
//   3. Recursion guard (no infinite re-entry)
//   4. install() is idempotent (second call returns same pointer)

#include "fasten.hpp"
#include "fasten/shim/glog.hpp"

#include <cassert>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>

namespace {

void reset() {
    auto& g = fasten::detail_::globals();
    g.registry.clear();
    g.seq        = 0;
    g.service_id = "";
    g.node_id    = "";
    g.syslog_ring.clear();
}

// Helper: call send() directly on an installed FastenLogSink.
void fire(fasten::shim::glog::FastenLogSink& s,
          google::LogSeverity sev,
          const std::string& msg)
{
    std::tm t{};
    s.send(sev, "file.cpp", "file.cpp", 1, &t, msg.c_str(), msg.size());
}

void test_ring_receives_row() {
    reset();
    fasten::init({"svc", "node"});
    fasten::shim::glog::FastenLogSink sink;
    fire(sink, google::GLOG_INFO, "user_connected");
    auto rows = fasten::detail_::globals().syslog_ring.query(1);
    assert(rows.size() == 1);
    assert(rows[0]["event"] == "user_connected");
    assert(rows[0]["level"] == "info");
    std::cout << "ok test_ring_receives_row\n";
}

void test_level_mapping() {
    reset();
    fasten::init({"svc", "node"});
    fasten::shim::glog::FastenLogSink sink;
    struct Case { google::LogSeverity in; std::string want; };
    for (auto& c : std::vector<Case>{
            {google::GLOG_INFO,    "info"},
            {google::GLOG_WARNING, "warn"},
            {google::GLOG_ERROR,   "error"},
            {google::GLOG_FATAL,   "error"},
    }) {
        reset(); fasten::init({"svc", "node"});
        fire(sink, c.in, "msg");
        auto rows = fasten::detail_::globals().syslog_ring.query(1);
        assert(rows.size() == 1 && rows[0]["level"] == c.want);
    }
    std::cout << "ok test_level_mapping\n";
}

void test_recursion_guard() {
    reset();
    fasten::init({"svc", "node"});
    fasten::shim::glog::detail_::sink_active = true;
    fasten::shim::glog::FastenLogSink sink;
    fire(sink, google::GLOG_INFO, "should-not-land");
    fasten::shim::glog::detail_::sink_active = false;
    assert(fasten::detail_::globals().syslog_ring.size() == 0);
    std::cout << "ok test_recursion_guard\n";
}

void test_install_idempotent() {
    reset();
    fasten::init({"svc", "node"});
    auto* a = fasten::shim::glog::install();
    auto* b = fasten::shim::glog::install();
    assert(a == b);
    std::cout << "ok test_install_idempotent\n";
}

} // namespace

int main() {
    test_ring_receives_row();
    test_level_mapping();
    test_recursion_guard();
    test_install_idempotent();
    std::cout << "\nALL P1-12 glog SHIM TESTS PASSED\n";
    return 0;
}
