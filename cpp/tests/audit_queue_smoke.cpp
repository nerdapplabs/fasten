// P1-15 smoke test for C++: audit-store failure handling.
//
// Same wire / semantic contract as Python / Go / JS / Rust:
//   - queue mode (default): emit() pushes onto a bounded queue;
//     drainer thread retries on sink exception with exponential
//     backoff; flush() blocks until drained.
//   - raise mode: emit() invokes sink synchronously and rethrows as
//     AuditStoreError on exception.
//   - capacity covers queued + in-flight retry combined.
//   - sys self-report on transitions (audit_drain_failed, _degraded,
//     _recovered, audit_queue_high_water, _near_full).
#include "fasten.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

void reset_state() {
    auto& eng = fasten::default_engine();
    eng.reset_for_tests();
    // Also clear the test-specific registry entries so each test
    // registers a fresh code. The registry is not touched by
    // reset_for_tests() — codes survive across tests by design.
    {
        std::lock_guard<std::mutex> lk(eng.reg_mu);
        for (auto it = eng.registry.begin(); it != eng.registry.end(); ) {
            if (it->first.rfind("USER_CREATED", 0) == 0) it = eng.registry.erase(it);
            else ++it;
        }
    }
}

void register_test_code() {
    fasten::Meta m;
    m.id              = "USER_CREATED";
    m.domain          = "user";
    m.category        = "account";
    m.action          = "create";
    m.severity        = fasten::Sev::Info;
    m.description     = "test";
    m.emitter         = "test";
    m.retention_class = fasten::Retention::Long;
    fasten::register_codes("user", {{"USER_CREATED", m}});
}

// ── #1 happy path ──────────────────────────────────────────────────────────

void test_queue_mode_drains_within_one_second() {
    reset_state();
    register_test_code();

    std::atomic<int> rows{0};
    fasten::set_audit_sink([&](const fasten::Row&) { rows.fetch_add(1); });

    fasten::Config cfg;
    cfg.service_id = "svc"; cfg.node_id = "node";
    fasten::init(cfg);

    fasten::emit("USER_CREATED", fasten::target("u-1"));
    fasten::emit("USER_CREATED", fasten::target("u-2"));
    bool ok = fasten::flush(std::chrono::seconds(1));
    assert(ok);
    assert(rows.load() == 2);
    fasten::uninstall_drainer();
    std::cout << "ok queue_mode_drains_within_one_second\n";
}

// ── #2 raise mode ──────────────────────────────────────────────────────────

void test_raise_mode_throws_audit_store_error() {
    reset_state();
    register_test_code();

    fasten::set_audit_sink([](const fasten::Row&) {
        throw std::runtime_error("store down");
    });

    fasten::Config cfg;
    cfg.service_id = "svc"; cfg.node_id = "node";
    cfg.audit_store_failure_strategy = "raise";
    fasten::init(cfg);

    bool caught = false;
    try {
        fasten::emit("USER_CREATED", fasten::target("u-1"));
    } catch (const fasten::AuditStoreError& e) {
        caught = true;
        std::string msg = e.what();
        assert(msg.find("store down") != std::string::npos);
    }
    assert(caught);
    std::cout << "ok raise_mode_throws_audit_store_error\n";
}

void test_raise_mode_does_not_install_drainer() {
    reset_state();
    register_test_code();
    fasten::set_audit_sink([](const fasten::Row&) {});

    fasten::Config cfg;
    cfg.service_id = "svc"; cfg.node_id = "node";
    cfg.audit_store_failure_strategy = "raise";
    fasten::init(cfg);

    auto stats = fasten::queue_stats();
    assert(stats == nullptr);
    std::cout << "ok raise_mode_does_not_install_drainer\n";
}

// ── #3 outage + recovery ───────────────────────────────────────────────────

void test_outage_then_recovery_drains_pending_rows() {
    reset_state();
    register_test_code();

    std::atomic<int> attempts{0};
    std::atomic<int> success{0};
    fasten::set_audit_sink([&](const fasten::Row&) {
        int n = attempts.fetch_add(1) + 1;
        if (n <= 2) throw std::runtime_error("transient");
        success.fetch_add(1);
    });

    fasten::Config cfg;
    cfg.service_id = "svc"; cfg.node_id = "node";
    cfg.queue_retry_initial_ms = 10;
    cfg.queue_retry_max_ms     = 50;
    cfg.disable_queue_jitter   = true;
    fasten::init(cfg);

    fasten::emit("USER_CREATED", fasten::target("u-1"));
    bool ok = fasten::flush(std::chrono::seconds(2));
    assert(ok);
    assert(success.load() == 1);
    assert(attempts.load() >= 3);
    fasten::uninstall_drainer();
    std::cout << "ok outage_then_recovery_drains_pending_rows\n";
}

// ── #6 queue_stats + flush ─────────────────────────────────────────────────

void test_queue_stats_fields() {
    reset_state();
    register_test_code();
    fasten::set_audit_sink([](const fasten::Row&) {});

    fasten::Config cfg;
    cfg.service_id = "svc"; cfg.node_id = "node";
    fasten::init(cfg);

    fasten::emit("USER_CREATED", fasten::target("u-1"));
    bool ok = fasten::flush(std::chrono::seconds(1));
    assert(ok);
    auto s = fasten::queue_stats();
    assert(s != nullptr);
    assert(s->depth == 0);
    assert(s->capacity == 100);
    assert(s->high_water >= 1);
    assert(s->drained_total == 1);
    assert(s->retry_count_active == 0);
    assert(s->last_error.empty());
    fasten::uninstall_drainer();
    std::cout << "ok queue_stats_fields\n";
}

void test_public_flush_no_op_in_raise_mode() {
    reset_state();
    register_test_code();
    fasten::set_audit_sink([](const fasten::Row&) {});

    fasten::Config cfg;
    cfg.service_id = "svc"; cfg.node_id = "node";
    cfg.audit_store_failure_strategy = "raise";
    fasten::init(cfg);

    fasten::emit("USER_CREATED", fasten::target("u-1"));
    bool ok = fasten::flush(std::chrono::milliseconds(100));
    assert(ok);
    std::cout << "ok public_flush_no_op_in_raise_mode\n";
}

void test_queue_stats_high_water_monotonic() {
    reset_state();
    register_test_code();
    fasten::set_audit_sink([](const fasten::Row&) {});

    fasten::Config cfg;
    cfg.service_id = "svc"; cfg.node_id = "node";
    cfg.queue_capacity = 10;
    fasten::init(cfg);

    for (int i = 0; i < 5; ++i) {
        fasten::emit("USER_CREATED", fasten::target("u"));
    }
    assert(fasten::flush(std::chrono::seconds(1)));
    auto high = fasten::queue_stats()->high_water;
    fasten::emit("USER_CREATED", fasten::target("u-x"));
    assert(fasten::flush(std::chrono::seconds(1)));
    assert(fasten::queue_stats()->high_water >= high);
    fasten::uninstall_drainer();
    std::cout << "ok queue_stats_high_water_monotonic\n";
}

// REVIEW #25: queue strategy with no drainer falls back to a sync
// sink invocation. That fallback used to swallow exceptions silently
// — the row would vanish with no signal. Now any sink throw surfaces
// `audit_sync_fallback_failed` on the sys ring (queryable via
// query_syslog) so adopters watching `/logs/sys` see it.
void test_sync_fallback_emits_sys_event_on_sink_failure() {
    reset_state();
    register_test_code();

    // Sink that always throws.
    fasten::set_audit_sink([](const fasten::Row&) {
        throw std::runtime_error("synthetic sink failure");
    });

    fasten::Config cfg;
    cfg.service_id = "svc"; cfg.node_id = "node";
    cfg.audit_store_failure_strategy = "queue";
    fasten::init(cfg);

    // Force the "queue strategy but no drainer" branch by uninstalling
    // the drainer immediately. emit() then takes the sync-fallback path.
    fasten::uninstall_drainer();

    fasten::emit("USER_CREATED", fasten::target("u"));

    auto syslog = fasten::query_syslog(/*limit=*/100);
    bool found = false;
    for (const auto& row : syslog) {
        auto event_it = row.find("event");
        if (event_it != row.end() &&
            event_it->second == "audit_sync_fallback_failed") {
            found = true;
            break;
        }
    }
    assert(found);
    std::cout << "ok sync_fallback_emits_sys_event_on_sink_failure\n";
}

// REVIEW #11: high-water sys events used to be decided across two
// mutexes (slot_mu_ then stats_mu_). Concurrent puts/releases in the
// gap caused duplicate or missed warns. The fix combines the read +
// flag flip in a single critical section using a parallel used_count_
// counter. This test hammers the put path from many threads with a
// slow sink; we read the syslog ring afterwards and assert the
// high-water + near-full events fire AT MOST once per crossing.
void test_high_water_no_double_fire_under_contention() {
    reset_state();
    register_test_code();

    fasten::set_audit_sink([](const fasten::Row&) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    });

    fasten::Config cfg;
    cfg.service_id = "svc"; cfg.node_id = "node";
    cfg.queue_capacity = 10;        // 50% = 5, 80% = 8
    fasten::init(cfg);

    // 8 emits from 8 threads — well past the 80% threshold.
    std::vector<std::thread> ts;
    ts.reserve(8);
    for (int i = 0; i < 8; ++i) {
        ts.emplace_back([] {
            fasten::emit("USER_CREATED", fasten::target("u"));
        });
    }
    for (auto& t : ts) t.join();
    assert(fasten::flush(std::chrono::seconds(5)));

    auto syslog = fasten::query_syslog(/*limit=*/100);
    int warn_count = 0, err_count = 0;
    for (const auto& row : syslog) {
        auto event_it = row.find("event");
        if (event_it == row.end()) continue;
        const auto& event = event_it->second;
        if (event == "audit_queue_high_water") ++warn_count;
        if (event == "audit_queue_near_full")  ++err_count;
    }
    // Each threshold crossing fires AT MOST once (debounced). Earlier
    // race could produce duplicates under concurrent put pressure.
    assert(warn_count <= 1);
    assert(err_count  <= 1);
    fasten::uninstall_drainer();
    std::cout << "ok high_water_no_double_fire_under_contention "
              << "(warn=" << warn_count << " err=" << err_count << ")\n";
}

}  // namespace

int main() {
    test_queue_mode_drains_within_one_second();
    test_raise_mode_throws_audit_store_error();
    test_raise_mode_does_not_install_drainer();
    test_outage_then_recovery_drains_pending_rows();
    test_queue_stats_fields();
    test_public_flush_no_op_in_raise_mode();
    test_queue_stats_high_water_monotonic();
    test_high_water_no_double_fire_under_contention();
    test_sync_fallback_emits_sys_event_on_sink_failure();
    std::cout << "\nALL P1-15 C++ TESTS PASSED\n";
    return 0;
}
