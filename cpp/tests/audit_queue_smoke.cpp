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
    fasten::uninstall_drainer();
    auto& g = fasten::detail_::globals();
    {
        std::lock_guard<std::mutex> lk(g.reg_mu);
        for (auto it = g.registry.begin(); it != g.registry.end(); ) {
            const auto& k = it->first;
            if (k.rfind("USER_CREATED", 0) == 0) it = g.registry.erase(it);
            else ++it;
        }
    }
    {
        std::lock_guard<std::mutex> lk(g.sink_mu);
        g.audit_sink = nullptr;
    }
    g.service_id.clear();
    g.node_id.clear();
    g.tenant_id.clear();
    g.seq = 0;
    g.failure_strategy = "queue";
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

}  // namespace

int main() {
    test_queue_mode_drains_within_one_second();
    test_raise_mode_throws_audit_store_error();
    test_raise_mode_does_not_install_drainer();
    test_outage_then_recovery_drains_pending_rows();
    test_queue_stats_fields();
    test_public_flush_no_op_in_raise_mode();
    test_queue_stats_high_water_monotonic();
    std::cout << "\nALL P1-15 C++ TESTS PASSED\n";
    return 0;
}
