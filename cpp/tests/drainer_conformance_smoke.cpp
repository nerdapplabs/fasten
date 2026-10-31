// Drainer conformance vectors V-1 to V-12 (spec/drainer-conformance.md §7),
// plus re-init under load (#138).
//
// The core drainer writes its sys events to stderr, so the vectors that check
// them capture file descriptor 2.
#include "fasten.hpp"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

namespace {

using std::chrono::milliseconds;

void reset_state() {
    fasten::detail_::globals().reset_for_tests();
    fasten_registry_clear();
    fasten::detail_::globals().registry.clear();
    fasten::Meta m;
    m.domain = "user"; m.category = "account"; m.action = "create";
    m.severity = fasten::Sev::Info; m.description = "x"; m.emitter = "t";
    fasten::register_codes("user", { {"USER_CREATED", m} });
}

fasten::Config cfg(const std::string& strategy) {
    fasten::Config c{"svc", "node", ""};
    c.audit_store_failure_strategy = strategy;
    return c;
}

void emit_one(const std::string& target = "u-1") {
    fasten::emit("USER_CREATED", fasten::target(target));
}

// Captures what is written to file descriptor 2 between start() and stop().
struct Stderr {
    int saved = -1;
    std::FILE* f = nullptr;
    void start() {
        std::cerr.flush(); std::fflush(stderr);
        f = std::tmpfile();
        saved = dup(2);
        dup2(fileno(f), 2);
    }
    std::string stop() {
        std::cerr.flush(); std::fflush(stderr);
        dup2(saved, 2); close(saved);
        std::string out;
        std::rewind(f);
        char buf[4096];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
        std::fclose(f);
        return out;
    }
};

size_t count(const std::string& text, const std::string& event) {
    const std::string needle = "\"event\":\"" + event + "\"";
    size_t n = 0;
    for (size_t p = text.find(needle); p != std::string::npos; p = text.find(needle, p + 1)) ++n;
    return n;
}

bool syslog_has(const std::string& event) {
    for (auto& r : fasten::query_syslog(1000)) {
        auto it = r.find("event");
        if (it != r.end() && it->second == event) return true;
    }
    return false;
}

void v1_happy_path() {
    reset_state();
    std::atomic<int> n{0};
    fasten::set_audit_sink([&](const fasten::Row&) { ++n; });
    fasten::init(cfg("queue"));
    emit_one("u-1"); emit_one("u-2");
    assert(fasten::flush(milliseconds(1000)));
    assert(n == 2);
    std::cout << "V-1: PASS\n";
}

void v2_raise_throws() {
    reset_state();
    fasten::set_audit_sink([](const fasten::Row&) { throw std::runtime_error("store down"); });
    fasten::init(cfg("raise"));
    bool caught = false;
    try { emit_one(); } catch (const fasten::AuditStoreError& e) {
        caught = std::string(e.what()).find("store down") != std::string::npos;
    }
    assert(caught);
    std::cout << "V-2: PASS\n";
}

void v3_raise_no_drainer() {
    reset_state();
    fasten::set_audit_sink([](const fasten::Row&) {});
    fasten::init(cfg("raise"));
    assert(fasten::queue_stats() == nullptr);
    std::cout << "V-3: PASS\n";
}

void v4_outage_then_recovery() {
    reset_state();
    std::atomic<int> attempts{0}, ok{0};
    fasten::set_audit_sink([&](const fasten::Row&) {
        if (++attempts <= 2) throw std::runtime_error("transient");
        ++ok;
    });
    auto c = cfg("queue");
    c.queue_retry_initial_ms = 10; c.queue_retry_max_ms = 50; c.disable_queue_jitter = true;
    Stderr err; err.start();
    fasten::init(c);
    emit_one();
    bool drained = fasten::flush(milliseconds(2000));
    err.stop();
    assert(drained);
    assert(ok == 1);
    assert(attempts >= 3);
    std::cout << "V-4: PASS\n";
}

void v5_stats_after_drain() {
    reset_state();
    fasten::set_audit_sink([](const fasten::Row&) {});
    fasten::init(cfg("queue"));
    emit_one();
    assert(fasten::flush(milliseconds(1000)));
    auto s = fasten::queue_stats();
    assert(s);
    assert(s->depth == 0);
    assert(s->capacity == 100);
    assert(s->high_water >= 1);
    assert(s->drained_total == 1);
    assert(s->retry_count_active == 0);
    assert(s->last_error.empty());
    std::cout << "V-5: PASS\n";
}

void v6_flush_noop_in_raise() {
    reset_state();
    fasten::set_audit_sink([](const fasten::Row&) {});
    fasten::init(cfg("raise"));
    emit_one();
    assert(fasten::flush(milliseconds(100)));
    std::cout << "V-6: PASS\n";
}

void v7_high_water_monotonic() {
    reset_state();
    fasten::set_audit_sink([](const fasten::Row&) {});
    auto c = cfg("queue");
    c.queue_capacity = 10;
    fasten::init(c);
    for (int i = 0; i < 5; ++i) emit_one();
    assert(fasten::flush(milliseconds(1000)));
    auto hw1 = fasten::queue_stats()->high_water;
    emit_one();
    assert(fasten::flush(milliseconds(1000)));
    assert(fasten::queue_stats()->high_water >= hw1);
    std::cout << "V-7: PASS\n";
}

void v8_threshold_debounce() {
    reset_state();
    fasten::set_audit_sink([](const fasten::Row&) {
        std::this_thread::sleep_for(milliseconds(20));
    });
    auto c = cfg("queue");
    c.queue_capacity = 10;
    Stderr err; err.start();
    fasten::init(c);
    std::vector<std::thread> ts;
    for (int i = 0; i < 8; ++i) ts.emplace_back([] { emit_one(); });
    for (auto& t : ts) t.join();
    fasten::flush(milliseconds(5000));
    auto out = err.stop();
    assert(count(out, "audit_queue_high_water") <= 1);
    assert(count(out, "audit_queue_near_full") <= 1);
    std::cout << "V-8: PASS\n";
}

void v9_sync_fallback_logs_failure() {
    reset_state();
    fasten::set_audit_sink([](const fasten::Row&) { throw std::runtime_error("down"); });
    fasten::init(cfg("queue"));
    fasten::uninstall_drainer();
    Stderr err; err.start();
    emit_one();
    err.stop();
    assert(syslog_has("audit_sync_fallback_failed"));
    std::cout << "V-9: PASS\n";
}

void v10_dead_letter() {
    reset_state();
    fasten::set_audit_sink([](const fasten::Row&) { throw std::runtime_error("down"); });
    auto c = cfg("queue");
    c.queue_drain_max_attempts = 3;
    c.queue_retry_initial_ms = 1; c.queue_retry_max_ms = 5; c.disable_queue_jitter = true;
    Stderr err; err.start();
    fasten::init(c);
    emit_one();
    fasten::flush(milliseconds(2000));
    auto s = fasten::queue_stats();
    auto out = err.stop();
    assert(s->dead_lettered_total == 1);
    assert(s->depth == 0);
    assert(count(out, "audit_drain_dead_letter") == 1);
    std::cout << "V-10: PASS\n";
}

void v11_events_in_order() {
    reset_state();
    std::atomic<int> attempts{0};
    fasten::set_audit_sink([&](const fasten::Row&) {
        if (++attempts <= 5) throw std::runtime_error("transient");
    });
    auto c = cfg("queue");
    c.queue_retry_initial_ms = 10; c.queue_retry_max_ms = 20; c.disable_queue_jitter = true;
    Stderr err; err.start();
    fasten::init(c);
    emit_one();
    fasten::flush(milliseconds(5000));
    auto out = err.stop();
    assert(count(out, "audit_drain_failed") == 1);
    assert(count(out, "audit_drain_degraded") == 1);
    assert(count(out, "audit_drain_recovered") == 1);
    auto f = out.find("audit_drain_failed");
    auto d = out.find("audit_drain_degraded");
    auto r = out.find("audit_drain_recovered");
    assert(f < d && d < r);
    std::cout << "V-11: PASS\n";
}

// A put() on a drainer that has been shut down (an emit that took it before a
// re-init swapped it out) is reported, not dropped.
void v12_abandoned_after_stop() {
    reset_state();
    fasten::init(cfg("raise"));
    fasten::detail_::CFastenDrainer d([](const fasten::Row&) {}, 10,
        milliseconds(10), milliseconds(50), false);
    d.shutdown(milliseconds(1000));
    fasten::Row row;
    row.id = "evt-abandoned";
    Stderr err; err.start();
    assert(!d.put(row));
    err.stop();
    bool found = false;
    for (auto& r : fasten::query_syslog(100)) {
        if (r["event"] == "audit_drain_abandoned" && r["row_id"] == "evt-abandoned") found = true;
    }
    assert(found);
    std::cout << "V-12: PASS\n";
}

// An emit that still holds a drainer a re-init has stopped stores its row
// synchronously, and the refusal is reported once.
void refused_row_is_stored_synchronously() {
    reset_state();
    std::vector<std::string> stored;
    fasten::set_audit_sink([&](const fasten::Row& r) { stored.push_back(r.target); });
    fasten::init(cfg("queue"));
    {
        auto& g = fasten::detail_::globals();
        std::lock_guard<std::mutex> lk(g.drainer_mu);
        g.drainer->shutdown(milliseconds(1000));
    }
    Stderr err; err.start();
    emit_one("u-refused");
    std::string out = err.stop();
    assert(stored.size() == 1 && stored[0] == "u-refused");
    assert(count(out, "audit_drain_abandoned") == 1);
    std::cout << "refused row stored synchronously: PASS\n";
}

// Runs fn on a thread and fails the test if it takes longer than limit.
template <typename Fn>
void within(milliseconds limit, Fn fn) {
    std::atomic<bool> done{false};
    std::thread t([&] { fn(); done = true; });
    auto deadline = std::chrono::steady_clock::now() + limit;
    while (!done && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(milliseconds(10));
    }
    assert(done && "timed out");
    t.join();
}

// A put() blocked on a full queue during a store outage must not hold
// shutdown() up: the core's close wakes it.
void shutdown_with_a_put_blocked_on_a_full_queue() {
    reset_state();
    fasten::init(cfg("raise"));
    fasten::detail_::CFastenDrainer d([](const fasten::Row&) {
        throw std::runtime_error("down");
    }, 1, milliseconds(10), milliseconds(50), false);
    fasten::Row a; a.id = "evt-a";
    fasten::Row b; b.id = "evt-b";
    Stderr err; err.start();
    d.put(a);
    std::thread blocked([&] { d.put(b); });
    std::this_thread::sleep_for(milliseconds(100));
    within(milliseconds(3000), [&] { d.shutdown(milliseconds(1000)); });
    blocked.join();
    err.stop();
    std::cout << "shutdown with a blocked put: PASS\n";
}

// A sink that puts a follow-up row while shutdown() drains the queue must not
// deadlock it; that put is reported as abandoned.
void shutdown_with_a_sink_that_puts() {
    reset_state();
    fasten::init(cfg("raise"));
    fasten::detail_::CFastenDrainer* self = nullptr;
    fasten::detail_::CFastenDrainer d([&](const fasten::Row& r) {
        if (r.id == "evt-first") {
            std::this_thread::sleep_for(milliseconds(100));
            fasten::Row next; next.id = "evt-follow-up";
            self->put(next);
        }
    }, 10, milliseconds(10), milliseconds(50), false);
    self = &d;
    fasten::Row first; first.id = "evt-first";
    Stderr err; err.start();
    d.put(first);
    std::this_thread::sleep_for(milliseconds(20));
    within(milliseconds(3000), [&] { d.shutdown(milliseconds(1000)); });
    err.stop();
    std::cout << "shutdown with a re-entrant sink: PASS\n";
}

// Re-init swaps and shuts down the drainer while other threads emit and log.
// Before the fix a put() could pass the stopped check and then use the freed
// store, and a sys line could copy a boot request id init() was freeing.
void reinit_under_load() {
    reset_state();
    std::atomic<int> stored{0};
    fasten::set_audit_sink([&](const fasten::Row&) { ++stored; });
    fasten::init(cfg("queue"));
    std::atomic<bool> stop{false};
    std::vector<std::thread> ts;
    for (int i = 0; i < 4; ++i) {
        ts.emplace_back([&] { while (!stop) emit_one(); });
    }
    // Sys lines read the ids and the boot request id that init() replaces.
    ts.emplace_back([&] { while (!stop) fasten::log::info("tick"); });
    Stderr err; err.start();
    for (int i = 0; i < 30; ++i) fasten::init(cfg("queue"));
    stop = true;
    for (auto& t : ts) t.join();
    fasten::flush(milliseconds(5000));
    err.stop();
    assert(stored > 0);
    std::cout << "re-init under load: PASS\n";
}

}  // namespace

int main() {
    v1_happy_path();
    v2_raise_throws();
    v3_raise_no_drainer();
    v4_outage_then_recovery();
    v5_stats_after_drain();
    v6_flush_noop_in_raise();
    v7_high_water_monotonic();
    v8_threshold_debounce();
    v9_sync_fallback_logs_failure();
    v10_dead_letter();
    v11_events_in_order();
    v12_abandoned_after_stop();
    refused_row_is_stored_synchronously();
    shutdown_with_a_put_blocked_on_a_full_queue();
    shutdown_with_a_sink_that_puts();
    reinit_under_load();
    return 0;
}
