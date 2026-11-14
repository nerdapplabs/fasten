// A sink that writes to a store local to main() is not called after the
// store is destroyed, at the end of its scope or at process exit.
#include "fasten.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <thread>

namespace {

std::atomic<int>  written{0};
std::atomic<int>  after_gone{0};
std::atomic<bool> store_gone{false};

struct LocalStore {
    ~LocalStore() { store_gone = true; }
    void insert(const fasten::Row&) {
        if (store_gone) ++after_gone;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        ++written;
    }
    fasten::AuditSink sink() {
        return [this](const fasten::Row& r) { insert(r); };
    }
};

// Registered before the engine exists, so it runs after the engine's
// static destructor.
void check_at_exit() {
    if (after_gone != 0) {
        std::fprintf(stderr, "sink called %d time(s) after the store was destroyed\n", after_gone.load());
        std::_Exit(1);
    }
}

}  // namespace

int main() {
    std::atexit(check_at_exit);

    fasten::Meta m;
    m.domain      = "user";
    m.category    = "account";
    m.action      = "create";
    m.severity    = fasten::Sev::Info;
    m.description = "x";
    m.emitter     = "t";
    fasten::register_codes("user", { {"USER_CREATED", m} });

    {
        LocalStore store;
        fasten::set_audit_sink(store.sink());
        fasten::init("svc", "node");
        fasten::ShutdownGuard guard;
        for (int i = 0; i < 20; ++i) {
            fasten::emit("USER_CREATED", fasten::target("u-" + std::to_string(i)));
        }
    }
    assert(written == 20);
    assert(after_gone == 0);

    // Emitting after shutdown has no sink and no drainer to reach.
    fasten::emit("USER_CREATED", fasten::target("u-late"));
    assert(written == 20);

    // shutdown() waits for an emit() on another thread that is already
    // running the sink (no drainer: the sink is set after init()).
    {
        std::atomic<bool> entered{false};
        std::atomic<bool> finished{false};
        fasten::init("svc", "node");
        fasten::set_audit_sink([&](const fasten::Row&) {
            entered = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            finished = true;
        });
        std::thread t([] { fasten::emit("USER_CREATED", fasten::target("u-thread")); });
        while (!entered) std::this_thread::yield();
        fasten::shutdown();
        assert(finished);
        t.join();
    }

    std::printf("shutdown_order_smoke: ok\n");
    return 0;
}
