/**
 * Minimal connector example: a Modbus TCP stub.
 *
 * Build (after building fasten-core):
 *   g++ -std=c++14 -I../include connector.cpp \
 *       -L../../fasten-core/target/release -lfasten_core -lpthread -o connector
 *
 * Run:
 *   FASTEN_SERVICE_ID=modbus-tcp FASTEN_NODE_ID=edge-01 ./connector
 */
#include "fasten.hpp"

#include <cstdio>

// Register codes once at startup.
void register_audit_codes() {
    fasten::register_codes("node", {
        {"CONNECTOR_CONNECTED",    {
            "CONNECTOR_CONNECTED",   "node", "connector", "connected",
            fasten::Sev::Info,  "Connector established connection", "modbus-tcp"}},
        {"CONNECTOR_DISCONNECTED", {
            "CONNECTOR_DISCONNECTED","node", "connector", "disconnected",
            fasten::Sev::Warn,  "Connector lost connection",         "modbus-tcp"}},
        {"CONNECTOR_ERROR",        {
            "CONNECTOR_ERROR",       "node", "connector", "error",
            fasten::Sev::Error, "Connector protocol error",          "modbus-tcp"}},
        {"CONNECTOR_DEVICE_ADDED", {
            "CONNECTOR_DEVICE_ADDED","node", "connector", "device_added",
            fasten::Sev::Info,  "New device or tag discovered",      "modbus-tcp"}},
    });
}

int main() {
    register_audit_codes();

    // Empty ids fall back to FASTEN_SERVICE_ID / FASTEN_NODE_ID.
    fasten::init("modbus-tcp", "edge-01");

    // Optional audit sink, e.g. fasten::SqliteStore::sink(). Set after
    // init(), so emit() calls it directly rather than through the queue.
    fasten::set_audit_sink([](const fasten::Row& row) {
        (void)row;
    });

    // One RequestScope per operation; emit() and log calls inside share its
    // request_id.
    {
        fasten::RequestScope scope; // new id, e.g. "a1b2c3d4e5f6"
        fasten::log::info("connector_starting",
            {{"protocol", "modbus-tcp"}, {"host", "192.168.1.10"}, {"port", "502"}});

        fasten::emit("CONNECTOR_CONNECTED",
            fasten::target("modbus://192.168.1.10:502"),
            fasten::method("mqtt"),
            fasten::detail({{"host", "192.168.1.10"}, {"port", "502"}, {"unit_id", "1"}}));

        fasten::log::info("poll_loop_started", {{"interval_ms", "1000"}});
    }

    // Error
    {
        fasten::RequestScope scope;
        fasten::emit("CONNECTOR_ERROR",
            fasten::target("modbus://192.168.1.10:502"),
            fasten::method("mqtt"),
            fasten::detail({{"error", "timeout"}, {"register", "40001"}}));
    }

    // Disconnect
    {
        fasten::RequestScope scope;
        fasten::emit("CONNECTOR_DISCONNECTED",
            fasten::target("modbus://192.168.1.10:502"),
            fasten::method("mqtt"),
            fasten::detail({{"reason", "timeout"}}));

        fasten::log::warn("connector_stopped", {{"reason", "timeout"}});
    }

    // Scheduled job, request id "scheduler-<hex>"
    {
        auto scope = fasten::scheduler::job_run();
        fasten::log::info("health_check_job",
            {{"status", "ok"}, {"latency_ms", "3"}});
    }

    // Print the registered codes.
    std::printf("\n-- fasten dump --\n%s\n", fasten::dump().c_str());

    return 0;
}
