/**
 * Minimal connector example — Modbus TCP stub.
 *
 * Build (C++14):
 *   g++ -std=c++14 -I../include connector.cpp -o connector
 *
 * Build (C++17, recommended):
 *   g++ -std=c++17 -I../include connector.cpp -o connector
 *
 * Run:
 *   FASTEN_SERVICE_ID=modbus-tcp FASTEN_NODE_ID=edge-01 ./connector
 */
#include "fasten.hpp"

#include <cstdio>

// Register codes once at startup — same string constants as Python/Go/JS.
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

    // Init from env (FASTEN_SERVICE_ID, FASTEN_NODE_ID) or explicit config.
    fasten::init({"modbus-tcp", "edge-01", ""});

    // Optional: register a persistent audit sink.
    // Replace with real SQLite/Postgres writes in production.
    fasten::set_audit_sink([](const fasten::Row& row) {
        // e.g. write row.to_json() to a SQLite DB here.
        (void)row;
    });

    // ── Connection attempt ──────────────────────────────────────────────────

    // Each logical operation gets its own RequestScope.
    // All emit/log calls inside inherit the scoped request_id.
    {
        fasten::RequestScope scope; // mints e.g. "a1b2c3d4e5f6"
        fasten::log::info("connector_starting",
            {{"protocol", "modbus-tcp"}, {"host", "192.168.1.10"}, {"port", "502"}});

        fasten::emit("CONNECTOR_CONNECTED",
            fasten::target("modbus://192.168.1.10:502"),
            fasten::method("mqtt"),
            fasten::detail({{"host", "192.168.1.10"}, {"port", "502"}, {"unit_id", "1"}}));

        fasten::log::info("poll_loop_started", {{"interval_ms", "1000"}});
    }

    // ── Error scenario ──────────────────────────────────────────────────────

    {
        fasten::RequestScope scope;
        fasten::emit("CONNECTOR_ERROR",
            fasten::target("modbus://192.168.1.10:502"),
            fasten::method("mqtt"),
            fasten::detail({{"error", "timeout"}, {"register", "40001"}}));
    }

    // ── Disconnect ──────────────────────────────────────────────────────────

    {
        fasten::RequestScope scope;
        fasten::emit("CONNECTOR_DISCONNECTED",
            fasten::target("modbus://192.168.1.10:502"),
            fasten::method("mqtt"),
            fasten::detail({{"reason", "timeout"}}));

        fasten::log::warn("connector_stopped", {{"reason", "timeout"}});
    }

    // ── Scheduled job with scheduler shim ──────────────────────────────────

    {
        // Mints "scheduler-<hex>" id automatically.
        auto scope = fasten::scheduler::job_run();
        fasten::log::info("health_check_job",
            {{"status", "ok"}, {"latency_ms", "3"}});
    }

    // ── Print dump for cross-language consistency gate ──────────────────────

    std::printf("\n-- fasten dump --\n%s\n", fasten::dump().c_str());

    return 0;
}
