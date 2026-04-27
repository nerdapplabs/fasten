/**
 * Minimal connector example — Modbus TCP stub.
 *
 * Build (C++14):
 *   g++ -std=c++14 -I../include connector.cpp -o connector
 *
 * Run:
 *   RIVET_SERVICE_ID=modbus-tcp RIVET_NODE_ID=edge-01 ./connector
 */
#include "rivet.hpp"

// Register codes once at startup — same string constants as Python/Go/Node.
void register_audit_codes() {
    rivet::register_codes("node", {
        {"CONNECTOR_CONNECTED",     {"node", "connector", "connected",
                                     rivet::Sev::Info,  "Connector established connection", "modbus-tcp"}},
        {"CONNECTOR_DISCONNECTED",  {"node", "connector", "disconnected",
                                     rivet::Sev::Warn,  "Connector lost connection", "modbus-tcp"}},
        {"CONNECTOR_ERROR",         {"node", "connector", "error",
                                     rivet::Sev::Error, "Connector protocol error", "modbus-tcp"}},
        {"CONNECTOR_DEVICE_ADDED",  {"node", "connector", "device_added",
                                     rivet::Sev::Info,  "New device or tag added", "modbus-tcp"}},
    });
}

int main() {
    register_audit_codes();
    rivet::init({"modbus-tcp", "edge-01"});  // tenant_id optional; or leave empty to read from env

    rivet::log::info("connector_starting", {{"protocol", "modbus-tcp"}, {"port", "502"}});

    // Simulate connection
    rivet::emit("CONNECTOR_CONNECTED",
        rivet::target("modbus://192.168.1.10:502"),
        rivet::detail({{"host", "192.168.1.10"}, {"port", "502"}, {"unit_id", "1"}}));

    rivet::log::info("poll_loop_started", {{"interval_ms", "1000"}});

    // Simulate an error
    rivet::emit("CONNECTOR_ERROR",
        rivet::target("modbus://192.168.1.10:502"),
        rivet::detail({{"error", "timeout"}, {"register", "40001"}}));

    // Simulate disconnect
    rivet::emit("CONNECTOR_DISCONNECTED",
        rivet::target("modbus://192.168.1.10:502"),
        rivet::detail({{"reason", "timeout"}}));

    rivet::log::warn("connector_stopped", {{"reason", "timeout"}});
    return 0;
}
