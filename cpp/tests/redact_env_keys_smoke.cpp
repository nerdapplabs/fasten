// FASTEN_REDACT_KEYS env parity — an extra key pattern supplied via the
// environment (not just Config.extra_redact_keys) must be redacted, alongside
// the built-in patterns. Matches the Python/Go/Rust/JS SDKs.
//
// Build via CMake (-DFASTEN_BUILD_TESTS=ON) like the other *_smoke.cpp tests.

#include "fasten.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

int main() {
    setenv("FASTEN_REDACT_KEYS", "badge_no, employee_ref", 1);

    fasten_registry_clear();
    auto& g = fasten::detail_::globals();
    g.registry.clear();
    g.seq = 0;
    g.service_id = "";
    g.node_id = "";

    fasten::Meta m;
    m.domain          = "test";
    m.category        = "redact";
    m.action          = "emit";
    m.severity        = fasten::Sev::Info;
    m.description     = "env redact keys";
    m.emitter         = "t";
    m.retention_class = fasten::Retention::Short;
    fasten::register_codes("test", {{"ENV_KEYS", m}});
    fasten::init({"svc", "host"});

    fasten::Row row = fasten::emit("ENV_KEYS",
        fasten::target("k"),
        fasten::detail({
            {"badge_no",     "b"},   // env extra key
            {"employee_ref", "e"},   // env extra key
            {"password",     "p"},   // built-in pattern
            {"ok",           "v"},   // safe
        }));

    auto check = [&](const std::string& k, const std::string& want) {
        auto it = row.detail.find(k);
        if (it == row.detail.end() || it->second != want) {
            std::cerr << "FAIL: " << k << " = "
                      << (it == row.detail.end() ? std::string("<missing>") : it->second)
                      << " (want " << want << ")\n";
            std::exit(1);
        }
    };
    check("badge_no", "***");      // redacted via env extra key
    check("employee_ref", "***");  // redacted via env extra key
    check("password", "***");      // built-in still redacts
    check("ok", "v");              // safe key preserved

    std::cout << "ok redact env keys\n";
    return 0;
}
