// Default redact patterns match anywhere in the key, so "customer_token"
// is redacted as well as "token".

#include "fasten.hpp"

#include <cassert>
#include <iostream>
#include <string>

namespace {

void reset_state() {
    fasten_registry_clear();
    auto& g = fasten::detail_::globals();
    g.registry.clear();
    g.seq = 0;
    g.service_id = "";
    g.node_id = "";
}

void register_one() {
    fasten::Meta m;
    m.domain          = "test";
    m.category        = "redact";
    m.action          = "emit";
    m.severity        = fasten::Sev::Info;
    m.description     = "redact substring case";
    m.emitter         = "redact-test";
    m.retention_class = fasten::Retention::Short;
    fasten::register_codes("test", {{"REDACT_SUBSTRING", m}});
}

void test_substring_match_redacts() {
    reset_state();
    register_one();
    fasten::init({"redact-test", "host-01"});

    fasten::Row row = fasten::emit("REDACT_SUBSTRING",
        fasten::target("k-1"),
        fasten::detail({
            // exact matches:
            {"api_key",    "should-redact"},
            {"password",   "should-redact"},
            // pattern inside a longer key:
            {"customer_token",     "tok-abc"},
            {"user_password",      "pw-xyz"},
            {"oauth_bearer_token", "tok-deep"},
            // not a secret, kept as is:
            {"email",      "alice@example.com"},
        }));

    auto must_redact = [&](const std::string& k) {
        auto it = row.detail.find(k);
        if (it == row.detail.end()) {
            std::cerr << "MISSING key: " << k << "\n";
            std::exit(1);
        }
        if (it->second != "***") {
            std::cerr << "FAIL: " << k << " = " << it->second
                      << " (expected ***)\n";
            std::exit(1);
        }
    };
    auto must_keep = [&](const std::string& k, const std::string& want) {
        auto it = row.detail.find(k);
        if (it == row.detail.end() || it->second != want) {
            std::cerr << "FAIL: " << k << " was mutated\n";
            std::exit(1);
        }
    };

    must_redact("api_key");
    must_redact("password");
    must_redact("customer_token");      // substring on 'token'
    must_redact("user_password");        // substring on 'password'
    must_redact("oauth_bearer_token");   // substring on 'bearer' or 'token'
    must_keep("email", "alice@example.com");

    std::cout << "ok test_substring_match_redacts\n";
}

}  // namespace

int main() {
    test_substring_match_redacts();
    std::cout << "\nALL REDACT_SUBSTRING TESTS PASSED\n";
    return 0;
}
