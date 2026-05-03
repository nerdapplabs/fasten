// REVIEW.md item #1 — guard against the anchored-regex regression that
// caused C++ to silently leak fields the other 4 SDKs scrubbed.
//
// The default REDACT_PATTERNS (api_key, password, token, secret, ...) are
// substring matches in Python (re.search) and JS (RegExp without anchors).
// Before this fix C++ wrapped them in `^...$`, so:
//
//   { "customer_token": "tok-abc" }   redacted in Py / JS / Go / Rust
//                                     leaked through C++
//
// This test asserts the substring-match behaviour: any key containing one
// of the default patterns gets redacted regardless of surrounding chars.
//
// Build (via CMake -DFASTEN_BUILD_TESTS=ON) — wired in CMakeLists.

#include "fasten.hpp"

#include <cassert>
#include <iostream>
#include <string>

namespace {

void reset_state() {
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
            // exact-match cases (always worked):
            {"api_key",    "should-redact"},
            {"password",   "should-redact"},
            // substring cases — would leak with anchored regex:
            {"customer_token",     "tok-abc"},
            {"user_password",      "pw-xyz"},
            {"oauth_bearer_token", "tok-deep"},
            // safe key — must NOT be redacted:
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
    std::cout << "\nALL P1-15 redact-substring TESTS PASSED\n";
    return 0;
}
