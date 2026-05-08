// P1-5 smoke test for C++: pii_in_detail enforcement.
//
// Build:
//   g++ -std=c++14 -Wall -Wextra -Wpedantic -I../include
//       pii_in_detail_smoke.cpp -o pii_smoke
//
// Three behaviours, mirrored from Python / Go / JS / Rust:
//   1. register_codes() forces Retention::Short and warns on stderr
//   2. emit() force-redacts detail; detail_passthrough_keys survive
//   3. Row.pii_in_detail mirrors Meta.pii_in_detail
#include "fasten.hpp"

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>

namespace {

void reset_state() {
    fasten_registry_clear();
    auto& g = fasten::detail_::globals();
    g.registry.clear();
    g.seq = 0;
}

// Capture stderr while running fn().
template<typename Fn>
std::string capture_stderr(Fn fn) {
    std::stringstream buf;
    auto* old = std::cerr.rdbuf(buf.rdbuf());
    fn();
    std::cerr.rdbuf(old);
    return buf.str();
}

// ── #1 force Short at registration ────────────────────────────────────────

void test_register_forces_short() {
    reset_state();
    fasten::Meta m;
    m.domain          = "pii";
    m.category        = "p";
    m.action          = "view";
    m.severity        = fasten::Sev::Info;
    m.description     = "x";
    m.emitter         = "t";
    m.pii_in_detail   = true;
    m.retention_class = fasten::Retention::Long;

    auto warned = capture_stderr([&] {
        fasten::register_codes("pii", { {"PII_FORCE_SHORT", m} });
    });

    auto reg = fasten::registry();
    assert(reg.count("PII_FORCE_SHORT") == 1);
    assert(reg["PII_FORCE_SHORT"].retention_class == fasten::Retention::Short);
    assert(warned.find("PII_FORCE_SHORT") != std::string::npos);
    assert(warned.find("forced to short") != std::string::npos);
    std::cout << "register_forces_short: PASS\n";
}

void test_register_already_short_no_warn() {
    reset_state();
    fasten::Meta m;
    m.domain          = "pii";
    m.category        = "p";
    m.action          = "view";
    m.severity        = fasten::Sev::Info;
    m.description     = "x";
    m.emitter         = "t";
    m.pii_in_detail   = true;
    m.retention_class = fasten::Retention::Short;

    auto warned = capture_stderr([&] {
        fasten::register_codes("pii", { {"PII_ALREADY_SHORT", m} });
    });
    assert(warned.find("forced") == std::string::npos);
    std::cout << "register_already_short_no_warn: PASS\n";
}

// ── #2 emit force-redact + passthrough ────────────────────────────────────

void test_emit_force_redacts_detail() {
    reset_state();
    fasten::Meta m;
    m.domain        = "pii";
    m.category      = "p";
    m.action        = "view";
    m.severity      = fasten::Sev::Info;
    m.description   = "x";
    m.emitter       = "t";
    m.pii_in_detail = true;
    fasten::register_codes("pii", { {"PII_FULL_REDACT", m} });

    fasten::init({"svc", "node", ""});
    auto row = fasten::emit("PII_FULL_REDACT",
        fasten::target("u-42"),
        fasten::detail({{"city", "Mumbai"}, {"ip", "203.0.113.1"}}));

    assert(row.pii_in_detail);
    assert(row.detail.count("city") == 0);
    assert(row.detail.count("ip") == 0);
    assert(row.detail["_redacted"] == fasten::kRedactReplacement);
    assert(row.detail["_pii_in_detail"] == "true");

    // Wire-format parity with Python/Go/JS/Rust: the marker MUST emit
    // as a JSON boolean inside detail, not the C++ Fields string "true".
    auto js = row.to_json();
    assert(js.find("\"_pii_in_detail\":true") != std::string::npos);
    assert(js.find("\"_pii_in_detail\":\"true\"") == std::string::npos);
    assert(js.find("\"pii_in_detail\":true") != std::string::npos);

    auto ce = row.to_cloud_event_json();
    assert(ce.find("\"_pii_in_detail\":true") != std::string::npos);
    assert(ce.find("\"pii_in_detail\":true") != std::string::npos);
    std::cout << "emit_force_redacts_detail: PASS\n";
}

void test_emit_passthrough_keys() {
    reset_state();
    fasten::Meta m;
    m.domain        = "pii";
    m.category      = "p";
    m.action        = "view";
    m.severity      = fasten::Sev::Info;
    m.description   = "x";
    m.emitter       = "t";
    m.pii_in_detail = true;
    m.detail_passthrough_keys = {"region"};
    fasten::register_codes("pii", { {"PII_PARTIAL", m} });

    fasten::init({"svc", "node", ""});
    auto row = fasten::emit("PII_PARTIAL",
        fasten::target("u-42"),
        fasten::detail({
            {"city",    "Mumbai"},
            {"region",  "MH"},
            {"api_key", "sk-secret"},
        }));

    assert(row.pii_in_detail);
    assert(row.detail["region"]   == "MH");
    assert(row.detail.count("city")    == 0);
    assert(row.detail.count("api_key") == 0);
    assert(row.detail["_redacted"]      == fasten::kRedactReplacement);
    assert(row.detail["_pii_in_detail"] == "true");
    std::cout << "emit_passthrough_keys: PASS\n";
}

void test_passthrough_secret_still_redacted() {
    reset_state();
    fasten::Meta m;
    m.domain        = "pii";
    m.category      = "p";
    m.action        = "view";
    m.severity      = fasten::Sev::Info;
    m.description   = "x";
    m.emitter       = "t";
    m.pii_in_detail = true;
    m.detail_passthrough_keys = {"api_key"};
    fasten::register_codes("pii", { {"PII_PASSTHROUGH_SECRET", m} });

    fasten::init({"svc", "node", ""});
    auto row = fasten::emit("PII_PASSTHROUGH_SECRET",
        fasten::target("u-42"),
        fasten::detail({{"api_key", "sk-secret"}}));

    // Even when an adopter explicitly opts api_key into passthrough,
    // the secret-key redactor still scrubs the value.
    assert(row.detail["api_key"] == fasten::kRedactReplacement);
    std::cout << "passthrough_secret_still_redacted: PASS\n";
}

// Non-PII code: detail kept, secret keys still redacted, no PII markers.
void test_non_pii_keeps_detail() {
    reset_state();
    fasten::Meta m;
    m.domain      = "nonpii";
    m.category    = "p";
    m.action      = "view";
    m.severity    = fasten::Sev::Info;
    m.description = "x";
    m.emitter     = "t";
    fasten::register_codes("nonpii", { {"NON_PII_BASIC", m} });

    fasten::init({"svc", "node", ""});
    auto row = fasten::emit("NON_PII_BASIC",
        fasten::target("u-42"),
        fasten::detail({{"city", "Mumbai"}, {"api_key", "sk-secret"}}));

    assert(!row.pii_in_detail);
    assert(row.detail["city"]    == "Mumbai");
    assert(row.detail["api_key"] == fasten::kRedactReplacement);
    assert(row.detail.count("_redacted")      == 0);
    assert(row.detail.count("_pii_in_detail") == 0);
    std::cout << "non_pii_keeps_detail: PASS\n";
}

}  // anonymous namespace

int main() {
    test_register_forces_short();
    test_register_already_short_no_warn();
    test_emit_force_redacts_detail();
    test_emit_passthrough_keys();
    test_passthrough_secret_still_redacted();
    test_non_pii_keeps_detail();
    std::cout << "\nALL P1-5 CPP TESTS PASSED\n";
    return 0;
}
