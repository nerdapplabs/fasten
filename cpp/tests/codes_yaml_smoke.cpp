// Local smoke test for fasten/codes_yaml.hpp.
//
// Build (requires libyaml-cpp-dev):
//   g++ -std=c++14 -I../include codes_yaml_smoke.cpp -lyaml-cpp -o smoke
//
// Run inside the same dir; tests write yaml files to $TMPDIR.
#include "fasten.hpp"
#include "fasten/codes_yaml.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

namespace {

const char* FLEET_YAML = R"(
domain: fleet
emitter: fleet-service
codes:
  FLEET_NODE_REGISTERED:
    category: node.lifecycle
    action: registered
    severity: info
    description: Node claimed and registered
  FLEET_DEPLOY_FAILED:
    category: deploy
    action: failed
    severity: error
    retention_class: long
    description: Deployment failed on node
)";

std::string write_yaml(const std::string& contents, const std::string& name) {
    const char* tmp = std::getenv("TMPDIR");
    std::string path = std::string(tmp ? tmp : "/tmp") + "/fasten-cpp-test-" + name;
    std::ofstream f(path);
    f << contents;
    return path;
}

void reset_state() {
    fasten_registry_clear();
    auto& g = fasten::detail_::globals();
    g.registry.clear();
    fasten::codes::detail_yaml::yaml_codes().clear();
    fasten::codes::detail_yaml::loaded_paths().clear();
}

void test_load_round_trip() {
    reset_state();
    auto path = write_yaml(FLEET_YAML, "round.yaml");
    fasten::codes::load(path);

    auto reg = fasten::registry();
    assert(reg.count("FLEET_NODE_REGISTERED") == 1);
    assert(reg["FLEET_NODE_REGISTERED"].action == "registered");
    assert(reg["FLEET_NODE_REGISTERED"].severity == fasten::Sev::Info);
    assert(reg["FLEET_DEPLOY_FAILED"].severity == fasten::Sev::Error);
    assert(reg["FLEET_DEPLOY_FAILED"].retention_class == fasten::Retention::Long);
    std::cout << "load_round_trip: PASS\n";
}

// A yaml pii_in_detail code is short retention and keeps its passthrough
// keys, as one from register_codes() does.
void test_load_pii_code() {
    reset_state();
    auto path = write_yaml(
        "domain: user\ncodes:\n  USER_PII_SEEN:\n    pii_in_detail: true\n"
        "    retention_class: long\n    detail_passthrough_keys: [tenant]\n",
        "pii.yaml");
    fasten::codes::load(path);
    auto reg = fasten::registry();
    assert(reg["USER_PII_SEEN"].pii_in_detail);
    assert(reg["USER_PII_SEEN"].retention_class == fasten::Retention::Short);
    assert(reg["USER_PII_SEEN"].detail_passthrough_keys == std::vector<std::string>{"tenant"});

    auto bad = write_yaml(
        "domain: x\ncodes:\n  BAD_PASS:\n    detail_passthrough_keys: tenant\n",
        "badpass.yaml");
    try {
        fasten::codes::load(bad);
        assert(false && "expected throw");
    } catch (const fasten::AuditCatalogError& e) {
        assert(std::string(e.what()).find("detail_passthrough_keys") != std::string::npos);
    }
    // Null, an empty value or a non-string item is an error, as in the
    // other loaders.
    for (const char* v : {"null", "", "[1, true]", "[tenant, 1.5]", "[tenant, ~]"}) {
        auto p = write_yaml(
            std::string("domain: x\ncodes:\n  BAD_PASS:\n    detail_passthrough_keys: ") + v + "\n",
            "badpass2.yaml");
        try {
            fasten::codes::load(p);
            std::cerr << "expected a throw for: " << v << "\n";
            assert(false);
        } catch (const fasten::AuditCatalogError& e) {
            assert(std::string(e.what()).find("BAD_PASS: detail_passthrough_keys") != std::string::npos);
        }
    }
    // Quoted values are strings; a list shared through an anchor is followed.
    reset_state();
    fasten::codes::load(write_yaml(
        "domain: user\ncodes:\n  USER_Q:\n    detail_passthrough_keys: [\"1\", 'true', tenant]\n",
        "quoted.yaml"));
    assert((fasten::registry()["USER_Q"].detail_passthrough_keys ==
            std::vector<std::string>{"1", "true", "tenant"}));
    reset_state();
    fasten::codes::load(write_yaml("domain: user\ncodes:\n  USER_A:\n    pii_in_detail: true\n    detail_passthrough_keys: &pt [tenant, region]\n  USER_B:\n    pii_in_detail: true\n    detail_passthrough_keys: *pt\n", "alias.yaml"));
    assert((fasten::registry()["USER_B"].detail_passthrough_keys ==
            std::vector<std::string>{"tenant", "region"}));
    std::cout << "load_pii_code: PASS\n";
}

void test_load_invalid_severity() {
    reset_state();
    auto path = write_yaml(
        "domain: x\ncodes:\n  BAD_CODE:\n    severity: huge\n",
        "badsev.yaml");
    try {
        fasten::codes::load(path);
        assert(false && "expected throw");
    } catch (const fasten::AuditCatalogError& e) {
        std::string msg = e.what();
        assert(msg.find("severity='huge'") != std::string::npos);
        std::cout << "load_invalid_severity: PASS\n";
    }
}

void test_load_lowercase_key() {
    reset_state();
    auto path = write_yaml(
        "domain: x\ncodes:\n  lowercase_bad:\n    severity: info\n",
        "badkey.yaml");
    try {
        fasten::codes::load(path);
        assert(false && "expected throw");
    } catch (const fasten::AuditCatalogError& e) {
        std::string msg = e.what();
        assert(msg.find("UPPER_SNAKE_CASE") != std::string::npos);
        std::cout << "load_lowercase_key: PASS\n";
    }
}

void test_reload_removes_codes() {
    reset_state();
    auto path = write_yaml(FLEET_YAML, "rm.yaml");
    fasten::codes::load(path);
    assert(fasten::registry().count("FLEET_DEPLOY_FAILED") == 1);

    // rewrite without DEPLOY_FAILED
    {
        std::ofstream f(path);
        f << "domain: fleet\ncodes:\n  FLEET_NODE_REGISTERED:\n"
             "    severity: info\n    description: x\n";
    }
    fasten::codes::reload();
    assert(fasten::registry().count("FLEET_DEPLOY_FAILED") == 0);
    assert(fasten::registry().count("FLEET_NODE_REGISTERED") == 1);
    std::cout << "reload_removes_codes: PASS\n";
}

void test_reload_fault_tolerant() {
    reset_state();
    auto path = write_yaml(FLEET_YAML, "ft.yaml");
    fasten::codes::load(path);
    auto before = fasten::registry().size();

    {
        std::ofstream f(path);
        f << "domain: fleet\ncodes:\n  FLEET_NODE_REGISTERED:\n"
             "    severity: completely_bogus\n";
    }
    bool threw = false;
    try { fasten::codes::reload(); } catch (...) { threw = true; }
    assert(threw && "expected reload to throw");

    // Live registry untouched
    assert(fasten::registry().size() == before);
    assert(fasten::registry().count("FLEET_NODE_REGISTERED") == 1);
    assert(fasten::registry().count("FLEET_DEPLOY_FAILED") == 1);
    std::cout << "reload_fault_tolerant: PASS\n";
}

void test_reload_preserves_programmatic() {
    reset_state();
    auto path = write_yaml(FLEET_YAML, "prog.yaml");
    fasten::codes::load(path);

    fasten::register_codes("extra", {
        {"EXTRA_PROG_CODE", {
            "" /* id filled by SDK */, "extra", "x", "x",
            fasten::Sev::Info, "x", "t",
        }},
    });
    assert(fasten::registry().count("EXTRA_PROG_CODE") == 1);

    {
        std::ofstream f(path);
        f << "domain: fleet\ncodes:\n  FLEET_NODE_REGISTERED:\n"
             "    severity: info\n    description: x\n";
    }
    fasten::codes::reload();

    assert(fasten::registry().count("EXTRA_PROG_CODE") == 1);
    assert(fasten::registry().count("FLEET_NODE_REGISTERED") == 1);
    assert(fasten::registry().count("FLEET_DEPLOY_FAILED") == 0);
    std::cout << "reload_preserves_programmatic: PASS\n";
}

void test_reload_no_op_without_load() {
    reset_state();
    fasten::codes::reload();   // must not throw
    std::cout << "reload_no_op_without_load: PASS\n";
}

}  // anonymous namespace

int main() {
    test_load_round_trip();
    test_load_invalid_severity();
    test_load_lowercase_key();
    test_load_pii_code();
    test_reload_removes_codes();
    test_reload_fault_tolerant();
    test_reload_preserves_programmatic();
    test_reload_no_op_without_load();
    std::cout << "\nALL CPP CODES_YAML TESTS PASSED\n";
    return 0;
}
