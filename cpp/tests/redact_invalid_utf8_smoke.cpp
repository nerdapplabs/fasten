// Fields with bytes that are not valid UTF-8 are still redacted, on emit()
// (stdout line and stored row) and on log::info(). If the core can't parse
// the input, every value is replaced and a redact_failed sys event is logged.

#include "fasten.hpp"

#include <cassert>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include <unistd.h>

namespace {

const std::string kSecret = "hunter2";

// Captures what is written to file descriptor fd between start() and stop().
struct Capture {
    int fd;
    int saved = -1;
    std::FILE* f = nullptr;
    explicit Capture(int which) : fd(which) {}
    void start() {
        std::cout.flush(); std::cerr.flush(); std::fflush(nullptr);
        f = std::tmpfile();
        saved = dup(fd);
        dup2(fileno(f), fd);
    }
    std::string stop() {
        std::cout.flush(); std::cerr.flush(); std::fflush(nullptr);
        dup2(saved, fd); close(saved);
        std::string out;
        std::rewind(f);
        char buf[4096];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
        std::fclose(f);
        return out;
    }
};

void fail(const std::string& msg) {
    std::cerr << "FAIL: " << msg << "\n";
    std::exit(1);
}

fasten::Fields invalid_fields() {
    return {{"password", kSecret}, {"name", "al\xff" "ice"}};
}

void reset_state() {
    fasten::detail_::globals().reset_for_tests();
    fasten_registry_clear();
    fasten::detail_::globals().registry.clear();
    fasten::Meta m;
    m.domain = "test"; m.category = "redact"; m.action = "emit";
    m.severity = fasten::Sev::Info; m.description = "x"; m.emitter = "t";
    fasten::register_codes("test", {{"REDACT_INVALID_UTF8", m}});
}

void emit_redacts_invalid_utf8() {
    reset_state();
    std::vector<std::string> stored;
    fasten::set_audit_sink([&](const fasten::Row& r) { stored.push_back(r.to_json()); });
    fasten::Config c{"svc", "node", ""};
    c.audit_store_failure_strategy = "raise";
    fasten::init(c);

    Capture out(1); out.start();
    fasten::Row row = fasten::emit("REDACT_INVALID_UTF8",
        fasten::target("t-1"), fasten::detail(invalid_fields()));
    const std::string line = out.stop();

    if (row.detail["password"] == kSecret) fail("emit: row detail kept the password");
    if (line.find(kSecret) != std::string::npos) fail("emit: stdout line has the password");
    if (stored.size() != 1) fail("emit: row not stored");
    if (stored[0].find(kSecret) != std::string::npos) fail("emit: stored row has the password");
    std::cout << "ok emit_redacts_invalid_utf8\n";
}

void log_redacts_invalid_utf8() {
    reset_state();
    fasten::init({"svc", "node"});

    Capture out(1); out.start();
    fasten::log::info("login", invalid_fields());
    const std::string line = out.stop();

    if (line.find(kSecret) != std::string::npos) fail("log: stdout line has the password");
    for (auto& r : fasten::query_syslog(100)) {
        if (r["event"] == "login" && r["password"] == kSecret) fail("log: sys ring has the password");
    }
    std::cout << "ok log_redacts_invalid_utf8\n";
}

void json_str_writes_valid_utf8() {
    using fasten::detail_::json_str;
    if (json_str("al\xff" "ice") != "\"al\xEF\xBF\xBD" "ice\"") fail("json_str: 0xff not replaced");
    if (json_str("caf\xC3\xA9") != "\"caf\xC3\xA9\"") fail("json_str: valid UTF-8 changed");
    if (json_str("\xC0\xAF") != "\"\xEF\xBF\xBD\xEF\xBF\xBD\"") fail("json_str: overlong kept");
    if (json_str("\xED\xA0\x80") != "\"\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\"") fail("json_str: surrogate kept");
    if (json_str("\xF0\x9F\x98") != "\"\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\"") fail("json_str: truncated sequence kept");
    std::cout << "ok json_str_writes_valid_utf8\n";
}

// The path taken when the core returns an error.
void core_error_replaces_every_value() {
    reset_state();
    fasten::init({"svc", "node"});

    Capture err(2); err.start();
    fasten::Fields out = fasten::detail_::redact_all_values_(invalid_fields(), "***", 4);
    const std::string lines = err.stop();

    if (out.size() != 2 || out["password"] != "***" || out["name"] != "***")
        fail("fallback: values not replaced");
    if (lines.find("\"event\":\"redact_failed\"") == std::string::npos)
        fail("fallback: no redact_failed line on stderr");
    bool found = false;
    for (auto& r : fasten::query_syslog(100)) {
        if (r["event"] == "redact_failed" && r["error_type"] == "invalid_input") found = true;
    }
    if (!found) fail("fallback: no redact_failed sys row");
    std::cout << "ok core_error_replaces_every_value\n";
}

}  // namespace

int main() {
    emit_redacts_invalid_utf8();
    log_redacts_invalid_utf8();
    json_str_writes_valid_utf8();
    core_error_replaces_every_value();
    std::cout << "\nALL REDACT_INVALID_UTF8 TESTS PASSED\n";
    return 0;
}
