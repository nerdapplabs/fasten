#pragma once
/**
 * rivet.hpp — C++14 audit + structured-log SDK.
 * Single-header, zero external dependencies.
 *
 * Usage:
 *   rivet::register_codes("connector", {
 *       {"CONNECTOR_CONNECTED",
 *           {"connector", "connector", "connected",
 *            rivet::Sev::Info, "Connector established", "my-connector"}},
 *   });
 *   rivet::init({"my-connector", "edge-01"});
 *
 *   rivet::emit("CONNECTOR_CONNECTED",
 *       rivet::target("modbus://192.168.1.10"),
 *       rivet::detail({{"host", "192.168.1.10"}, {"port", "502"}}));
 *
 *   rivet::log::info("poll_started", {{"interval_ms", "1000"}});
 */

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <deque>
#include <functional>
#include <iostream>
#include <mutex>
#include <random>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace rivet {

// ── Types ──────────────────────────────────────────────────────────────────

// Domain is a plain string — adopters define their own vocabulary.
// rivet has no built-in domain constants; use string literals in your code.
using Domain = std::string;
enum class Sev        { Debug, Info, Warn, Error, Critical };
enum class Retention  { Short, Medium, Long };

using Fields = std::unordered_map<std::string, std::string>;

struct Meta {
    Domain      domain;
    std::string category;
    std::string action;
    Sev         severity   = Sev::Info;
    std::string description;
    std::string emitter;
    Retention   retention  = Retention::Medium;
    bool        high_volume = false;
};

struct Row {
    std::string id;
    std::string origin_id;
    int64_t     monotonic_seq;
    std::string timestamp;       // ISO-8601 UTC
    std::string code;
    std::string action;
    std::string severity;
    std::string service_id;
    std::string source_node_id;
    std::string tenant_id;
    std::string actor;
    std::string actor_kind;
    std::string target;
    std::string category;
    std::string domain;
    std::string method;
    std::string request_id;
    Fields      detail;
};

// ── Helpers ────────────────────────────────────────────────────────────────

namespace detail_ {

inline std::string env_or(const char* key, const char* fallback = "") {
    const char* v = std::getenv(key);
    return (v && *v) ? v : fallback;
}

// Domain is now std::string — no conversion needed.

inline std::string sev_str(Sev s) {
    switch (s) {
        case Sev::Debug:    return "debug";
        case Sev::Info:     return "info";
        case Sev::Warn:     return "warn";
        case Sev::Error:    return "error";
        case Sev::Critical: return "critical";
    }
    return "info";
}

// Minimal JSON escaping for string values.
inline std::string json_str(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (char c : s) {
        if (c == '"')  { out += "\\\""; }
        else if (c == '\\') { out += "\\\\"; }
        else if (c == '\n') { out += "\\n"; }
        else if (c == '\r') { out += "\\r"; }
        else if (c == '\t') { out += "\\t"; }
        else { out += c; }
    }
    out += '"';
    return out;
}

// Serialize a flat Fields map to inline JSON object string.
inline std::string fields_to_json(const Fields& f) {
    std::string out = "{";
    bool first = true;
    for (auto& kv : f) {
        if (!first) out += ',';
        out += json_str(kv.first) + ':' + json_str(kv.second);
        first = false;
    }
    out += '}';
    return out;
}

inline std::string now_iso8601() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
    return buf;
}

inline std::string mint_id(size_t bytes = 10) {
    static std::mutex mu;
    static std::mt19937_64 rng(std::random_device{}());
    std::lock_guard<std::mutex> lk(mu);
    std::string out;
    out.reserve(bytes * 2);
    for (size_t i = 0; i < bytes; ++i) {
        uint8_t b = rng() & 0xFF;
        const char* hex = "0123456789abcdef";
        out += hex[b >> 4];
        out += hex[b & 0xF];
    }
    return out;
}

// Redactor — same key pattern as Python/Go implementations.
inline const std::regex& secret_pattern() {
    static const std::regex pat(
        "(?i)(api[_-]?key|password|passwd|token|secret|authorization|"
        "bearer|m2m[_-]?key|cert[_-]?private|private[_-]?key|"
        "access_key|session_id|cookie|credential|auth)",
        std::regex::icase);
    return pat;
}

inline Fields redact(const Fields& f, const std::string& replacement = "***") {
    Fields out;
    for (auto& kv : f) {
        if (std::regex_search(kv.first, secret_pattern())) {
            out[kv.first] = replacement;
        } else {
            out[kv.first] = kv.second;
        }
    }
    return out;
}

// Thread-safe ring buffer.
struct RingBuffer {
    size_t                       max;
    std::deque<Fields>           buf;
    mutable std::mutex           mu;

    explicit RingBuffer(size_t m = 2000) : max(m) {}

    void push(Fields row) {
        std::lock_guard<std::mutex> lk(mu);
        buf.push_front(std::move(row));
        if (buf.size() > max) buf.pop_back();
    }

    std::vector<Fields> query(size_t limit = 100,
                              const std::string& level = "",
                              const std::string& method = "",
                              const std::string& path = "") const {
        std::lock_guard<std::mutex> lk(mu);
        std::vector<Fields> out;
        for (auto& r : buf) {
            if (!level.empty()) {
                auto it = r.find("level");
                if (it == r.end() || it->second != level) continue;
            }
            if (!method.empty()) {
                auto it = r.find("method");
                if (it == r.end() || it->second != method) continue;
            }
            if (!path.empty()) {
                auto it = r.find("path");
                if (it == r.end() || it->second.find(path) == std::string::npos) continue;
            }
            out.push_back(r);
            if (out.size() >= limit) break;
        }
        return out;
    }
};

} // namespace detail_

// ── Globals ────────────────────────────────────────────────────────────────

namespace global_ {
    std::mutex                                  reg_mu;
    std::unordered_map<std::string, Meta>       registry;

    std::string  service_id;
    std::string  node_id;
    std::string  tenant_id;
    int64_t      seq = 0;
    std::mutex   seq_mu;

    detail_::RingBuffer syslog_ring;
    detail_::RingBuffer api_ring;

    thread_local std::string request_id;
} // namespace global_

// ── Registry ───────────────────────────────────────────────────────────────

inline void register_codes(Domain domain,
                            std::initializer_list<std::pair<std::string, Meta>> codes) {
    std::lock_guard<std::mutex> lk(global_::reg_mu);
    for (auto& kv : codes) {
        if (global_::registry.count(kv.first)) {
            throw std::runtime_error("rivet: duplicate code: " + kv.first);
        }
        if (kv.second.domain != domain) {
            throw std::runtime_error("rivet: domain mismatch for code: " + kv.first);
        }
        global_::registry[kv.first] = kv.second;
    }
}

// ── Init ───────────────────────────────────────────────────────────────────

struct Config {
    std::string service_id;
    std::string node_id;
    std::string tenant_id;
};

inline void init(Config cfg = {}) {
    using detail_::env_or;
    global_::service_id = cfg.service_id.empty() ? env_or("RIVET_SERVICE_ID") : cfg.service_id;
    global_::node_id    = cfg.node_id.empty()    ? env_or("RIVET_NODE_ID")    : cfg.node_id;
    global_::tenant_id  = cfg.tenant_id.empty()  ? env_or("RIVET_TENANT_ID")  : cfg.tenant_id;

    if (global_::service_id.empty() || global_::node_id.empty()) {
        throw std::runtime_error("rivet::init: service_id and node_id are required");
    }
}

// ── Correlation ────────────────────────────────────────────────────────────

inline void set_request_id(const std::string& id) { global_::request_id = id; }
inline std::string current_request_id()            { return global_::request_id; }

// ── Emit options ───────────────────────────────────────────────────────────

struct EmitOpts {
    std::string target;
    std::string actor     = "system";
    std::string actor_kind = "service";
    std::string method    = "mqtt";
    Fields      detail;
};

inline std::function<void(EmitOpts&)> target(const std::string& t) {
    return [t](EmitOpts& o){ o.target = t; };
}
inline std::function<void(EmitOpts&)> actor(const std::string& a, const std::string& kind = "service") {
    return [a, kind](EmitOpts& o){ o.actor = a; o.actor_kind = kind; };
}
inline std::function<void(EmitOpts&)> detail(Fields d) {
    return [d](EmitOpts& o){ o.detail = std::move(d); };
}
inline std::function<void(EmitOpts&)> method(const std::string& m) {
    return [m](EmitOpts& o){ o.method = m; };
}

// ── Emit ───────────────────────────────────────────────────────────────────

template<typename... Opts>
inline Row emit(const std::string& code, Opts&&... opts) {
    if (global_::service_id.empty()) {
        throw std::runtime_error("rivet::init() must be called before emit()");
    }

    Meta meta;
    {
        std::lock_guard<std::mutex> lk(global_::reg_mu);
        auto it = global_::registry.find(code);
        if (it == global_::registry.end()) {
            throw std::runtime_error("rivet: unknown audit code: " + code);
        }
        meta = it->second;
    }

    EmitOpts o;
    int dummy[] = {0, (std::forward<Opts>(opts)(o), 0)...};
    (void)dummy;

    int64_t seq;
    {
        std::lock_guard<std::mutex> lk(global_::seq_mu);
        seq = ++global_::seq;
    }

    std::string rid = global_::request_id;
    if (rid.empty()) rid = detail_::mint_id(6);

    Row row;
    row.id             = "evt-" + detail_::mint_id(10);
    row.origin_id      = row.id;
    row.monotonic_seq  = seq;
    row.timestamp      = detail_::now_iso8601();
    row.code           = code;
    row.action         = meta.action;
    row.severity       = detail_::sev_str(meta.severity);
    row.service_id     = global_::service_id;
    row.source_node_id = global_::node_id;
    row.tenant_id      = global_::tenant_id;
    row.actor          = o.actor;
    row.actor_kind     = o.actor_kind;
    row.target         = o.target;
    row.category       = meta.category;
    row.domain         = meta.domain;
    row.method         = o.method;
    row.request_id     = rid;
    row.detail         = detail_::redact(o.detail);

    // NDJSON to stdout — Docker log driver captures and rotates.
    std::ostringstream js;
    js << "{\"shape\":\"audit\""
       << ",\"id\":"             << detail_::json_str(row.id)
       << ",\"origin_id\":"      << detail_::json_str(row.origin_id)
       << ",\"monotonic_seq\":"  << row.monotonic_seq
       << ",\"timestamp\":"      << detail_::json_str(row.timestamp)
       << ",\"code\":"           << detail_::json_str(row.code)
       << ",\"action\":"         << detail_::json_str(row.action)
       << ",\"severity\":"       << detail_::json_str(row.severity)
       << ",\"service_id\":"     << detail_::json_str(row.service_id)
       << ",\"source_node_id\":" << detail_::json_str(row.source_node_id)
       << ",\"tenant_id\":"       << detail_::json_str(row.tenant_id)
       << ",\"actor\":"          << detail_::json_str(row.actor)
       << ",\"actor_kind\":"     << detail_::json_str(row.actor_kind)
       << ",\"target\":"         << detail_::json_str(row.target)
       << ",\"category\":"       << detail_::json_str(row.category)
       << ",\"domain\":"         << detail_::json_str(row.domain)
       << ",\"method\":"         << detail_::json_str(row.method)
       << ",\"request_id\":"     << detail_::json_str(row.request_id)
       << ",\"detail\":"         << detail_::fields_to_json(row.detail)
       << "}\n";
    std::cout << js.str() << std::flush;

    return row;
}

// ── Structured log ─────────────────────────────────────────────────────────

namespace log {

inline void _write(const std::string& level, const std::string& event, const Fields& fields) {
    std::ostringstream js;
    js << "{\"shape\":\"sys\""
       << ",\"level\":"      << detail_::json_str(level)
       << ",\"event\":"      << detail_::json_str(event)
       << ",\"request_id\":" << detail_::json_str(global_::request_id)
       << ",\"service_id\":" << detail_::json_str(global_::service_id)
       << ",\"timestamp\":"  << detail_::json_str(detail_::now_iso8601());
    for (auto& kv : detail_::redact(fields)) {
        js << ',' << detail_::json_str(kv.first) << ':' << detail_::json_str(kv.second);
    }
    js << "}\n";

    auto row = fields;
    row["level"] = level; row["event"] = event;
    row["request_id"] = global_::request_id;
    global_::syslog_ring.push(row);

    std::cout << js.str() << std::flush;
}

inline void debug(const std::string& event, const Fields& fields = {}) { _write("debug",    event, fields); }
inline void info (const std::string& event, const Fields& fields = {}) { _write("info",     event, fields); }
inline void warn (const std::string& event, const Fields& fields = {}) { _write("warn",     event, fields); }
inline void error(const std::string& event, const Fields& fields = {}) { _write("error",    event, fields); }

} // namespace log

} // namespace rivet
