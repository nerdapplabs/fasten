#pragma once
/**
 * fasten.hpp — C++14 audit + correlation SDK.
 * Single-header, zero external dependencies.
 *
 * Usage:
 *   fasten::register_codes("node", {
 *       {"CONN_UP", {
 *           "CONN_UP", "node", "connector", "connected",
 *           fasten::Sev::Info, "Connection established", "my-service"
 *       }},
 *   });
 *   fasten::init({"my-service", "edge-01"});
 *
 *   // RAII scope — all emit/log inside inherit this request_id.
 *   fasten::RequestScope scope("req-a1b2c3");
 *
 *   fasten::emit("CONN_UP",
 *       fasten::target("modbus://192.168.1.10"),
 *       fasten::detail({{"host", "192.168.1.10"}, {"port", "502"}}));
 *
 *   fasten::log::info("poll_started", {{"interval_ms", "1000"}});
 *
 * Env vars: FASTEN_SERVICE_ID, FASTEN_NODE_ID, FASTEN_TENANT_ID
 */

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <functional>
#include <iostream>
#include <mutex>
#include <random>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace fasten {

// ── Types ──────────────────────────────────────────────────────────────────

// Domain is a plain string — adopters define their own vocabulary.
// Examples: "node", "user", "billing", "device" — fasten has no opinions.
using Domain = std::string;

enum class Sev        { Debug, Info, Warn, Error, Critical };
enum class Retention  { Short, Medium, Long };

using Fields = std::unordered_map<std::string, std::string>;

struct Meta {
    std::string id;                             // must equal the registry key
    Domain      domain;
    std::string category;
    std::string action;
    Sev         severity        = Sev::Info;
    std::string description;
    std::string emitter;
    Retention   retention_class = Retention::Medium;
    bool        high_volume     = false;
    bool        pii_in_detail   = false;
};

// ── Row ────────────────────────────────────────────────────────────────────

struct Row {
    std::string id;                  // evt-<20 hex chars>
    std::string origin_id;           // dedup key for replication
    int64_t     monotonic_seq   = 0;
    std::string timestamp;           // ISO-8601 UTC with ms
    std::string code;
    std::string action;
    std::string severity;
    std::string service_id;
    std::string source_node_id;
    std::string tenant_id;
    std::string actor           = "system";
    std::string actor_kind      = "service";
    std::string target;
    std::string category;
    std::string domain;
    std::string method          = "sdk";
    std::string request_id;
    Fields      detail;
    std::string shipped_at;          // empty = not shipped

    // Declared here, defined after detail_ helpers below.
    std::string to_json() const;
    std::string to_cloud_event_json() const;
};

// ── Exceptions ─────────────────────────────────────────────────────────────

struct AuditCatalogError : std::runtime_error {
    explicit AuditCatalogError(const std::string& msg)
        : std::runtime_error("fasten: " + msg) {}
};

struct InitError : std::runtime_error {
    explicit InitError(const std::string& msg)
        : std::runtime_error("fasten: " + msg) {}
};

// ── Internal helpers ───────────────────────────────────────────────────────

namespace detail_ {

inline std::string env_or(const char* key, const char* fallback = "") {
    const char* v = std::getenv(key);
    return (v && *v) ? v : fallback;
}

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

// JSON-escape a string value (including control chars below 0x20).
inline std::string json_str(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    out += '"';
    return out;
}

// Serialize Fields to a JSON object — keys sorted for deterministic output.
inline std::string fields_to_json(const Fields& f) {
    std::vector<std::pair<std::string, std::string>> pairs(f.begin(), f.end());
    std::sort(pairs.begin(), pairs.end());
    std::string out = "{";
    bool first = true;
    for (auto& kv : pairs) {
        if (!first) out += ',';
        out += json_str(kv.first) + ':' + json_str(kv.second);
        first = false;
    }
    out += '}';
    return out;
}

// UTC ISO-8601 with milliseconds — thread-safe (gmtime_r / gmtime_s).
inline std::string now_iso8601() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms  = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    auto t   = system_clock::to_time_t(now);
    struct tm tmb {};
#ifdef _WIN32
    gmtime_s(&tmb, &t);
#else
    gmtime_r(&t, &tmb);
#endif
    char buf[32];
    std::snprintf(buf, sizeof(buf),
        "%04d-%02d-%02dT%02d:%02d:%02d.%03lldZ",
        tmb.tm_year + 1900, tmb.tm_mon + 1, tmb.tm_mday,
        tmb.tm_hour, tmb.tm_min, tmb.tm_sec,
        static_cast<long long>(ms.count()));
    return buf;
}

// Hex-random id — `bytes` random bytes → 2*bytes lowercase hex chars.
inline std::string mint_id_bytes(size_t bytes) {
    static std::mutex mu;
    static std::mt19937_64 rng(std::random_device{}());
    static const char hex[] = "0123456789abcdef";
    std::lock_guard<std::mutex> lk(mu);
    std::string out;
    out.reserve(bytes * 2);
    for (size_t i = 0; i < bytes; ++i) {
        auto b = static_cast<uint8_t>(rng());
        out += hex[b >> 4];
        out += hex[b & 0x0F];
    }
    return out;
}

// Secret-key redactor — same pattern as Python / Go.
// Note: no (?i) prefix — case-insensitivity comes from std::regex::icase flag.
inline const std::regex& secret_pattern() {
    static const std::regex pat(
        "api[_-]?key|password|passwd|token|secret|authorization|"
        "bearer|m2m[_-]?key|cert[_-]?private|private[_-]?key|"
        "access_key|session_id|cookie|credential|auth",
        std::regex::icase);
    return pat;
}

inline Fields redact(const Fields& f, const std::string& repl = "***") {
    Fields out;
    for (auto& kv : f) {
        out[kv.first] = std::regex_search(kv.first, secret_pattern())
            ? repl
            : kv.second;
    }
    return out;
}

// Thread-safe ring buffer (syslog + api streams).
struct RingBuffer {
    size_t             max_;
    std::deque<Fields> buf_;
    mutable std::mutex mu_;

    explicit RingBuffer(size_t max = 2000) : max_(max) {}

    // Non-copyable — mutex can't be copied.
    RingBuffer(const RingBuffer&) = delete;
    RingBuffer& operator=(const RingBuffer&) = delete;

    void push(Fields row) {
        std::lock_guard<std::mutex> lk(mu_);
        buf_.push_front(std::move(row));
        while (buf_.size() > max_) buf_.pop_back();
    }

    std::vector<Fields> query(
        size_t             limit      = 100,
        const std::string& level      = "",
        const std::string& request_id = "",
        const std::string& method     = "",
        const std::string& path       = "") const
    {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<Fields> out;
        for (auto& r : buf_) {
            if (!level.empty()) {
                auto it = r.find("level");
                if (it == r.end() || it->second != level) continue;
            }
            if (!request_id.empty()) {
                auto it = r.find("request_id");
                if (it == r.end() || it->second != request_id) continue;
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

    size_t size() const {
        std::lock_guard<std::mutex> lk(mu_);
        return buf_.size();
    }
};

// All mutable global state lives in one Meyers-singleton struct.
// This is the correct pattern for a single-header library — one instance
// per process regardless of how many translation units include the header.
struct Globals {
    std::mutex                            reg_mu;
    std::unordered_map<std::string, Meta> registry;

    std::string service_id;
    std::string node_id;
    std::string tenant_id;

    int64_t    seq{0};
    std::mutex seq_mu;

    RingBuffer syslog_ring;
    RingBuffer api_ring;

    // Adopter-supplied audit sink — called for every emitted Row.
    std::function<void(const Row&)> audit_sink;
    std::mutex                      sink_mu;
};

inline Globals& globals() {
    static Globals g;
    return g;
}

// Thread-local request_id — function-local thread_local is ODR-safe in C++14.
inline std::string& tl_request_id() {
    thread_local std::string rid;
    return rid;
}

} // namespace detail_

// ── Row serialisation (needs detail_ helpers) ──────────────────────────────

inline std::string Row::to_json() const {
    std::string js = "{";
    js += "\"id\":"              + detail_::json_str(id);
    js += ",\"origin_id\":"      + detail_::json_str(origin_id);
    js += ",\"monotonic_seq\":"  + std::to_string(monotonic_seq);
    js += ",\"timestamp\":"      + detail_::json_str(timestamp);
    js += ",\"code\":"           + detail_::json_str(code);
    js += ",\"action\":"         + detail_::json_str(action);
    js += ",\"severity\":"       + detail_::json_str(severity);
    js += ",\"service_id\":"     + detail_::json_str(service_id);
    js += ",\"source_node_id\":" + detail_::json_str(source_node_id);
    js += ",\"tenant_id\":"      + detail_::json_str(tenant_id);
    js += ",\"actor\":"          + detail_::json_str(actor);
    js += ",\"actor_kind\":"     + detail_::json_str(actor_kind);
    js += ",\"target\":"         + detail_::json_str(target);
    js += ",\"category\":"       + detail_::json_str(category);
    js += ",\"domain\":"         + detail_::json_str(domain);
    js += ",\"method\":"         + detail_::json_str(method);
    js += ",\"request_id\":"     + detail_::json_str(request_id);
    js += ",\"detail\":"         + detail_::fields_to_json(detail);
    if (!shipped_at.empty()) {
        js += ",\"shipped_at\":" + detail_::json_str(shipped_at);
    }
    js += "}";
    return js;
}

inline std::string Row::to_cloud_event_json() const {
    // CloudEvent 1.0 — id / source / type / time / data.
    std::string data = "{";
    bool first = true;
    for (auto& kv : detail) {
        if (!first) data += ',';
        data += detail_::json_str(kv.first) + ':' + detail_::json_str(kv.second);
        first = false;
    }
    if (!first) data += ',';
    data += "\"actor\":"       + detail_::json_str(actor);
    data += ",\"actor_kind\":" + detail_::json_str(actor_kind);
    data += ",\"target\":"     + detail_::json_str(target);
    data += ",\"method\":"     + detail_::json_str(method);
    data += ",\"request_id\":" + detail_::json_str(request_id);
    data += "}";

    std::string js = "{";
    js += "\"specversion\":\"1.0\"";
    js += ",\"id\":"     + detail_::json_str(id);
    js += ",\"source\":" + detail_::json_str(source_node_id);
    js += ",\"type\":"   + detail_::json_str(code);
    js += ",\"time\":"   + detail_::json_str(timestamp);
    js += ",\"data\":"   + data;
    js += "}";
    return js;
}

// ── Registry ───────────────────────────────────────────────────────────────

inline void register_codes(
    const Domain& domain,
    std::initializer_list<std::pair<std::string, Meta>> codes)
{
    auto& g = detail_::globals();
    std::lock_guard<std::mutex> lk(g.reg_mu);
    for (auto& kv : codes) {
        if (kv.second.id != kv.first) {
            throw AuditCatalogError(
                "code " + kv.first + " has meta.id=" + kv.second.id + " — they must match");
        }
        if (g.registry.count(kv.first)) {
            throw AuditCatalogError("duplicate code: " + kv.first);
        }
        if (kv.second.domain != domain) {
            throw AuditCatalogError(
                "code " + kv.first + " declares domain=" + kv.second.domain +
                " but registered under " + domain);
        }
        g.registry[kv.first] = kv.second;
    }
}

// Overload for std::vector — allows runtime-built code tables.
inline void register_codes(
    const Domain& domain,
    const std::vector<std::pair<std::string, Meta>>& codes)
{
    auto& g = detail_::globals();
    std::lock_guard<std::mutex> lk(g.reg_mu);
    for (auto& kv : codes) {
        if (kv.second.id != kv.first) {
            throw AuditCatalogError(
                "code " + kv.first + " has meta.id=" + kv.second.id + " — they must match");
        }
        if (g.registry.count(kv.first)) {
            throw AuditCatalogError("duplicate code: " + kv.first);
        }
        if (kv.second.domain != domain) {
            throw AuditCatalogError(
                "code " + kv.first + " declares domain=" + kv.second.domain +
                " but registered under " + domain);
        }
        g.registry[kv.first] = kv.second;
    }
}

// Return a snapshot of the current catalog.
inline std::unordered_map<std::string, Meta> registry() {
    auto& g = detail_::globals();
    std::lock_guard<std::mutex> lk(g.reg_mu);
    return g.registry;
}

// "id,domain,severity\n..." sorted — feeds cross-language consistency gate.
inline std::string dump() {
    auto reg = registry();
    std::vector<std::tuple<std::string, std::string, std::string>> rows;
    rows.reserve(reg.size());
    for (auto& kv : reg) {
        rows.emplace_back(kv.first, kv.second.domain,
                          detail_::sev_str(kv.second.severity));
    }
    std::sort(rows.begin(), rows.end());
    std::string out;
    for (auto& t : rows) {
        out += std::get<0>(t) + ',' + std::get<1>(t) + ',' + std::get<2>(t) + '\n';
    }
    if (!out.empty()) out.pop_back(); // strip trailing newline
    return out;
}

// ── Init ───────────────────────────────────────────────────────────────────

struct Config {
    std::string service_id;
    std::string node_id;
    std::string tenant_id;  // optional
};

inline void init(Config cfg = {}) {
    using detail_::env_or;
    auto& g = detail_::globals();
    g.service_id = cfg.service_id.empty() ? env_or("FASTEN_SERVICE_ID") : cfg.service_id;
    g.node_id    = cfg.node_id.empty()    ? env_or("FASTEN_NODE_ID")    : cfg.node_id;
    g.tenant_id  = cfg.tenant_id.empty()  ? env_or("FASTEN_TENANT_ID")  : cfg.tenant_id;

    if (g.service_id.empty() || g.node_id.empty()) {
        throw InitError("init: FASTEN_SERVICE_ID and FASTEN_NODE_ID are required");
    }
}

// ── Audit sink ─────────────────────────────────────────────────────────────

// Register a callback invoked for every emitted Row.
// Use this to persist rows to SQLite, PostgreSQL, or any durable store.
// The callback is called on the emitting thread — keep it fast or dispatch.
using AuditSink = std::function<void(const Row&)>;

inline void set_audit_sink(AuditSink sink) {
    auto& g = detail_::globals();
    std::lock_guard<std::mutex> lk(g.sink_mu);
    g.audit_sink = std::move(sink);
}

// ── Correlation ────────────────────────────────────────────────────────────

// Mint a new 12-char hex request id.
inline std::string mint_id() {
    return detail_::mint_id_bytes(6);
}

// Set the ambient request id for the current thread.
// Prefer RequestScope for automatic cleanup.
inline void set_request_id(const std::string& id) {
    detail_::tl_request_id() = id;
}

inline std::string current_request_id() {
    return detail_::tl_request_id();
}

// RAII scope — sets request_id on construction, restores previous on exit.
// Equivalent to Python's `with with_request_id(rid) as ctx`.
//
//   fasten::RequestScope scope;           // mints a new id
//   fasten::RequestScope scope("req-42"); // uses provided id
//   scope.id()                            // read the active id
struct RequestScope {
    std::string prev_;
    bool        owns_ = true;

    explicit RequestScope(std::string rid = "") {
        prev_ = detail_::tl_request_id();
        detail_::tl_request_id() = rid.empty() ? mint_id() : std::move(rid);
    }

    const std::string& id() const { return detail_::tl_request_id(); }

    ~RequestScope() {
        if (owns_) detail_::tl_request_id() = prev_;
    }

    RequestScope(const RequestScope&) = delete;
    RequestScope& operator=(const RequestScope&) = delete;

    RequestScope(RequestScope&& o) noexcept
        : prev_(std::move(o.prev_)), owns_(o.owns_) { o.owns_ = false; }
};

// ── Emit option builders ───────────────────────────────────────────────────

struct EmitOpts {
    std::string target;
    std::string actor      = "system";
    std::string actor_kind = "service";
    std::string method_val = "sdk";
    Fields      fields;
};

inline std::function<void(EmitOpts&)> target(const std::string& t) {
    return [t](EmitOpts& o) { o.target = t; };
}
inline std::function<void(EmitOpts&)> actor(const std::string& a,
                                             const std::string& kind = "service") {
    return [a, kind](EmitOpts& o) { o.actor = a; o.actor_kind = kind; };
}
inline std::function<void(EmitOpts&)> detail(Fields d) {
    return [d](EmitOpts& o) { o.fields = d; };
}
inline std::function<void(EmitOpts&)> method(const std::string& m) {
    return [m](EmitOpts& o) { o.method_val = m; };
}

// ── Emit ───────────────────────────────────────────────────────────────────

template<typename... Opts>
inline Row emit(const std::string& code, Opts&&... opts) {
    auto& g = detail_::globals();
    if (g.service_id.empty()) {
        throw InitError("emit: fasten::init() must be called first");
    }

    Meta meta;
    {
        std::lock_guard<std::mutex> lk(g.reg_mu);
        auto it = g.registry.find(code);
        if (it == g.registry.end()) {
            throw std::invalid_argument("fasten: unknown audit code: " + code);
        }
        meta = it->second;
    }

    EmitOpts o;
    // C++14 parameter-pack expansion into dummy array.
    int dummy[] = {0, (std::forward<Opts>(opts)(o), 0)...};
    (void)dummy;

    int64_t seq;
    {
        std::lock_guard<std::mutex> lk(g.seq_mu);
        seq = ++g.seq;
    }

    std::string rid = detail_::tl_request_id();
    if (rid.empty()) rid = mint_id();

    Row row;
    row.id             = "evt-" + detail_::mint_id_bytes(10);
    row.origin_id      = row.id;
    row.monotonic_seq  = seq;
    row.timestamp      = detail_::now_iso8601();
    row.code           = code;
    row.action         = meta.action;
    row.severity       = detail_::sev_str(meta.severity);
    row.service_id     = g.service_id;
    row.source_node_id = g.node_id;
    row.tenant_id      = g.tenant_id;
    row.actor          = o.actor;
    row.actor_kind     = o.actor_kind;
    row.target         = o.target;
    row.category       = meta.category;
    row.domain         = meta.domain;
    row.method         = o.method_val;
    row.request_id     = rid;
    row.detail         = detail_::redact(o.fields);

    // NDJSON to stdout — Docker log driver captures and rotates.
    std::cout << "{\"shape\":\"audit\""
              << ",\"id\":"             << detail_::json_str(row.id)
              << ",\"origin_id\":"      << detail_::json_str(row.origin_id)
              << ",\"monotonic_seq\":"  << row.monotonic_seq
              << ",\"timestamp\":"      << detail_::json_str(row.timestamp)
              << ",\"code\":"           << detail_::json_str(row.code)
              << ",\"action\":"         << detail_::json_str(row.action)
              << ",\"severity\":"       << detail_::json_str(row.severity)
              << ",\"service_id\":"     << detail_::json_str(row.service_id)
              << ",\"source_node_id\":" << detail_::json_str(row.source_node_id)
              << ",\"tenant_id\":"      << detail_::json_str(row.tenant_id)
              << ",\"actor\":"          << detail_::json_str(row.actor)
              << ",\"actor_kind\":"     << detail_::json_str(row.actor_kind)
              << ",\"target\":"         << detail_::json_str(row.target)
              << ",\"category\":"       << detail_::json_str(row.category)
              << ",\"domain\":"         << detail_::json_str(row.domain)
              << ",\"method\":"         << detail_::json_str(row.method)
              << ",\"request_id\":"     << detail_::json_str(row.request_id)
              << ",\"detail\":"         << detail_::fields_to_json(row.detail)
              << "}\n" << std::flush;

    // Invoke adopter-provided audit sink if registered.
    {
        std::lock_guard<std::mutex> lk(g.sink_mu);
        if (g.audit_sink) g.audit_sink(row);
    }

    return row;
}

// ── Ring buffer accessors ──────────────────────────────────────────────────

inline std::vector<Fields> query_syslog(
    size_t             limit      = 100,
    const std::string& level      = "",
    const std::string& request_id = "")
{
    return detail_::globals().syslog_ring.query(limit, level, request_id);
}

inline std::vector<Fields> query_api(
    size_t             limit      = 100,
    const std::string& request_id = "",
    const std::string& method_str = "",
    const std::string& path       = "")
{
    return detail_::globals().api_ring.query(limit, "", request_id, method_str, path);
}

// ── Structured log ─────────────────────────────────────────────────────────

namespace log {

inline void _write(const std::string& level, const std::string& event,
                   const Fields& fields)
{
    auto& g = detail_::globals();
    auto clean = detail_::redact(fields);

    // Build NDJSON line.
    std::string js = "{\"shape\":\"sys\"";
    js += ",\"level\":"      + detail_::json_str(level);
    js += ",\"event\":"      + detail_::json_str(event);
    js += ",\"request_id\":" + detail_::json_str(detail_::tl_request_id());
    js += ",\"service_id\":" + detail_::json_str(g.service_id);
    js += ",\"timestamp\":"  + detail_::json_str(detail_::now_iso8601());
    for (auto& kv : clean) {
        js += ',' + detail_::json_str(kv.first) + ':' + detail_::json_str(kv.second);
    }
    js += "}\n";

    // Buffer in ring for /logs/sys.
    auto row = clean;
    row["level"]      = level;
    row["event"]      = event;
    row["request_id"] = detail_::tl_request_id();
    g.syslog_ring.push(std::move(row));

    std::cout << js << std::flush;
}

inline void debug(const std::string& event, const Fields& f = {}) { _write("debug",    event, f); }
inline void info (const std::string& event, const Fields& f = {}) { _write("info",     event, f); }
inline void warn (const std::string& event, const Fields& f = {}) { _write("warn",     event, f); }
inline void error(const std::string& event, const Fields& f = {}) { _write("error",    event, f); }

} // namespace log

// ── Scheduler shim ─────────────────────────────────────────────────────────

namespace scheduler {

// Begin a scheduled-job scope — mints a "scheduler-<hex>" request id.
// Returns a RequestScope; all emit/log calls in scope inherit the id.
//
//   auto scope = fasten::scheduler::job_run();
//   fasten::emit("JOB_STARTED", ...);
//   // scope destructs → previous request_id restored
inline RequestScope job_run(const std::string& run_id = "") {
    std::string rid = run_id.empty()
        ? "scheduler-" + detail_::mint_id_bytes(4)
        : run_id;
    return RequestScope(std::move(rid));
}

} // namespace scheduler

} // namespace fasten
