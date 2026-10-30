#pragma once
/**
 * fasten.hpp: C++14 audit and correlation SDK.
 * Header-only; redaction, the code catalog and the audit queue live in
 * libfasten_core, so link with -lfasten_core.
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
 *   // emit() and log calls inside this scope use this request_id.
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
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <atomic>
#include <condition_variable>
#include <queue>
#include <thread>
#include <unordered_map>
#include <vector>

// libfasten_core C ABI, declared here so no extra header is needed.
extern "C" {
    // Functions returning int32_t return 0 on success.
    int32_t fasten_redact(
        const char* in_json, char** out_json, char** out_err);
    int32_t fasten_redact_full(
        const char* in_json,
        const char* extra_keys_json,
        const char* replacement,
        const char* extra_value_patterns_json,
        char** out_json, char** out_err);
    int32_t fasten_register_codes(
        const char* domain, const char* codes_json, char** out_err);
    int32_t fasten_meta_of(
        const char* code, char** out_json, char** out_err);
    void fasten_registry_clear(void);
    void fasten_store_free_str(char* s);

    // Opaque store and queue drainer handle.
    typedef int32_t (*FastenInsertCallbackFn)(const char* row_json, void* userdata);
    struct FastenStore;
    struct FastenStore* fasten_store_from_callback(
        FastenInsertCallbackFn fn, void* userdata, char** out_err);
    void fasten_store_close(struct FastenStore* store);
    int32_t fasten_drainer_install(
        struct FastenStore* store, uint64_t capacity,
        uint64_t retry_initial_ms, uint64_t retry_max_ms,
        int retry_jitter, uint32_t max_attempts, char** out_err);
    int32_t fasten_drainer_enqueue(
        struct FastenStore* store, const char* row_json, char** out_err);
    int32_t fasten_drainer_flush(
        struct FastenStore* store, uint64_t timeout_ms,
        int* out_fully_drained, char** out_err);
    int32_t fasten_drainer_stats_json(
        struct FastenStore* store, char** out_json, char** out_err);
    void fasten_drainer_close(struct FastenStore* store);
}

namespace fasten {

// Domain is any string the application chooses, e.g. "node" or "billing".
using Domain = std::string;

// ── FASTEN GENERATED ─ source: spec/row-schema.json ─ run: python spec/codegen.py ──
enum class Sev       { Debug, Info, Warn, Error, Critical };
enum class Retention { Short, Medium, Long };

inline std::string to_string(Sev s) {
    switch (s) {
        case Sev::Debug: return "debug";
        case Sev::Info: return "info";
        case Sev::Warn: return "warn";
        case Sev::Error: return "error";
        case Sev::Critical: return "critical";
    }
    return "info";
}
inline std::string to_string(Retention r) {
    switch (r) {
        case Retention::Short: return "short";
        case Retention::Medium: return "medium";
        case Retention::Long: return "long";
    }
    return "medium";
}

// WHO anchor wire values.
struct ActorKind {
    static constexpr const char* user = "user";  // Human user (browser, mobile, CLI on behalf of a user)
    static constexpr const char* service = "service";  // Internal service or daemon
    static constexpr const char* schedule = "schedule";  // Cron job or task scheduler
    static constexpr const char* agent = "agent";  // AI agent
};

// HOW anchor — set by transport shims. Use Method::sdk for direct calls.
struct Method {
    static constexpr const char* http = "http";  // HTTP/HTTPS request (REST, GraphQL, gRPC-web, webhook)
    static constexpr const char* mqtt = "mqtt";  // MQTT message (IoT telemetry, device command)
    static constexpr const char* cli = "cli";  // CLI command typed by a human
    static constexpr const char* scheduler = "scheduler";  // Automated cron or task scheduler
    static constexpr const char* ui = "ui";  // Web or desktop UI action, human-initiated
    static constexpr const char* agent_tool = "agent_tool";  // AI agent tool call
    static constexpr const char* sdk = "sdk";  // Direct SDK call, no transport shim active. Default.
};

constexpr const char* kRedactReplacement = "***";
// ── END FASTEN GENERATED ──────────────────────────────────────────────────

using Fields = std::unordered_map<std::string, std::string>;

struct Meta {
    // Optional; register_codes() fills it from the key. If set, it must
    // match the key.
    std::string id;
    Domain      domain;
    std::string category;
    std::string action;
    Sev         severity        = Sev::Info;
    std::string description;
    std::string emitter;
    Retention   retention_class = Retention::Medium;
    bool        high_volume     = false;
    bool        pii_in_detail   = false;
    // With pii_in_detail, only these detail keys are kept; their values
    // still go through the normal redactor.
    std::vector<std::string> detail_passthrough_keys;
};

struct Row {
    std::string wire_version     = "1";  // wire schema version; readers tolerate higher values
    std::string id;                  // evt-<20 hex chars>
    std::string origin_id;           // dedup key for replication
    int64_t     monotonic_seq   = 0;
    std::string timestamp;           // ISO-8601 UTC with ms
    std::string code;
    std::string action;
    std::string severity;
    std::string service_id;
    std::string source_node_id;
    std::string tenant_id;           // empty = null on wire
    std::string actor           = "system";
    std::string actor_kind      = "service";
    std::string target;
    std::string category;
    std::string domain;
    std::string method          = "sdk";
    std::string request_id;
    Fields      detail;
    bool        pii_in_detail   = false;
    std::string shipped_at;          // empty = not shipped

    std::string to_json() const;
    std::string to_cloud_event_json() const;
};

struct AuditCatalogError : std::runtime_error {
    explicit AuditCatalogError(const std::string& msg)
        : std::runtime_error("fasten: " + msg) {}
};

struct InitError : std::runtime_error {
    explicit InitError(const std::string& msg)
        : std::runtime_error("fasten: " + msg) {}
};

namespace detail_ {

inline std::string env_or(const char* key, const char* fallback = "") {
    const char* v = std::getenv(key);
    return (v && *v) ? v : fallback;
}

inline std::string sev_str(Sev s) { return fasten::to_string(s); }

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

// Fields as a JSON object with sorted keys. Fields holds only strings, but
// `_pii_in_detail` is a boolean on the wire, so it is written as one.
inline std::string fields_to_json(const Fields& f) {
    std::vector<std::pair<std::string, std::string>> pairs(f.begin(), f.end());
    std::sort(pairs.begin(), pairs.end());
    std::string out = "{";
    bool first = true;
    for (auto& kv : pairs) {
        if (!first) out += ',';
        out += json_str(kv.first) + ':';
        if (kv.first == "_pii_in_detail") {
            out += (kv.second == "true" ? "true" : "false");
        } else {
            out += json_str(kv.second);
        }
        first = false;
    }
    out += '}';
    return out;
}

// UTC ISO-8601 with milliseconds.
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

// `bytes` random bytes as lowercase hex.
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

// Redaction settings from init(). The redaction itself runs in libfasten_core.
struct RedactConfig {
    std::vector<std::string> extra_keys;
    std::string              replacement { fasten::kRedactReplacement };
};

// Minimal JSON readers for the flat objects libfasten_core returns. They
// look keys up by text search and are not general JSON parsers.

// Read a string body starting just after its opening quote, unescaping
// \" \\ \n \r \t. Leaves `i` on the closing quote.
inline std::string read_json_str(const std::string& j, size_t& i) {
    std::string val;
    while (i < j.size() && j[i] != '"') {
        if (j[i] == '\\' && i + 1 < j.size()) {
            ++i;
            switch (j[i]) {
                case '"':  val += '"';  break;
                case '\\': val += '\\'; break;
                case 'n':  val += '\n'; break;
                case 'r':  val += '\r'; break;
                case 't':  val += '\t'; break;
                default:   val += j[i]; break;
            }
        } else { val += j[i]; }
        ++i;
    }
    return val;
}

inline std::string json_extract_str_(const std::string& j, const std::string& k) {
    std::string needle = "\"" + k + "\":\"";
    auto pos = j.find(needle);
    if (pos == std::string::npos) return "";
    pos += needle.size();
    return read_json_str(j, pos);
}

// Parse a flat JSON object with string or boolean values into Fields,
// e.g. fasten_redact output {"key":"val","_pii_in_detail":true}.
inline Fields parse_flat_json_fields(const std::string& json) {
    Fields out;
    if (json.size() < 2) return out;
    size_t i = 0;
    while (i < json.size() && json[i] != '{') ++i;
    if (i >= json.size()) return out;
    ++i;
    while (i < json.size()) {
        while (i < json.size() &&
               (json[i] == ' ' || json[i] == '\n' || json[i] == '\r' ||
                json[i] == '\t' || json[i] == ',')) ++i;
        if (i >= json.size() || json[i] == '}') break;
        if (json[i] != '"') break;
        ++i;
        std::string key = read_json_str(json, i);
        if (i < json.size()) ++i; // skip closing '"'
        while (i < json.size() && (json[i] == ' ' || json[i] == ':')) ++i;
        std::string val;
        if (i < json.size() && json[i] == '"') {
            ++i;
            val = read_json_str(json, i);
            if (i < json.size()) ++i; // skip closing '"'
        } else if (i + 4 <= json.size() && json.substr(i, 4) == "true") {
            val = "true"; i += 4;
        } else if (i + 5 <= json.size() && json.substr(i, 5) == "false") {
            val = "false"; i += 5;
        } else {
            while (i < json.size() && json[i] != ',' && json[i] != '}') ++i;
            continue;
        }
        if (!key.empty()) out[key] = val;
    }
    return out;
}

// Serialize a Meta to JSON for fasten_register_codes.
inline std::string meta_to_codes_json_entry(
    const std::string& key, const Meta& m)
{
    const std::string id  = m.id.empty() ? key : m.id;
    std::string ret;
    switch (m.retention_class) {
        case Retention::Short:  ret = "short";  break;
        case Retention::Medium: ret = "medium"; break;
        case Retention::Long:   ret = "long";   break;
    }
    std::string out = "{";
    out += "\"domain\":"            + json_str(m.domain);
    out += ",\"category\":"         + json_str(m.category);
    out += ",\"action\":"           + json_str(m.action);
    out += ",\"severity\":"         + json_str(sev_str(m.severity));
    out += ",\"description\":"      + json_str(m.description);
    out += ",\"emitter\":"          + json_str(m.emitter);
    out += ",\"id\":"               + json_str(id);
    out += ",\"retention_class\":"  + json_str(ret);
    out += ",\"high_volume\":";     out += (m.high_volume   ? "true" : "false");
    out += ",\"pii_in_detail\":";   out += (m.pii_in_detail ? "true" : "false");
    out += ",\"detail_passthrough_keys\":[";
    bool first = true;
    for (const auto& k : m.detail_passthrough_keys) {
        if (!first) out += ',';
        out += json_str(k); first = false;
    }
    out += "]}";
    return out;
}

// Parse a Meta JSON object returned by fasten_meta_of.
inline Meta parse_meta_json(const std::string& json) {
    Meta m;
    auto extract_str = [&](const std::string& k) { return json_extract_str_(json, k); };
    auto extract_bool = [&](const std::string& k) -> bool {
        return json.find("\"" + k + "\":true") != std::string::npos;
    };
    m.id          = extract_str("id");
    m.domain      = extract_str("domain");
    m.category    = extract_str("category");
    m.action      = extract_str("action");
    m.description = extract_str("description");
    m.emitter     = extract_str("emitter");
    const auto sev = extract_str("severity");
    if      (sev == "debug")    m.severity = Sev::Debug;
    else if (sev == "info")     m.severity = Sev::Info;
    else if (sev == "warn")     m.severity = Sev::Warn;
    else if (sev == "error")    m.severity = Sev::Error;
    else if (sev == "critical") m.severity = Sev::Critical;
    const auto ret = extract_str("retention_class");
    if      (ret == "short")    m.retention_class = Retention::Short;
    else if (ret == "long")     m.retention_class = Retention::Long;
    else                        m.retention_class = Retention::Medium;
    m.high_volume   = extract_bool("high_volume");
    m.pii_in_detail = extract_bool("pii_in_detail");
    const std::string ak = "\"detail_passthrough_keys\":[";
    auto pos = json.find(ak);
    if (pos != std::string::npos) {
        pos += ak.size();
        while (pos < json.size() && json[pos] != ']') {
            if (json[pos] == '"') {
                ++pos;
                std::string k;
                while (pos < json.size() && json[pos] != '"') k += json[pos++];
                if (!k.empty()) m.detail_passthrough_keys.push_back(k);
                if (pos < json.size()) ++pos;
            } else { ++pos; }
        }
    }
    return m;
}

// Bounded, newest-first buffer behind query_syslog() and query_api().
struct RingBuffer {
    size_t             max_;
    std::deque<Fields> buf_;
    mutable std::mutex mu_;

    explicit RingBuffer(size_t max = 2000) : max_(max) {}

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

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        buf_.clear();
    }
};

}  // namespace detail_

// Thrown by emit() in "raise" mode when the audit sink throws. Carries
// only the original message.
struct AuditStoreError : std::runtime_error {
    explicit AuditStoreError(const std::string& msg)
        : std::runtime_error("fasten audit store: " + msg) {}
};

// Returned by queue_stats(). depth counts queued and in-flight rows.
struct QueueStats {
    std::size_t depth                = 0;
    std::size_t capacity             = 0;
    std::size_t high_water           = 0;
    std::size_t drained_total        = 0;
    std::size_t retry_count_active   = 0;
    double      in_backoff_seconds   = 0.0;
    std::string last_error;
    std::size_t dead_lettered_total  = 0;
    std::size_t dead_letter_depth    = 0;
    std::string capacity_semantics   = "block";
};

namespace detail_ {

using SysLog = std::function<void(const std::string&,
                                  const std::string&,
                                  const std::vector<std::pair<std::string, std::string>>&)>;

inline int64_t json_extract_int_(const std::string& j, const std::string& k) {
    std::string needle = "\"" + k + "\":";
    auto pos = j.find(needle);
    if (pos == std::string::npos) return 0;
    pos += needle.size();
    while (pos < j.size() && j[pos] == ' ') ++pos;
    if (pos >= j.size() || j[pos] == '"') return 0;
    std::string num;
    if (j[pos] == '-') { num += '-'; ++pos; }
    while (pos < j.size() && j[pos] >= '0' && j[pos] <= '9') num += j[pos++];
    if (num.empty() || num == "-") return 0;
    return std::stoll(num);
}

inline double json_extract_double_(const std::string& j, const std::string& k) {
    std::string needle = "\"" + k + "\":";
    auto pos = j.find(needle);
    if (pos == std::string::npos) return 0.0;
    pos += needle.size();
    while (pos < j.size() && j[pos] == ' ') ++pos;
    if (pos >= j.size()) return 0.0;
    std::string num;
    if (j[pos] == '-') { num += '-'; ++pos; }
    while (pos < j.size() && ((j[pos] >= '0' && j[pos] <= '9') || j[pos] == '.'))
        num += j[pos++];
    if (num.empty()) return 0.0;
    try { return std::stod(num); } catch (...) { return 0.0; }
}

inline bool json_extract_bool_(const std::string& j, const std::string& k) {
    std::string needle = "\"" + k + "\":";
    auto pos = j.find(needle);
    if (pos == std::string::npos) return false;
    pos += needle.size();
    while (pos < j.size() && j[pos] == ' ') ++pos;
    return pos + 4 <= j.size() && j.substr(pos, 4) == "true";
}

inline Fields json_extract_detail_(const std::string& j) {
    std::string needle = "\"detail\":";
    auto pos = j.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    while (pos < j.size() && (j[pos] == ' ' || j[pos] == '\t')) ++pos;
    if (pos >= j.size() || j[pos] != '{') return {};
    int depth = 0;
    size_t start = pos, end_pos = pos;
    while (pos < j.size()) {
        if      (j[pos] == '{') ++depth;
        else if (j[pos] == '}') { --depth; if (depth == 0) { end_pos = pos + 1; break; } }
        ++pos;
    }
    return parse_flat_json_fields(j.substr(start, end_pos - start));
}

inline Row row_from_json_(const std::string& j) {
    Row r;
    r.wire_version   = json_extract_str_(j, "wire_version");
    r.id             = json_extract_str_(j, "id");
    r.origin_id      = json_extract_str_(j, "origin_id");
    r.monotonic_seq  = json_extract_int_(j, "monotonic_seq");
    r.timestamp      = json_extract_str_(j, "timestamp");
    r.code           = json_extract_str_(j, "code");
    r.action         = json_extract_str_(j, "action");
    r.severity       = json_extract_str_(j, "severity");
    r.service_id     = json_extract_str_(j, "service_id");
    r.source_node_id = json_extract_str_(j, "source_node_id");
    r.tenant_id      = json_extract_str_(j, "tenant_id");
    r.actor          = json_extract_str_(j, "actor");
    r.actor_kind     = json_extract_str_(j, "actor_kind");
    r.target         = json_extract_str_(j, "target");
    r.category       = json_extract_str_(j, "category");
    r.domain         = json_extract_str_(j, "domain");
    r.method         = json_extract_str_(j, "method");
    r.request_id     = json_extract_str_(j, "request_id");
    r.detail         = json_extract_detail_(j);
    r.pii_in_detail  = json_extract_bool_(j, "pii_in_detail");
    r.shipped_at     = json_extract_str_(j, "shipped_at");
    return r;
}

// Keeps the audit sink alive while the drainer thread can call it.
struct SinkRef {
    std::function<void(const Row&)> sink;
};

// Queue mode: rows go to the libfasten_core drainer, whose background
// thread calls the sink with retry and backoff.
class CFastenDrainer {
  public:
    CFastenDrainer(std::function<void(const Row&)> sink,
                   std::size_t               capacity,
                   std::chrono::milliseconds retry_initial,
                   std::chrono::milliseconds retry_max,
                   bool                      retry_jitter,
                   std::size_t               max_attempts = 50) {
        auto* ref = new SinkRef{std::move(sink)};
        char* err = nullptr;
        store_ = fasten_store_from_callback(&CFastenDrainer::bridge_, ref, &err);
        if (!store_) {
            delete ref;
            std::string msg = err ? err : "fasten_store_from_callback failed";
            if (err) fasten_store_free_str(err);
            throw std::runtime_error(msg);
        }
        sink_ref_ = ref;
        int jitter = retry_jitter ? 1 : 0;
        int32_t rc = fasten_drainer_install(
            store_,
            static_cast<uint64_t>(capacity),
            static_cast<uint64_t>(retry_initial.count()),
            static_cast<uint64_t>(retry_max.count()),
            jitter,
            static_cast<uint32_t>(max_attempts),
            &err
        );
        if (rc != 0) {
            std::string msg = err ? err : "fasten_drainer_install failed";
            if (err) fasten_store_free_str(err);
            fasten_store_close(store_);
            delete sink_ref_;
            store_ = nullptr; sink_ref_ = nullptr;
            throw std::runtime_error(msg);
        }
    }

    ~CFastenDrainer() { shutdown(std::chrono::seconds(2)); }

    CFastenDrainer(const CFastenDrainer&)            = delete;
    CFastenDrainer& operator=(const CFastenDrainer&) = delete;

    void put(const Row& row) {
        if (stopped_.load()) return;
        std::string json = row.to_json();
        char* err = nullptr;
        fasten_drainer_enqueue(store_, json.c_str(), &err);
        if (err) fasten_store_free_str(err);
    }

    QueueStats stats() const {
        char* out_json = nullptr;
        char* err      = nullptr;
        fasten_drainer_stats_json(store_, &out_json, &err);
        if (err) fasten_store_free_str(err);
        QueueStats s;
        if (out_json) {
            std::string j(out_json);
            fasten_store_free_str(out_json);
            s.depth               = static_cast<std::size_t>(json_extract_int_(j, "depth"));
            s.capacity            = static_cast<std::size_t>(json_extract_int_(j, "capacity"));
            s.high_water          = static_cast<std::size_t>(json_extract_int_(j, "high_water"));
            s.drained_total       = static_cast<std::size_t>(json_extract_int_(j, "drained_total"));
            s.retry_count_active  = static_cast<std::size_t>(json_extract_int_(j, "retry_count_active"));
            s.in_backoff_seconds  = json_extract_double_(j, "in_backoff_seconds");
            s.last_error          = json_extract_str_(j, "last_error");
            s.dead_lettered_total = static_cast<std::size_t>(json_extract_int_(j, "dead_lettered_total"));
            s.dead_letter_depth   = static_cast<std::size_t>(json_extract_int_(j, "dead_letter_depth"));
            s.capacity_semantics  = json_extract_str_(j, "capacity_semantics");
        }
        return s;
    }

    bool flush(std::chrono::milliseconds timeout) {
        int drained = 0;
        fasten_drainer_flush(store_,
            static_cast<uint64_t>(timeout.count()), &drained, nullptr);
        return drained != 0;
    }

    void shutdown(std::chrono::milliseconds /*timeout*/) {
        if (stopped_.exchange(true)) return;
        fasten_drainer_close(store_);
        delete sink_ref_; sink_ref_ = nullptr;
        fasten_store_close(store_); store_ = nullptr;
    }

  private:
    static int32_t bridge_(const char* row_json, void* userdata) {
        auto* ref = static_cast<SinkRef*>(userdata);
        if (!ref || !row_json) return 1;
        try {
            ref->sink(row_from_json_(std::string(row_json)));
            return 0;
        } catch (...) { return 1; }
    }

    struct FastenStore*  store_    = nullptr;
    SinkRef*             sink_ref_ = nullptr;
    std::atomic<bool>    stopped_{false};
};

// All mutable state. globals() returns one instance per process, however
// many translation units include this header.
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

    std::function<void(const Row&)> audit_sink;
    std::mutex                      sink_mu;

    std::string                     failure_strategy{"queue"};  // "queue" or "raise"
    std::shared_ptr<CFastenDrainer> drainer;  // null in raise mode or with no sink
    std::mutex                      drainer_mu;

    RedactConfig redact_cfg;

    // Reset runtime state between tests: stops the drainer and clears config,
    // seq, the audit sink and the log rings. The code registry is kept.
    void reset_for_tests() {
        {
            std::lock_guard<std::mutex> lk(drainer_mu);
            if (drainer) {
                drainer->shutdown(std::chrono::seconds(2));
                drainer.reset();
            }
        }
        service_id.clear();
        node_id.clear();
        tenant_id.clear();
        { std::lock_guard<std::mutex> lk(seq_mu); seq = 0; }
        failure_strategy = "queue";
        { std::lock_guard<std::mutex> lk(sink_mu); audit_sink = nullptr; }
        redact_cfg = RedactConfig{};
        syslog_ring.clear();
        api_ring.clear();
    }
};

inline Globals& globals() {
    static Globals g;
    return g;
}

// Function-local so every translation unit shares the same thread_local.
inline std::string& tl_request_id() {
    thread_local std::string rid;
    return rid;
}

// Redact detail fields through libfasten_core.
inline Fields redact(const Fields& f) {
    if (f.empty()) return f;
    const auto& cfg = globals().redact_cfg;
    const std::string in_json = fields_to_json(f);
    char* out_json = nullptr;
    char* out_err  = nullptr;
    int32_t rc;
    if (cfg.extra_keys.empty() &&
        (cfg.replacement.empty() || cfg.replacement == fasten::kRedactReplacement)) {
        rc = fasten_redact(in_json.c_str(), &out_json, &out_err);
    } else {
        std::string ek = "[";
        bool first = true;
        for (const auto& k : cfg.extra_keys) {
            if (!first) ek += ',';
            ek += json_str(k); first = false;
        }
        ek += ']';
        const char* repl = cfg.replacement.empty()
            ? nullptr : cfg.replacement.c_str();
        rc = fasten_redact_full(in_json.c_str(),
                                cfg.extra_keys.empty() ? nullptr : ek.c_str(),
                                repl, nullptr,
                                &out_json, &out_err);
    }
    if (out_err) { fasten_store_free_str(out_err); }
    if (rc != 0 || !out_json) {
        if (out_json) fasten_store_free_str(out_json);
        return f; // on error, return original (safe fallback)
    }
    std::string result(out_json);
    fasten_store_free_str(out_json);
    return parse_flat_json_fields(result);
}

} // namespace detail_

inline std::string Row::to_json() const {
    std::string js = "{";
    js += "\"wire_version\":"    + detail_::json_str(wire_version);
    js += ",\"id\":"             + detail_::json_str(id);
    js += ",\"origin_id\":"      + detail_::json_str(origin_id);
    js += ",\"monotonic_seq\":"  + std::to_string(monotonic_seq);
    js += ",\"timestamp\":"      + detail_::json_str(timestamp);
    js += ",\"code\":"           + detail_::json_str(code);
    js += ",\"action\":"         + detail_::json_str(action);
    js += ",\"severity\":"       + detail_::json_str(severity);
    js += ",\"service_id\":"     + detail_::json_str(service_id);
    js += ",\"source_node_id\":" + detail_::json_str(source_node_id);
    js += ",\"tenant_id\":"      + (tenant_id.empty() ? "null" : detail_::json_str(tenant_id));
    js += ",\"actor\":"          + detail_::json_str(actor);
    js += ",\"actor_kind\":"     + detail_::json_str(actor_kind);
    js += ",\"target\":"         + detail_::json_str(target);
    js += ",\"category\":"       + detail_::json_str(category);
    js += ",\"domain\":"         + detail_::json_str(domain);
    js += ",\"method\":"         + detail_::json_str(method);
    js += ",\"request_id\":"     + detail_::json_str(request_id);
    js += ",\"detail\":"         + detail_::fields_to_json(detail);
    js += ",\"pii_in_detail\":";
    js += (pii_in_detail ? "true" : "false");
    if (!shipped_at.empty()) {
        js += ",\"shipped_at\":" + detail_::json_str(shipped_at);
    }
    js += "}";
    return js;
}

inline std::string Row::to_cloud_event_json() const {
    // CloudEvents 1.0 envelope. `data` holds detail plus actor, target,
    // method, request_id and pii_in_detail.
    std::string data = "{";
    bool first = true;
    for (auto& kv : detail) {
        if (!first) data += ',';
        data += detail_::json_str(kv.first) + ':';
        if (kv.first == "_pii_in_detail") {
            data += (kv.second == "true" ? "true" : "false");
        } else {
            data += detail_::json_str(kv.second);
        }
        first = false;
    }
    if (!first) data += ',';
    data += "\"actor\":"          + detail_::json_str(actor);
    data += ",\"actor_kind\":"    + detail_::json_str(actor_kind);
    data += ",\"target\":"        + detail_::json_str(target);
    data += ",\"method\":"        + detail_::json_str(method);
    data += ",\"request_id\":"    + detail_::json_str(request_id);
    // Lets consumers apply retention and access rules without reading detail.
    data += ",\"pii_in_detail\":";
    data += (pii_in_detail ? "true" : "false");
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

namespace detail_ {

// Validate and register in libfasten_core, then cache the stored Meta here.
template<typename CodesRange>
inline void register_codes_impl(
    const Domain& domain, const CodesRange& codes)
{
    for (const auto& kv : codes) {
        if (kv.second.pii_in_detail &&
            kv.second.retention_class != Retention::Short) {
            std::cerr << "fasten: code " << kv.first
                      << " has pii_in_detail=true; retention_class forced to short (was "
                      << fasten::to_string(kv.second.retention_class) << ").\n";
        }
    }

    std::string codes_json = "{";
    bool first = true;
    for (const auto& kv : codes) {
        if (!first) codes_json += ',';
        codes_json += json_str(kv.first) + ':' +
                      meta_to_codes_json_entry(kv.first, kv.second);
        first = false;
    }
    codes_json += '}';

    char* out_err = nullptr;
    const int32_t rc = fasten_register_codes(
        domain.c_str(), codes_json.c_str(), &out_err);
    std::string err_msg;
    if (out_err) {
        err_msg = out_err;
        fasten_store_free_str(out_err);
    }
    if (rc != 0) throw AuditCatalogError(err_msg.empty() ? "register_codes failed" : err_msg);

    // Read back what the core stored (id filled in, retention forced to
    // short for pii_in_detail codes).
    auto& g = globals();
    std::lock_guard<std::mutex> lk(g.reg_mu);
    for (const auto& kv : codes) {
        char* meta_json = nullptr;
        char* meta_err  = nullptr;
        if (fasten_meta_of(kv.first.c_str(), &meta_json, &meta_err) == 0 &&
            meta_json) {
            const std::string mj(meta_json);
            fasten_store_free_str(meta_json);
            if (mj != "{}") g.registry[kv.first] = parse_meta_json(mj);
        }
        if (meta_err) fasten_store_free_str(meta_err);
    }
}

}  // namespace detail_

inline void register_codes(
    const Domain& domain,
    std::initializer_list<std::pair<std::string, Meta>> codes)
{
    detail_::register_codes_impl(domain, codes);
}

// For code tables built at runtime.
inline void register_codes(
    const Domain& domain,
    const std::vector<std::pair<std::string, Meta>>& codes)
{
    detail_::register_codes_impl(domain, codes);
}

// Return a snapshot of the current catalog.
inline std::unordered_map<std::string, Meta> registry() {
    auto& g = detail_::globals();
    std::lock_guard<std::mutex> lk(g.reg_mu);
    return g.registry;
}

// The catalog as sorted "id,domain,severity" lines, for comparing catalogs.
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

// The process-wide state that init(), emit() and the other free functions
// use. Tests call fasten::default_engine().reset_for_tests() between cases.
using Engine = detail_::Globals;

inline Engine& default_engine() { return detail_::globals(); }

struct Config {
    std::string              service_id;
    std::string              node_id;
    std::string              tenant_id;           // optional

    std::vector<std::string> extra_redact_keys;   // added to the built-in patterns; env FASTEN_REDACT_KEYS
    std::string              redact_replacement;  // default "***"; env FASTEN_REDACT_REPLACEMENT

    // "queue" (default): emit() queues the row and a background thread calls
    //   the audit sink, retrying with exponential backoff if it throws.
    // "raise": emit() calls the sink directly and throws AuditStoreError if
    //   it fails.
    // Empty means env FASTEN_AUDIT_STORE_FAILURE_STRATEGY, then "queue".
    std::string              audit_store_failure_strategy;
    std::size_t              queue_capacity        = 100;   // queued + in-flight
    int                      queue_retry_initial_ms = 100;
    int                      queue_retry_max_ms     = 60000;
    bool                     disable_queue_jitter   = false; // false = jitter ON
};

inline void install_drainer_(const Config& cfg);

inline void init(Config cfg = {}) {
    using detail_::env_or;
    auto& g = detail_::globals();
    g.service_id = cfg.service_id.empty() ? env_or("FASTEN_SERVICE_ID") : cfg.service_id;
    g.node_id    = cfg.node_id.empty()    ? env_or("FASTEN_NODE_ID")    : cfg.node_id;
    g.tenant_id  = cfg.tenant_id.empty()  ? env_or("FASTEN_TENANT_ID")  : cfg.tenant_id;

    if (g.service_id.empty() || g.node_id.empty()) {
        throw InitError("init: FASTEN_SERVICE_ID and FASTEN_NODE_ID are required");
    }

    if (!cfg.extra_redact_keys.empty()) {
        g.redact_cfg.extra_keys = cfg.extra_redact_keys;
    } else {
        // Comma-separated, whitespace trimmed.
        std::string env_keys = env_or("FASTEN_REDACT_KEYS", "");
        if (!env_keys.empty()) {
            std::stringstream ss(env_keys);
            std::string tok;
            while (std::getline(ss, tok, ',')) {
                size_t a = tok.find_first_not_of(" \t");
                size_t b = tok.find_last_not_of(" \t");
                if (a != std::string::npos) g.redact_cfg.extra_keys.push_back(tok.substr(a, b - a + 1));
            }
        }
    }
    g.redact_cfg.replacement = cfg.redact_replacement.empty()
        ? env_or("FASTEN_REDACT_REPLACEMENT", g.redact_cfg.replacement.c_str())
        : cfg.redact_replacement;

    std::string strategy = cfg.audit_store_failure_strategy;
    if (strategy.empty()) strategy = env_or("FASTEN_AUDIT_STORE_FAILURE_STRATEGY", "queue");
    if (strategy != "queue" && strategy != "raise") {
        throw InitError("init: audit_store_failure_strategy must be \"queue\" or \"raise\"");
    }
    g.failure_strategy = strategy;
    install_drainer_(cfg);
}

// Shorthand for init(Config{...}) with only the ids set.
inline void init(std::string service_id,
                 std::string node_id,
                 std::string tenant_id = "") {
    Config cfg;
    cfg.service_id = std::move(service_id);
    cfg.node_id    = std::move(node_id);
    cfg.tenant_id  = std::move(tenant_id);
    init(std::move(cfg));
}

// Called with every emitted Row, e.g. to write it to SQLite or PostgreSQL.
// In queue mode the drainer thread calls the sink that was set when init()
// ran; if none was, emit() calls the current sink directly and
// reports its failures as sys events instead of throwing.
using AuditSink = std::function<void(const Row&)>;

inline void set_audit_sink(AuditSink sink) {
    auto& g = detail_::globals();
    std::lock_guard<std::mutex> lk(g.sink_mu);
    g.audit_sink = std::move(sink);
}

namespace detail_ {

// Write a {"shape":"sys"} NDJSON line to `out` and add it to the sys ring.
// `fields` is written as given; callers redact first if needed.
template <typename KeyValues>
inline void write_sys_line(std::ostream& out,
                           const std::string& level,
                           const std::string& event,
                           const KeyValues& fields) {
    auto& g = globals();
    Fields ring_row;
    std::string js = "{\"shape\":\"sys\"";
    js += ",\"level\":"      + json_str(level);
    js += ",\"event\":"      + json_str(event);
    js += ",\"request_id\":" + json_str(tl_request_id());
    js += ",\"service_id\":" + json_str(g.service_id);
    js += ",\"timestamp\":"  + json_str(now_iso8601());
    for (const auto& kv : fields) {
        js += ',' + json_str(kv.first) + ':' + json_str(kv.second);
        ring_row[kv.first] = kv.second;
    }
    js += "}\n";
    ring_row["level"]      = level;
    ring_row["event"]      = event;
    ring_row["request_id"] = tl_request_id();
    g.syslog_ring.push(std::move(ring_row));
    out << js << std::flush;
}

// SDK self-reports go to stderr so a slow stdout reader can't stall them.
inline void drainer_sys_log(const std::string& level,
                            const std::string& event,
                            const std::vector<std::pair<std::string, std::string>>& fields) {
    write_sys_line(std::cerr, level, event, fields);
}

}  // namespace detail_

inline void install_drainer_(const Config& cfg) {
    auto& g = detail_::globals();
    // Swap in the new drainer under the lock, then flush and stop the old
    // one outside it so emit() isn't blocked for up to 7 s. A put() that
    // reaches the old drainer after shutdown is dropped.
    std::shared_ptr<detail_::CFastenDrainer> next;
    if (g.failure_strategy == "queue") {
        std::function<void(const Row&)> sink_copy;
        {
            std::lock_guard<std::mutex> sk(g.sink_mu);
            sink_copy = g.audit_sink;
        }
        if (sink_copy) {
            next = std::make_shared<detail_::CFastenDrainer>(
                std::move(sink_copy),
                cfg.queue_capacity,
                std::chrono::milliseconds(cfg.queue_retry_initial_ms),
                std::chrono::milliseconds(cfg.queue_retry_max_ms),
                !cfg.disable_queue_jitter);
        }
    }
    std::shared_ptr<detail_::CFastenDrainer> old;
    {
        std::lock_guard<std::mutex> lk(g.drainer_mu);
        old = g.drainer;
        g.drainer = next;
    }
    if (old) {
        old->flush(std::chrono::seconds(5));
        old->shutdown(std::chrono::seconds(2));
    }
}

// Drainer stats, or nullptr when no drainer is running (raise mode, or no
// sink at init()).
inline std::unique_ptr<QueueStats> queue_stats() {
    auto& g = detail_::globals();
    std::lock_guard<std::mutex> lk(g.drainer_mu);
    if (!g.drainer) return nullptr;
    return std::unique_ptr<QueueStats>(new QueueStats(g.drainer->stats()));
}

// Wait until queued audit rows are written or the timeout passes. Returns
// true if everything drained, and true at once when no drainer is running.
inline bool flush(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)) {
    auto& g = detail_::globals();
    std::shared_ptr<detail_::CFastenDrainer> d;
    {
        std::lock_guard<std::mutex> lk(g.drainer_mu);
        d = g.drainer;
    }
    if (!d) return true;
    return d->flush(timeout);
}

// Stop the drainer; rows still queued get one last attempt without retries.
// Afterwards emit() calls the sink directly.
inline void uninstall_drainer() {
    auto& g = detail_::globals();
    std::shared_ptr<detail_::CFastenDrainer> old;
    {
        std::lock_guard<std::mutex> lk(g.drainer_mu);
        old = g.drainer;
        g.drainer.reset();
    }
    if (old) {
        old->shutdown(std::chrono::seconds(2));
    }
}

// New 12-char hex request id.
inline std::string mint_id() {
    return detail_::mint_id_bytes(6);
}

// Set the request id for the current thread. RequestScope also restores
// the previous one.
inline void set_request_id(const std::string& id) {
    detail_::tl_request_id() = id;
}

inline std::string current_request_id() {
    return detail_::tl_request_id();
}

// Sets the thread's request_id and restores the previous one on exit.
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

// Options for emit(), set with target(), actor(), detail() and method().
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
    // Apply each option in order (C++14 has no fold expressions).
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
    row.pii_in_detail  = meta.pii_in_detail;

    // For pii_in_detail codes only detail_passthrough_keys are kept, and
    // those still go through the redactor.
    if (meta.pii_in_detail) {
        Fields kept;
        for (const auto& k : meta.detail_passthrough_keys) {
            auto it = o.fields.find(k);
            if (it != o.fields.end()) kept[k] = it->second;
        }
        row.detail = detail_::redact(kept);
        row.detail["_redacted"]      = kRedactReplacement;
        row.detail["_pii_in_detail"] = "true";
    } else {
        row.detail = detail_::redact(o.fields);
    }

    // NDJSON audit line on stdout: the row's JSON with "shape" first.
    std::cout << "{\"shape\":\"audit\"," << row.to_json().substr(1) << "\n"
              << std::flush;

    {
        std::shared_ptr<detail_::CFastenDrainer> drainer_copy;
        {
            std::lock_guard<std::mutex> lk(g.drainer_mu);
            drainer_copy = g.drainer;
        }
        if (drainer_copy && g.failure_strategy == "queue") {
            drainer_copy->put(row);
        } else {
            std::function<void(const Row&)> sink_copy;
            {
                std::lock_guard<std::mutex> lk(g.sink_mu);
                sink_copy = g.audit_sink;
            }
            if (sink_copy) {
                if (g.failure_strategy == "raise") {
                    try {
                        sink_copy(row);
                    } catch (const std::exception& e) {
                        throw AuditStoreError(e.what());
                    } catch (...) {
                        throw AuditStoreError("unknown exception");
                    }
                } else {
                    // Queue mode with no drainer (no sink at init()): call
                    // the sink here and report failures as sys events.
                    try {
                        sink_copy(row);
                    } catch (const std::exception& e) {
                        detail_::drainer_sys_log("error",
                            "audit_sync_fallback_failed",
                            {{"error", e.what()},
                             {"row_id", row.id}});
                    } catch (...) {
                        detail_::drainer_sys_log("error",
                            "audit_sync_fallback_failed",
                            {{"error", "unknown exception"},
                             {"row_id", row.id}});
                    }
                }
            }
        }
    }

    return row;
}

// Newest-first reads of the in-process log buffers.
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

// Structured logs: redacted {"shape":"sys"} lines on stdout, also kept
// for query_syslog().
namespace log {

inline void _write(const std::string& level, const std::string& event,
                   const Fields& fields)
{
    detail_::write_sys_line(std::cout, level, event, detail_::redact(fields));
}

inline void debug(const std::string& event, const Fields& f = {}) { _write("debug",    event, f); }
inline void info (const std::string& event, const Fields& f = {}) { _write("info",     event, f); }
inline void warn (const std::string& event, const Fields& f = {}) { _write("warn",     event, f); }
inline void error(const std::string& event, const Fields& f = {}) { _write("error",    event, f); }

} // namespace log

namespace scheduler {

// Scope for one scheduled job run, with request id run_id or a new
// "scheduler-<hex>" id.
//
//   auto scope = fasten::scheduler::job_run();
//   fasten::emit("JOB_STARTED", ...);
inline RequestScope job_run(const std::string& run_id = "") {
    std::string rid = run_id.empty()
        ? "scheduler-" + detail_::mint_id_bytes(4)
        : run_id;
    return RequestScope(std::move(rid));
}

} // namespace scheduler

} // namespace fasten
