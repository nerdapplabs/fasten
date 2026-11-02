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

// Canonical UTC timestamp (spec §4.3): six fractional digits and Z, e.g.
// 2026-08-21T10:00:00.500000Z. Thread-safe (gmtime_r / gmtime_s).
inline std::string now_iso8601() {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto us  = duration_cast<microseconds>(now.time_since_epoch()) % 1000000;
    auto t   = system_clock::to_time_t(now);
    struct tm tmb {};
#ifdef _WIN32
    gmtime_s(&tmb, &t);
#else
    gmtime_r(&t, &tmb);
#endif
    char buf[64];
    std::snprintf(buf, sizeof(buf),
        "%04d-%02d-%02dT%02d:%02d:%02d.%06lldZ",
        tmb.tm_year + 1900, tmb.tm_mon + 1, tmb.tm_mday,
        tmb.tm_hour, tmb.tm_min, tmb.tm_sec,
        static_cast<long long>(us.count()));
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

// Appends the character a JSON escape stands for. pos is on the character
// after the backslash and is left on the escape's last character. A "u"
// escape with four hex digits, or a surrogate pair of them, is written as UTF-8.
inline void json_unescape_(const std::string& j, size_t& pos, std::string& out) {
    auto hex4 = [&j](size_t at, unsigned& cp) {
        if (at + 4 > j.size()) return false;
        cp = 0;
        for (size_t k = at; k < at + 4; ++k) {
            char c = j[k];
            cp <<= 4;
            if      (c >= '0' && c <= '9') cp |= static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') cp |= static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') cp |= static_cast<unsigned>(c - 'A' + 10);
            else return false;
        }
        return true;
    };
    switch (j[pos]) {
        case 'n': out += '\n'; return;
        case 'r': out += '\r'; return;
        case 't': out += '\t'; return;
        case 'b': out += '\b'; return;
        case 'f': out += '\f'; return;
        case 'u': break;
        default:  out += j[pos]; return;  // " \\ / and anything else
    }
    unsigned cp = 0;
    if (!hex4(pos + 1, cp)) { out += 'u'; return; }
    pos += 4;
    unsigned lo = 0;
    if (cp >= 0xD800 && cp < 0xDC00 && pos + 6 < j.size() &&
        j[pos + 1] == '\\' && j[pos + 2] == 'u' && hex4(pos + 3, lo) &&
        lo >= 0xDC00 && lo < 0xE000) {
        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
        pos += 6;
    }
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

// Read a string body starting just after its opening quote, unescaping it
// with json_unescape_. Leaves `i` on the closing quote.
inline std::string read_json_str(const std::string& j, size_t& i) {
    std::string val;
    while (i < j.size() && j[i] != '"') {
        if (j[i] == '\\' && i + 1 < j.size()) {
            ++i;
            json_unescape_(j, i, val);
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

// The members of a JSON object, each value as its raw text. Strings and
// nested values are skipped whole, so a key inside "detail" is never read as
// a column.
inline std::unordered_map<std::string, std::string> json_members_(const std::string& j) {
    std::unordered_map<std::string, std::string> out;
    size_t i = j.find('{');
    if (i == std::string::npos) return out;
    ++i;
    auto skip_ws = [&] {
        while (i < j.size() && (j[i] == ' ' || j[i] == '\t' || j[i] == '\n' || j[i] == '\r')) ++i;
    };
    auto skip_string = [&] {  // at the opening quote
        for (++i; i < j.size() && j[i] != '"'; ++i)
            if (j[i] == '\\') ++i;
        ++i;
    };
    while (true) {
        skip_ws();
        if (i >= j.size() || j[i] != '"') break;
        size_t key_start = i + 1;
        skip_string();
        if (i > j.size()) break;
        std::string key = j.substr(key_start, i - 1 - key_start);
        skip_ws();
        if (i >= j.size() || j[i] != ':') break;
        ++i;
        skip_ws();
        size_t val_start = i;
        if (i < j.size() && j[i] == '"') {
            skip_string();
        } else if (i < j.size() && (j[i] == '{' || j[i] == '[')) {
            int depth = 0;
            while (i < j.size()) {
                if (j[i] == '"') { skip_string(); continue; }
                if (j[i] == '{' || j[i] == '[') ++depth;
                else if ((j[i] == '}' || j[i] == ']') && --depth == 0) { ++i; break; }
                ++i;
            }
        } else {
            while (i < j.size() && j[i] != ',' && j[i] != '}') ++i;
        }
        if (i > j.size()) break;
        std::string val = j.substr(val_start, i - val_start);
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t' ||
                                val.back() == '\n' || val.back() == '\r')) val.pop_back();
        out[key] = val;
        skip_ws();
        if (i >= j.size() || j[i] != ',') break;
        ++i;
    }
    return out;
}

inline Row row_from_json_(const std::string& j) {
    const auto m = json_members_(j);
    auto raw = [&](const char* k) {
        auto it = m.find(k);
        return it == m.end() ? std::string() : it->second;
    };
    // null or absent reads as "".
    auto str = [&](const char* k) -> std::string {
        std::string v = raw(k);
        if (v.empty() || v[0] != '"') return {};
        size_t i = 1;
        return read_json_str(v, i);
    };
    Row r;
    r.wire_version   = str("wire_version");
    r.id             = str("id");
    r.origin_id      = str("origin_id");
    try { r.monotonic_seq = std::stoll(raw("monotonic_seq")); } catch (...) {}
    r.timestamp      = str("timestamp");
    r.code           = str("code");
    r.action         = str("action");
    r.severity       = str("severity");
    r.service_id     = str("service_id");
    r.source_node_id = str("source_node_id");
    r.tenant_id      = str("tenant_id");
    r.actor          = str("actor");
    r.actor_kind     = str("actor_kind");
    r.target         = str("target");
    r.category       = str("category");
    r.domain         = str("domain");
    r.method         = str("method");
    r.request_id     = str("request_id");
    r.detail         = parse_flat_json_fields(raw("detail"));
    r.pii_in_detail  = raw("pii_in_detail") == "true";
    r.shipped_at     = str("shipped_at");
    return r;
}

// Keeps the audit sink alive while the drainer thread can call it.
struct SinkRef {
    std::function<void(const Row&)> sink;
};

inline void drainer_sys_log(const std::string& level,
                            const std::string& event,
                            const std::vector<std::pair<std::string, std::string>>& fields);

// Queue mode: rows go to the libfasten_core drainer, whose background
// thread calls the sink with retry and backoff.
//
// Every call that uses store_ is counted in busy_ (see Use). shutdown() first
// closes the core drainer, which wakes a put() blocked on a full queue and
// drains with one attempt per row, then waits for busy_ to reach 0 before it
// frees store_. A put() that starts after stopped_ is set, including one made
// by the sink while the drain finishes, never touches store_. Closing while a
// call is still inside the core needs a core where calls in progress keep
// their drainer (fasten-core #161).
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

    // Returns false if the row was not queued, so the caller can store it
    // itself (spec §10). Each refusal is reported once: the core reports the
    // rows it refuses at stop, and this reports the rest.
    bool put(const Row& row) {
        Use use(*this);
        if (!use.ok) {
            drainer_sys_log("error", "audit_drain_abandoned",
                {{"reason", "drainer_stopped"}, {"row_id", row.id}});
            return false;
        }
        std::string json = row.to_json();
        char* err = nullptr;
        int32_t rc = fasten_drainer_enqueue(store_, json.c_str(), &err);
        if (rc != 0 && rc != kErrDrainerStopped) {
            drainer_sys_log("error", "audit_drain_abandoned",
                {{"reason", err ? err : "enqueue failed"}, {"row_id", row.id}});
        }
        if (err) fasten_store_free_str(err);
        return rc == 0;
    }

    QueueStats stats() const {
        Use use(*this);
        QueueStats s;
        if (!use.ok) return s;
        char* out_json = nullptr;
        char* err      = nullptr;
        fasten_drainer_stats_json(store_, &out_json, &err);
        if (err) fasten_store_free_str(err);
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
        Use use(*this);
        if (!use.ok) return true;
        int drained = 0;
        fasten_drainer_flush(store_,
            static_cast<uint64_t>(timeout.count()), &drained, nullptr);
        return drained != 0;
    }

    void shutdown(std::chrono::milliseconds /*timeout*/) {
        if (stopped_.exchange(true)) return;
        fasten_drainer_close(store_);
        {
            std::unique_lock<std::mutex> lk(mu_);
            idle_.wait(lk, [this] { return busy_.load() == 0; });
        }
        delete sink_ref_; sink_ref_ = nullptr;
        fasten_store_close(store_); store_ = nullptr;
    }

  private:
    // fasten_drainer_enqueue's FASTEN_ERR_DRAINER_STOPPED: the drainer is
    // stopping, the row was not queued, and the core has reported it.
    static constexpr int32_t kErrDrainerStopped = 10;

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

    // Counts a call in busy_ for its lifetime; ok is false once stopped_ is
    // set. Incrementing before reading stopped_ (both seq_cst) means
    // shutdown() either sees this call in busy_ or this call sees stopped_.
    struct Use {
        const CFastenDrainer& d;
        bool ok;
        explicit Use(const CFastenDrainer& owner) : d(owner) {
            ++d.busy_;
            ok = !d.stopped_.load();
        }
        ~Use() {
            std::lock_guard<std::mutex> lk(d.mu_);
            if (--d.busy_ == 0) d.idle_.notify_all();
        }
    };
    mutable std::atomic<int>        busy_{0};
    mutable std::mutex              mu_;
    mutable std::condition_variable idle_;
};

// All mutable state. globals() returns one instance per process, however
// many translation units include this header.
struct Globals {
    std::mutex                            reg_mu;
    std::unordered_map<std::string, Meta> registry;

    // init() replaces the strings guarded by cfg_mu while other threads may
    // be emitting or logging, so readers copy them under it (identity(),
    // strategy(), redaction()) and a re-init can't free one mid-copy.
    mutable std::mutex cfg_mu;
    std::string service_id;
    std::string node_id;
    std::string tenant_id;

    RingBuffer syslog_ring;
    RingBuffer api_ring;

    // Sys rows with no request in scope carry this until the first real
    // request_id is seen (spec persistent-streams §7). Set by init(), guarded
    // by cfg_mu.
    std::string       boot_request_id;
    std::atomic<bool> boot_over{false};

    std::function<void(const Row&)> audit_sink;
    std::mutex                      sink_mu;

    std::string                     failure_strategy{"queue"};  // "queue" or "raise"
    std::shared_ptr<CFastenDrainer> drainer;  // null in raise mode or with no sink
    std::mutex                      drainer_mu;

    RedactConfig redact_cfg;

    struct Identity {
        std::string service_id;
        std::string node_id;
        std::string tenant_id;
    };

    Identity identity() const {
        std::lock_guard<std::mutex> lk(cfg_mu);
        return Identity{service_id, node_id, tenant_id};
    }

    std::string strategy() const {
        std::lock_guard<std::mutex> lk(cfg_mu);
        return failure_strategy;
    }

    RedactConfig redaction() const {
        std::lock_guard<std::mutex> lk(cfg_mu);
        return redact_cfg;
    }

    // Reset runtime state between tests: stops the drainer and clears config,
    // seq, the audit sink and the log rings. The code registry is kept.
    void reset_for_tests() {
        // Shut down outside drainer_mu, as uninstall_drainer() does: a sink
        // that emits during the final drain needs it.
        std::shared_ptr<CFastenDrainer> old;
        {
            std::lock_guard<std::mutex> lk(drainer_mu);
            old.swap(drainer);
        }
        if (old) old->shutdown(std::chrono::seconds(2));
        {
            std::lock_guard<std::mutex> lk(cfg_mu);
            service_id.clear();
            node_id.clear();
            tenant_id.clear();
            failure_strategy = "queue";
            redact_cfg = RedactConfig{};
            boot_request_id.clear();
        }
        { std::lock_guard<std::mutex> lk(sink_mu); audit_sink = nullptr; }
        syslog_ring.clear();
        api_ring.clear();
        boot_over = false;
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

// Sentinel request_ids (spec persistent-streams §7), recognised by prefix.
inline bool is_sentinel(const std::string& rid) {
    for (const char* p : {"boot-", "sched-", "bg-", "lib-", "orphan-"}) {
        if (rid.compare(0, std::char_traits<char>::length(p), p) == 0) return true;
    }
    return false;
}

inline std::string mint_sentinel(const std::string& kind, const std::string& svc) {
    return kind + "-" + (svc.empty() ? "svc" : svc) + "-" + mint_id_bytes(6);
}

// The request_id for a sys row: the one in scope, else the boot sentinel until
// a real id has been seen, else a fresh orphan sentinel. Never empty.
inline std::string sys_request_id() {
    auto& g = globals();
    const std::string& rid = tl_request_id();
    if (!rid.empty()) {
        if (!is_sentinel(rid)) g.boot_over = true;
        return rid;
    }
    if (!g.boot_over) {
        std::lock_guard<std::mutex> lk(g.cfg_mu);
        if (!g.boot_request_id.empty()) return g.boot_request_id;
    }
    return mint_sentinel("orphan", g.identity().service_id);
}

// Adds a sys row to the ring with its request_id and the engine's tenant_id,
// so a tenant-scoped reader can return it.
inline void push_sys_row(Fields row) {
    auto& g = globals();
    auto rid = row.find("request_id");
    if (rid == row.end() || rid->second.empty()) row["request_id"] = sys_request_id();
    const std::string tenant = g.identity().tenant_id;
    if (!tenant.empty() && !row.count("tenant_id")) row["tenant_id"] = tenant;
    g.syslog_ring.push(std::move(row));
}

// Redact detail fields through libfasten_core.
inline Fields redact(const Fields& f) {
    if (f.empty()) return f;
    const RedactConfig cfg = globals().redaction();
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
    std::size_t              queue_drain_max_attempts = 50;  // then dead-letter
};

inline void install_drainer_(const Config& cfg);

inline void init(Config cfg = {}) {
    using detail_::env_or;
    auto& g = detail_::globals();
    std::string service_id = cfg.service_id.empty() ? env_or("FASTEN_SERVICE_ID") : cfg.service_id;
    std::string node_id    = cfg.node_id.empty()    ? env_or("FASTEN_NODE_ID")    : cfg.node_id;
    std::string tenant_id  = cfg.tenant_id.empty()  ? env_or("FASTEN_TENANT_ID")  : cfg.tenant_id;

    if (service_id.empty() || node_id.empty()) {
        throw InitError("init: FASTEN_SERVICE_ID and FASTEN_NODE_ID are required");
    }

    detail_::RedactConfig redact_cfg = g.redaction();
    if (!cfg.extra_redact_keys.empty()) {
        redact_cfg.extra_keys = cfg.extra_redact_keys;
    } else {
        // Comma-separated, whitespace trimmed.
        std::string env_keys = env_or("FASTEN_REDACT_KEYS", "");
        if (!env_keys.empty()) {
            std::stringstream ss(env_keys);
            std::string tok;
            while (std::getline(ss, tok, ',')) {
                size_t a = tok.find_first_not_of(" \t");
                size_t b = tok.find_last_not_of(" \t");
                if (a != std::string::npos) redact_cfg.extra_keys.push_back(tok.substr(a, b - a + 1));
            }
        }
    }
    redact_cfg.replacement = cfg.redact_replacement.empty()
        ? env_or("FASTEN_REDACT_REPLACEMENT", redact_cfg.replacement.c_str())
        : cfg.redact_replacement;

    std::string strategy = cfg.audit_store_failure_strategy;
    if (strategy.empty()) strategy = env_or("FASTEN_AUDIT_STORE_FAILURE_STRATEGY", "queue");
    if (strategy != "queue" && strategy != "raise") {
        throw InitError("init: audit_store_failure_strategy must be \"queue\" or \"raise\"");
    }

    std::string boot_id = detail_::mint_sentinel("boot", service_id);
    {
        std::lock_guard<std::mutex> lk(g.cfg_mu);
        g.service_id       = std::move(service_id);
        g.node_id          = std::move(node_id);
        g.tenant_id        = std::move(tenant_id);
        g.redact_cfg       = std::move(redact_cfg);
        g.failure_strategy = std::move(strategy);
        g.boot_request_id  = std::move(boot_id);
    }
    g.boot_over = false;
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
    const auto id = globals().identity();
    const std::string rid = sys_request_id();
    Fields ring_row;
    std::string js = "{\"shape\":\"sys\"";
    js += ",\"level\":"      + json_str(level);
    js += ",\"event\":"      + json_str(event);
    js += ",\"request_id\":" + json_str(rid);
    js += ",\"service_id\":" + json_str(id.service_id);
    if (!id.tenant_id.empty()) js += ",\"tenant_id\":" + json_str(id.tenant_id);
    js += ",\"timestamp\":"  + json_str(now_iso8601());
    for (const auto& kv : fields) {
        js += ',' + json_str(kv.first) + ':' + json_str(kv.second);
        ring_row[kv.first] = kv.second;
    }
    js += "}\n";
    ring_row["level"]      = level;
    ring_row["event"]      = event;
    ring_row["request_id"] = rid;
    push_sys_row(std::move(ring_row));
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
    // reaches the old drainer after shutdown is refused (an
    // audit_drain_abandoned sys event) and the row is stored synchronously.
    std::shared_ptr<detail_::CFastenDrainer> next;
    if (g.strategy() == "queue") {
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
                !cfg.disable_queue_jitter,
                cfg.queue_drain_max_attempts);
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
    const auto id = g.identity();
    if (id.service_id.empty()) {
        throw InitError("emit: fasten::init() must be called first");
    }
    const std::string strategy = g.strategy();

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

    std::string rid = detail_::tl_request_id();
    if (rid.empty()) rid = mint_id();
    else if (!detail_::is_sentinel(rid)) g.boot_over = true;

    Row row;
    row.id             = "evt-" + detail_::mint_id_bytes(10);
    row.origin_id      = row.id;
    // Spec §2.1 / §8: the store allocates seq; emit() never makes one up.
    row.monotonic_seq  = 0;
    row.timestamp      = detail_::now_iso8601();
    row.code           = code;
    row.action         = meta.action;
    row.severity       = detail_::sev_str(meta.severity);
    row.service_id     = id.service_id;
    row.source_node_id = id.node_id;
    row.tenant_id      = id.tenant_id;
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
        // A row the drainer refuses (a re-init stopped it) is stored below.
        const bool offered = drainer_copy && strategy == "queue";
        const bool queued  = offered && drainer_copy->put(row);
        if (!queued) {
            std::function<void(const Row&)> sink_copy;
            {
                std::lock_guard<std::mutex> lk(g.sink_mu);
                sink_copy = g.audit_sink;
            }
            if (sink_copy) {
                if (strategy == "raise") {
                    try {
                        sink_copy(row);
                    } catch (const std::exception& e) {
                        throw AuditStoreError(e.what());
                    } catch (...) {
                        throw AuditStoreError("unknown exception");
                    }
                } else {
                    // Queue mode with no drainer (sink registered after
                    // init()), or the drainer refused the row: call the
                    // sink here and report failures as sys events.
                    try {
                        sink_copy(row);
                        if (offered) {
                            // Follows the abandoned event.
                            detail_::drainer_sys_log("info",
                                "audit_drain_stored_inline",
                                {{"row_id", row.id}});
                        }
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
// "sched-<hex>" id (spec §7).
//
//   auto scope = fasten::scheduler::job_run();
//   fasten::emit("JOB_STARTED", ...);
inline RequestScope job_run(const std::string& run_id = "") {
    std::string rid = run_id.empty()
        ? "sched-" + detail_::mint_id_bytes(6)
        : run_id;
    return RequestScope(std::move(rid));
}

} // namespace scheduler

} // namespace fasten
