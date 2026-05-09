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

// ── libfasten_store_core C ABI ─────────────────────────────────────────────
// Forward-declare the Rust shared library functions so fasten.hpp stays
// self-contained. Link with -lfasten_store_core at build time.
extern "C" {
    // All catalog + redaction functions return int32_t (0 = OK).
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
}

namespace fasten {

// ── Types ──────────────────────────────────────────────────────────────────

// Domain is a plain string — adopters define their own vocabulary.
// Examples: "node", "user", "billing", "device" — fasten has no opinions.
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
    // `id` is optional in adopter code — `register_codes()` fills it from
    // the registry key. Setting `id` explicitly is allowed but must match
    // the key (mismatch is a typo, never a feature).
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
    // P1-5: detail keys that survive force-redact when pii_in_detail=true.
    // Each surviving value still passes through the secret-key redactor.
    std::vector<std::string> detail_passthrough_keys;
};

// ── Row ────────────────────────────────────────────────────────────────────

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

// Serialize Fields to a JSON object — keys sorted for deterministic output.
//
// `_pii_in_detail` is the one cross-language P1-5 marker: Fields can only
// hold strings, but Python/Go/JS/Rust emit it as a JSON boolean. We
// special-case the wire format here so the NDJSON shape matches.
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

// Per-process redactor config — stored in Globals, configured by init().
// Redaction logic lives in libfasten_store_core; we only cache config here.
struct RedactConfig {
    std::vector<std::string> extra_keys;
    std::string              replacement { fasten::kRedactReplacement };
};

// ── Flat-JSON helpers (used by redact / register_codes) ────────────────────

// Parse a flat JSON object with string or boolean values back to Fields.
// Used to round-trip fasten_redact output: {"key":"val","_pii_in_detail":true}
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
        std::string key;
        while (i < json.size() && json[i] != '"') {
            if (json[i] == '\\' && i + 1 < json.size()) {
                ++i;
                switch (json[i]) {
                    case '"':  key += '"';  break;
                    case '\\': key += '\\'; break;
                    case 'n':  key += '\n'; break;
                    case 'r':  key += '\r'; break;
                    case 't':  key += '\t'; break;
                    default:   key += json[i]; break;
                }
            } else { key += json[i]; }
            ++i;
        }
        if (i < json.size()) ++i; // skip closing '"'
        while (i < json.size() && (json[i] == ' ' || json[i] == ':')) ++i;
        std::string val;
        if (i < json.size() && json[i] == '"') {
            ++i;
            while (i < json.size() && json[i] != '"') {
                if (json[i] == '\\' && i + 1 < json.size()) {
                    ++i;
                    switch (json[i]) {
                        case '"':  val += '"';  break;
                        case '\\': val += '\\'; break;
                        case 'n':  val += '\n'; break;
                        case 'r':  val += '\r'; break;
                        case 't':  val += '\t'; break;
                        default:   val += json[i]; break;
                    }
                } else { val += json[i]; }
                ++i;
            }
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
    auto extract_str = [&](const std::string& k) -> std::string {
        std::string search = "\"" + k + "\":\"";
        auto pos = json.find(search);
        if (pos == std::string::npos) return "";
        pos += search.size();
        std::string val;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                ++pos;
                switch (json[pos]) {
                    case '"':  val += '"';  break;
                    case '\\': val += '\\'; break;
                    case 'n':  val += '\n'; break;
                    case 'r':  val += '\r'; break;
                    case 't':  val += '\t'; break;
                    default:   val += json[pos]; break;
                }
            } else { val += json[pos]; }
            ++pos;
        }
        return val;
    };
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
    // Parse detail_passthrough_keys array.
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

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        buf_.clear();
    }
};

}  // namespace detail_

// ── P1-15: audit-store failure handling ───────────────────────────────────

// AuditStoreError is thrown by emit() in raise mode when the audit
// sink throws. Carries the original message so adopters don't depend
// on sqlite3 / pqxx types directly.
struct AuditStoreError : std::runtime_error {
    explicit AuditStoreError(const std::string& msg)
        : std::runtime_error("fasten audit store: " + msg) {}
};

// Snapshot returned by queue_stats(). depth = queued + in-flight.
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

class AuditQueueDrainer {
  public:
    static constexpr double      kHwWarnPct     = 0.50;
    static constexpr double      kHwErrPct      = 0.80;
    static constexpr std::size_t kDegradedAfter = 5;

    AuditQueueDrainer(std::function<void(const Row&)> sink,
                      SysLog sys_log,
                      std::size_t capacity,
                      std::chrono::milliseconds retry_initial,
                      std::chrono::milliseconds retry_max,
                      bool retry_jitter,
                      std::size_t max_attempts = 50)
        : sink_(std::move(sink)),
          sys_log_(std::move(sys_log)),
          capacity_(capacity),
          retry_initial_(retry_initial),
          retry_max_(retry_max),
          retry_jitter_(retry_jitter),
          max_attempts_(max_attempts),
          slots_free_(capacity),
          rng_(std::random_device{}()) {
        thread_ = std::thread([this] { run(); });
    }

    ~AuditQueueDrainer() { shutdown(std::chrono::seconds(2)); }

    AuditQueueDrainer(const AuditQueueDrainer&)            = delete;
    AuditQueueDrainer& operator=(const AuditQueueDrainer&) = delete;

    void put(Row row) {
        // Drainer-swap race: install_drainer_ may have stopped this
        // drainer between emit()'s shared_ptr snapshot and our entry.
        // Surface abandoned rows on the sys stream instead of dropping
        // silently into a queue whose worker thread has already exited.
        if (stop_.load()) {
            sys_log_("error", "audit_drain_abandoned",
                     {{"reason", "drainer_stopped"}, {"row_id", row.id}});
            return;
        }
        // Acquire a slot — blocks if all capacity slots are taken
        // (queued + in-flight retry combined). Released only on
        // successful sink invocation or shutdown abandon.
        {
            std::unique_lock<std::mutex> lk(slot_mu_);
            slot_cv_.wait(lk, [this] { return slots_free_ > 0 || stop_.load(); });
            if (stop_.load()) {
                // Stop fired while we waited for a slot. Same
                // abandon path — never leave the row on the floor.
                sys_log_("error", "audit_drain_abandoned",
                         {{"reason", "drainer_stopped_mid_put"},
                          {"row_id", row.id}});
                return;
            }
            --slots_free_;
        }
        // Bump the parallel used counter under stats_mu_ so
        // emit_high_water_if_crossed() can read `used` and decide
        // the warn/err flag flip in a SINGLE critical section.
        // Reading slots_free_ separately (under slot_mu_) and then
        // making the decision under stats_mu_ leaves a window where
        // concurrent puts/releases skew the threshold check, causing
        // duplicate or missed high-water sys events.
        { std::lock_guard<std::mutex> lk(stats_mu_); ++used_count_; }
        {
            std::lock_guard<std::mutex> lk(q_mu_);
            q_.push(std::move(row));
        }
        q_cv_.notify_one();
        emit_high_water_if_crossed();
    }

    QueueStats stats() const {
        std::lock_guard<std::mutex> lk(stats_mu_);
        QueueStats s;
        s.depth               = used_count_;
        s.capacity            = capacity_;
        s.high_water          = high_water_;
        s.drained_total       = drained_total_;
        s.retry_count_active  = retry_count_;
        if (in_backoff_until_ms_ > 0) {
            auto now_ms = static_cast<int64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
            int64_t rem = in_backoff_until_ms_ - now_ms;
            if (rem > 0) s.in_backoff_seconds = static_cast<double>(rem) / 1000.0;
        }
        s.last_error           = last_error_;
        s.dead_lettered_total  = dead_lettered_total_;
        s.dead_letter_depth    = dlq_.size();
        s.capacity_semantics   = "block";
        return s;
    }

    bool flush(std::chrono::milliseconds timeout) {
        // Use the slot semaphore as the canonical "rows pending"
        // signal: slots_free_ is decremented by put() before pushing
        // onto the queue and incremented only after successful sink
        // invocation, so it covers the transient window where a row
        // has been popped from q_ but in_flight_ has not yet been
        // incremented in drain_one. Checking q_ + in_flight_
        // separately allowed flush() to return prematurely during
        // that gap.
        auto deadline = std::chrono::steady_clock::now() + timeout;
        for (;;) {
            std::size_t used;
            {
                std::lock_guard<std::mutex> lk(stats_mu_);
                used = used_count_;
            }
            if (used == 0) return true;
            if (std::chrono::steady_clock::now() >= deadline) return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    void shutdown(std::chrono::milliseconds /*timeout*/) {
        if (stop_.exchange(true)) return;
        q_cv_.notify_all();
        slot_cv_.notify_all();
        if (thread_.joinable()) thread_.join();
    }

  private:
    void run() {
        while (!stop_.load()) {
            Row row;
            bool got;
            {
                std::unique_lock<std::mutex> lk(q_mu_);
                q_cv_.wait_for(lk, std::chrono::milliseconds(100), [this] {
                    return !q_.empty() || stop_.load();
                });
                got = !q_.empty();
                if (got) { row = std::move(q_.front()); q_.pop(); }
            }
            if (got) drain_one(row, /*in_shutdown=*/false);
        }
        for (;;) {
            Row row;
            bool got;
            {
                std::lock_guard<std::mutex> lk(q_mu_);
                got = !q_.empty();
                if (got) { row = std::move(q_.front()); q_.pop(); }
            }
            if (!got) break;
            drain_one(row, /*in_shutdown=*/true);
        }
    }

    void drain_one(const Row& row, bool in_shutdown) {
        { std::lock_guard<std::mutex> lk(stats_mu_); ++in_flight_; }
        bool slot_released = false;
        std::size_t attempt = 0;
        for (;;) {
            ++attempt;
            try {
                sink_(row);
                on_success();
                release_slot(); slot_released = true;
                break;
            } catch (const std::exception& e) {
                if (attempt >= max_attempts_) {
                    on_dead_letter(row, attempt, e.what());
                    release_slot(); slot_released = true; break;
                }
                on_failure(e.what());
                if (in_shutdown) { release_slot(); slot_released = true; break; }
                if (wait_backoff()) { release_slot(); slot_released = true; break; }
            } catch (...) {
                if (attempt >= max_attempts_) {
                    on_dead_letter(row, attempt, "unknown exception");
                    release_slot(); slot_released = true; break;
                }
                on_failure("unknown exception");
                if (in_shutdown) { release_slot(); slot_released = true; break; }
                if (wait_backoff()) { release_slot(); slot_released = true; break; }
            }
        }
        { std::lock_guard<std::mutex> lk(stats_mu_); --in_flight_; }
        if (!slot_released) release_slot();
    }

    void release_slot() {
        { std::lock_guard<std::mutex> lk(slot_mu_); if (slots_free_ < capacity_) ++slots_free_; }
        // Decrement parallel counter under stats_mu_ — see put() for why.
        { std::lock_guard<std::mutex> lk(stats_mu_); if (used_count_ > 0) --used_count_; }
        slot_cv_.notify_one();
    }

    void emit_high_water_if_crossed() {
        bool fire_warn = false, fire_err = false;
        std::size_t used = 0, cap = 0;
        {
            // Single critical section: read `used` AND make the
            // flag-flip decision under the same lock so concurrent
            // puts/releases can't change state between read + decide.
            // Earlier this read `used` under slot_mu_ then decided
            // under stats_mu_ — concurrent activity in the gap caused
            // duplicate / missed warns.
            std::lock_guard<std::mutex> lk(stats_mu_);
            used = used_count_;
            cap  = capacity_;
            if (used > high_water_) high_water_ = used;
            if (cap == 0) return;
            double pct = static_cast<double>(used) / static_cast<double>(cap);
            if (pct >= kHwErrPct && !err_hw_fired_) { err_hw_fired_ = true; fire_err = true; }
            else if (pct >= kHwWarnPct && !warn_hw_fired_) { warn_hw_fired_ = true; fire_warn = true; }
            else if (pct < kHwWarnPct) { warn_hw_fired_ = false; err_hw_fired_ = false; }
        }
        if (fire_err) {
            sys_log_("error", "audit_queue_near_full",
                     {{"depth", std::to_string(used)}, {"capacity", std::to_string(capacity_)}});
        } else if (fire_warn) {
            sys_log_("warn", "audit_queue_high_water",
                     {{"depth", std::to_string(used)}, {"capacity", std::to_string(capacity_)}});
        }
    }

    void on_failure(const std::string& msg) {
        bool first = false, crossed = false;
        std::size_t rc = 0;
        double bo = 0.0;
        {
            std::lock_guard<std::mutex> lk(stats_mu_);
            first = retry_count_ == 0;
            if (first) {
                failure_burst_started_at_ms_ = static_cast<int64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count());
            }
            ++retry_count_;
            last_error_ = msg;
            rc = retry_count_;
            if (in_backoff_until_ms_ > 0) {
                auto now_ms = static_cast<int64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count());
                int64_t rem = in_backoff_until_ms_ - now_ms;
                if (rem > 0) bo = static_cast<double>(rem) / 1000.0;
            }
            if (retry_count_ >= kDegradedAfter && !degraded_fired_) {
                degraded_fired_ = true; crossed = true;
            }
        }
        if (first) sys_log_("warn", "audit_drain_failed", {{"error", msg}});
        if (crossed) {
            sys_log_("error", "audit_drain_degraded",
                     {{"retry_count", std::to_string(rc)},
                      {"in_backoff_seconds", std::to_string(bo)},
                      {"last_error", msg}});
        }
    }

    void on_success() {
        bool emit_recovered = false;
        double recovery_seconds = 0.0;
        {
            std::lock_guard<std::mutex> lk(stats_mu_);
            if (retry_count_ > 0 && failure_burst_started_at_ms_ != 0) {
                auto now_ms = static_cast<int64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count());
                recovery_seconds =
                    static_cast<double>(now_ms - failure_burst_started_at_ms_) / 1000.0;
                emit_recovered = true;
            }
            retry_count_                 = 0;
            in_backoff_until_ms_         = 0;
            failure_burst_started_at_ms_ = 0;
            last_error_.clear();
            degraded_fired_              = false;
            ++drained_total_;
        }
        if (emit_recovered) {
            double r = std::round(recovery_seconds * 1000.0) / 1000.0;
            sys_log_("info", "audit_drain_recovered",
                     {{"recovery_after_seconds", std::to_string(r)}});
        }
    }

    void on_dead_letter(const Row& row, std::size_t attempt, const std::string& msg) {
        {
            std::lock_guard<std::mutex> lk(stats_mu_);
            ++dead_lettered_total_;
            retry_count_ = 0;
            last_error_  = msg;
            if (dlq_.size() >= 10) dlq_.pop_front();
            dlq_.push_back(row);
        }
        sys_log_("error", "audit_drain_dead_letter",
                 {{"row_id", row.id},
                  {"attempt_count", std::to_string(attempt)},
                  {"last_error", msg}});
    }

    bool wait_backoff() {
        std::size_t n;
        { std::lock_guard<std::mutex> lk(stats_mu_); n = retry_count_; }
        auto delay = retry_initial_;
        for (std::size_t i = 1; i < n; ++i) {
            delay *= 2;
            if (delay >= retry_max_) { delay = retry_max_; break; }
        }
        if (delay > retry_max_) delay = retry_max_;
        if (retry_jitter_) {
            std::uniform_real_distribution<double> dist(-0.2, 0.2);
            double r = dist(rng_);
            auto adj = std::chrono::milliseconds(static_cast<int64_t>(delay.count() * r));
            delay += adj;
            if (delay.count() < 0) delay = std::chrono::milliseconds(0);
        }
        {
            std::lock_guard<std::mutex> lk(stats_mu_);
            auto now_ms = static_cast<int64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
            in_backoff_until_ms_ = now_ms + delay.count();
        }
        auto deadline = std::chrono::steady_clock::now() + delay;
        while (std::chrono::steady_clock::now() < deadline) {
            if (stop_.load()) return true;
            auto rem = deadline - std::chrono::steady_clock::now();
            auto step = std::min(
                std::chrono::duration_cast<std::chrono::milliseconds>(rem),
                std::chrono::milliseconds(50));
            if (step.count() <= 0) break;
            std::this_thread::sleep_for(step);
        }
        return stop_.load();
    }

    std::function<void(const Row&)> sink_;
    SysLog                          sys_log_;
    std::size_t                     capacity_;
    std::chrono::milliseconds       retry_initial_;
    std::chrono::milliseconds       retry_max_;
    bool                            retry_jitter_;
    std::size_t                     max_attempts_;

    std::queue<Row>                 q_;
    mutable std::mutex              q_mu_;
    std::condition_variable         q_cv_;

    mutable std::mutex              slot_mu_;
    std::condition_variable         slot_cv_;
    std::size_t                     slots_free_;

    std::atomic<bool>               stop_{false};
    std::thread                     thread_;

    mutable std::mutex              stats_mu_;
    // Parallel "used slots" counter — incremented under stats_mu_ in
    // put() after slot acquired, decremented in release_slot() after
    // slot released. Used so the high-water threshold check + flag
    // flip happen in a SINGLE critical section (eliminates the cross-
    // mutex race that produced duplicate / missed sys events).
    std::size_t                     used_count_                  = 0;
    std::size_t                     high_water_                  = 0;
    std::size_t                     drained_total_               = 0;
    std::size_t                     retry_count_                 = 0;
    std::size_t                     in_flight_                   = 0;
    int64_t                         in_backoff_until_ms_         = 0;
    int64_t                         failure_burst_started_at_ms_ = 0;
    std::string                     last_error_;
    bool                            warn_hw_fired_      = false;
    bool                            err_hw_fired_       = false;
    bool                            degraded_fired_     = false;
    std::size_t                     dead_lettered_total_ = 0;
    std::deque<Row>                 dlq_;               // bounded ring, max 10

    std::mt19937_64                 rng_;
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

    // P1-15: failure-strategy + drainer ownership.
    std::string                                 failure_strategy{"queue"};
    std::shared_ptr<AuditQueueDrainer>          drainer;
    std::mutex                                  drainer_mu;

    // Redactor config — built by init(), defaults to built-in pattern + "***".
    RedactConfig redact_cfg;

    /// Reset all runtime state for test isolation.
    ///
    /// Stops the active drainer (best-effort), clears service config, resets
    /// seq, clears the audit sink and in-process log rings. Does NOT clear the
    /// code registry — codes are registered once at startup.
    ///
    /// Mirrors `reset_for_tests()` / `ResetForTests()` / `resetForTests()` in
    /// Python / Go / JS / Rust.
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

// Thread-local request_id — function-local thread_local is ODR-safe in C++14.
inline std::string& tl_request_id() {
    thread_local std::string rid;
    return rid;
}

// ── Redaction via libfasten_store_core ────────────────────────────────────
// Delegates all key-pattern + value-shape logic to the shared Rust engine.
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
        // Build extra_keys JSON array.
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

// ── Row serialisation (needs detail_ helpers) ──────────────────────────────

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
    // CloudEvent 1.0 — id / source / type / time / data.
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
    // Row-level PII flag — downstream consumers route on this for
    // retention + access-control before opening `data`.
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

// ── Registry ───────────────────────────────────────────────────────────────

namespace detail_ {

// Shared core of register_codes: build JSON, call Rust, populate C++ cache.
template<typename CodesRange>
inline void register_codes_impl(
    const Domain& domain, const CodesRange& codes)
{
    // Emit pii_in_detail warning before delegating to Rust (test expects
    // the warning to appear on stderr during the register_codes() call).
    for (const auto& kv : codes) {
        if (kv.second.pii_in_detail &&
            kv.second.retention_class != Retention::Short) {
            std::cerr << "fasten: code " << kv.first
                      << " has pii_in_detail=true; retention_class forced to short (was "
                      << fasten::to_string(kv.second.retention_class) << ").\n";
        }
    }

    // Serialize codes to JSON for Rust validation + registration.
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

    // Populate C++ registry cache from canonical Rust meta (includes forced
    // retention_class=short, filled id, etc.).
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

// Overload for std::vector — allows runtime-built code tables.
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

// ── Engine ─────────────────────────────────────────────────────────────────
//
// Engine holds all mutable runtime state for one fasten deployment context.
// The free-function API (init, emit, ...) delegates to the default_engine()
// singleton. Applications needing multiple isolated fasten contexts in one
// process can create additional Engine instances.
//
// For test isolation, call:
//   fasten::default_engine().reset_for_tests();
//
// The code registry (register_codes) is global and is NOT reset by
// reset_for_tests() — mirrors Python / Go / JS / Rust behaviour.

using Engine = detail_::Globals;

inline Engine& default_engine() { return detail_::globals(); }

// ── Init ───────────────────────────────────────────────────────────────────

struct Config {
    std::string              service_id;
    std::string              node_id;
    std::string              tenant_id;           // optional

    // Redaction — both are additive to / override the built-in defaults.
    std::vector<std::string> extra_redact_keys;   // appended to built-in pattern
    std::string              redact_replacement;  // default "***"; env FASTEN_REDACT_REPLACEMENT

    // P1-15: audit-store failure handling.
    //
    // "queue" (default) — emit() pushes rows onto a bounded in-memory
    //   queue and returns immediately. A background thread invokes the
    //   audit sink with exponential backoff on exception.
    // "raise" — emit() invokes the sink synchronously and rethrows as
    //   AuditStoreError on exception. Useful for tests / dev mode.
    //
    // Empty falls back to env FASTEN_AUDIT_STORE_FAILURE_STRATEGY.
    std::string              audit_store_failure_strategy;  // "queue" | "raise"
    std::size_t              queue_capacity        = 100;   // queued + in-flight
    int                      queue_retry_initial_ms = 100;
    int                      queue_retry_max_ms     = 60000;
    bool                     disable_queue_jitter   = false; // false = jitter ON
};

// Forward declaration — defined below set_audit_sink so it can read
// the active sink. P1-15.
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
    }
    g.redact_cfg.replacement = cfg.redact_replacement.empty()
        ? env_or("FASTEN_REDACT_REPLACEMENT", g.redact_cfg.replacement.c_str())
        : cfg.redact_replacement;

    // P1-15: failure-strategy + drainer wiring.
    std::string strategy = cfg.audit_store_failure_strategy;
    if (strategy.empty()) strategy = env_or("FASTEN_AUDIT_STORE_FAILURE_STRATEGY", "queue");
    if (strategy != "queue" && strategy != "raise") {
        throw InitError("init: audit_store_failure_strategy must be \"queue\" or \"raise\"");
    }
    g.failure_strategy = strategy;
    install_drainer_(cfg);
}

// Convenience overload — positional args for the common case.
// Extra redact config can still be set via init(Config{...}).
inline void init(std::string service_id,
                 std::string node_id,
                 std::string tenant_id = "") {
    Config cfg;
    cfg.service_id = std::move(service_id);
    cfg.node_id    = std::move(node_id);
    cfg.tenant_id  = std::move(tenant_id);
    init(std::move(cfg));
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

// ── P1-15: drainer install + public surface ────────────────────────────────

namespace detail_ {

inline void drainer_sys_log(const std::string& level,
                            const std::string& event,
                            const std::vector<std::pair<std::string, std::string>>& fields) {
    // Non-recursive: writes a {shape:"sys"} NDJSON line to stderr +
    // pushes to the sys ring. Never recurses through the sink.
    // stderr is mandatory: a slow stdout consumer stalls the drainer thread
    // if self-reports share the wire stream (stdout backpressure deadlock).
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
    std::cerr << js << std::flush;
}

}  // namespace detail_

inline void install_drainer_(const Config& cfg) {
    auto& g = detail_::globals();
    // Race-safe re-init: build the new drainer first, swap the global
    // under lock, then flush + shutdown the old OUTSIDE the lock.
    // Holding drainer_mu through a 5 s flush + 2 s shutdown would
    // block every concurrent emit() on the request path.
    //
    // Concurrent emit() that snapshotted the old drainer before the
    // swap and lands a put() after we shutdown self-aborts via the
    // put() stop check (audit_drain_abandoned sys event) — no silent
    // loss into a dead queue.
    std::shared_ptr<detail_::AuditQueueDrainer> next;
    if (g.failure_strategy == "queue") {
        std::function<void(const Row&)> sink_copy;
        {
            std::lock_guard<std::mutex> sk(g.sink_mu);
            sink_copy = g.audit_sink;
        }
        if (sink_copy) {
            next = std::make_shared<detail_::AuditQueueDrainer>(
                std::move(sink_copy),
                detail_::drainer_sys_log,
                cfg.queue_capacity,
                std::chrono::milliseconds(cfg.queue_retry_initial_ms),
                std::chrono::milliseconds(cfg.queue_retry_max_ms),
                !cfg.disable_queue_jitter);
        }
    }
    std::shared_ptr<detail_::AuditQueueDrainer> old;
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

// Snapshot of the active drainer, or nullptr in raise mode (no
// drainer running). Mirrors Python's queue_stats() / Go's
// GetQueueStats().
inline std::unique_ptr<QueueStats> queue_stats() {
    auto& g = detail_::globals();
    std::lock_guard<std::mutex> lk(g.drainer_mu);
    if (!g.drainer) return nullptr;
    return std::unique_ptr<QueueStats>(new QueueStats(g.drainer->stats()));
}

// Block until pending audit rows drain or the timeout elapses.
// Returns true iff drained. No-op + true in raise mode.
inline bool flush(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000)) {
    auto& g = detail_::globals();
    std::shared_ptr<detail_::AuditQueueDrainer> d;
    {
        std::lock_guard<std::mutex> lk(g.drainer_mu);
        d = g.drainer;
    }
    if (!d) return true;
    return d->flush(timeout);
}

// Stop and drop the active drainer. Adopter shutdown paths call this
// before exiting; init() also calls this internally to swap drainers.
inline void uninstall_drainer() {
    auto& g = detail_::globals();
    // Symmetric with install_drainer_: clear the global FIRST under
    // the mutex so any new emit() sees no drainer and falls through
    // to its sync path, instead of racing against a half-shutdown
    // drainer. Then shut down the old one outside the lock.
    std::shared_ptr<detail_::AuditQueueDrainer> old;
    {
        std::lock_guard<std::mutex> lk(g.drainer_mu);
        old = g.drainer;
        g.drainer.reset();
    }
    if (old) {
        old->shutdown(std::chrono::seconds(2));
    }
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
    row.pii_in_detail  = meta.pii_in_detail;

    // P1-5 #2: PII codes force-redact the whole detail. Detail keys listed
    // in meta.detail_passthrough_keys survive but still pass through the
    // secret-key redactor. Adopters opt-in by listing keys explicitly.
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

    // NDJSON to stdout — Docker log driver captures and rotates.
    std::cout << "{\"shape\":\"audit\""
              << ",\"wire_version\":"   << detail_::json_str(row.wire_version)
              << ",\"id\":"             << detail_::json_str(row.id)
              << ",\"origin_id\":"      << detail_::json_str(row.origin_id)
              << ",\"monotonic_seq\":"  << row.monotonic_seq
              << ",\"timestamp\":"      << detail_::json_str(row.timestamp)
              << ",\"code\":"           << detail_::json_str(row.code)
              << ",\"action\":"         << detail_::json_str(row.action)
              << ",\"severity\":"       << detail_::json_str(row.severity)
              << ",\"service_id\":"     << detail_::json_str(row.service_id)
              << ",\"source_node_id\":" << detail_::json_str(row.source_node_id)
              << ",\"tenant_id\":"      << (row.tenant_id.empty() ? "null" : detail_::json_str(row.tenant_id))
              << ",\"actor\":"          << detail_::json_str(row.actor)
              << ",\"actor_kind\":"     << detail_::json_str(row.actor_kind)
              << ",\"target\":"         << detail_::json_str(row.target)
              << ",\"category\":"       << detail_::json_str(row.category)
              << ",\"domain\":"         << detail_::json_str(row.domain)
              << ",\"method\":"         << detail_::json_str(row.method)
              << ",\"request_id\":"     << detail_::json_str(row.request_id)
              << ",\"detail\":"         << detail_::fields_to_json(row.detail)
              << ",\"pii_in_detail\":"  << (row.pii_in_detail ? "true" : "false")
              << "}\n" << std::flush;

    // P1-15: route through the drainer (queue mode) or invoke the
    // sink synchronously and wrap exceptions (raise mode).
    {
        std::shared_ptr<detail_::AuditQueueDrainer> drainer_copy;
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
                    // Queue strategy but no drainer (sink registered
                    // after init()) — fall back to sync to avoid
                    // silently dropping rows. Surface any sink error
                    // on the sys stream instead of swallowing it; an
                    // adopter watching `/logs/sys` (or queue_stats())
                    // sees the failure instead of it vanishing.
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
