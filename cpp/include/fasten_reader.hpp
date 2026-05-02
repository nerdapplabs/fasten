#pragma once
/**
 * fasten_reader.hpp — framework-agnostic /logs reader core.
 *
 * Exposes three pure handler functions that any HTTP framework can call.
 * Each takes a flat string map of query params and returns {status, body}.
 *
 * Usage pattern (any framework):
 *   fasten::reader::Params p = {{"level","warn"},{"limit","50"}};
 *   auto r = fasten::reader::handle_sys(p);
 *   // r.status == 200, r.body == {"rows":[...]}
 *   // → set Content-Type: application/json and write r.body
 *
 * For Simple-Web-Server: include fasten_reader_simplehttp.hpp instead.
 * For Crow / Drogon / Pistache / custom server: call handle_* directly.
 *
 * Audit endpoint requires an adopter-provided query callback:
 *   fasten::reader::set_audit_query([](auto rid, auto code, auto dom, int lim) {
 *       return my_sqlite.query(rid, code, dom, lim);
 *   });
 */

#include "fasten.hpp"

namespace fasten {
namespace reader {

// Flat query-param map — framework fills this from its own parsed query string.
using Params = std::unordered_map<std::string, std::string>;

struct Response {
    int         status = 200;  // HTTP status code
    std::string body;          // always JSON; Content-Type: application/json
};

// Adopter-provided audit store query — called by handle_audit().
// Returns rows matching the supplied filters (empty string = no filter).
using AuditQueryFn = std::function<
    std::vector<fasten::Row>(
        const std::string& request_id,
        const std::string& code,
        const std::string& domain,
        int                limit)>;

// Register the audit query function once at startup.
// Without it, /audit returns empty rows + an informational warning field.
inline void set_audit_query(AuditQueryFn fn);

// ── Handler functions ─────────────────────────────────────────────────────
//
// All three are safe to call from multiple threads simultaneously.
//
// Recognised params:
//   /sys   — level, request_id, limit (default 100, max 1000)
//   /api   — method, path, request_id, limit
//   /audit — request_id, code, domain, limit

inline Response handle_sys  (const Params& p);
inline Response handle_api  (const Params& p);
inline Response handle_audit(const Params& p);

// ── Implementation ────────────────────────────────────────────────────────

namespace detail_ {

inline AuditQueryFn& audit_query_fn() {
    static AuditQueryFn fn;
    return fn;
}

inline std::string param(const Params& p, const std::string& key,
                          const std::string& def = "") {
    auto it = p.find(key);
    return it != p.end() ? it->second : def;
}

inline int param_int(const Params& p, const std::string& key, int def = 100) {
    auto s = param(p, key);
    if (s.empty()) return def;
    try { return std::stoi(s); } catch (...) { return def; }
}

inline int clamp(int v, int lo, int hi) {
    return v < lo ? lo : v > hi ? hi : v;
}

inline std::string fields_rows_to_json(const std::vector<fasten::Fields>& rows) {
    std::string js = "{\"rows\":[";
    bool first = true;
    for (auto& r : rows) {
        if (!first) js += ',';
        js += fasten::detail_::fields_to_json(r);
        first = false;
    }
    js += "]}";
    return js;
}

inline std::string audit_rows_to_json(const std::vector<fasten::Row>& rows) {
    std::string js = "{\"rows\":[";
    bool first = true;
    for (auto& r : rows) {
        if (!first) js += ',';
        js += r.to_json();
        first = false;
    }
    js += "]}";
    return js;
}

} // namespace detail_

inline void set_audit_query(AuditQueryFn fn) {
    detail_::audit_query_fn() = std::move(fn);
}

inline Response handle_sys(const Params& p) {
    using namespace detail_;
    auto level = param(p, "level");
    auto rid   = param(p, "request_id");
    auto limit = clamp(param_int(p, "limit", 100), 1, 1000);
    auto rows  = fasten::query_syslog(static_cast<size_t>(limit), level, rid);
    return {200, fields_rows_to_json(rows)};
}

inline Response handle_api(const Params& p) {
    using namespace detail_;
    auto meth  = param(p, "method");
    auto path  = param(p, "path");
    auto rid   = param(p, "request_id");
    auto limit = clamp(param_int(p, "limit", 100), 1, 1000);
    auto rows  = fasten::query_api(static_cast<size_t>(limit), rid, meth, path);
    return {200, fields_rows_to_json(rows)};
}

inline Response handle_audit(const Params& p) {
    using namespace detail_;
    auto& fn = audit_query_fn();
    if (!fn) {
        return {200,
            "{\"rows\":[],"
            "\"warning\":\"call fasten::reader::set_audit_query() to enable this endpoint\"}"};
    }
    auto rid   = param(p, "request_id");
    auto code  = param(p, "code");
    auto dom   = param(p, "domain");
    auto limit = clamp(param_int(p, "limit", 100), 1, 1000);
    try {
        auto rows = fn(rid, code, dom, limit);
        return {200, audit_rows_to_json(rows)};
    } catch (const std::exception& e) {
        return {500,
            "{\"error\":" + fasten::detail_::json_str(e.what()) + "}"};
    }
}

} // namespace reader
} // namespace fasten
