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
 *
 * Tenant isolation (shared-store multi-tenant deployments): resolve the
 * caller's tenant from your own auth and call the handlers that take it.
 * Rows are limited to that tenant and ?tenant_id= is ignored; an empty tenant
 * answers 401. enforce_tenant_isolation() makes the handlers without a tenant
 * answer 401 too, so a route that forgets to pass one fails closed.
 *   auto r = fasten::reader::handle_audit(p, tenant_from_my_auth(req));
 * set_scoped_audit_query() passes the tenant to your store query; with only
 * set_audit_query(), rows from other tenants are dropped after the query.
 */

#include "fasten.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <typeinfo>

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

// Same as AuditQueryFn, with the caller's tenant ("" when not scoped).
using ScopedAuditQueryFn = std::function<
    std::vector<fasten::Row>(
        const std::string& request_id,
        const std::string& code,
        const std::string& domain,
        const std::string& tenant_id,
        int                limit)>;

// Register the audit query function once at startup.
// Without it, /audit returns empty rows + an informational warning field.
inline void set_audit_query(AuditQueryFn fn);
inline void set_scoped_audit_query(ScopedAuditQueryFn fn);

// Make the handlers without a tenant answer 401.
inline void enforce_tenant_isolation(bool on = true);

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

// Scoped to `tenant`; an empty tenant answers 401.
inline Response handle_sys  (const Params& p, const std::string& tenant);
inline Response handle_api  (const Params& p, const std::string& tenant);
inline Response handle_audit(const Params& p, const std::string& tenant);

// ── Implementation ────────────────────────────────────────────────────────

namespace detail_ {

inline AuditQueryFn& audit_query_fn() {
    static AuditQueryFn fn;
    return fn;
}

inline ScopedAuditQueryFn& scoped_audit_query_fn() {
    static ScopedAuditQueryFn fn;
    return fn;
}

inline std::atomic<bool>& isolation_enforced() {
    static std::atomic<bool> on{false};
    return on;
}

inline Response unscoped() {
    return {401, "{\"error\":\"unauthenticated: tenant scope unresolved\"}"};
}

// Stream rows carry tenant_id as a field; a row without it is dropped
// (fail closed).
inline std::vector<fasten::Fields> scope_rows(std::vector<fasten::Fields> rows,
                                              const std::string& tenant) {
    rows.erase(std::remove_if(rows.begin(), rows.end(), [&](const fasten::Fields& r) {
        auto it = r.find("tenant_id");
        return it == r.end() || it->second != tenant;
    }), rows.end());
    return rows;
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

inline void set_scoped_audit_query(ScopedAuditQueryFn fn) {
    detail_::scoped_audit_query_fn() = std::move(fn);
}

inline void enforce_tenant_isolation(bool on) {
    detail_::isolation_enforced() = on;
}

namespace detail_ {

// The ring is scanned past `limit` when scoping, so a busy tenant can't hide
// the caller's rows behind its own.
inline Response sys_rows(const Params& p, const std::string* tenant) {
    auto level = param(p, "level");
    auto rid   = param(p, "request_id");
    auto limit = static_cast<size_t>(clamp(param_int(p, "limit", 100), 1, 1000));
    auto rows  = fasten::query_syslog(tenant ? SIZE_MAX : limit, level, rid);
    if (tenant) {
        rows = scope_rows(std::move(rows), *tenant);
        if (rows.size() > limit) rows.resize(limit);
    }
    return {200, fields_rows_to_json(rows)};
}

inline Response api_rows(const Params& p, const std::string* tenant) {
    auto meth  = param(p, "method");
    auto path  = param(p, "path");
    auto rid   = param(p, "request_id");
    auto limit = static_cast<size_t>(clamp(param_int(p, "limit", 100), 1, 1000));
    auto rows  = fasten::query_api(tenant ? SIZE_MAX : limit, rid, meth, path);
    if (tenant) {
        rows = scope_rows(std::move(rows), *tenant);
        if (rows.size() > limit) rows.resize(limit);
    }
    return {200, fields_rows_to_json(rows)};
}

inline Response audit_rows(const Params& p, const std::string* tenant) {
    auto& scoped = scoped_audit_query_fn();
    auto& plain  = audit_query_fn();
    if (!scoped && !plain) {
        return {200,
            "{\"rows\":[],"
            "\"warning\":\"call fasten::reader::set_audit_query() to enable this endpoint\"}"};
    }
    auto rid   = param(p, "request_id");
    auto code  = param(p, "code");
    auto dom   = param(p, "domain");
    auto limit = clamp(param_int(p, "limit", 100), 1, 1000);
    try {
        std::vector<fasten::Row> rows;
        if (scoped) {
            rows = scoped(rid, code, dom, tenant ? *tenant : "", limit);
        } else {
            rows = plain(rid, code, dom, limit);
        }
        // Drop other tenants' rows even if the query didn't.
        if (tenant) {
            rows.erase(std::remove_if(rows.begin(), rows.end(), [&](const fasten::Row& r) {
                return r.tenant_id != *tenant;
            }), rows.end());
        }
        return {200, audit_rows_to_json(rows)};
    } catch (const std::exception& e) {
        // The store's message can quote SQL and the database host and user;
        // log its type, not the text.
#if defined(__cpp_rtti) || defined(__GXX_RTTI) || defined(_CPPRTTI)
        const char* type = typeid(e).name();
#else
        (void)e;
        const char* type = "std::exception";
#endif
        fasten::detail_::drainer_sys_log("error", "reader_query_failed",
            {{"path", "/audit"}, {"error_type", type}});
        return {500, "{\"error\":\"internal error\"}"};
    }
}

} // namespace detail_

inline Response handle_sys(const Params& p) {
    if (detail_::isolation_enforced()) return detail_::unscoped();
    return detail_::sys_rows(p, nullptr);
}

inline Response handle_api(const Params& p) {
    if (detail_::isolation_enforced()) return detail_::unscoped();
    return detail_::api_rows(p, nullptr);
}

inline Response handle_audit(const Params& p) {
    if (detail_::isolation_enforced()) return detail_::unscoped();
    return detail_::audit_rows(p, nullptr);
}

inline Response handle_sys(const Params& p, const std::string& tenant) {
    if (tenant.empty()) return detail_::unscoped();
    return detail_::sys_rows(p, &tenant);
}

inline Response handle_api(const Params& p, const std::string& tenant) {
    if (tenant.empty()) return detail_::unscoped();
    return detail_::api_rows(p, &tenant);
}

inline Response handle_audit(const Params& p, const std::string& tenant) {
    if (tenant.empty()) return detail_::unscoped();
    return detail_::audit_rows(p, &tenant);
}

} // namespace reader
} // namespace fasten
