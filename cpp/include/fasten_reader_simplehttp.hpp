#pragma once
/**
 * fasten_reader_simplehttp.hpp — Simple-Web-Server adapter for fasten reader.
 *
 * Requires:
 *   - fasten_reader.hpp (included automatically)
 *   - Simple-Web-Server: https://gitlab.com/eidheim/Simple-Web-Server
 *     Add its directory to your include path; no linking required.
 *
 * CMake:
 *   target_include_directories(mytarget PRIVATE path/to/Simple-Web-Server)
 *   target_link_libraries(mytarget PRIVATE fasten pthread)
 *
 * Usage — no auth (trusted network only):
 *   auto t = fasten::reader::simplehttp::start(9000);
 *   t.detach();
 *
 * Usage — API key auth:
 *   auto t = fasten::reader::simplehttp::start(9000, "/api/v1/logs",
 *       [](const SimpleWeb::CaseInsensitiveMultimap& h) {
 *           auto it = h.find("x-api-key");
 *           return it != h.end() && it->second == "secret";
 *       });
 *   t.detach();
 *
 * Usage — tenant isolation on a shared multi-tenant store: return the caller's
 * tenant from your auth ("" answers 401); rows are limited to that tenant:
 *   fasten::reader::simplehttp::mount(server, "/api/v1/logs", auth_fn,
 *       [](const SimpleWeb::CaseInsensitiveMultimap& h) {
 *           return tenant_for_api_key(h);
 *       });
 *
 * Usage — mount onto an existing server (e.g. alongside app routes):
 *   HttpServer server;
 *   server.config.port = 9000;
 *   // ... register your own routes ...
 *   fasten::reader::simplehttp::mount(server, "/api/v1/logs", auth_fn);
 *   server.start();
 */

#include "fasten_reader.hpp"
#include "server_http.hpp"

#include <memory>
#include <thread>

namespace fasten {
namespace reader {
namespace simplehttp {

using HttpServer = SimpleWeb::Server<SimpleWeb::HTTP>;
using AuthFn     = std::function<bool(const SimpleWeb::CaseInsensitiveMultimap&)>;
using TenantFn   = std::function<std::string(const SimpleWeb::CaseInsensitiveMultimap&)>;

namespace detail_ {

// Flatten SimpleWeb's CaseInsensitiveMultimap into fasten::reader::Params.
inline fasten::reader::Params to_params(const SimpleWeb::CaseInsensitiveMultimap& q) {
    fasten::reader::Params p;
    for (auto& kv : q) p[kv.first] = kv.second;
    return p;
}

inline void send(std::shared_ptr<HttpServer::Response> response,
                 const fasten::reader::Response& r)
{
    SimpleWeb::CaseInsensitiveMultimap headers;
    headers.emplace("Content-Type", "application/json");
    response->write(static_cast<SimpleWeb::StatusCode>(r.status), r.body, headers);
}

inline bool check_auth(const SimpleWeb::CaseInsensitiveMultimap& h, const AuthFn& auth) {
    return !auth || auth(h);
}

inline void unauthorized(std::shared_ptr<HttpServer::Response> response) {
    send(response, {401, "{\"error\":\"unauthorized\"}"});
}

} // namespace detail_

// Mount /sys, /api, /audit under `prefix` on an existing server.
// With `tenant`, each request is scoped to the tenant it returns.
// Call this before server.start().
inline void mount(HttpServer& server,
                  const std::string& prefix = "/api/v1/logs",
                  AuthFn auth = {},
                  TenantFn tenant = {})
{
    // Build regex route string — prefix is treated as a literal path.
    auto route = [&prefix](const std::string& s) {
        return "^" + prefix + s + "$";
    };
    using Unscoped = fasten::reader::Response (*)(const fasten::reader::Params&);
    using Scoped   = fasten::reader::Response (*)(const fasten::reader::Params&,
                                                  const std::string&);
    auto handler = [auth, tenant](Unscoped unscoped, Scoped scoped) {
        return [auth, tenant, unscoped, scoped](auto resp, auto req) {
            if (!detail_::check_auth(req->header, auth)) {
                return detail_::unauthorized(resp);
            }
            auto params = detail_::to_params(req->parse_query_string());
            detail_::send(resp, tenant ? scoped(params, tenant(req->header))
                                       : unscoped(params));
        };
    };

    server.resource[route("/sys")]["GET"] =
        handler(&fasten::reader::handle_sys, &fasten::reader::handle_sys);
    server.resource[route("/api")]["GET"] =
        handler(&fasten::reader::handle_api, &fasten::reader::handle_api);
    server.resource[route("/audit")]["GET"] =
        handler(&fasten::reader::handle_audit, &fasten::reader::handle_audit);
}

// Start a dedicated HTTP server on `port` in a new thread.
// Returns the thread — call detach() for fire-and-forget, join() to block.
inline std::thread start(unsigned short     port   = 9000,
                          const std::string& prefix = "/api/v1/logs",
                          AuthFn             auth   = {},
                          TenantFn           tenant = {})
{
    auto srv = std::make_shared<HttpServer>();
    srv->config.port = port;
    mount(*srv, prefix, std::move(auth), std::move(tenant));
    return std::thread([srv]() { srv->start(); });
}

} // namespace simplehttp
} // namespace reader
} // namespace fasten
