#pragma once
/**
 * fasten_reader_simplehttp.hpp: Simple-Web-Server adapter for fasten_reader.hpp.
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
 * mount() and start() need an auth function: the routes return audit rows
 * and log payloads. It gets the request headers and returns whether the
 * caller may read. An empty function throws std::invalid_argument.
 *
 * API key auth:
 *   auto t = fasten::reader::simplehttp::start(9000, "/api/v1/logs",
 *       [](const SimpleWeb::CaseInsensitiveMultimap& h) {
 *           auto it = h.find("x-api-key");
 *           return it != h.end() && it->second == api_key_from_my_config();
 *       });
 *   t.detach();
 *
 * No auth, for a port only a trusted network can reach:
 *   auto t = fasten::reader::simplehttp::start(9000, "/api/v1/logs",
 *       fasten::reader::simplehttp::no_auth());
 *   t.detach();
 *
 * Tenant isolation on a shared multi-tenant store: return the caller's
 * tenant from your auth ("" answers 401); rows are limited to that tenant:
 *   fasten::reader::simplehttp::mount(server, "/api/v1/logs", auth_fn,
 *       [](const SimpleWeb::CaseInsensitiveMultimap& h) {
 *           return tenant_for_api_key(h);
 *       });
 *
 * On an existing server, next to the app routes:
 *   HttpServer server;
 *   server.config.port = 9000;
 *   // ... register your own routes ...
 *   fasten::reader::simplehttp::mount(server, "/api/v1/logs", auth_fn);
 *   server.start();
 */

#include "fasten_reader.hpp"
#include "server_http.hpp"

#include <memory>
#include <stdexcept>
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

inline void unauthorized(std::shared_ptr<HttpServer::Response> response) {
    send(response, {401, "{\"error\":\"unauthorized\"}"});
}

} // namespace detail_

// An auth function that lets every request through. Pass it to mount() or
// start() only when the port is reachable from a trusted network alone.
inline AuthFn no_auth() {
    return [](const SimpleWeb::CaseInsensitiveMultimap&) { return true; };
}

// Mount /sys, /api, /audit under `prefix` on an existing server.
// `auth` decides each request; a request it refuses gets 401. It is
// required: an empty function throws std::invalid_argument (see no_auth()).
// With `tenant`, each request is scoped to the tenant it returns.
// Call this before server.start().
inline void mount(HttpServer& server,
                  const std::string& prefix,
                  AuthFn auth,
                  TenantFn tenant = {})
{
    if (!auth) {
        throw std::invalid_argument(
            "fasten::reader::simplehttp: an auth function is required; "
            "pass no_auth() to serve the routes without one");
    }
    // Routes are regexes and `prefix` is not escaped.
    auto route = [&prefix](const std::string& s) {
        return "^" + prefix + s + "$";
    };
    using Unscoped = fasten::reader::Response (*)(const fasten::reader::Params&);
    using Scoped   = fasten::reader::Response (*)(const fasten::reader::Params&,
                                                  const std::string&);
    auto handler = [auth, tenant](Unscoped unscoped, Scoped scoped) {
        return [auth, tenant, unscoped, scoped](auto resp, auto req) {
            if (!auth(req->header)) {
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

// Start a dedicated HTTP server on `port` in a new thread, with the
// routes mount() adds. `auth` is required, as in mount().
// Returns the thread; detach() it or join() it.
inline std::thread start(unsigned short     port,
                          const std::string& prefix,
                          AuthFn             auth,
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
