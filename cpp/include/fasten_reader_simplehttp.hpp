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
// Call this before server.start().
inline void mount(HttpServer& server,
                  const std::string& prefix = "/api/v1/logs",
                  AuthFn auth = {})
{
    // Build regex route string — prefix is treated as a literal path.
    auto route = [&prefix](const std::string& s) {
        return "^" + prefix + s + "$";
    };

    server.resource[route("/sys")]["GET"] =
        [auth](auto resp, auto req) {
            if (!detail_::check_auth(req->header, auth)) {
                return detail_::unauthorized(resp);
            }
            detail_::send(resp,
                fasten::reader::handle_sys(
                    detail_::to_params(req->parse_query_string())));
        };

    server.resource[route("/api")]["GET"] =
        [auth](auto resp, auto req) {
            if (!detail_::check_auth(req->header, auth)) {
                return detail_::unauthorized(resp);
            }
            detail_::send(resp,
                fasten::reader::handle_api(
                    detail_::to_params(req->parse_query_string())));
        };

    server.resource[route("/audit")]["GET"] =
        [auth](auto resp, auto req) {
            if (!detail_::check_auth(req->header, auth)) {
                return detail_::unauthorized(resp);
            }
            detail_::send(resp,
                fasten::reader::handle_audit(
                    detail_::to_params(req->parse_query_string())));
        };
}

// Start a dedicated HTTP server on `port` in a new thread.
// Returns the thread — call detach() for fire-and-forget, join() to block.
inline std::thread start(unsigned short     port   = 9000,
                          const std::string& prefix = "/api/v1/logs",
                          AuthFn             auth   = {})
{
    auto srv = std::make_shared<HttpServer>();
    srv->config.port = port;
    mount(*srv, prefix, std::move(auth));
    return std::thread([srv]() { srv->start(); });
}

} // namespace simplehttp
} // namespace reader
} // namespace fasten
