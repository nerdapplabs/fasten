/**
 * reader_example.cpp: serving the /logs endpoints.
 *
 * Patterns A to D (commented out) show Simple-Web-Server, Crow, Pistache
 * and a hand-written server. main() calls the handlers directly and prints
 * the responses.
 *
 * Build:
 *   g++ -std=c++14 -I../include reader_example.cpp \
 *       -L../../fasten-core/target/release -lfasten_core -lpthread -o reader
 */

#include "fasten_reader.hpp"

#include <iostream>
#include <thread>
#include <chrono>

// ---------------------------------------------------------------------------
// Pattern A: Simple-Web-Server
// ---------------------------------------------------------------------------
// #include "fasten_reader_simplehttp.hpp"
//
// void start_simplehttp() {
//     // No auth: trusted network only.
//     auto t = fasten::reader::simplehttp::start(9000);
//     t.detach();
//
//     // With API key auth:
//     // auto t = fasten::reader::simplehttp::start(9000, "/api/v1/logs",
//     //     [](const SimpleWeb::CaseInsensitiveMultimap& h) {
//     //         auto it = h.find("x-api-key");
//     //         return it != h.end() && it->second == "secret-key";
//     //     });
//     // t.detach();
// }

// ---------------------------------------------------------------------------
// Pattern B: Crow (https://crowcpp.org)
// ---------------------------------------------------------------------------
// #include "crow.h"
// #include "fasten_reader.hpp"
//
// void setup_crow_routes(crow::SimpleApp& app) {
//     CROW_ROUTE(app, "/api/v1/logs/sys")
//     ([](const crow::request& req) {
//         fasten::reader::Params p;
//         for (auto& kv : req.url_params)
//             p[kv.first] = kv.second;
//         auto r = fasten::reader::handle_sys(p);
//         return crow::response(r.status, r.body);
//     });
//
//     CROW_ROUTE(app, "/api/v1/logs/api")
//     ([](const crow::request& req) {
//         fasten::reader::Params p;
//         for (auto& kv : req.url_params) p[kv.first] = kv.second;
//         auto r = fasten::reader::handle_api(p);
//         return crow::response(r.status, r.body);
//     });
//
//     CROW_ROUTE(app, "/api/v1/logs/audit")
//     ([](const crow::request& req) {
//         fasten::reader::Params p;
//         for (auto& kv : req.url_params) p[kv.first] = kv.second;
//         auto r = fasten::reader::handle_audit(p);
//         return crow::response(r.status, r.body);
//     });
// }

// ---------------------------------------------------------------------------
// Pattern C: Pistache (https://pistacheio.github.io/pistache)
// ---------------------------------------------------------------------------
// #include <pistache/endpoint.h>
// #include "fasten_reader.hpp"
//
// struct FastenHandler : Pistache::Http::Handler {
//     HTTP_PROTOTYPE(FastenHandler)
//
//     void onRequest(const Pistache::Http::Request& req,
//                    Pistache::Http::ResponseWriter resp) override
//     {
//         fasten::reader::Params p;
//         for (auto& kv : req.query())
//             p[kv.name()] = kv.value();
//
//         fasten::reader::Response r{404, "{\"error\":\"not found\"}"};
//         auto path = req.resource();
//         if      (path == "/api/v1/logs/sys")   r = fasten::reader::handle_sys(p);
//         else if (path == "/api/v1/logs/api")   r = fasten::reader::handle_api(p);
//         else if (path == "/api/v1/logs/audit") r = fasten::reader::handle_audit(p);
//
//         auto code = static_cast<Pistache::Http::Code>(r.status);
//         resp.headers().add<Pistache::Http::Header::ContentType>("application/json");
//         resp.send(code, r.body);
//     }
// };

// ---------------------------------------------------------------------------
// Pattern D: any other server (boost::beast, POCO, raw sockets, ...)
// ---------------------------------------------------------------------------
//
//
//   1. Parse query string into fasten::reader::Params
//      (unordered_map<string, string>)
//   2. Call handle_sys / handle_api / handle_audit
//   3. Return response.status, "Content-Type: application/json", response.body
//
// With some parse_qs() helper:
//
//   fasten::reader::Params p = parse_qs(request.query_string);
//   auto r = fasten::reader::handle_sys(p);
//   send_response(conn, r.status, "application/json", r.body);

// ---------------------------------------------------------------------------
// Demo: call the handlers in-process without any HTTP server
// ---------------------------------------------------------------------------

int main() {
    fasten::register_codes("node", {
        {"CONN_UP", {"CONN_UP", "node", "connector", "up",
                     fasten::Sev::Info, "Connected", "demo"}},
    });
    fasten::init("demo-svc", "node-01");

    // Stand-in for a query against the audit store.
    fasten::reader::set_audit_query(
        [](const std::string& /*rid*/, const std::string& /*code*/,
           const std::string& /*domain*/, int limit) {
            (void)limit;
            return std::vector<fasten::Row>{};
        });

    // Emit something so the log buffers have data.
    {
        fasten::RequestScope scope;
        fasten::log::info("demo_started", {{"version", "0.1"}});
        fasten::emit("CONN_UP",
            fasten::target("tcp://10.0.0.1:502"),
            fasten::detail({{"host", "10.0.0.1"}}));
    }

    // The same handlers the HTTP adapters call.
    auto r_sys   = fasten::reader::handle_sys({{"limit", "10"}});
    auto r_api   = fasten::reader::handle_api({});
    auto r_audit = fasten::reader::handle_audit({{"limit", "5"}});

    std::cout << "GET /sys   -> " << r_sys.status   << " " << r_sys.body   << "\n";
    std::cout << "GET /api   -> " << r_api.status   << " " << r_api.body   << "\n";
    std::cout << "GET /audit -> " << r_audit.status << " " << r_audit.body << "\n";

    return 0;
}
