/**
 * reader_example.cpp — shows two ways to expose the fasten reader:
 *
 *   1. Simple-Web-Server adapter (fasten_reader_simplehttp.hpp)
 *   2. Custom / other-framework adapter (fasten_reader.hpp directly)
 *
 * Build with Simple-Web-Server (must clone alongside this repo):
 *   g++ -std=c++14 -I../include -I/path/to/Simple-Web-Server \
 *       reader_example.cpp -o reader -lpthread
 *
 * Run:
 *   FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=node-01 ./reader
 *   curl http://localhost:9000/api/v1/logs/sys
 *   curl http://localhost:9000/api/v1/logs/audit
 */

// ── 1. Core reader (no framework dep) ────────────────────────────────────
#include "fasten_reader.hpp"

// ── 2. Simple-Web-Server adapter (comment out if not available) ───────────
// #include "fasten_reader_simplehttp.hpp"

#include <iostream>
#include <thread>
#include <chrono>

// ---------------------------------------------------------------------------
// Pattern A — Simple-Web-Server (one-liner start)
// ---------------------------------------------------------------------------
// #include "fasten_reader_simplehttp.hpp"
//
// void start_simplehttp() {
//     // No auth — trusted network only.
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
// Pattern B — Crow (https://crowcpp.org)
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
// Pattern C — Pistache (https://pistacheio.github.io/pistache)
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
// Pattern D — custom / minimal raw server
// The general contract: parse URL query string → Params, call handle_*,
// write status + "Content-Type: application/json" + body.
// ---------------------------------------------------------------------------
//
// Any server (boost::beast, POCO, raw POSIX sockets, etc.) follows the same
// three steps:
//
//   1. Parse query string into fasten::reader::Params
//      (unordered_map<string, string>)
//   2. Call handle_sys / handle_api / handle_audit
//   3. Return response.status, "Content-Type: application/json", response.body
//
// Example with a hypothetical parse_qs() utility:
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

    // Register a fake audit query (normally this hits your SQLite/Postgres).
    fasten::reader::set_audit_query(
        [](const std::string& /*rid*/, const std::string& /*code*/,
           const std::string& /*domain*/, int limit) {
            // Return an empty list — replace with real store query.
            (void)limit;
            return std::vector<fasten::Row>{};
        });

    // Emit something so the ring buffers have data.
    {
        fasten::RequestScope scope;
        fasten::log::info("demo_started", {{"version", "0.1"}});
        fasten::emit("CONN_UP",
            fasten::target("tcp://10.0.0.1:502"),
            fasten::detail({{"host", "10.0.0.1"}}));
    }

    // Call handlers directly — same functions the HTTP adapters use.
    auto r_sys   = fasten::reader::handle_sys({{"limit", "10"}});
    auto r_api   = fasten::reader::handle_api({});
    auto r_audit = fasten::reader::handle_audit({{"limit", "5"}});

    std::cout << "GET /sys   → " << r_sys.status   << " " << r_sys.body   << "\n";
    std::cout << "GET /api   → " << r_api.status   << " " << r_api.body   << "\n";
    std::cout << "GET /audit → " << r_audit.status << " " << r_audit.body << "\n";

    return 0;
}
