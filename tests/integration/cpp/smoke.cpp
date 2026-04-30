// C++ smoke: register, init, log::info (sys), emit (audit) with PII detail.
//
// Build (C++14):
//   g++ -std=c++14 -I<repo>/cpp/include smoke.cpp -o smoke
#include "fasten.hpp"

int main() {
    fasten::register_codes("user", {
        {"USER_CREATED", {
            "USER_CREATED", "user", "account", "create",
            fasten::Sev::Info, "New user account created", "auth-service",
        }},
    });

    fasten::init("itest-cpp", "host-itest");

    fasten::RequestScope scope; // mint a 12-char request_id

    // 1. sys row
    fasten::log::info("startup_ok", {{"lang", "cpp"}});

    // 2. audit row with PII detail (flat Fields — no nested map in C++ adapter)
    fasten::emit("USER_CREATED",
        fasten::target("u-42"),
        fasten::actor("admin", "user"),
        fasten::detail({
            {"email", "alice@acme.com"},
            {"api_key", "sk-secret-abc"},
        }));

    return 0;
}
