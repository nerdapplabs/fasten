# fasten — C++14

Audit + correlation SDK for C++14+. Single-header, **zero external
dependencies**. v1.0.0-beta.

## Install

Copy [`include/fasten.hpp`](include/fasten.hpp) into your project. That's
it. (Optional: `include/fasten/codes_yaml.hpp` for YAML-loaded code
catalogs — adds a libyaml-cpp dep only when included.)

## Quickstart

```cpp
#include "fasten.hpp"

int main() {
    fasten::register_codes("node", {
        {"CONN_UP", {
            "CONN_UP", "node", "connector", "connected",
            fasten::Sev::Info, "Connection established", "edge-svc",
        }},
    });

    // Optional: register a sink that persists rows to your store.
    fasten::set_audit_sink([](const fasten::Row& r) {
        // r.id, r.code, r.detail, r.request_id, ...
    });

    fasten::init({"edge-svc", "host-01"});

    {
        fasten::RequestScope scope("req-a1b2c3");          // RAII; restores prev
        fasten::emit("CONN_UP",
            fasten::target("modbus://192.168.1.10"),
            fasten::detail({{"host", "192.168.1.10"}, {"port", "502"}}));
        fasten::log::info("poll_started", {{"interval_ms", "1000"}});
    }

    fasten::flush(std::chrono::seconds(5));   // drain pending audit rows
    return 0;
}
```

Both lines stream NDJSON to stdout under the same `request_id`.

## Worked examples

Two complete examples in [`examples/`](examples/):

- [`connector.cpp`](examples/connector.cpp) — Modbus TCP stub showing
  `RequestScope`, `emit`, retry-with-context wiring.
- [`reader_example.cpp`](examples/reader_example.cpp) — full reader
  endpoint demo backed by `FastenReader` (use the bundled
  `reader_simplehttp_main.cpp` to wire it to a real HTTP server).

Build either with the project's CMakeLists:

```bash
cd cpp && mkdir -p build && cd build
cmake -DFASTEN_BUILD_TESTS=ON ..
cmake --build .
./connector
```

Or single-file (no CMake):

```bash
g++ -std=c++14 -O2 -I include examples/connector.cpp -o connector
FASTEN_SERVICE_ID=modbus-tcp FASTEN_NODE_ID=edge-01 ./connector
```

## P1-15: audit-store failure handling

When you register an audit sink and call `fasten::init()` with the
default `audit_store_failure_strategy = "queue"`, fasten spawns a
background `std::thread` that drains the queue with exponential
backoff (100 ms → 60 s, ±20 % jitter). Sink exceptions stay off the
request path. Set `audit_store_failure_strategy = "raise"` to opt
into synchronous semantics with `fasten::AuditStoreError`.
`fasten::queue_stats()` and `fasten::flush(timeout)` complete the
public surface.

## Tests

```bash
docker run --rm -v $PWD/cpp:/work gcc:14-bookworm sh -c \
  "apt-get update && apt-get install -y cmake libyaml-cpp-dev && \
   mkdir -p /work/build && cd /work/build && \
   cmake /work -DFASTEN_BUILD_TESTS=ON && cmake --build . && ctest"
```

Current: 3/3 ctest suites pass (pii_in_detail, redact_substring, codes_yaml).

## Docs + design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/) ·
Design + cross-language design: [README.md](../README.md).
