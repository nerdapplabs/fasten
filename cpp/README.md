# fasten for C++14

Audit and correlation SDK for C++14 and later. v1.0.0-beta.

The SDK is header-only. Redaction, the code catalog and the audit queue live
in `libfasten_core` (the Rust library in [`fasten-core/`](../fasten-core)),
so programs must link with `-lfasten_core`.

## Install

1. Build `libfasten_core`:

   ```bash
   cd fasten-core && cargo build --release --features all
   ```

2. Copy [`include/fasten.hpp`](include/fasten.hpp) into your project and
   link against `fasten-core/target/release/libfasten_core`.

Optional: `include/fasten/codes_yaml.hpp` loads code catalogs from YAML. It
adds a libyaml-cpp dependency only when you include it.

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

Both lines go to stdout as NDJSON with the same `request_id`.

## Worked examples

Two complete examples are in [`examples/`](examples/):

- [`connector.cpp`](examples/connector.cpp): a Modbus TCP stub showing
  `RequestScope`, `emit`, and retry-with-context wiring.
- [`reader_example.cpp`](examples/reader_example.cpp): the reader
  endpoints backed by `FastenReader`. To serve them over HTTP, use
  [`include/fasten_reader_simplehttp.hpp`](include/fasten_reader_simplehttp.hpp),
  the Simple-Web-Server adapter.

Build them with the project's CMakeLists, after building `libfasten_core`.
`FASTEN_CORE_LIB_DIR` defaults to `../fasten-core/target/release`:

```bash
cd cpp && mkdir -p build && cd build
cmake -DFASTEN_BUILD_TESTS=ON ..
cmake --build .
./connector
```

Or as a single file, without CMake:

```bash
g++ -std=c++14 -O2 -I include examples/connector.cpp \
    -L ../fasten-core/target/release -lfasten_core -lpthread -o connector
FASTEN_SERVICE_ID=modbus-tcp FASTEN_NODE_ID=edge-01 ./connector
```

On Linux, add `fasten-core/target/release` to `LD_LIBRARY_PATH` when running.

## Audit-store failure handling

When you register an audit sink and call `fasten::init()` with the default
`audit_store_failure_strategy = "queue"`, fasten starts a background
`std::thread` that drains the queue with exponential backoff (100 ms to
60 s, plus or minus 20 % jitter). Sink exceptions stay off the request
path. Set `audit_store_failure_strategy = "raise"` for synchronous writes
that throw `fasten::AuditStoreError`. `fasten::queue_stats()` and
`fasten::flush(timeout)` complete the public surface.

## Tests

The same steps CI runs (see
[`fasten-cpp.yml`](../.github/workflows/fasten-cpp.yml)), from the repo
root:

```bash
(cd fasten-core && cargo build --release --locked --features all)
sudo apt-get install -y cmake g++ libyaml-cpp-dev libsqlite3-dev
cd cpp
cmake -S . -B build -DFASTEN_BUILD_TESTS=ON -DFASTEN_BUILD_EXAMPLES=ON \
  -DFASTEN_CORE_LIB_DIR=$PWD/../fasten-core/target/release
cmake --build build --parallel
LD_LIBRARY_PATH=$PWD/../fasten-core/target/release \
  ctest --test-dir build --output-on-failure
```

ctest suites: `pii_in_detail_smoke`, `redact_substring_smoke`,
`redact_env_keys_smoke`, `redact_conformance_smoke`, `shim_spdlog_smoke`,
`shim_glog_smoke`, and, when their dependencies are found,
`sqlite_store_smoke`, `postgres_store_smoke`, `codes_yaml_smoke` and
`shim_boost_log_smoke`.

## Docs and design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/).
Design and cross-language design: [README.md](../README.md).
