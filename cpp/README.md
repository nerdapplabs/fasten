# fasten for C++14

Audit and correlation SDK for C++14 and later. v1.0.0-beta.

The SDK is header-only. Redaction, the code catalog and the audit queue live
in `libfasten_core` (the Rust library in [`fasten-core/`](../fasten-core)),
so programs must link with `-lfasten_core`.

## Install

You need the headers in [`include/`](include/) and `libfasten_core`, built
with `--features all`. A program that only includes `fasten.hpp` compiles
with `-std=c++14` (or later) and links `-lfasten_core -pthread`. Add
`-lsqlite3` when you include `fasten_store_sqlite.hpp`, `-lpq` (and the
libpq include path, `-I/usr/include/postgresql` on Debian) for
`fasten_store_postgres.hpp`, and `-lyaml-cpp` for
`include/fasten/codes_yaml.hpp` (it loads code catalogs from YAML).
`fasten_core.h` is not needed; `fasten.hpp` declares the functions it calls.

### From a GitHub release

Each `vX.Y.Z` release has two files for C++:

- `fasten-cpp-vX.Y.Z.tar.gz`: the headers, under
  `fasten-cpp-vX.Y.Z/cpp/include/`.
- `fasten-core-vX.Y.Z-linux-x86_64.tar.gz`: `lib/libfasten_core.so`,
  `lib/libfasten_core.a` and `include/fasten_core.h`. It needs glibc 2.34 or
  later and OpenSSL 3 (`libssl3`) at run time.

The release has a prebuilt library for Linux x86_64 only. On macOS or
another target, build it from a clone (below). `SHA256SUMS` on the release
lists the checksum of each file.

From the directory with your `app.cpp` and the two downloaded files:

```bash
V=vX.Y.Z
tar xzf fasten-cpp-$V.tar.gz
tar xzf fasten-core-$V-linux-x86_64.tar.gz
g++ -std=c++14 -O2 -I fasten-cpp-$V/cpp/include app.cpp \
    -L fasten-core-$V-linux-x86_64/lib -lfasten_core -lsqlite3 -pthread -o app
LD_LIBRARY_PATH=$PWD/fasten-core-$V-linux-x86_64/lib ./app
```

Drop `-lsqlite3` if you do not use `SqliteStore`. To skip
`LD_LIBRARY_PATH`, copy `libfasten_core.so` to a directory the loader
searches (for example `/usr/local/lib`, then run `ldconfig`).

### From a clone

Building `libfasten_core` needs Rust (the version in
[`rust-toolchain.toml`](../rust-toolchain.toml)), `pkg-config` and the
OpenSSL headers (`libssl-dev` on Debian).

```bash
git clone https://github.com/nerdapplabs/fasten.git
(cd fasten/fasten-core && cargo build --release --locked --features all)
g++ -std=c++14 -O2 -I fasten/cpp/include app.cpp \
    -L fasten/fasten-core/target/release -lfasten_core -lsqlite3 -pthread -o app
LD_LIBRARY_PATH=$PWD/fasten/fasten-core/target/release ./app
```

On macOS the library is `libfasten_core.dylib`; use `DYLD_LIBRARY_PATH`
instead of `LD_LIBRARY_PATH`.

With CMake, add the clone's `cpp/` directory and link the `fasten`
target. It finds `libfasten_core` in `fasten-core/target/release` of the
same clone (set `FASTEN_CORE_LIB_DIR` to use another directory):

```cmake
cmake_minimum_required(VERSION 3.18)
project(app LANGUAGES CXX)
set(FASTEN_BUILD_EXAMPLES OFF CACHE BOOL "")
add_subdirectory(fasten/cpp fasten)
find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)
add_executable(app app.cpp)
target_link_libraries(app PRIVATE fasten SQLite::SQLite3 Threads::Threads)
```

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

    fasten::shutdown();   // write pending audit rows, stop the drainer
    return 0;
}
```

The engine is a static, destroyed after `main()`'s locals. If the sink
writes to a local store, call `fasten::shutdown()` before the store goes
out of scope, or declare a `fasten::ShutdownGuard` after it:

```cpp
fasten::SqliteStore store("audit.db");
fasten::set_audit_sink(store.sink());
fasten::init({"edge-svc", "host-01"});
fasten::ShutdownGuard guard;   // runs before store is destroyed
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
`queue_drain_max_attempts` (default 50) sets how many inserts a row gets
before it is dead-lettered.

`emit()` returns the row with `monotonic_seq` 0. The bundled
`SqliteStore` and `PostgresStore` give it the node's next seq in the
insert's transaction; rows are not sealed. A row put on a drainer that
`init()` has just replaced is reported as `audit_drain_abandoned`.

## PII retention

Rows of a code with `pii_in_detail` (or retention class short) can be
redacted once they are older than your PII period:

```cpp
fasten::SqliteStore store("audit.db");
auto ids = fasten::redact_expired(store,
    std::chrono::system_clock::now() - std::chrono::hours(24 * 30));
```

Each row keeps its place, and its `detail` becomes `null`. An
`AUDIT_ROW_REDACTED` row naming it is written to the store first. fasten
runs no background job for this, so call it on a schedule. C++ rows are
unsealed, so all of them can be redacted. A row sealed under canonical form
`"1"` by another SDK is left alone and counted on the sys stream.

## Reader tenant isolation

On a store shared by several tenants, resolve the caller's tenant from
your own auth and call the reader handlers that take it:

```cpp
auto r = fasten::reader::handle_audit(params, tenant_from_my_auth(req));
fasten::reader::enforce_tenant_isolation();  // handlers without a tenant answer 401
```

Rows are limited to that tenant and `?tenant_id=` is ignored. Register
`set_scoped_audit_query()` to pass the tenant to your store query. Sys
rows carry the engine's `tenant_id`. The Simple-Web-Server adapter takes
a tenant resolver as the fourth argument of `mount()` / `start()`.

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
`shim_glog_smoke`, `drainer_conformance_smoke`, `row_fields_smoke`,
`reader_scope_smoke`, and, when their dependencies are found,
`sqlite_store_smoke`, `postgres_store_smoke`, `codes_yaml_smoke` and
`shim_boost_log_smoke`.

## Docs and design

Full reference: [https://fasten.sh/docs/](https://fasten.sh/docs/).
Design and cross-language design: [README.md](../README.md).
