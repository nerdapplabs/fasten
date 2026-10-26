# Changelog

All notable changes to fasten are documented here.
Format: [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning 2.0](https://semver.org/).

## [Unreleased]

### Added: unified correlation, search and stream persistence (gh #58, Python + Go)

- **Stream persistence**: opt-in durable `api`/`sys` streams (SQLite +
  Postgres), written through behind the ring, with per-stream retention
  (`purge(before=...)`) and a background retention loop that calls purge on a
  schedule when `retention_api` / `retention_syslog` (config, or env
  `FASTEN_RETENTION_API` / `FASTEN_RETENTION_SYSLOG`) is set. Durations look
  like `"7d"` / `"24h"`.
- **`persist_streams` allowlist**: an explicit config knob (Python
  `fasten.init(persist_streams=...)` / Go `Config.PersistStreams` / env
  `FASTEN_PERSIST_STREAMS`) that must exactly match the streams with stores
  attached. A mismatch fails Init in either direction: a stream named
  without a store, or an attached store missing from the allowlist. When
  unset, persistence follows store attachment (the default).
- **Correlation**: `GET /logs/correlate?request_id=X` fans out to audit, api
  and sys in one call, and signals truncation with `counts`/`totals`.
- **Search**: `GET /logs/search?streams=audit,api,sys` (comma-separated
  subset; default `sys`), plus a gated `q=` on `/logs/sys`. `since=` is
  mandatory, results are hard-capped and unranked, and the feature is opt-in
  via `search.enabled` / `FASTEN_SEARCH_ENABLED`. Each named stream must have
  a store; ring-only streams report `errors.<stream>` instead of an empty
  match list. Results come back in stream order sys, api, audit, the same as
  `/correlate`.
- **Completeness**: every read reports `store` / `ring` / `store-degraded`
  per stream.
- **Structured field indexes** on `api`/`sys` (`method`/`path`/`status`,
  `level`/`service_id`/`event`) for fast, indexed lookups.
- **Sentinel `request_id` invariant**: `boot`/`orphan` (automatic) plus the
  `sched`/`bg`/`lib` namespaces, so every persisted stream row can be
  correlated. Covered by a conformance test that runs boot, request,
  background work and shutdown in sequence.
- **Query translator** (`fasten.query`): turns natural-language or smart-box
  text into structured chips plus a bounded `q=`. It is an interface with a
  deterministic reference parser, not a new endpoint.
- **Reader parity**: Go gains `/topology`, the `tenant_id`/`actor`/`target`
  filters on `/audit`, and `redactor`/`chain`/`worker_pid` in
  `/audit/doctor`.
- `spec/persistent-streams.md`: the normative contract for schema,
  completeness, sentinels, retention and constrained search.

### Changed: canonical UTC timestamp form on both SDKs

- Every outbound fasten timestamp now uses the canonical form named in
  spec §4.3: **RFC3339 with exactly six microsecond digits and always `Z`**
  (`2026-08-21T10:00:00.500000Z`, 27 chars). This covers audit
  `timestamp`/`shipped_at`, stream `timestamp`, purge cutoffs, drainer sys
  events, `/audit/doctor` `last_verified_at`, and the retention-loop cutoff:
  every place the two SDKs used to disagree.
- **Fixes** the cross-SDK window truncation that skipped Python rows 0.5 s
  after a Go `since` bound (Python emitted `…:00.500+00:00`; Go emitted
  `…:00Z` because `RFC3339Nano` strips trailing zeros), and the Go-only
  same-second inversion where whole-second rows sorted above fractional rows
  in the same second (`'Z'` 0x5A > `'.'` 0x2E).
- **One form, one parser.** The reader parsers (`parseCanonicalTS` in Go,
  `parse_canonical` in Python) are strict. Any other form is a bug at the
  source and fails loudly instead of being silently converted.
- Pinned by matching conformance tests in each SDK
  (`python/tests/test_canonical_ts.py`, `go/canonical_ts_test.go`) that
  assert byte-identical output for the same instant and reject every
  non-canonical form.

### Changed: ring filter semantics now match the store (gh #58, Python)

- `python/fasten/store/ring.py` filter comparisons switched from lax to
  strict to match the store (spec §4.2). This closes a real divergence
  between ring and store:
  - `level` is now case-sensitive (`level == "ERROR"` no longer matches `error`).
  - `method` is now case-sensitive (`method == "GET"` no longer matches `get`).
  - `path` now requires an exact match, not a substring (`path == "/users"` no
    longer matches `/users/42`).
- **Breaking for existing callers** who relied on the lax behaviour without
  persistence attached. If a dashboard calls `/logs/sys?level=ERROR` and rows
  were logged with `error`, or `/logs/api?path=/users` for prefix matches, the
  query now returns zero rows. Match the case of your query values to what
  the emitter writes, or switch to an indexed store-backed read.

### Fixed: reader hardening (gh #58, Python + Go)

- `/sys`, `/api`, `/audit` and `/correlate` reject a non-positive `limit` (a
  negative limit became `LIMIT -1`, an unbounded read on SQLite and a 500 on
  Postgres).
- `completeness.audit` no longer reports `store` in stdout-only mode (no
  audit store); it reports `ring`.
- The ring treats a `None`/absent timestamp the same way the store does
  (`COALESCE`), so ring and store agree on `since`/`until`.
- Go `LogSys`/`drainerSysLog` no longer mutate the row shared with the ring.
  This fixes a `concurrent map read and map write` crash and a `shape`
  mismatch between store and ring.

### Fixed: PostgresStore idle-in-transaction deadlock (Python)

- `PostgresStore` read methods (`query`, `count`, `list_unshipped`, `sources`,
  `max_monotonic_seq`) no longer leave their connection *idle in
  transaction*. A bare `SELECT` holds an `ACCESS SHARE` lock until the
  transaction ends. The engine's startup hash-chain seed reads
  (`max_monotonic_seq` + `query`) left such a transaction open, which
  blocked a concurrent store-init `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
  (`ACCESS EXCLUSIVE`, even as a no-op) indefinitely. Adopters that
  initialize the audit store from two processes (e.g. api + worker) against
  the same Postgres table would hang.
  `_execute_with_retry` now rolls back any transaction a read leaves open,
  whether the read returned (`INTRANS`) or raised (`INERROR`, which
  otherwise keeps the lock and leaves the connection unusable). Committed
  writes are already `IDLE` and are not touched. The cleanup is guarded so
  it cannot hide a stale-connection error during the reconnect retry, and
  the retry now logs. Regression coverage: `tests/test_store_idle_in_tx.py`
  (Postgres deadlock and error-path cases, plus a no-database
  reconnect/cleanup unit test). Downstream adopters no longer need the
  `idle_in_transaction_session_timeout` reaper workaround.

### Changed: README

- New "Where it fits" section linking to Membrane and fasten fleet.
- "What it solves" table moved above the install and quickstart.
- Opening paragraphs tightened.
- Install, Quickstart and reference sections (CLI + TUI, Languages,
  C++ logger bridges, wire schema) replaced with pointers to
  fasten.sh/docs, where the same material is at the top of the page.

### Added: redaction conformance corpus

- `spec/redact-conformance.json`: a 50-case cross-language test corpus
  covering all 14 key patterns, 7 value-shape rules
  (JWT/PEM/AWS/GH/Stripe/OpenAI/CC-Luhn), priority ordering (key pattern
  wins over value shape), nested dicts, arrays, and safe values passing
  through. All five SDKs run it: Python (`test_redact_conformance.py`), Go
  (`redact_conformance_test.go`), JS (`redact_conformance.test.mjs`), Swift
  (`RedactConformanceTests.swift`), C++ (`redact_conformance_smoke.cpp`).
- **JS `core_ffi.js`**: value-shape redaction added (it was key-pattern
  only): JWT, PEM private key, AWS AKIA/ASIA, GitHub ghp/gho/ghu/ghs/ghr
  tokens, Stripe live key, OpenAI legacy/proj keys, CC/Luhn. The patterns
  and Luhn algorithm match `fasten-core/src/redact.rs` exactly.
  Also fixed the `password`, `passwd` and `cookie` key patterns: removed
  incorrect `^...$` anchors so they match substrings (e.g. `user_password`),
  consistent with Rust/Python/Go.
- **Swift `Redactor.swift`**: value-shape patterns aligned with the
  canonical Rust ones. Removed `^...$` anchors (substring matching), added
  the ASIA variant for AWS, added the gho/ghu/ghr GitHub token types,
  updated the OpenAI pattern to include `sk-proj-...` with a 32-char
  threshold, restricted Stripe to `sk_live_` only (matches Rust), and
  extended the CC range to 13 to 19 digits (was 13 to 16).

### Changed: shared drainer (Python / Go / C++) and pure-language drainers (JS / Swift)

- The Python, Go and C++ drainers were replaced by FFI bindings to the
  shared `fasten-core` C ABI drainer (`fasten_store_from_callback` +
  `fasten_drainer_install/enqueue/flush/stats_json/close`).
  - **Python**: `ctypes` binding in `fasten/drainer.py`; `audit_queue.py` deleted (427 lines)
  - **Go**: `cgo` binding in `go/drainer.go`; `audit_queue.go` deleted (429 lines)
  - **C++**: `CFastenDrainer` class in `fasten.hpp` replaces `AuditQueueDrainer`; `audit_queue_smoke.cpp` deleted (310 lines)
  - **Rust**: remains the reference implementation inside `fasten-core`
  - **JS**: spec-conformant drainer loop in pure JS, in-process; `koffi` and all native deps removed
  - **Swift**: spec-conformant drainer loop in pure Swift, in-process (`QueueDrainer.swift`); `CFastenDrainer.swift` and the `libfasten_core` dependency removed
- Net reduction: about 3,200 lines of duplicated drainer code removed
  (Python/Go/C++).
- Drainer conformance spec (`spec/drainer-conformance.md`) updated for the
  shared-ABI architecture (v1.1).

### Added: value-shape redaction (all SDKs)

- JS, Go, Rust and C++ now match Python and Swift: string values that match
  known secret shapes are replaced with a type-hinting token before the
  row is written. Covered patterns: JWT (`***JWT***`), PEM private key
  (`***PRIVATE_KEY***`), AWS access key (`***AWS_KEY***`), GitHub token
  (`***GH_TOKEN***`), Stripe live secret (`***STRIPE_KEY***`), OpenAI
  key (`***OPENAI_KEY***`), and credit-card numbers that pass the Luhn
  checksum (`***CC***`). Runs after key-pattern redaction, so values that
  are already redacted are never processed twice.
- JS: also fixes a syntax bug where `REDACT_REPLACEMENT` was assigned
  as `` x"***" `` (an invalid JS literal); it is now `"***"`.

### Added: C++ logger bridges

Three opt-in, header-only shims in `cpp/include/fasten/shim/`:

- `fasten/shim/spdlog.hpp`: `spdlog_sink_mt` / `spdlog_sink_st`.
  Add one to an spdlog logger's sink list and each `LOG()` call also
  writes a syslog row to fasten's `/logs/sys` ring.
- `fasten/shim/glog.hpp`: call `fasten::shim::glog::install()` once and
  every `LOG(INFO/WARNING/ERROR/FATAL)` also writes to the ring.
  `install()` is idempotent; `uninstall()` is provided for tests.
- `fasten/shim/boost_log.hpp`: a `sink_mt` backend. Add it to
  `boost::log::core::get()` to mirror `BOOST_LOG_TRIVIAL` records.

All three shims apply key-pattern and value-shape redaction to the log
message before pushing it to the ring, and carry a per-thread recursion
guard so fasten's own internal log writes cannot re-enter them.
Per-shim integration tests: `shim_spdlog_smoke` and `shim_glog_smoke` use
stub headers (no install required); `shim_boost_log_smoke` is guarded by
`find_package(Boost COMPONENTS log)`.

### Added: Go `/logs/audit/doctor` health endpoint (parity with Python)

- `GET /api/v1/logs/audit/doctor` is now available in Go via `NewReader()`.
  It returns the same `store` / `queue` / `transport` / `init` JSON shape
  as Python's reader, so k8s liveness probes and compliance health checks
  work without a Python dependency.
- Added the `Transport.SyslogDepth()` / `APIDepth()` ring-depth accessors.
- Added `SQLiteStore.Count(ctx)`, used by the doctor endpoint to check that
  the store is reachable and to count rows.

### Changed: audit-store failure handling (Python), new default behaviour

- `fasten.emit()` is now **asynchronous by default**: rows go onto a
  bounded in-memory queue, drained by a background thread with exponential
  backoff (100 ms to 60 s, plus or minus 20 % jitter). A locked or down
  audit store no longer turns into 5xx responses on the request path.
- Adopters who relied on the old synchronous-raise contract opt back in
  with `audit_store_failure_strategy="raise"` (or
  `FASTEN_AUDIT_STORE_FAILURE_STRATEGY=raise`). Test fixtures that emit
  and then immediately query the store should switch to `raise` mode or
  call `flush()`.

### Added: audit-store failure handling (Python)

- `fasten.init(audit_store_failure_strategy="queue" | "raise", queue_capacity=100, queue_retry_initial_ms=100, queue_retry_max_ms=60_000, queue_retry_jitter=True)`:
  the full set of drainer tuning options.
- `fasten.flush(timeout=5.0)`: block until pending rows drain. Useful
  for deterministic shutdown (k8s preStop hook, CLI exit) and test
  setup/teardown. Returns True only if fully drained. In `raise` mode it
  does nothing and returns True, so shutdown code works in either mode.
- `fasten.queue_stats()`: a snapshot of queue depth, capacity, high-water
  mark, drained total, retry count, current backoff window, and last
  error. Returns `None` in `raise` mode.
- `fasten.AuditStoreError`: the one fasten exception type raised by
  `emit()` in `raise` mode. It wraps the underlying store exception so
  callers don't depend on sqlite3 / psycopg types.
- `GET /logs/audit/doctor` reader endpoint: a JSON health snapshot
  covering store reachability and row count, queue stats, transport ring
  depths, redactor state, and the current init parameters. Inherits the
  router's `dependencies=[Depends(...)]` for auth.
- The drainer reports state changes to the sys stream, so existing log
  aggregation catches audit-pipeline problems without polling:
  `audit_drain_failed` (warn), `audit_drain_degraded` (error, after 5 or
  more consecutive failures), `audit_drain_recovered` (info),
  `audit_queue_high_water` (warn, at 50 % capacity or more), and
  `audit_queue_near_full` (error, at 80 % or more).
- Capacity counts queued **and** in-flight retry rows. A row waiting out
  a retry backoff still occupies a slot, so `emit()` blocks once the
  audit pipeline is really saturated instead of silently dropping rows.

### Added: catalog YAML loader (Python)

- `fasten.codes.load("path.yaml")`: reads a YAML catalog into the
  registry. `pyyaml` is imported lazily, so adopters who only use
  programmatic `register()` don't need it.
- `fasten.codes.reload()`: atomic and fault-tolerant. It parses and
  validates into a fresh dict, then swaps it in under a lock. If anything
  fails (YAML parse error, invalid severity, missing field), the previous
  catalog stays active. Reload is **not additive**: codes removed from the
  file become unknown after the swap (stored audit rows stay readable; the
  wire `code` field is a free string).
- Validation errors include file:key context. Programmatic registrations
  survive a reload (they are tracked separately from YAML-loaded codes).

### Added: catalog ergonomics (Go, JS, Rust, C++)

- `Meta.id` (Go) / `meta.id` (JS) / `Meta.id` (Rust) / `Meta.id` (C++)
  is now optional and is filled from the registry key at register time.
- An explicit id that doesn't match raises with a message saying how to
  fix it (Go and Rust used to overwrite it silently).
- Key shape (`UPPER_SNAKE_CASE`) is validated everywhere.
- New error variants: `Error::IdMismatch`, `Error::InvalidKey` (Rust);
  matching error messages in Go / JS / C++.

### Added: Python logging ergonomics

- `fasten.shim.structlog.configure(json=True, debug=False, ...)`: one-call
  setup for structlog plus the stdlib bridge. Installs the redactor
  processor, `make_fasten_processor()`, a renderer (JSON or Console), and a
  stdlib `LoggingHandler` so `import logging` calls also reach the ring.
  The equivalent of Go's `slog.New(fasten.NewSlogHandler(base))`.
- `fasten.shim.stdlib.LoggingHandler`: a standalone bridge for adopters
  who don't use structlog. Pushes every stdlib `LogRecord` to the ring,
  applies redaction to extras, and includes a recursion guard for fasten's
  own pre-init fallback path.
- `fasten.log.bound(name=..., **fields)`: a per-module logger. Its log
  lines carry `logger=<name>` plus any bound fields. Chained `.bound()`
  calls compose, and explicit fields on `.info()` override bound fields.
  The Python counterpart of slog's `Logger.With`.

### Added: catalog ergonomics (Python)

- `fasten.codes.register("user", {"USER_CREATED": Meta(...)})`: dict
  form. Saves repeating `id="USER_CREATED"` for each code; the SDK fills
  `Meta.id` from the key at registration time.
- Validation: the key must be `UPPER_SNAKE_CASE`, and an explicit `Meta.id`
  must match the key (a mismatch raises; it is always a typo).
- `Meta.id` is now optional (default `""`). Existing code that passes `id=`
  still works as long as it matches the key.
- The legacy tuple-list form `register("user", [("X", Meta(...))])`
  is still supported.

### Added: Python public-API parity

- `fasten.transport()`: public accessor for the active StdoutTransport,
  so adopter middleware can push api/sys rows without reaching into
  `fasten.emit._get_stdout()`.
- `fasten.redactor()`: public accessor for the active Redactor, so
  adopter logging layers can apply the same key-pattern scrubbing
  fasten applies on emit.
- `fasten.shim.http.APILogger`: ASGI middleware that pushes one api
  row per request (`method`, `path`, `status`, `duration_ms`,
  `request_id`, `timestamp`). The counterpart of Go's
  `fasten.APILogger(skipPaths...)`, with a configurable `skip` set for
  paths like `/health` and `/metrics`.
- `AuditRepository.count(...)`: total rows matching a filter, for
  pagination on top of `query()`.
- `/audit` reader: `actor` and `target` filters and an `offset` query
  param; the response now includes `total`, `limit` and `offset`.

### Changed: Python public-API parity

- `fasten.reader.router()` now fetches the audit store and transport
  from `fasten.init()` at request time. Pass `store=` / `transport=`
  to `router()` to override them (tests, read replica).
- The `fasten.reader.router()` docstring leads with the `Depends(...)`
  gated example; trusted-network usage is the secondary example.
- The `fasten.init()` docstring lists `FASTEN_AUDIT_DSN` (and related
  variables) explicitly, split into required and optional env vars.
- Added `fasten.audit_store()` to complete the public accessor trio
  (`transport`, `redactor`, `audit_store`).

### Removed: Python public-API parity

- `fasten.emit._get_stdout`, `_get_redactor`, `_get_audit_store`.
  Use `fasten.transport()`, `fasten.redactor()` and
  `fasten.audit_store()` instead. (Pre-1.0 surface; clean break.)
- `fasten.reader.init(store, transport)`: redundant with the
  `router(store=, transport=)` keyword arguments. Remove the call;
  the router fetches from `fasten.init()` by default.

## [1.0.0-beta.0] - 2026-05-01

Promotion to 1.0.0-beta. The Python, Go and Node.js SDKs back the API
contract (emit, log, redaction and correlation, all driven by
`spec/row-schema.json`). The C++14 single-header SDK and Rust ship at beta
alongside them; Java remains a placeholder until its own beta.

### Changed
- Version bumped from `0.1.0-alpha` to `1.0.0-beta.0` in the Python,
  JS (`@nerdapplabs/fasten`) and Rust manifests
- Python `pyproject.toml` Development Status: Alpha to Beta
- JS `package.json` `exports` block: dropped the non-existent
  `./shim/*`, `./store/*` and `./reader` entries (deferred to later
  releases). The core `.` export is unchanged.
- CI: `astral-sh/setup-uv` upgraded to `v8.1.0`. Note: GitHub action
  version tags are mutable and can be re-pointed by the action owner;
  SHA-pinning every `uses:` reference is a planned follow-up.

### Added (since 0.1.0-alpha)
- Go: built-in `LogInfo/Warn/Error/Debug` for the sys stream, and deep
  `RedactDetail` (was missing). Go consumers no longer need slog
  to get `shape:"sys"` lines
- Rust: `fasten::log::info/warn/error/debug` writing `shape:"sys"`
  NDJSON (previously absent)
- Per-language Docker integration tests (`tests/integration/`)

### Notes
- Java SDK still pre-beta; `emit()` throws `UnsupportedOperationException`.
  Marketing and docs label it "coming soon."

## [0.1.0-alpha] - 2026-04-30

Initial public release of the fasten audit and correlation SDK.

### Added
- **Python** reference implementation: `emit()`, `log.*`, `init()`, SQLite store,
  HTTP / MQTT / scheduler shims, structlog shim, mountable reader, CLI (`doctor`, `tail`), TUI
- **Go** SDK: `Register`, `Init`, `Emit`, `LogInfo/Warn/Error/Debug`, `RedactDetail`,
  SQLiteStore, slog handler, HTTP shim, ring-buffer transport
- **Node.js / TypeScript** SDK: `init`, `emit`, `log.*`, deep redaction,
  AsyncLocalStorage correlation, HTTP / MQTT / scheduler shims
- **Rust** SDK (beta): typed `Row`, `Severity`, `RetentionClass`, `with_request_id`,
  `AuditRepository` + `AuditOutboxRepository` traits, `EmitBuilder`
- **C++14** single-header SDK: `fasten::emit()`, `RedactConfig`, `RequestIDMiddleware`,
  `FastenReader`, transport shims
- **Java** placeholder (emit throws; planned for v0.1.1)
- `spec/row-schema.json`: JSON Schema as the single source of truth for enums and redact rules
- `spec/codegen.py`: generates enum/constant blocks into all 6 adapters (`--write` / `--check`)
- Per-language Docker integration smokes + `tests/integration/verify.py` contract checker

[1.0.0-beta.0]: https://github.com/nerdapplabs/fasten/releases/tag/v1.0.0-beta.0
[0.1.0-alpha]: https://github.com/nerdapplabs/fasten/releases/tag/v0.1.0-alpha
[Unreleased]: https://github.com/nerdapplabs/fasten/compare/v1.0.0-beta.0...HEAD
