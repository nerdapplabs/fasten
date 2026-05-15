# Changelog

All notable changes to fasten are documented here.
Format: [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning 2.0](https://semver.org/).

## [Unreleased]

### Added — Redact conformance corpus (P0-7 Step 1)

- `spec/redact-conformance.json` — 50-case cross-language test corpus covering all 14 key
  patterns, 7 value-shape rules (JWT/PEM/AWS/GH/Stripe/OpenAI/CC-Luhn), priority ordering
  (key-pattern wins over value-shape), nested dicts, arrays, and safe-value pass-through.
  All five SDKs run it: Python (`test_redact_conformance.py`), Go (`redact_conformance_test.go`),
  JS (`redact_conformance.test.mjs`), Swift (`RedactConformanceTests.swift`),
  C++ (`redact_conformance_smoke.cpp`).
- **JS `core_ffi.js`** — value-shape redaction added (was key-pattern only): JWT, PEM private key,
  AWS AKIA/ASIA, GitHub ghp/gho/ghu/ghs/ghr tokens, Stripe live key, OpenAI legacy/proj keys,
  CC/Luhn. Patterns and Luhn algorithm mirror `fasten-core/src/redact.rs` exactly.
  Also fixed `password`, `passwd`, `cookie` key patterns: removed incorrect `^...$` anchors so they
  match substrings (e.g. `user_password`) consistently with Rust/Python/Go.
- **Swift `Redactor.swift`** — value-shape patterns aligned with Rust canonical: removed `^...$`
  anchors (substring matching), added ASIA variant for AWS, added gho/ghu/ghr GitHub token types,
  updated OpenAI pattern to include `sk-proj-...` and 32-char threshold, restricted Stripe to
  `sk_live_` only (matches Rust), extended CC range to 13–19 digits (was 13–16).

### Changed — Shared drainer unification (P0-7, Python / Go / C++) + Pure-language ports (P1-25, JS / Swift)

- Python, Go, and C++ drainer implementations replaced by FFI bindings to
  the shared `fasten-core` C ABI drainer (`fasten_store_from_callback` +
  `fasten_drainer_install/enqueue/flush/stats_json/close`).
  - **Python** — `ctypes` binding in `fasten/drainer.py`; `audit_queue.py` deleted (427 lines)
  - **Go** — `cgo` binding in `go/drainer.go`; `audit_queue.go` deleted (429 lines)
  - **C++** — `CFastenDrainer` class in `fasten.hpp` replaces `AuditQueueDrainer`; `audit_queue_smoke.cpp` deleted (310 lines)
  - **Rust** — remains the authoritative reference implementation inside `fasten-core`
  - **JS** — spec-conformant pure JS in-process drainer loop; `koffi` and all native deps removed (P1-25)
  - **Swift** — spec-conformant pure Swift in-process drainer loop (`QueueDrainer.swift`); `CFastenDrainer.swift` and `libfasten_core` dependency removed (P1-25)
- Net reduction: ~3,200 lines of duplicated drainer code eliminated (Python/Go/C++).
- Drainer conformance spec (`spec/drainer-conformance.md`) updated to
  reflect the shared-ABI architecture (v1.1).

### Added — Value-shape redaction (P1-24, all SDKs)

- JS, Go, Rust, C++ now match Python and Swift: string values matching
  known secret shapes are replaced with a type-hinting token before the
  row is written. Covered patterns: JWT (`***JWT***`), PEM private key
  (`***PRIVATE_KEY***`), AWS access key (`***AWS_KEY***`), GitHub token
  (`***GH_TOKEN***`), Stripe live secret (`***STRIPE_KEY***`), OpenAI
  key (`***OPENAI_KEY***`), credit-card numbers passing Luhn checksum
  (`***CC***`). Applies after key-pattern redaction so already-redacted
  values are never double-processed.
- JS: also fixes a syntax bug where `REDACT_REPLACEMENT` was assigned
  as `` x"***" `` (invalid JS literal) — corrected to `"***"`.

### Added — C++ logger bridges (P1-12)

Three opt-in, header-only shims in `cpp/include/fasten/shim/`:

- `fasten/shim/spdlog.hpp` — `spdlog_sink_mt` / `spdlog_sink_st`:
  push onto an spdlog logger's sink list; each `LOG()` call mirrors
  a syslog row into fasten's `/logs/sys` ring.
- `fasten/shim/glog.hpp` — call `fasten::shim::glog::install()` once;
  every `LOG(INFO/WARNING/ERROR/FATAL)` also writes to the ring.
  `install()` is idempotent; `uninstall()` provided for tests.
- `fasten/shim/boost_log.hpp` — `sink_mt` backend; add to
  `boost::log::core::get()` to mirror `BOOST_LOG_TRIVIAL` records.

All three shims apply key-pattern + value-shape redaction on the log
message before pushing to the ring, and carry a per-thread recursion
guard to prevent re-entry from fasten's own internal log writes.
Per-shim integration tests added: `shim_spdlog_smoke` and
`shim_glog_smoke` use stub headers (no install required); 
`shim_boost_log_smoke` is guarded by `find_package(Boost COMPONENTS log)`.

### Added — Go `/logs/audit/doctor` health endpoint (P1-15 parity)

- `GET /api/v1/logs/audit/doctor` now available in Go via `NewReader()`.
  Returns the same `store` / `queue` / `transport` / `init` JSON shape
  as Python's reader, enabling k8s liveness probes and compliance
  health checks without a Python dependency.
- `Transport.SyslogDepth()` / `APIDepth()` ring-depth accessors added.
- `SQLiteStore.Count(ctx)` added; used by the doctor endpoint for
  store reachability + row-count probe.

### Changed — Audit-store failure handling (P1-15, Python) — DEFAULT BEHAVIOR

- `fasten.emit()` is now **asynchronous by default**: rows are pushed
  onto a bounded in-memory queue, drained by a background thread with
  exponential backoff (100 ms → 60 s, ±20 % jitter). A locked / down
  audit store no longer cascades into 5xxs on the request path.
- Adopters who relied on the old synchronous-raise contract opt in via
  `audit_store_failure_strategy="raise"` (or
  `FASTEN_AUDIT_STORE_FAILURE_STRATEGY=raise`). Test fixtures that
  emit-then-immediately-query-the-store should switch to `raise` mode
  or call the eventual `flush()` API.

### Added — Audit-store failure handling (P1-15, Python)

- `fasten.init(audit_store_failure_strategy="queue" | "raise", queue_capacity=100, queue_retry_initial_ms=100, queue_retry_max_ms=60_000, queue_retry_jitter=True)` —
  full surface for tuning the drainer.
- `fasten.flush(timeout=5.0)` — block until pending rows drain. Useful
  for deterministic shutdown (k8s preStop hook, CLI exit) and test
  setup/teardown. Returns True iff fully drained; no-op + returns True
  in `raise` mode so adopter shutdown code stays mode-agnostic.
- `fasten.queue_stats()` — programmatic snapshot of queue depth,
  capacity, high-water mark, drained-total, retry count, current
  backoff window, and last error. Returns `None` in `raise` mode.
- `fasten.AuditStoreError` — single fasten-namespaced exception type
  raised by `emit()` in `raise` mode; wraps the underlying store
  exception so callers don't depend on sqlite3 / psycopg types.
- `GET /logs/audit/doctor` reader endpoint — JSON health snapshot
  covering store reachability + row count, queue stats, transport
  ring depths, redactor state, and current init parameters. Inherits
  the router's `dependencies=[Depends(...)]` for auth.
- Drainer self-reports state transitions to the sys stream so
  existing log aggregation catches audit-pipeline issues without
  polling: `audit_drain_failed` (warn), `audit_drain_degraded` (error,
  after 5+ consecutive failures), `audit_drain_recovered` (info),
  `audit_queue_high_water` (warn, ≥ 50 % capacity), and
  `audit_queue_near_full` (error, ≥ 80 %).
- Capacity counts queued **and** in-flight retry rows — a row in
  retry-backoff still occupies a slot, so `emit()` blocks once the
  audit pipeline is genuinely saturated rather than silently dropping.

### Added — Catalog YAML loader (P1-11, Python)

- `fasten.codes.load("path.yaml")` — reads a yaml catalog into the
  registry. Lazy `pyyaml` import: adopters who stay on programmatic
  `register()` never pay the dep.
- `fasten.codes.reload()` — atomic + fault-tolerant. Parses + validates
  fully into a fresh dict, then swaps under a lock. If anything fails
  (yaml parse error, invalid severity, missing field), the previous
  catalog stays active. Reload is **not additive** — codes removed from
  the file become unknown after the swap (stored audit rows still
  readable; the wire `code` field is a free string).
- Validation includes file:key context in error messages. Programmatic
  registrations survive reload (tracked separately from yaml-loaded
  codes).

### Added — Cross-language P1-10 (Go, JS, Rust, C++)

- `Meta.id` (Go) / `meta.id` (JS) / `Meta.id` (Rust) / `Meta.id` (C++)
  is now optional — fills from the registry key at register time.
- Explicit id mismatch raises with a fix-it message (was silently
  overwritten before in Go and Rust).
- Key-shape validation (`UPPER_SNAKE_CASE`) enforced everywhere.
- New error variants: `Error::IdMismatch`, `Error::InvalidKey` (Rust);
  matching error messages in Go / JS / C++.

### Added — Python logging ergonomics (P1-9)

- `fasten.shim.structlog.configure(json=True, debug=False, ...)` — one-call
  setup for structlog + stdlib bridge. Installs the redactor processor
  + `make_fasten_processor()` + a renderer (JSON or Console), plus a
  stdlib `LoggingHandler` so `import logging` calls also reach the ring.
  Mirrors Go's `slog.New(fasten.NewSlogHandler(base))`.
- `fasten.shim.stdlib.LoggingHandler` — standalone bridge for adopters
  who don't use structlog. Pushes every stdlib `LogRecord` to the ring,
  applies redaction to extras, includes a recursion guard for fasten's
  own pre-init fallback path.
- `fasten.log.bound(name=..., **fields)` — per-module logger; emissions
  carry `logger=<name>` plus any bound fields. Chained `.bound()` calls
  compose; explicit fields on `.info()` override bound fields. Pythonic
  mirror of slog's `Logger.With`.

### Added — Catalog ergonomics (P1-10, Python)

- `fasten.codes.register("user", {"USER_CREATED": Meta(...)})` — dict
  form. Saves the redundant `id="USER_CREATED"` per code; SDK fills
  `Meta.id` from the key at registration time.
- Validation: key must be `UPPER_SNAKE_CASE`, explicit `Meta.id` must
  match the key (raise on mismatch — that's a typo, never a feature).
- `Meta.id` is now optional (default `""`). Old code passing `id=` still
  works as long as it matches the key.
- Legacy tuple-list form `register("user", [("X", Meta(...))])`
  remains supported.

### Added — Python public-API parity (P1-8)

- `fasten.transport()` — public accessor for the active StdoutTransport,
  so adopter middleware can push api/sys rows without reaching into
  `fasten.emit._get_stdout()`.
- `fasten.redactor()` — public accessor for the active Redactor, so
  adopter logging layers can apply the same key-pattern scrubbing
  fasten applies on emit.
- `fasten.shim.http.APILogger` — ASGI middleware that pushes one api
  row per request (`method`, `path`, `status`, `duration_ms`,
  `request_id`, `timestamp`). Mirrors Go's `fasten.APILogger(skipPaths...)`;
  configurable `skip` set for paths like `/health`, `/metrics`.
- `AuditRepository.count(...)` — total rows matching a filter, for
  pagination on top of `query()`.
- `/audit` reader: `actor`, `target` filters; `offset` query param;
  response now includes `total`, `limit`, `offset`.

### Changed — Python public-API parity (P1-8)

- `fasten.reader.router()` now auto-fetches the audit store + transport
  from `fasten.init()` at request time. Pass `store=` / `transport=`
  to `router()` itself for overrides (tests, read-replica).
- `fasten.reader.router()` docstring leads with the `Depends(...)`
  gated example; trusted-network usage demoted to the secondary path.
- `fasten.init()` docstring lists `FASTEN_AUDIT_DSN` (and friends)
  explicitly in the required/optional env-var split.
- Added `fasten.audit_store()` to round out the public accessor trio
  (`transport`, `redactor`, `audit_store`).

### Removed — Python public-API parity (P1-8)

- `fasten.emit._get_stdout`, `_get_redactor`, `_get_audit_store` —
  callers must use `fasten.transport()`, `fasten.redactor()`,
  `fasten.audit_store()` respectively. (Pre-1.0 surface; clean break.)
- `fasten.reader.init(store, transport)` — redundant with the
  `router(store=, transport=)` keyword arguments. Remove the call;
  the router auto-fetches from `fasten.init()` by default.

## [1.0.0-beta.0] — 2026-05-01

Promotion to 1.0.0-beta. Python, Go, and Node.js SDKs back the API
contract — emit + log + redaction + correlation, all driven by
`spec/row-schema.json`. C++14 single-header and Rust ship at beta
status alongside; Java remains a placeholder pending its own beta.

### Changed
- Version bumped from `0.1.0-alpha` to `1.0.0-beta.0` across Python,
  JS (`@nerdapplabs/fasten`), and Rust manifests
- Python `pyproject.toml` Development Status: Alpha → Beta
- JS `package.json` `exports` block — dropped non-existent
  `./shim/*`, `./store/*`, and `./reader` entries (deferred to
  follow-on releases). Core `.` export is unchanged.
- CI: `astral-sh/setup-uv` upgraded to `v8.1.0`. Note: GitHub action
  version tags are mutable and can be re-pointed by the action owner;
  SHA-pinning every `uses:` reference is tracked as a follow-up.

### Added (since 0.1.0-alpha)
- Go: built-in `LogInfo/Warn/Error/Debug` for the sys stream + deep
  `RedactDetail` (was missing) — Go consumers no longer need slog
  to get `shape:"sys"` lines
- Rust: `fasten::log::info/warn/error/debug` writing `shape:"sys"`
  NDJSON (was previously absent)
- Per-language Docker integration tests (`tests/integration/`)

### Notes
- Java SDK still pre-beta; `emit()` throws `UnsupportedOperationException`.
  Marketing + docs label it "coming soon."

## [0.1.0-alpha] — 2026-04-30

Initial public release of the fasten audit + correlation SDK.

### Added
- **Python** reference implementation — `emit()`, `log.*`, `init()`, SQLite store,
  HTTP / MQTT / scheduler shims, structlog shim, mountable reader, CLI (`doctor`, `tail`), TUI
- **Go** SDK — `Register`, `Init`, `Emit`, `LogInfo/Warn/Error/Debug`, `RedactDetail`,
  SQLiteStore, slog handler, HTTP shim, ring-buffer transport
- **Node.js / TypeScript** SDK — `init`, `emit`, `log.*`, deep redaction,
  AsyncLocalStorage correlation, HTTP / MQTT / scheduler shims
- **Rust** SDK (beta) — typed `Row`, `Severity`, `RetentionClass`, `with_request_id`,
  `AuditRepository` + `AuditOutboxRepository` traits, `EmitBuilder`
- **C++14** single-header SDK — `fasten::emit()`, `RedactConfig`, `RequestIDMiddleware`,
  `FastenReader`, transport shims
- **Java** placeholder (emit throws — coming in v0.1.1)
- `spec/row-schema.json` — JSON Schema as single source of truth for enums + redact rules
- `spec/codegen.py` — generates enum/constant blocks into all 6 adapters (`--write` / `--check`)
- Per-language Docker integration smokes + `tests/integration/verify.py` contract checker

[1.0.0-beta.0]: https://github.com/nerdapplabs/fasten/releases/tag/v1.0.0-beta.0
[0.1.0-alpha]: https://github.com/nerdapplabs/fasten/releases/tag/v0.1.0-alpha
[Unreleased]: https://github.com/nerdapplabs/fasten/compare/v1.0.0-beta.0...HEAD
