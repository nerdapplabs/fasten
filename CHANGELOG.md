# Changelog

All notable changes to fasten are documented here.
Format: [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning 2.0](https://semver.org/).

## [Unreleased]

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
- CI: `astral-sh/setup-uv` pinned to immutable `v8.0.0` tag

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
