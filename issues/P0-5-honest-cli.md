# [P0-5] Honest CLI: implement doctor + tail; require RIVET_AUDIT_DSN

**Priority:** P0 · **Effort:** S · **Labels:** `priority/P0` `area/cli` `area/dx`

## What

Two stub subcommands and one silent fallback that destroy day-1 trust.

**1. `rivet doctor` — implement**

Currently [`cli/__init__.py:38-41`](../python/rivet/cli/__init__.py#L38-L41) prints
`"TODO: rivet doctor"` and returns 0. Implement the real check:

```
$ rivet doctor
✓ env vars: RIVET_SERVICE_ID=auth-service, RIVET_NODE_ID=host-01
✓ audit DSN: sqlite:///var/lib/rivet/audit.db (writable, 12,304 rows)
✗ api DSN:   not configured (ring-buffer only — set RIVET_API_DSN to persist)
✓ catalog: 47 codes registered across 5 domains
✓ correlation: shim.http loaded; X-Request-ID middleware wired
✓ sample emit: USER_CREATED → roundtrip OK in 0.4 ms
```

Each step prints ✓ / ✗ / ⚠. Non-zero exit on any ✗. Output is machine-readable
with `--json`.

**2. `rivet tail` — implement**

Currently [`cli/__init__.py:42-45`](../python/rivet/cli/__init__.py#L42-L45) prints
`"TODO: tail …"`. Implement a polling client (SSE comes when the reader
exposes `/stream` — out of scope here):

```
$ rivet tail --stream audit --request-id a1b2c3d4
2026-04-26T14:23:17Z  USER_CREATED       admin   target=u-42       req=a1b2c3d4
2026-04-26T14:23:18Z  ORDER_PLACED       u-42    target=ord-9001   req=a1b2c3d4
…
```

- Poll `/api/v1/logs/{stream}?request_id=…&since=…` every `--interval` (default 2s).
- Track the last seen timestamp; only print new rows.
- Honour `RIVET_READER_KEY` (sends `X-Rivet-Key` per [P0-4]).
- `--json` for line-delimited JSON output.
- `Ctrl-C` clean exit.

**3. `rivet.init()` no-DSN — fail fast, no fallback**

[`emit.py`](../python/rivet/emit.py) previously fell back silently to
`sqlite:///:memory:?table=audit_log` when `RIVET_AUDIT_DSN` was unset.
**Removed.** Audit data must go to durable storage; rivet does not
provide an in-memory fallback. New behaviour:

- If `RIVET_AUDIT_DSN` is set → use it.
- Else → raise `RuntimeError`:
  `"rivet.init: RIVET_AUDIT_DSN is required. Audit rows must go to
  durable storage — rivet does not provide in-memory fallback. Set
  RIVET_AUDIT_DSN to a sqlite:// or postgres:// URL (e.g.,
  'sqlite:///./rivet-audit.db'). For tests, construct a store directly
  and pass via init(audit_store=...)."`

Tests that need ephemeral storage construct an `AuditStore` directly and
pass it through the `audit_store=` kwarg — explicit, not magic.

The SQLiteStore parser is also hardened: `from_dsn()` raises
`ValueError` if the DSN has no path (no silent `:memory:` fallback at
the parser level either).

This is a **breaking change** for anyone relying on the silent
in-memory fallback in production — that pattern was the bug this issue
removes. Migration: set `RIVET_AUDIT_DSN=sqlite:///./audit.db`.

## Why

`rivet doctor` and `rivet tail` are advertised on the website hero
([website/index.html](../website/index.html)) and in the
[bundled-tooling table in README.md](../README.md). The first thing a new
user runs after `pip install rivet` is one of these. Stub output destroys
trust on day 1 of the public OSS launch — and undermines the whole pitch
that rivet is "audit you can verify."

The silent in-memory fallback was the more dangerous version of the
same problem. A team in production with a misconfigured `.env`
discovered *after* an incident that 30 days of "audit logs" never
persisted. A WARNING wasn't enough — for an audit + compliance SDK,
the only correct answer is to refuse to start. Tests opt in to
ephemeral storage explicitly via `init(audit_store=...)`.

## Acceptance

- [x] `rivet doctor` runs the 6 checks above; exits non-zero on any failure — [`cli/_doctor.py`](../python/rivet/cli/_doctor.py)
- [x] `rivet doctor --json` emits structured output
- [x] `rivet tail` polls + dedupes by timestamp; survives reader 5xx; honours `RIVET_READER_KEY` — [`cli/_tail.py`](../python/rivet/cli/_tail.py)
- [x] `rivet tail --json` emits NDJSON
- [x] `rivet.init()` without `RIVET_AUDIT_DSN` raises `RuntimeError` with the exact message above — [`emit.py`](../python/rivet/emit.py)
- [x] `SQLiteStore.from_dsn(dsn)` raises `ValueError` if the DSN has no path (no silent `:memory:`) — [`store/sqlite.py`](../python/rivet/store/sqlite.py)
- [x] All "in-memory by default" claims removed from website + docs + README
- [ ] All behaviours covered by tests added in [P0-1]
- [ ] [`website/index.html`](../website/index.html) tooling table updated once [P0-4] auth lands (drop the "v0.1 polls" caveat note on `tail` is fine to keep — SSE is post-v0.1)

## Related

- **Pairs with:** [P0-4] (`rivet tail` must send `X-Rivet-Key` once Mode-2 auth lands)
- **Depends on:** [P0-1] (tests gate the implementation)
- **Splits-from:** earlier "Bundled CLI" claim across multiple website sections
