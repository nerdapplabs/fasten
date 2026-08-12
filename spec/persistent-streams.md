# Persistent streams spec (`api` / `sys`)

**Version:** 1.0
**Date:** 2026-08-12
**Status:** Normative — every SDK that persists the `api` / `sys` streams MUST conform.

---

## Purpose

fasten emits three observability streams that share a `request_id`:

| Stream | Default sink | Durability |
|---|---|---|
| `audit` | SQL store (SQLite/Postgres) | full, hash-chained |
| `api` | in-memory ring | recent window only |
| `sys` | in-memory ring | recent window only |

The rings are bounded, so correlation and search against past `api`/`sys`
activity silently shrink as log volume grows. **Persistent streams (FR1)** let
`api` and `sys` write through to the same class of durable backend `audit`
already uses, so a `request_id` from hours or days ago still resolves to a
complete correlated view (FR2) bounded only by retention, not by ring size.

This document is the single source of truth for the persisted stream **row
model, table schema, indexed-field set, query semantics, completeness
signalling, retention, free-text search, and cross-language parity**. When an
SDK deviates, the spec wins. It is the `spec/persistent-streams.md` that
[`chain-replication.md`](./chain-replication.md) is the model for.

Persistence is **opt-in**. With no stream store configured a stream is
ring-only — today's behaviour, fully backward compatible. Nothing here changes
the emit path or the wire format; it governs the read side and the durable sink.

---

## §1 Stream row model

Unlike an `audit` row (a typed, tamper-evident record), an `api`/`sys` row is a
**schemaless dict** produced by the logging / HTTP shims. The store therefore:

1. Persists the **entire row** verbatim as a JSON `payload`, and
2. **Lifts** a fixed set of queryable fields into indexed columns.

A store read reconstructs each row from `payload`, so it is **equivalent to a
ring read in content and ordering** (§4). The lifted columns exist only to drive
indexed filters; they are never the source of returned data.

### §1.1 Not hash-chained, not tamper-evident

Stream rows carry **no `canonical_form_id`, no `prev_hash`, no `hash`**. They
are observability data, not evidence: an SDK MUST NOT extend the audit hash
chain over stream rows, and MUST NOT present them as tamper-evident. The schema
`canonical_form_id` discipline (§8) that governs stream persistence is about
**versioning the lifted columns**, and is deliberately distinct from the audit
row's `canonical_form_id`.

### §1.2 JSON round-trip fidelity

`payload = json_encode(row)` on write, `row = json_decode(payload)` on read.
JSON-native scalars round-trip exactly; non-JSON values (e.g. a native timestamp
object) are coerced to their string form on the way in and MUST be decoded as
that string. SDKs MUST NOT assume type-identity between the emitted object and
the stored row — only value-equality of the JSON projection.

---

## §2 Table schema

**One table per stream.** `api` and `sys` never share rows (Open Question #1
resolved: per-stream tables, one shared column set — not a unified `events`
table). Default table names `api_log` and `syslog`; a DSN MAY override the name
(`?table=…`) but the SDK MUST validate it as a bare SQL identifier
(`^[A-Za-z_][A-Za-z0-9_]*$`, optionally one `schema.` prefix on backends that
support schemas).

### §2.1 Columns (schema form `"1"`)

| Column | SQLite / Postgres | Meaning |
|---|---|---|
| `seq` | `INTEGER PK AUTOINCREMENT` / `BIGSERIAL PK` | monotonic insert order; the sort key |
| `request_id` | `TEXT` | correlation id (§7 — always non-empty) |
| `timestamp` | `TEXT` | canonical UTC ISO-8601 string |
| `level` | `TEXT` | `sys` only |
| `service_id` | `TEXT` | emitting service |
| `event` | `TEXT` | `sys` only (structured event name) |
| `method` | `TEXT` | `api` only (HTTP method) |
| `path` | `TEXT` | `api` only (HTTP path) |
| `status` | `INTEGER` | `api` only (HTTP status) |
| `payload` | `TEXT NOT NULL` | full JSON row (§1) |

A stream leaves the columns it does not populate `NULL`.

### §2.2 Indexes

An index MUST exist on every lifted column a read filters on:
`request_id`, `timestamp`, `level`, `service_id`, `event`, `method`, `path`,
`status`. `request_id` (correlation) and `timestamp` (windows + retention) are
mandatory; the rest back §3 structured discovery. All are `IF NOT EXISTS` at
bootstrap.

---

## §3 Indexed fields (structured-first discovery)

Operators arrive at a `request_id` from **structured fields** — target, actor,
code, method, path, time — far more often than by pasting an id. Indexing those
is cheap at write time and answers ~80% of discovery. The lifted set is
`request_id, timestamp, level, service_id, event, method, path, status`; `sys`
populates `level`/`service_id`/`event`, `api` populates
`method`/`path`/`status`/`service_id`. Free-text `q=` (§9) is the escape hatch,
not the primary path.

---

## §4 Query semantics

A store read and a ring read of the same stream MUST return the same rows in the
same order for the same filters:

1. **Ordering:** newest-first (`seq DESC` ≡ ring push order).
2. **Filter matching:** every structured filter is **exact-match** equality,
   including `level` — no case-folding, no substring (that is `q=` only). A
   cross-SDK invariant.
3. **Time window:** optional inclusive `[since, until]` on `timestamp`. A
   missing/`NULL` timestamp is treated as the empty string
   (`COALESCE(timestamp,'')`, matching the ring). Comparison is **lexicographic**
   — correct for canonical UTC timestamps; callers MUST keep one canonical form.
4. **Limit:** every read is capped (default 100, max 1000) after filtering and
   ordering. A non-positive limit is refused.

### §4.1 Truncation signalling (`totals` vs `counts`)

A capped read MUST expose an uncapped count alongside `query` so `/correlate` can
report `totals` next to `counts`. `counts < totals` ⇒ truncated. This is the
per-response signal, orthogonal to the durability class (§6).

---

## §5 Write path

Persistence is **write-through**: the ring stays the hot path; the store is a
synchronous sink behind it.

1. Row pushed to the ring first (never blocks).
2. Store insert. On SQLite it MUST use WAL + `synchronous=NORMAL` so a commit is
   a WAL append without a per-commit fsync. Very hot streams should stay
   ring-only.
3. **A sink failure MUST NOT break the logging path.** The error is logged to
   stderr and swallowed, AND recorded as a write-failure on the store (§6.1).

Reads for a store-backed stream are served **from the store, never the ring**
(the store is the superset) — which is exactly why a swallowed write must
degrade completeness.

---

## §6 Completeness / durability class (FR4)

Every read reports, per stream, its **durability class**:

| Value | Meaning |
|---|---|
| `ring` | ring-only (or no store at all — audit in stdout-only mode). Rows *can* be lost. |
| `store` | store-backed. Durable to retention. |
| `store-degraded` | store-backed, but ≥1 persist failure was swallowed — durable history has known holes. |

`ring` says the stream *can* lose rows, never that *this* response did. A stream
is `store` **only when it actually has a store** — audit included: stdout-only
audit (no store) reports `ring`, not a durability it lacks.

### §6.1 `store-degraded` is sticky

Once a store swallows a persist failure it reports `store-degraded` for its
lifetime. A hole in history does not heal. The write-failure counter need only
be "at least one".

---

## §7 Sentinel `request_id` invariant

**Every persisted stream row MUST carry a non-empty `request_id`** (§5.1 of the
issue). Otherwise `/correlate?request_id=X` silently degrades. The transport
stamps one before persisting when the row has none. Sentinel namespaces
(recognisable by prefix, so a UI can tell a real correlation from a bucket):

| Context | `request_id` form | Lifetime |
|---|---|---|
| Boot / init (before first request) | `boot-<service>-<id>` | one per process |
| Scheduler-fired job pre-shim | `sched-<id>` | per run |
| Background task / worker | `bg-<service>-<id>` | per task |
| Third-party library write | `lib-<service>-<id>` | per write batch |
| Unrecoverable (no context) | `orphan-<service>-<id>` | per write |

`boot` and `orphan` are auto-stamped by the transport; `sched`/`bg`/`lib` are
minted explicitly by the relevant shims. The boot window ends at the first row
carrying a real (non-sentinel) id. A conformance test (§8.7 of the issue) drives
boot → request → background → shutdown and asserts every persisted sys row has a
non-empty `request_id`.

---

## §8 Schema `canonical_form_id` discipline

The lifted-column set (§2.1) is **form `"1"`**, versioned so a future change is
explicit and cross-language:

- The set of lifted columns and their order is fixed for a form id.
- Adding/removing a lifted column, or changing which stream populates it, is a
  **new form** — never a silent redefinition of `"1"`.
- Bootstrap DDL is additive; a later form migrates with `ADD COLUMN IF NOT
  EXISTS`, never a destructive rewrite.
- All SDKs MUST agree on the form-`"1"` column set so a table written by one
  reads in another.

This is **not** the audit `canonical_form_id`: stream rows are not hashed, so
there is no tamper-evident form. The discipline here is schema compatibility.

---

## §9 Free-text search (FR3) — constrained

`q=` substring search over persisted stream history is **opt-in and deliberately
constrained** (§4.1 of the issue — the escape hatch, not the discovery path):

- **`sys` only** in v1.
- **`since=` mandatory** — an unbounded substring scan is refused.
- **Hard result cap** (default 50, max 200), **no relevance ranking**
  (newest-first).
- **Gated** behind `search.enabled` (config or `FASTEN_SEARCH_ENABLED`);
  disabled until persistence is on (a ring-only sys stream reports "search
  requires sys persistence").
- Case-insensitive substring over the JSON `payload`; `%` / `_` / `\` in `q` are
  escaped so they match literally (SQLite `LIKE … ESCAPE`, Postgres `ILIKE`).

Surfaces as `GET /logs/search` (returns matches with `request_id` for a
follow-up `/correlate`) and a gated `q=` on `/logs/sys`. Discovery input reaches
these primitives through the query translator (§3.7 of the issue): NL / smart-box
text is parsed into structured chips + the bounded `q=`, never a fourth query
semantic.

---

## §10 Retention

Retention is **per-stream** (`api`/`sys` are higher-volume, shorter-lived than
`audit`). A store MUST expose `purge(before)` deleting rows older than a cutoff
by `timestamp`, backed by the ts index. Unlike `audit`, stream rows have no
ship/replication lifecycle, so purge is an unconditional age-based delete. A row
with a `NULL`/absent timestamp is **never** purged (its age is unknown). Expose
`retention.<stream>` as a max age.

---

## §11 Backends & cross-language parity (FR5)

**SQLite is the v1 baseline; Postgres is a supported stream backend** in both
SDKs — same form-`"1"` schema (`BIGSERIAL seq`, `ILIKE` for `q=`), selected by
the stream DSN scheme (`sqlite://…` vs `postgres://…`; the Go SDK constructs the
store explicitly and passes it via config). High-volume `api`/`sys` where
SQLite's single-writer lock is the bottleneck should use Postgres.

The feature MUST behave identically in Python and Go:

- Same form-`"1"` columns and indexes (§2), so a table is portable.
- Same exact-match filter + lexicographic time-window semantics (§4).
- Same `store` / `ring` / `store-degraded` completeness values (§6).
- Same sentinel invariant and namespaces (§7).
- Same constrained `q=` contract (§9) and per-stream retention (§10).
