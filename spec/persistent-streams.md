# Persistent streams spec (`api` / `sys`)

**Version:** 1.0
**Date:** 2026-08-12
**Status:** Normative. Every SDK that persists the `api` / `sys` streams MUST conform.

---

## Purpose

fasten emits three observability streams that share a `request_id`:

| Stream | Default sink | Durability |
|---|---|---|
| `audit` | SQL store (SQLite/Postgres) | full, hash-chained |
| `api` | in-memory ring | recent window only |
| `sys` | in-memory ring | recent window only |

The rings are bounded, so as log volume grows, less past `api`/`sys` activity
is left to correlate and search, without any warning. **Persistent streams**
let `api` and `sys` write through to the same kind of durable backend `audit`
already uses. A `request_id` from hours or days ago then still resolves to a
complete correlated view, limited by retention rather than ring size.

This document is the single source of truth for the persisted stream **row
model, table schema, indexed-field set, query semantics, completeness
signalling, retention, free-text search, and cross-language parity**. Where an
SDK differs from it, the spec wins. It follows the model of
[`chain-replication.md`](./chain-replication.md).

Persistence is **opt-in**. With no stream store configured, a stream is
ring-only, which is the default behaviour and fully backward compatible. This
spec does not change the emit path or the wire format. It covers the read side
and the durable sink.

---

## §1 Stream row model

An `audit` row is a typed, tamper-evident record. An `api`/`sys` row is a
**schemaless dict** produced by the logging and HTTP shims. The store
therefore:

1. Persists the **entire row** unchanged as a JSON `payload`, and
2. **Lifts** a fixed set of queryable fields into indexed columns.

A store read rebuilds each row from `payload`, so it **matches a ring read in
content and ordering** (§4). The lifted columns exist only to drive indexed
filters. Returned data never comes from them.

### §1.1 Not hash-chained, not tamper-evident

Stream rows carry **no `canonical_form_id`, no `prev_hash`, no `hash`**. They
are observability data, not evidence. An SDK MUST NOT extend the audit hash
chain over stream rows, and MUST NOT present them as tamper-evident. The schema
`canonical_form_id` rules for stream persistence (§8) are about **versioning
the lifted columns**. They are separate from the audit row's
`canonical_form_id`.

### §1.2 JSON round-trip fidelity

`payload = json_encode(row)` on write, `row = json_decode(payload)` on read.
JSON-native scalars round-trip exactly. Non-JSON values (for example a native
timestamp object) are converted to their string form on write and MUST be
decoded as that string. SDKs MUST NOT assume the stored row has the same types
as the emitted object, only that the JSON projections are equal.

---

## §2 Table schema

**One table per stream.** `api` and `sys` never share rows. The per-stream
tables share one column set; there is no unified `events` table.

- Default table names are `api_log` and `syslog`.
- A DSN MAY override the name (`?table=…`), but the SDK MUST validate it as a
  bare SQL identifier: `^[A-Za-z_][A-Za-z0-9_]*$`, optionally with one
  `schema.` prefix on backends that support schemas.

### §2.1 Columns (schema form `"1"`)

| Column | SQLite / Postgres | Meaning |
|---|---|---|
| `seq` | `INTEGER PK AUTOINCREMENT` / `BIGSERIAL PK` | monotonic insert order; the sort key |
| `request_id` | `TEXT` | correlation id (§7: always non-empty) |
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

An index MUST exist on every lifted column that a read filters on:
`request_id`, `timestamp`, `level`, `service_id`, `event`, `method`, `path`,
`status`.

- `request_id` (correlation) and `timestamp` (windows and retention) are
  mandatory.
- The others back structured discovery (§3).
- All are created with `IF NOT EXISTS` at bootstrap.

---

## §3 Indexed fields (structured-first discovery)

Operators find a `request_id` from **structured fields** (target, actor, code,
method, path, time) far more often than by pasting an id. Indexing those fields
is cheap at write time and covers about 80% of discovery.

The lifted set is:

```
request_id, timestamp, level, service_id, event, method, path, status
```


- `sys` populates `level`, `service_id` and `event`.
- `api` populates `method`, `path`, `status` and `service_id`.

Free-text `q=` (§9) is the fallback, not the primary path.

---

## §4 Query semantics

A store read and a ring read of the same stream MUST return the same rows in the
same order for the same filters:

1. **Ordering:** newest first (`seq DESC`, equivalent to ring push order).
2. **Filter matching:** every structured filter is an **exact-match**
   equality, `level` included. No case-folding and no substring matching (that
   is `q=` only). This holds across SDKs.
3. **Time window:** optional inclusive `[since, until]` on `timestamp`. A
   missing or `NULL` timestamp is treated as the empty string
   (`COALESCE(timestamp,'')`, as the ring does). Comparison is
   **lexicographic** over the canonical UTC form in §4.3.
4. **Limit:** every read is capped (default 100, max 1000) after filtering and
   ordering. A limit of zero or less is refused.

### §4.1 Truncation signalling (`totals` vs `counts`)

A capped read MUST expose an uncapped count alongside `query`, so `/correlate`
can report `totals` next to `counts`. `counts < totals` means the result was
truncated. This is the per-response signal and is independent of the
durability class (§6).

### §4.3 Canonical UTC timestamp form (writer obligation)

Every timestamp fasten writes MUST render as **RFC 3339 with a fixed six-digit
sub-second and an always-`Z` suffix**. This covers audit `timestamp` /
`shipped_at`, stream `timestamp`, purge cutoffs, drainer sys events,
`last_verified_at` and retention cutoffs.

    2026-08-21T10:00:00.000000Z
    2026-08-21T10:00:00.500000Z

With a fixed width, the fractional dot is at byte 19 in every stamp and
`.NNNNNNZ` sorts as digits, so string order matches time order. A variable
width breaks this: Go's `RFC3339Nano` drops `.000000` on whole seconds, and
since `'Z'` (0x5A) sorts above `'.'` (0x2E), a whole-second stamp then sorts
after fractional stamps in the same second. Six digits matches Postgres
`timestamptz` default resolution and the Python stdlib default. No
sub-microsecond type exists across all runtimes.

Both SDKs write timestamps through `canonical_ts` (Python:
`fasten/canonical_ts.py`; Go: `go/canonical_ts.go`). Parallel conformance tests
in each SDK pin the two to byte-identical output. Adopter code that writes rows
into a fasten table (custom loaders, replication) MUST use the same form, or
windowed reads on the mixed table will compare wrongly at boundary instants.

Parsers are strict as well. `parseCanonicalTS` (Go) and
`fasten.canonical_ts.parse_canonical` (Python) accept only the exact 27-char
canonical form. Any other shape means a writer did not use the canonical
helper, which is a bug at the source. Reads fail loudly instead of silently
round-tripping a shape the comparison does not handle.

---

## §5 Write path

Persistence is **write-through**. The ring stays the hot path; the store is a
synchronous sink behind it.

1. The row is pushed to the ring first. This never blocks.
2. The row is inserted into the store. On SQLite the store MUST use WAL with
   `synchronous=NORMAL`, so a commit is a WAL append without a per-commit
   fsync. Very hot streams should stay ring-only.
3. **A sink failure MUST NOT break the logging path.** The error is logged to
   stderr and swallowed, AND recorded as a write failure on the store (§6.1).

Reads for a store-backed stream are served **from the store, never the ring**,
because the store holds a superset. That is why a swallowed write must mark
the stream as degraded.

---

## §6 Completeness / durability class

Every read reports, per stream, its **durability class**:

| Value | Meaning |
|---|---|
| `ring` | ring-only (or no store at all, as with audit in stdout-only mode). Rows *can* be lost. |
| `store` | store-backed. Durable for the retention period. |
| `store-degraded` | store-backed, but at least one persist failure was swallowed, so the durable history has known gaps. |

`ring` says the stream *can* lose rows, not that *this* response did. A stream
is `store` **only when it actually has a store**, audit included: stdout-only
audit (no store) reports `ring`, not a durability it does not have.

### §6.1 `store-degraded` is sticky

Once a store swallows a persist failure, it reports `store-degraded` for the
rest of its lifetime. A gap in history does not go away. The write-failure
counter only needs to record "at least one".

---

## §7 Sentinel `request_id` invariant

**Every persisted stream row MUST carry a non-empty `request_id`** (#58 §5.1).
Otherwise `/correlate?request_id=X` quietly returns less than it should. When a
row has no `request_id`, the transport stamps one before persisting it.
Sentinel ids live in namespaces recognisable by prefix, so a UI can tell a real
correlation from a bucket:

| Context | `request_id` form | Lifetime |
|---|---|---|
| Boot / init (before first request) | `boot-<service>-<id>` | one per process |
| Scheduler-fired job pre-shim | `sched-<service>-<id>` | per run |
| Background task / worker | `bg-<service>-<id>` | per task |
| Third-party library write | `lib-<service>-<id>` | per write batch |
| Unrecoverable (no context) | `orphan-<service>-<id>` | per write |

- The transport stamps `boot` and `orphan` automatically.
- `sched`, `bg` and `lib` ids are minted explicitly, e.g. with `mint_sentinel`.
- The boot window ends at the first row that carries a real (non-sentinel) id.

A conformance test (#58 §8.7) runs a service through boot, a request,
background work and shutdown, and asserts that every persisted sys row has a
non-empty `request_id`.

---

## §8 Schema `canonical_form_id` rules

The lifted-column set (§2.1) is **form `"1"`**. It is versioned so any future
change is explicit and the same across languages:

- The set of lifted columns and their order is fixed for a form id.
- Adding or removing a lifted column, or changing which stream populates it,
  makes a **new form**. Form `"1"` is never quietly redefined.
- Bootstrap DDL is additive. A later form migrates with `ADD COLUMN IF NOT
  EXISTS`, never with a destructive rewrite.
- All SDKs MUST agree on the form-`"1"` column set, so a table written by one
  SDK can be read by another.

This is **not** the audit `canonical_form_id`. Stream rows are not hashed, so
there is no tamper-evident form. These rules are about schema compatibility.

---

## §9 Free-text search (constrained)

`q=` substring search over persisted stream history is **opt-in and
deliberately constrained**. It is the fallback, not the discovery path
(#58 §4.1).

- **`streams=`** takes a comma-separated subset of `{audit, api, sys}`.
  - Default: `sys`, so a linear scan stays opt-in.
  - Every named stream must have a store attached. A ring-only stream reports a
    per-stream error in `errors.<stream>` instead of an empty match list.
  - Streams appear in the response in a stable order (`sys`, `api`, `audit`),
    the same as `/correlate`.
- **`since=` is mandatory.** An unbounded substring scan is refused.
- **Hard result cap** (default 50, max 200) and **no relevance ranking**
  (newest first per stream).
- **Gated** behind `search.enabled` (config or `FASTEN_SEARCH_ENABLED`).
- Matching is a case-insensitive substring match over each stream's payload:
  the JSON `payload` column on `api`/`sys`, the JSON `detail` column on
  `audit`.
  - `%`, `_` and `\` in `q` are escaped so they match literally (SQLite
    `LIKE … ESCAPE`, Postgres `ILIKE`).
  - On Postgres the escape character is declared as `ESCAPE E'\\'` (an explicit
    escape string), so it means one backslash whatever the server's
    `standard_conforming_strings` setting is.

Endpoints:

- `GET /logs/search?streams=…` returns matches with their `request_id` for a
  follow-up `/correlate`.
- `/logs/sys` accepts a gated `q=`.
- `/logs/api?q=` is refused (400) with a pointer to `/search?streams=api`.
  Mixing free-text and structured filters on a per-stream endpoint would mean
  two different query semantics on one endpoint.

Discovery input reaches these endpoints through the query translator
(#58 §3.7). Natural-language or smart-box text is parsed into structured chips
plus the bounded `q=`. It never becomes a fourth kind of query.

---

## §10 Retention

Retention is **per stream**, since `api`/`sys` have more volume and a shorter
useful life than `audit`.

- A store MUST expose `purge(before)`, which deletes rows older than a cutoff by
  `timestamp`, using the timestamp index.
- Stream rows have no ship/replication lifecycle (unlike `audit`), so purge is
  an unconditional age-based delete.
- A row with a `NULL` or missing timestamp is **never** purged, because its age
  is unknown.
- Expose `retention.<stream>` as a max age.

---

## §11 Backends & cross-language parity

**SQLite is the baseline for v1, and Postgres is a supported stream backend**
in both SDKs.

- Postgres uses the same form-`"1"` schema (`BIGSERIAL seq`, `ILIKE` for `q=`).
- The backend is selected by the stream DSN scheme (`sqlite://…` or
  `postgres://…`). The Go SDK instead has the caller construct the store and
  pass it in through config.
- High-volume `api`/`sys` streams, where SQLite's single-writer lock is the
  bottleneck, should use Postgres.

The feature MUST behave the same in Python and Go:

- Same form-`"1"` columns and indexes (§2), so a table is portable.
- Same exact-match filters and lexicographic time windows (§4).
- Same `store` / `ring` / `store-degraded` completeness values (§6).
- Same sentinel invariant and namespaces (§7).
- Same constrained `q=` contract (§9) and per-stream retention (§10).
