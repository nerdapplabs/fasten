# Audit hash-chain & replication spec

**Version:** 1.0
**Date:** 2026-10-26
**Status:** Normative. All SDK chain and replication implementations MUST conform.

---

## Purpose

fasten's audit rows form a tamper-evidence hash chain per `source_node_id`:
one node, one chain (§2). A node ships its chain to an upstream aggregator,
which may be written against a different SDK (for example a Python edge node
shipping to a Go control plane). The aggregator verifies the chain again. For
that to work, **every SDK must hash the exact same bytes for a row** and follow
the same replication contract.

This document is the single source of truth for:

- the canonical hashed form,
- the cross-language rendering rules,
- the form-id registry,
- the replication semantics (`ingest` / `IngestResult`).

Where an SDK differs from it, the spec wins.

Each SDK's test suite SHOULD include the §6 vectors so the SDKs do not drift
apart again unnoticed.

---

## §1 Canonical form `"1"`

The row hash is the `SHA-256` of the **canonical JSON** of the row, with the
`hash` field left out. The hashed form is versioned through the
`canonical_form_id` field, so the choice of bytes is itself covered by the hash
and new forms can be added without touching old ones.

### §1.1 Hashed field set (form `"1"`)

Exactly these 22 keys, and no others:

```
actor, actor_kind, action, canonical_form_id, category, code, detail, domain,
id, method, monotonic_seq, origin_id, prev_hash, request_id, service_id,
severity, shipped_at, source_node_id, target, tenant_id, timestamp, wire_version
```

- `hash` is **excluded**. It is the output.
- `canonical_form_id` is **included**, so the form choice is covered by the
  hash.
- `pii_in_detail` is **excluded**. The Go wire `Row` has this field; the Python
  `AuditRow` does not. Both SDKs MUST leave it out of the hash so a Go
  aggregator can verify a chain sealed in Python. This is a fixed rule, NOT a
  per-SDK choice.

### §1.2 Canonical JSON rendering

The reference rendering is CPython:

```python
json.dumps(d, sort_keys=True, separators=(',', ':'), default=str)
```

Every SDK MUST produce the same bytes:

| Rule | Requirement |
|---|---|
| Key order | Sorted ascending, **recursively** (top level and every nested object). |
| Whitespace | None: `,` and `:` separators, no spaces. |
| Non-ASCII | Escaped as `\uXXXX` (UTF-16 surrogate pairs for astral characters), as with CPython `ensure_ascii=True`. |
| `<` `>` `&` | Left **literal**. CPython does NOT HTML-escape; a Go encoder MUST turn HTML escaping off. |
| Null | `None` renders as `null` for `tenant_id` and `shipped_at` when absent. |
| Timestamps | `datetime.isoformat()` of a tz-aware UTC value: `+00:00` offset (not `Z`), six-digit microseconds only when nonzero. Applies to `timestamp` and `shipped_at`. |

### §1.3 Number rendering (cross-language hazard)

Numbers inside `detail` MUST render **exactly as CPython `json.dumps` renders
them**:

| Value | CPython renders | Note |
|---|---|---|
| `7` (int) | `7` | |
| `75.0` (whole-number float) | `75.0` | **NOT `75`** |
| `12.5` | `12.5` | |
| `1e20` | `1e+20` | |

A Go SDK MUST NOT decode `detail` numbers into `float64` and re-encode them with
the default encoder. `float64(75.0)` renders as `75`, not CPython's `75.0`. A
Python-sealed row with a whole-number float in `detail` (for example a setpoint
of `75.0`) would then **fail verification** in Go, with no other sign that
anything is wrong.

The conformant technique is to **keep the original number tokens**. Decode
`detail` with number-token preservation (Go `json.Decoder.UseNumber()`) so each
value keeps its source token (`"75.0"`, `"7"`, `"1e+20"`) and is written back
unchanged. The stored JSON was produced by the canonical (CPython) rendering, so
keeping its tokens reproduces it byte for byte, whatever type the number had
originally.

### §1.4 Canonical form `"2"`: committed detail

Form `"2"` differs from form `"1"` in two ways:

1. In the hashed field set, `detail` is replaced by a **salted commitment** to
   it.
2. **Timestamps use the canonical wire form** of
   [persistent-streams.md §4.3](./persistent-streams.md): RFC 3339 with `Z` and
   a fixed six-digit sub-second (`2026-06-15T10:30:45.000000Z`), not form
   `"1"`'s `+00:00` with variable-width microseconds.

Key sorting, number handling (§1.3) and the inclusion of `canonical_form_id`
are the same as in form `"1"`.

**Why one timestamp form.** Form `"1"` hashes a *different* timestamp spelling
from the one the row carries on the wire, so every SDK needs a second timestamp
renderer used only for hashing. With two renderers for one value, Go and Python
agreed on the instant but disagreed on the bytes (#91). Form `"2"` has exactly
one timestamp form: the one already written to the wire and already pinned by
the conformance tests for that form. `Z` is also the spelling used in RFC 3339 examples,
JSON Schema `date-time` and OpenAPI, so it is what a reader of a row expects.

Implementations MUST hash the timestamp exactly as serialised and MUST NOT
re-render it. A private `pyISOFormat`-style helper in the hash path is
non-conformant under form `"2"`.

```
form "1": sha256(canonical_json(row − {hash}))                  ts: +00:00, var width
form "2": sha256(canonical_json(row − {hash, detail, detail_salt}
                                     + {detail_commitment}))     ts: Z, fixed 6 digits

detail_commitment = sha256(detail_salt || canonical_json(detail))   hex
detail_salt       = 32 random bytes, hex, unique per row
```

`detail` and `detail_salt` are **stored columns but not hashed fields**.
`detail_commitment` is both stored and hashed.

**Why a commitment instead of leaving `detail` out.** Redaction must be able to
destroy `detail` without invalidating the row. If `detail` were hashed
directly, destroying it would change the row's `hash`. Since `prev_hash` is a
hashed field (§1.1), that change would carry on to every later row, so each
redaction would need an O(n) re-seal of the rest of the chain. That re-seal
cannot be told apart from tampering. With a commitment, redaction is O(1) and
the row's `hash` never changes.

**Redaction under form `"2"`** is therefore:

```
UPDATE {table} SET detail = NULL, detail_salt = NULL WHERE ...
```

`hash`, `prev_hash`, `canonical_form_id` and `monotonic_seq` are untouched. The
chain still verifies, and the row still proves *what it committed to*: anyone
holding the original `detail` and `detail_salt` can recompute the commitment
and show the row was not altered. Once the salt is destroyed the commitment is
computationally hiding, so the digest does not reveal the redacted value.

**Which form new rows use.** New rows are sealed under form `"2"`. Form `"1"`
stays registered permanently so existing rows verify bit for bit; adding form
`"2"` changed no stored hash. A form-`"1"` row **cannot** be redacted without
the re-seal described above, so SDKs MUST refuse to redact one and say why.

### §1.5 Form-id registry & unknown ids

Each SDK keeps a `canonical_form_id` to hash-function registry holding `"1"`
(§1.1) and `"2"` (§1.4). Adding a form only adds to it: register a new id and
stamp it at seal time.

- `verify_chain` MUST pick the hash function per row from `canonical_form_id`.
- It MUST **reject** (not skip, not crash on) any row whose id is not in the
  registry.
- A row with no `canonical_form_id` (sealed before the field existed) is
  treated as form `"1"`.

---

## §2 Chain identity & sealing

- **The chain key is `source_node_id` alone.** One node, one chain. Every row a
  node originates joins the same sequence, whichever `service_id` wrote it and
  however many engine instances are running.
- `monotonic_seq` is strictly increasing and **unique** within a
  `source_node_id`. Two originated rows on one node MUST NOT share a
  `monotonic_seq`.
- `prev_hash` is the hex SHA-256 of the previous row in that sequence, or the
  literal `"genesis"` for the first row.
- Rows with an empty `hash` (written before hash-chain support, or emitted in
  stdout-only mode, §8) are skipped by `verify_chain`, not rejected.

### §2.1 Allocation (normative)

`monotonic_seq` and `prev_hash` MUST be allocated **by the store, in the same
transaction as the insert**. An in-memory counter per engine instance is
non-conformant. With two engine instances on one node (two services sharing a
store, a forking supervisor, `uvicorn --workers`), each would count `seq` from
1, producing two rows at `seq 1` that both claim `prev_hash = "genesis"`.
`verify_chain` then reports a `prev_hash` break, which cannot be told apart from
tampering.

A conformant allocation does the following atomically:

```
BEGIN
  seq  := COALESCE(MAX(monotonic_seq), 0) + 1   -- WHERE source_node_id = ?
  prev := hash of the row at seq-1               -- same predicate, or "genesis"
  row  := seal(prev, row WITH monotonic_seq = seq)
  INSERT row
COMMIT
```

The transaction MUST serialise against concurrent allocations for the same
`source_node_id`. SQLite: `BEGIN IMMEDIATE`. Postgres: a node-scoped advisory
lock, `pg_advisory_xact_lock(hashtextextended(source_node_id, 0))`, with the
same key in every SDK. `SELECT … FOR UPDATE` on the
node's tip row is not enough on its own: before a node's first row there is no
tip row to lock.

### §2.2 Sealing

`seal(prev_hash, row)` is the one sealing function. It stamps the current
`canonical_form_id`, sets `prev_hash`, and computes `hash` as in §1. Emit MUST
go through `seal`, so emit and verify cannot disagree.

Because §2.1 puts allocation in the store transaction, **sealing happens at
drain/insert time, not at `emit()`**, and `emit()` returns an unsealed row. §8
covers what the stdout stream carries until then.

---

## §3 Verification

`verify_chain(rows)`:

1. Sort by `monotonic_seq`.
2. For each row that has a hash, recompute the §1 hash for its
   `canonical_form_id` and compare it with the stored `hash`.
3. Compare each row's `prev_hash` with the previous row's `hash`.
4. Stop at the first failure and report `first_break_at` = that row's
   `monotonic_seq`.

The result carries `ok`, `total_rows`, `first_break_at` and `reason`.

---

## §4 Replication (`ingest` / `IngestResult`)

An aggregator receives rows reverse-synced from a node and ingests them WITHOUT
re-sealing them. Re-sealing would re-hash the rows and remove the tamper
evidence. Replicated rows keep their origin's `hash`, `prev_hash`, `origin_id`
and `monotonic_seq`.

- **Verified prefix, not all-or-nothing.** `ingest` verifies the incoming chain
  and inserts the longest verified prefix (the rows before the first break). It
  MUST NOT raise on a break.
- **`IngestResult`** reports:
  - `inserted`: rows passed to the idempotent insert,
  - `rejected_from_seq`: the `monotonic_seq` of the first broken row, or null
    when the whole batch verified,
  - `reason`.

  The sender resyncs from `rejected_from_seq` instead of re-sending a batch
  that will never verify.
- **Atomicity.** The verified prefix is inserted in one transaction. The insert
  is idempotent, so re-delivery is a no-op.
- **`origin_id == id`** marks a row as originated on this node. A node's
  `list_unshipped` returns only rows it originated, never replicated ones.

---

## §5 Originated vs replicated inserts

- `insert_originated(row)`: the engine's own emit path. Asserts
  `origin_id == id`.
- `insert_replicated(row)`: the replication path. Asserts the row is already
  sealed (`hash != ""`); the caller has verified the chain.

The two paths are separate types, not a naming convention, so a bug that hands
the engine a row from another origin cannot pass as a replicated insert.

---

## §6 Cross-language test vectors

SDKs SHOULD pin these to catch drift. Each is a single Python-sealed row with
`prev_hash = "genesis"`; another SDK MUST compute the same hash.

| Vector | `detail` | Expected hash |
|---|---|---|
| Base | `{"qty": 3, "sku": "WIDGET"}` | `cbf5a1ee4bb7baeb0b433bedfa60434bdea42627b9671183895970bbff02f9ac` |
| Whole-number float | `{"setpoint": 75.0, "tolerance": 12.5, "retries": 7}` | `512021c690ddfd2077192cb6d75921ea36d35b3270a12fdf91888d5ffabcf54b` |

The float vector guards §1.3: it fails for any SDK that renders `75.0` as `75`.

---

## §7 Redaction

Retention differs by code. A row carrying personal data (`pii_in_detail`) may
have to go after 30 days while operational history is kept for a year.

`DELETE` is **non-conformant**. It removes a row from the middle of the
sequence, which is exactly what §3 step 3 detects as tampering. Redact instead.

### §7.1 The operation

Under form `"2"` (§1.4), redaction is a single-row update in one transaction:

```
UPDATE {table} SET detail = NULL, detail_salt = NULL WHERE id = ?
```

No hash changes and no other row is touched. `verify_chain` passes before and
after.

SDKs MUST refuse to redact a form-`"1"` row, because its `detail` is hashed
directly and redacting it would mean re-sealing the rest of the chain. They
MUST report that the row predates form `"2"`.

### §7.2 The redaction event

Every redaction MUST itself be an originated, chained row:

- code `AUDIT_ROW_REDACTED`
- `target` = the redacted row's `id`
- `detail` = `{"redacted_seq": <n>, "reason": <retention policy id>}`
- sealed and allocated as usual (§2.1)

Without this row, an honest erasure and a quiet redaction look the same: both
leave a row whose `detail` is null. The event records who destroyed the data,
when, and under which policy. It turns "the data is gone" into "the data is
gone and we can show why".

### §7.3 What redaction does and does not give you

- It **does** destroy the personal data, keeps the sequence verifiable, and
  records that the destruction happened.
- It does **not** give non-repudiation. An operator who can redact can also
  re-seal the whole chain from genesis. Redaction is only meaningfully
  constrained when the chain tip is anchored externally, so that a full re-seal
  fails against a digest published before the rewrite.

---

## §8 Emit-time vs seal-time (stdout contract)

Because §2.1 allocates in the store transaction, `emit()` cannot know
`monotonic_seq`, `prev_hash` or `hash`. The stdout audit stream is therefore
written in **two phases**:

1. **At `emit()`**, the row is written to stdout immediately, before any store
   routing, with `monotonic_seq: 0`, `prev_hash: ""`, `hash: ""`. A row still
   reaches the log stream if the store path blocks or raises.
2. **At insert**, once the store has allocated and sealed the row, the sealed
   row is written again with its final `monotonic_seq`, `prev_hash` and `hash`.

Both lines carry the same `id`, which is minted at emit time and is the join
key. Consumers that need the chain MUST use phase-2 lines (`hash != ""`).
Consumers that only need the event MAY use phase-1 lines and drop phase-2
duplicates by `id`.

`spec/drainer-conformance.md` describes what the drainer side must do.

### §8.1 Stdout-only mode (no audit store)

With no audit store attached there is nothing to allocate against. In this mode
an SDK MUST emit phase-1 lines only, with `hash = ""`, and MUST log once at init
that chaining is disabled. `verify_chain` already skips rows with an empty hash
(§2), so such a stream verifies trivially instead of failing. An SDK MUST NOT
keep an in-memory sequence in this mode; that is exactly what §2.1 forbids.
