# Audit hash-chain & replication spec

**Version:** 1.0
**Date:** 2026-06-22
**Status:** Normative — all SDK chain / replication implementations MUST conform.

---

## Purpose

fasten's audit rows form a per-`source_node_id` tamper-evidence hash chain
(one node, one chain — see §2). A node ships its chain to an upstream aggregator (a different SDK,
e.g. a Python edge node → a Go control plane), which re-verifies it. For that to
work, **every SDK must compute the row hash over the identical bytes** and agree
on the replication contract.

This document is the single source of truth for the canonical hashed form, the
cross-language rendering rules, the form-id registry, and the replication
(`ingest` / `IngestResult`) semantics. When an SDK deviates, the spec wins.

Each SDK's test suite SHOULD include the §6 vectors to prevent silent
re-divergence.

---

## §1 Canonical form `"1"`

The row hash is `SHA-256` of the **canonical JSON** of the row, with the `hash`
field excluded. The hashed form is itself versioned via the `canonical_form_id`
field so the choice of bytes is tamper-evident and future forms are additive.

### §1.1 Hashed field set (form `"1"`)

Exactly these 22 keys, and no others:

```
actor, actor_kind, action, canonical_form_id, category, code, detail, domain,
id, method, monotonic_seq, origin_id, prev_hash, request_id, service_id,
severity, shipped_at, source_node_id, target, tenant_id, timestamp, wire_version
```

- `hash` is **excluded** (it is the output).
- `canonical_form_id` is **included** — the form choice is covered by the hash.
- `pii_in_detail` is **excluded**. The Go wire `Row` carries it as a field; the
  Python `AuditRow` does not. Both SDKs MUST exclude it from the hash so a Go
  aggregator can verify a Python-sealed chain. This is a deliberate, fixed
  decision — NOT a per-SDK choice.

### §1.2 Canonical JSON rendering

The reference rendering is CPython:

```python
json.dumps(d, sort_keys=True, separators=(',', ':'), default=str)
```

Every SDK MUST reproduce these bytes:

| Rule | Requirement |
|---|---|
| Key order | Sorted ascending, **recursively** (top level and every nested object). |
| Whitespace | None — `,` and `:` separators, no spaces. |
| Non-ASCII | Escaped as `\uXXXX` (and UTF-16 surrogate pairs for astral chars), i.e. CPython `ensure_ascii=True`. |
| `<` `>` `&` | Left **literal** (CPython does NOT HTML-escape; a Go encoder MUST disable HTML escaping). |
| Null | `None` → `null` for `tenant_id` and `shipped_at` when absent. |
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
the default encoder: `float64(75.0)` renders as `75`, diverging from CPython's
`75.0`, and a Python-sealed row with a whole-number float in `detail` (e.g. a
setpoint value `75.0`) would then **fail verification** — a silent cross-language
break.

The conformant technique is to **preserve the original numeric tokens**: decode
`detail` with number-token preservation (Go `json.Decoder.UseNumber()`), so each
value keeps its source token (`"75.0"`, `"7"`, `"1e+20"`) and is re-emitted
verbatim. Because the stored JSON was produced by the canonical (CPython)
rendering, preserving its tokens reproduces it byte-for-byte regardless of how
the number was originally typed.

### §1.4 Canonical form `"2"` — committed detail

Form `"2"` replaces `detail` in the hashed field set with a **salted commitment**
to it. Everything else — rendering, number handling, key sorting, the inclusion
of `canonical_form_id` — is identical to §1.2 and §1.3.

```
form "1": sha256(canonical_json(row − {hash}))
form "2": sha256(canonical_json(row − {hash, detail, detail_salt}
                                     + {detail_commitment}))

detail_commitment = sha256(detail_salt || canonical_json(detail))   hex
detail_salt       = 32 random bytes, hex, unique per row
```

`detail` and `detail_salt` are **stored columns but not hashed fields**.
`detail_commitment` is both stored and hashed.

**Why a commitment rather than omitting `detail`.** Redaction must be able to
destroy `detail` without invalidating the row. If `detail` were hashed directly,
destroying it would change the row's `hash`; because `prev_hash` is itself a
hashed field (§1.1), that change cascades to every following row, forcing an
O(n) re-seal of the whole chain suffix on every redaction — an operation
indistinguishable from tampering. Committing instead means redaction is O(1) and
the row's `hash` never moves.

**Redaction under form `"2"`** is therefore:

```
UPDATE {table} SET detail = NULL, detail_salt = NULL WHERE ...
```

`hash`, `prev_hash`, `canonical_form_id` and `monotonic_seq` are untouched. The
chain still verifies, and the row still proves *what it committed to* — a party
holding the original `detail` and `detail_salt` can recompute the commitment and
demonstrate the row was not altered. Destroying the salt makes the commitment
computationally hiding, so the digest does not leak the redacted value.

**Which form new rows use.** New rows seal under form `"2"`. Form `"1"` remains
registered forever so existing rows verify bit-identically — introducing form
`"2"` changes no stored hash. A form-`"1"` row **cannot** be redacted without the
cascade described above; SDKs MUST refuse to redact one and say why.

### §1.5 Form-id registry & unknown ids

Each SDK maintains a `canonical_form_id → hash-fn` registry holding `"1"` (§1.1)
and `"2"` (§1.4). Adding a form is purely additive: register a new id and stamp it
at seal time. `verify_chain` MUST dispatch per row on `canonical_form_id` and MUST
**reject** (not skip, not crash) any row carrying an id absent from the registry.
A row with no `canonical_form_id` (sealed before the field existed) defaults to
form `"1"`.

---

## §2 Chain identity & sealing

- **The chain key is `source_node_id` alone.** One node, one chain. Every row a
  node originates joins the same sequence regardless of which `service_id` wrote
  it or how many engine instances are live.
- `monotonic_seq` is strictly increasing and **unique** within a
  `source_node_id`. Two originated rows on one node MUST NOT share a
  `monotonic_seq`.
- `prev_hash` is the hex SHA-256 of the preceding row in that sequence, or the
  literal `"genesis"` for the first row.
- Rows with an empty `hash` (written before hash-chain support, or emitted in
  stdout-only mode per §8) are skipped by `verify_chain`, not rejected.

### §2.1 Allocation (normative)

`monotonic_seq` and `prev_hash` MUST be allocated **by the store, inside the same
transaction as the insert**. An in-memory per-instance counter is non-conformant:
two engine instances on one node — two services sharing a store, a forking
supervisor, `uvicorn --workers` — otherwise each mint `seq` from 1 and produce two
rows at `seq 1` both claiming `prev_hash = "genesis"`. `verify_chain` then reports
a `prev_hash` break, which is indistinguishable from tampering.

A conformant allocation is, atomically:

```
BEGIN
  seq  := COALESCE(MAX(monotonic_seq), 0) + 1   -- WHERE source_node_id = ?
  prev := hash of the row at seq-1               -- same predicate, or "genesis"
  row  := seal(prev, row WITH monotonic_seq = seq)
  INSERT row
COMMIT
```

The transaction MUST serialise against concurrent allocations for the same
`source_node_id` (SQLite: `BEGIN IMMEDIATE`; Postgres: `SELECT … FOR UPDATE` on
the node's tip row, or a node-scoped advisory lock).

### §2.2 Sealing

`seal(prev_hash, row)` is the single blessed sealing primitive: it stamps the
current `canonical_form_id`, sets `prev_hash`, and computes `hash` over §1. Emit
MUST go through `seal` so emit and verify never diverge.

Because §2.1 puts allocation in the store transaction, **sealing happens at
drain/insert time, not at `emit()`**. `emit()` therefore returns an unsealed row.
See §8 for what the stdout stream carries in the interim.

---

## §3 Verification

`verify_chain(rows)`:

1. Sort by `monotonic_seq`.
2. For each hash-bearing row, recompute the §1 hash for its `canonical_form_id`
   and compare to the stored `hash`.
3. Compare each row's `prev_hash` to the preceding row's `hash`.
4. On the first failure, stop and report `first_break_at` = that row's
   `monotonic_seq`.

The result carries `ok`, `total_rows`, `first_break_at`, and `reason`.

---

## §4 Replication (`ingest` / `IngestResult`)

An aggregator receives rows reverse-synced from a node and ingests them WITHOUT
re-sealing (re-sealing would re-hash and destroy tamper evidence). Replicated
rows keep their origin's `hash` / `prev_hash` / `origin_id` / `monotonic_seq`.

- **Verified-prefix, not all-or-nothing.** `ingest` verifies the incoming chain
  and inserts the longest verified prefix (rows before the first break). It MUST
  NOT raise on a break.
- **`IngestResult`** reports `inserted` (rows offered to the idempotent insert),
  `rejected_from_seq` (the `monotonic_seq` of the first broken row, or null when
  the whole batch verified), and `reason`. The sender resyncs from
  `rejected_from_seq` instead of re-shipping a poison-pilled batch forever.
- **Atomicity.** The verified prefix is inserted in a single transaction; insert
  is idempotent so re-delivery is a no-op.
- **`origin_id == id`** is the "originated-here" discriminator: a node's
  `list_unshipped` returns only its own originated rows, never replicated ones.

---

## §5 Originated vs replicated inserts

- `insert_originated(row)` — the engine's own emit path. Asserts
  `origin_id == id`.
- `insert_replicated(row)` — the replication path. Asserts the row is already
  sealed (`hash != ""`); the chain was verified by the caller.

The intent is type-level, not by convention, so a bug that hands the engine a
foreign-origin row cannot masquerade as a replicated insert.

---

## §6 Cross-language test vectors

SDKs SHOULD pin these to detect re-divergence. Both are a single Python-sealed
row with `prev_hash = "genesis"`; a foreign SDK MUST recompute the same hash.

| Vector | `detail` | Expected hash |
|---|---|---|
| Base | `{"qty": 3, "sku": "WIDGET"}` | `cbf5a1ee4bb7baeb0b433bedfa60434bdea42627b9671183895970bbff02f9ac` |
| Whole-number float | `{"setpoint": 75.0, "tolerance": 12.5, "retries": 7}` | `512021c690ddfd2077192cb6d75921ea36d35b3270a12fdf91888d5ffabcf54b` |

The float vector is the §1.3 regression guard — it fails for any SDK that renders
`75.0` as `75`.

---

## §7 Redaction

Retention policy differs by code: a row carrying personal data (`pii_in_detail`)
may have to go at 30 days while operational history is kept for a year.

`DELETE` is **non-conformant**. It removes a row from the middle of the sequence,
and §3 step 3 exists specifically to detect that as tampering. Redact instead.

### §7.1 The operation

Under form `"2"` (§1.4), redaction is a single-row update inside one transaction:

```
UPDATE {table} SET detail = NULL, detail_salt = NULL WHERE id = ?
```

No hash changes. No other row is touched. `verify_chain` passes before and after.

SDKs MUST refuse to redact a form-`"1"` row (its `detail` is hashed directly, so
redaction would require re-sealing the entire suffix) and MUST report that the row
predates form `"2"`.

### §7.2 The redaction event

Every redaction MUST itself be an originated, chained row:

- code `AUDIT_ROW_REDACTED`
- `target` = the redacted row's `id`
- `detail` = `{"redacted_seq": <n>, "reason": <retention policy id>}`
- sealed normally, allocated normally (§2.1)

Without it, an honest erasure and a quiet redaction are indistinguishable: both
leave a row whose `detail` is null. The event is what makes the destruction
accountable — who, when, under which policy. This is the difference between
"the data is gone" and "the data is gone and we can show why".

### §7.3 What redaction does and does not give you

- It **does** destroy the personal data while leaving the sequence verifiable,
  and it records that the destruction happened.
- It does **not** provide non-repudiation. An operator who can redact can also
  re-seal the whole chain from genesis. Redaction is only meaningfully
  constrained when the chain tip is anchored externally (P1-23), so a full
  re-seal fails against a digest published before the rewrite.

---

## §8 Emit-time vs seal-time (stdout contract)

§2.1 moves allocation into the store transaction, so `emit()` cannot know
`monotonic_seq`, `prev_hash` or `hash`. The stdout audit stream is therefore
**two-phase**:

1. **At `emit()`** — the row is written to stdout immediately, before any store
   routing, with `monotonic_seq: 0`, `prev_hash: ""`, `hash: ""`. This preserves
   the existing guarantee that a row reaches the log stream even if the store
   path blocks or raises.
2. **At insert** — once the store has allocated and sealed, the sealed row is
   written again with its final `monotonic_seq`, `prev_hash` and `hash`.

Both lines carry the same `id`, which is minted at emit time and is the join key.
Consumers that need the chain MUST use phase-2 lines (`hash != ""`); consumers
that only need the event MAY use phase-1 and ignore phase-2 duplicates by `id`.

`spec/drainer-conformance.md` describes the drainer-side obligations.

### §8.1 Stdout-only mode (no audit store)

With no audit store attached there is nothing to allocate against. In that mode
an SDK MUST emit phase-1 lines only, with `hash = ""`, and MUST log once at init
that chaining is disabled. `verify_chain` already skips empty-hash rows (§2), so
such a stream verifies vacuously rather than failing. An SDK MUST NOT fabricate
an in-memory sequence in this mode — that is the exact non-conformance §2.1
exists to forbid.
