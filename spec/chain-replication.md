# Audit hash-chain & replication spec

**Version:** 1.0
**Date:** 2026-06-22
**Status:** Normative — all SDK chain / replication implementations MUST conform.

---

## Purpose

fasten's audit rows form a per-`(service_id, source_node_id)` tamper-evidence
hash chain. A node ships its chain to an upstream aggregator (a different SDK,
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

### §1.4 Form-id registry & unknown ids

Each SDK maintains a `canonical_form_id → hash-fn` registry. `"1"` is the only
form today. Adding a form is purely additive: register a new id and stamp it at
seal time. `verify_chain` MUST dispatch per row on `canonical_form_id` and MUST
**reject** (not skip, not crash) any row carrying an id absent from the registry.
A row with no `canonical_form_id` (sealed before the field existed) defaults to
form `"1"`.

---

## §2 Chain identity & sealing

- The chain key is `(service_id, source_node_id)`. `monotonic_seq` is a per-node
  counter that also resolves same-millisecond ordering.
- `prev_hash` is the hex SHA-256 of the preceding row in that sequence, or the
  literal `"genesis"` for the first row.
- `seal(prev_hash, row)` is the single blessed sealing primitive: it stamps the
  current `canonical_form_id`, sets `prev_hash`, and computes `hash` over §1.
  `Emit` MUST go through `seal` so emit and verify never diverge.
- Rows with an empty `hash` (written before hash-chain support) are skipped by
  `verify_chain`, not rejected.

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
