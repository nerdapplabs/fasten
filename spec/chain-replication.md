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
- `shipped_at` is hashed as **`null`** in every form, whatever the row holds.
  Rows are sealed with it `null` and `mark_shipped` sets it later, so it must
  not move the hash. Rows sealed through emit keep their existing hashes.
  A row sealed earlier with `shipped_at` already set was hashed over that
  value; verifiers MUST accept it when the hash matches with the stored
  `shipped_at` (rendered like `timestamp`) in place of `null`.
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
| DEL (0x7f) | Escaped as `\u007f`, as CPython does. |
| `<` `>` `&` | Left **literal**. CPython does NOT HTML-escape; a Go encoder MUST turn HTML escaping off. |
| Null | `None` renders as `null` for `tenant_id` when absent; `shipped_at` is always `null` (§1.1). |
| Timestamps | `datetime.isoformat()` of a tz-aware UTC value: `+00:00` offset (not `Z`), six-digit microseconds only when nonzero. Applies to `timestamp`. |

Rows the Go SDK sealed before it escaped DEL hold it raw in the hashed bytes.
When a row's detail commitment or hash does not match and a hashed string holds
DEL, verifiers MUST retry that check with DEL written raw, every other rule
unchanged, and accept the row if it then matches. This applies to every form
and combines with the other hash fallbacks: the `shipped_at` rule in §1.1, and
for form `"1"` a hash over the wire `Z` timestamp, as Python sealed form `"1"`
before it used `+00:00`.

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
- `prev_hash` is the `hash` of the preceding sealed row in that sequence, or
  the literal `"genesis"` for the node's first sealed row (§2.1).
- Rows with an empty `hash` (written before hash-chain support, or emitted in
  stdout-only mode, §8) are skipped by `verify_chain`, not rejected, as long
  as their `monotonic_seq` is below the node's first sealed row. They are not
  covered by the chain. A conformant store never writes an unsealed row at or
  above that seq (§2.1), so one there is a break. Only the node's first sealed
  row is exempt from the `prev_hash` check against the row before it: directly
  after an unsealed row (seq + 1) it carries `prev_hash = "genesis"`, and after
  a gap below it, as left by a purged head, the chain is checked from that row
  on. A gap between two sealed rows is a `prev_hash` break. Since an
  unsealed row can carry any seq, losing the head of a chain is detectable only
  against an external record of it; tail truncation is detected against a
  checkpoint (§9).

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
  prev := hash of the node's last sealed row     -- or "genesis" if none
  row  := seal(prev, row WITH monotonic_seq = seq)
  INSERT row
COMMIT
```

`seq` counts every row on the node, sealed or not. `prev` is the `hash` of the
node's sealed row (`hash <> ''`) with the highest `monotonic_seq`, or
`"genesis"` when the node has no sealed row.

The transaction MUST serialise against concurrent allocations for the same
`source_node_id`. SQLite: `BEGIN IMMEDIATE`. Postgres: the transaction MUST
first run `SELECT pg_advisory_xact_lock(hashtextextended(source_node_id, 0))`.
Every SDK takes this same lock, so writers from different SDKs on one table
exclude each other; `SELECT … FOR UPDATE` on the tip row does not, and locks
nothing when the node has no rows yet.

### §2.2 Sealing

`seal(prev_hash, row)` is the one sealing function. It stamps the current
`canonical_form_id`, sets `prev_hash`, and computes `hash` as in §1. Emit MUST
go through `seal`, so emit and verify cannot disagree.

Because §2.1 puts allocation in the store transaction, **sealing happens at
drain/insert time, not at `emit()`**, and `emit()` returns an unsealed row. §8
covers what the stdout stream carries until then.

### §2.3 Purge (normative)

An age purge (`purge(before, respect_unshipped)`) MUST delete only a seq
prefix of each node's rows. Per `source_node_id`, the rows it keeps are those
with `timestamp >= before` and, when `respect_unshipped` is set, those with
`shipped_at` null. It deletes the rows below the lowest kept seq, and every
row of a node with nothing to keep. A row older than the cutoff above a kept
row stays until that row ages out too. Rows at seq 0 are not chained; they
never count as kept for this rule and are deleted by age, unshipped ones
staying when `respect_unshipped` is set.

`timestamp` order is not `monotonic_seq` order: the timestamp is taken at
emit and the seq at insert (§2.1), and a clock stepped back stamps later rows
earlier. Deleting by `timestamp < before` alone can remove a row above a kept
one, and the next kept row's `prev_hash` then names a deleted row, a §3
break. A prefix leaves a purged head, which verifies (§3).

---

## §3 Verification

The SDKs that verify name it `verify_chain(rows)` (Python) and
`VerifyChain(rows)` (Go); this spec uses the Python name. Both follow
these steps and give the same result for the same rows.

`verify_chain(rows)`:

1. Keep one copy of each row `id` per node (re-delivery, §4; or a stdout
   capture holding both §8 lines). A sealed copy wins over an unsealed one.
   Two sealed copies MUST have the same `hash`, and each MUST pass step 2;
   otherwise the chain breaks at the lower `monotonic_seq` of the two copies.
   Sort by `monotonic_seq`.
2. For each hash-bearing row, recompute the §1 hash for its `canonical_form_id`
   and compare it with the stored `hash`. A row with an empty `hash` at or above
   its node's first sealed seq is a break (§2).
3. Compare each row's `prev_hash` with the previous row's `hash` on its node,
   or with `"genesis"` when the previous row is unsealed and directly before it.
   Only the node's first sealed row, after a gap, skips this check (§2).
4. Report `first_break_at` = the lowest `monotonic_seq` at which any node's
   chain fails.

The result carries `ok`, `total_rows`, `first_break_at` and `reason`.

---

## §4 Replication (`ingest` / `IngestResult`)

An aggregator receives rows reverse-synced from a node and ingests them WITHOUT
re-sealing them. Re-sealing would re-hash the rows and remove the tamper
evidence. Replicated rows keep their origin's `hash`, `prev_hash`, `origin_id`
and `monotonic_seq`.

- **Verified prefix, not all-or-nothing.** `ingest` verifies the incoming chain
  and inserts the longest verified prefix (the rows before the first break). It
  MUST NOT raise on a break. An unsealed row below its node's first sealed
  row, in the batch and in the store, is not inserted (§5) and is not a break.
  If the store holds a sealed row for its node at a lower seq, it is a break at
  that row, with the reason `verify_chain` gives (§2).
- **`IngestResult`** reports:
  - `inserted`: rows passed to the idempotent insert,
  - `rejected_from_seq`: the `monotonic_seq` of the first broken row, or null
    when the whole batch verified,
  - `reason`.

  The sender resyncs from `rejected_from_seq` instead of re-sending a batch
  that will never verify.
- **Stored rows.** In the same transaction, `ingest` checks the verified prefix
  against what the store already holds for each node. A row whose `id`, or
  whose (`source_node_id`, `monotonic_seq`), is stored with different content
  is a break at that row; so is a new row whose `prev_hash` does not match the
  stored row at `seq - 1` (`"genesis"` when that row is unsealed, §2), or whose
  `hash` the stored row at `seq + 1` does not link to. Since `id` is unique,
  a repeat of an `id` within a batch on another node is a break at the later
  row; on the same node, `verify_chain` already breaks at the lower seq when
  the copies differ (§3), and copies with the same `hash` are a re-delivery,
  inserted once. `ingest` MUST
  NOT keep one version silently: an insert skipped because another writer
  stored that `id` in the meantime is checked again, not counted as inserted.
  A row stored with the same `hash` is a re-delivery.
- **Local node.** A node's own rows come only from its emit path, so a row
  whose `source_node_id` is the receiving node is a break at that row; as
  with stored rows, the batch is cut at the lowest such `monotonic_seq`. The
  break is permanent: resending the same row fails again, so the sender must
  drop it (it usually means two nodes share a node id). An SDK's
  engine-level ingest checks against its own node id; store-level ingest can
  be given the receiving node's id, and without it makes no such check.
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

An unsealed row (`hash = ""`) is not in the chain, so SDKs MUST redact it
like any other candidate, whatever its `canonical_form_id`; the form-`"1"`
refusal above applies only to sealed rows.

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
  constrained when the chain tip is checkpointed externally (§9), so that a
  full re-seal fails against a checkpoint published before the rewrite.

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

### §8.2 Allocation without sealing

A store MAY allocate `monotonic_seq` (§2.1) for a writer that cannot seal, for
example one writing through fasten-core. Such rows have an empty `hash`;
`verify_chain` treats them as unsealed (§2). The writer MUST log
`audit_chain_unavailable` once per init, as in §8.1.

A node that writes unsealed rows MUST NOT share its `source_node_id` with a
writer that seals; give it a distinct node id.

---

## §9 Checkpoints

The chain shows edits, insertions, deletions and reordering on its own. It
cannot show rows cut off at the end, or a chain re-sealed from genesis by
someone with write access to the store: both leave a chain that verifies.
A checkpoint records a node's latest sealed row so that both can be detected
later.

### §9.1 Format

A checkpoint is a JSON object with exactly these fields:

| Field | Type | Value |
|---|---|---|
| `source_node_id` | string | The node (§2). |
| `monotonic_seq` | integer | `monotonic_seq` of the node's sealed row (`hash <> ''`) with the highest seq. |
| `hash` | string | That row's `hash`. |
| `anchored_at` | string | When the checkpoint was taken, in the canonical timestamp form ([persistent-streams.md §4.3](./persistent-streams.md)). |

Taking checkpoints yields one per node that has a sealed row; unsealed rows
are not checkpointed. A file of checkpoints holds one object per line,
each ending in a newline. A reader MUST reject a line that is not such an
object (another key, a key in other case, a missing key or a value of
another type), with one exception: when the file does not end in a newline
and its last line is not valid JSON, as a crash part way through an append
leaves it, that line is skipped and the reader reports it to the caller (Go
returns `ErrPartialLastLine` with the checkpoints before it; Python logs a
warning). Before appending, a file sink MUST truncate such an unfinished
last line, so that it never ends up before a later line, and MUST add the
missing newline after a complete last line. A file has one publisher at a
time; concurrent appends to one file are not supported. An HTTP sink receives a JSON array of them in one `POST`. Any
status other than 2xx, a 3xx included, is a failed publish: a redirect is
not followed, since a client would repeat a `POST` as a `GET` without the
body. Userinfo in the sink URL (`user:password@`) is sent as an
`Authorization: Basic` header and is not part of the request URL. Error
messages name the sink URL as `scheme://host[:port]/path`, without
userinfo or query.

### §9.2 Where to publish

Where checkpoints are published is the operator's choice. They SHOULD go
somewhere outside the operator's own write control, such as a write-once
bucket, a transparency log or a third party, and SHOULD be published often
enough that the rows written since the last checkpoint are an acceptable
loss. A checkpoint held where the store's operator can rewrite it proves
nothing about that operator.

### §9.3 Verifying against checkpoints

SDKs that verify chains (Python, Go) MUST be able to verify a batch of rows
against checkpoints, in two modes:

- **Whole chain** (the default): the batch is taken to be every row the
  store holds. Every node that has a checkpoint MUST have rows in the
  batch, and no checkpoint may be below its lowest row seq or above its
  highest.
- **Partial** (an explicit option): the batch is a page, one node or a
  sample, so a checkpoint outside it says nothing about it.

In either mode these rules apply after §3 step 1, per checkpoint whose node
has rows in the batch:

1. A row of that node at the checkpoint's seq exists: its `hash` MUST equal
   the checkpoint's `hash` (when more than one row holds that seq, one of them
   must). Otherwise the chain breaks at that seq, with reason
   `row <id>: hash differs from checkpoint at seq <seq>`, naming the row with
   the lowest `id`.
2. The checkpoint's seq is above the node's highest row seq. In a partial
   verify the batch ends earlier and the checkpoint is skipped. In a
   whole-chain verify the chain was cut off: it breaks at the node's highest
   seq + 1, with reason
   `node '<node>': chain ends at seq <highest> before checkpoint at seq <seq>`.
   Tail truncation is therefore detected only by a whole-chain verify.
3. The checkpoint's seq is below the node's lowest row seq. In a partial
   verify the batch starts later and the checkpoint is skipped. In a
   whole-chain verify the rows it covers were deleted, or the chain was
   rewritten or re-sealed above it: it breaks at the node's lowest seq, with
   reason
   `node '<node>': rows start at seq <lowest>, after the checkpoint at seq <seq>`.
4. Otherwise the row is missing from inside the span. The chain breaks at the
   checkpoint's seq, with reason
   `node '<node>': no row at checkpointed seq <seq>`.

A node with checkpoints but no rows in the batch is skipped in a partial
verify. In a whole-chain verify it breaks at the seq of its newest
checkpoint, with reason
`node '<node>': no rows, but checkpointed at seq <seq>`; this holds for an
empty batch too. Checkpoints are checked ordered by
`source_node_id`, then `monotonic_seq`. `first_break_at` is the lowest seq
across the §3 breaks and the checkpoint breaks; on a tie the §3 break is
reported, and between checkpoint breaks the first in that order.

A whole-chain verify of a store under retention MUST be given only the
checkpoints taken since the latest purge finished. A checkpoint taken
before it is below the purged rows and fails the verify by rule 3, and a
node whose rows have all been purged fails as a node with no rows. A cutoff of the retention period alone
is not enough, since a node's last checkpoint can be taken just before the
purge that removes its rows. Python's `checkpoints_since(checkpoints,
cutoff)` and Go's `CheckpointsSince(checkpoints, cutoff)` keep the
checkpoints whose `anchored_at` is at or after the cutoff, and reject an
`anchored_at` that is not in the canonical form. Publish again after each
purge, so that every node still in the store has a checkpoint after it.

Rows deleted from the start of a chain show only when a checkpoint given
to the verify falls among them. Deleting rows below every given checkpoint
looks the same as a purge, so the checkpoints since the latest purge cover
only what was written after it.

A checkpoint covers a node's rows up to its seq. Rows written after a
node's newest checkpoint are not covered until the next checkpoint is
published: they can be cut off or rewritten without a break, and a node
first seen since then has no checkpoint at all.

`spec/checkpoint-vectors.json` (generated by
`scripts/gen_checkpoint_vectors.py`) holds rows, checkpoints, `partial`
and the expected `ok`, `first_break_at` and `reason`; every verifying SDK
MUST reproduce them.
