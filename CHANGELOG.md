# Changelog

All notable changes to fasten are documented here.
Format: [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning 2.0](https://semver.org/).

## [Unreleased]

### Fixed: queued rows, sys and log lines, re-init report (Rust)

- `submit()` stores a row inline when the drainer is stopping and refuses it,
  then emits `audit_drain_stored_inline`. If that insert fails too, it emits
  `audit_sync_fallback_failed` and returns the error. Before, such a row was
  dropped and `submit()` returned `Ok`.
- Redact sys and log lines (`fasten::log::*` included) with the configured
  extra keys and replacement, as the other SDKs do.
- SDK sys events (`audit_chain_unavailable`, `retention_purge_failed`,
  `pii_redaction_skipped_legacy_form`) go to stderr, as spec
  drainer-conformance §4 asks. `fasten::log::*` lines stay on stdout.
- Re-init emits `audit_drain_install_incomplete {flushed, unstored}` when the
  old drainer's flush timed out or rows it held were not stored (spec §10).
- A failed insert through the drainer is reported as `CallbackFailed`, not
  `InvalidTableName`, in `audit_drain_lost_at_stop.error_type`.
- `PostgresStore::redact_rows` returns only the ids it redacted.

### Changed: Go SDK requires Go 1.26

- The Go module now declares `go 1.26.0`, up from `go 1.22`. It moves to
  modernc.org/sqlite v1.61.1 (from v1.34.4) for a current SQLite engine, and
  that release requires Go 1.26. Go 1.26 is the oldest Go release still
  supported upstream.
- Adopters on Go 1.25 or older need to upgrade Go before taking this release.

### Fixed: Swift `FastenStore` binding (#149)

- `close()` can be called more than once, and `deinit` goes through it. Calls
  after `close()` throw `FastenStoreError` instead of using a stale handle.
- The binding builds again: the status check compares with `FASTEN_OK`, the
  module map links `fasten_core`, and the build points at
  `fasten-core/target/release`.

### Fixed: Swift store-assigned monotonic_seq, no non-spec hash, PII redaction (#124)

- **Breaking:** the store assigns `monotonic_seq` inside the insert
  transaction (`BEGIN IMMEDIATE` on SQLite, spec §2.1), so two engines on one
  file and node no longer write duplicate seqs. `emit` hands the store a row
  with `monotonic_seq` 0, so a custom `AuditStore` must assign it, and the
  stdout line carries 0 too. `hash` and `prev_hash` are now empty. The old
  Swift hash did not follow spec §1, so `verify_chain` in Python and Go
  reported those rows as tampered. Rows are written unsealed, and `configure`
  logs `audit_chain_unavailable` once. A store given a non-zero seq writes it
  as given.
- `SQLiteStore` sets a 5 s busy timeout (`busyTimeoutMs`), adds the
  `pii_in_detail`, `canonical_form_id`, `detail_salt` and `detail_commitment`
  columns, and indexes `(source_node_id, monotonic_seq)` so the seq lookup on
  insert does not scan the table. `pii_in_detail` is set from the code's
  `Meta`. `init` throws if adding a column fails for any reason other than
  the column already existing.
- `Fasten.redactExpired(before:codes:reason:)` sets `detail` to null on rows
  of `codes` older than `before`, after writing an `AUDIT_ROW_REDACTED` row
  for each one (spec §7). `codes` defaults to `Fasten.piiCodes()`, which only
  holds codes registered in this process; a retention job that never calls
  `register` passes them. With no codes it logs `pii_redaction_no_codes` and
  redacts nothing. Rows are never deleted, and sealed form-"1" rows are not
  touched; their count is logged as `pii_redaction_skipped_legacy_form`. The
  SDK runs no retention loop, so call it on a schedule. `Meta` gains
  `piiInDetail`. A custom `AuditStore` that supports redaction implements
  `listRedactionCandidates`, `redactRows` and `countRefusedLegacyRows`; the
  default implementations throw.
- Rows written by the previous Swift release are form "1" with a hash that
  never covered `detail`, so `redactExpired` refuses them. If only Swift has
  written to the table, call `SQLiteStore.clearLegacySwiftHashes()` once to
  unseal them and let `redactExpired` reach them. Do not call it on a table Go
  or Python also write: their form "1" hashes do cover `detail`.
- The swift-crypto dependency is gone. `SQLiteStore.ping` and
  `maxMonotonicSeq` take the store lock, so calling them while the drainer
  inserts no longer crashes. The connection is opened with
  `SQLITE_OPEN_NOMUTEX`, so that lock is what serializes it on every platform.
- `AuditStore.maxMonotonicSeq(sourceNodeID:)` returns one node's highest seq,
  or the table's with nil; `maxMonotonicSeq()` is the table-wide shorthand.
  A custom `AuditStore` implements the new requirement.

### Fixed: Swift `SQLiteStore.insert` reports SQLite errors

- `insert` throws when prepare or step fails. Raise mode reports the error and
  the queue drainer retries the row; before, the row was dropped silently.
- `FastenError` conforms to `LocalizedError`, so `localizedDescription` carries
  the store's message.

### Fixed: C++ PII redaction (#124)

- `fasten::redact_expired(store, before, reason)` redacts rows of the codes in
  `pii_codes()` (`pii_in_detail`, or retention class short) older than
  `before`, as Python and Go do (spec §7). `detail` becomes the JSON literal
  `null`; rows are never deleted. An `AUDIT_ROW_REDACTED` row is inserted
  into the store before each row is redacted. There is no background loop:
  the adopter calls it on a schedule.
- `SqliteStore` and `PostgresStore` gain `list_redaction_candidates()` and
  `redact_rows()`, and the `prev_hash`, `hash`, `canonical_form_id`,
  `detail_salt` and `detail_commitment` columns. They are added to existing
  tables, with `pii_in_detail` for a table the Python store made; `SqliteStore`
  adds them under one write lock, so stores opening an old file at once don't
  fail. C++ rows are unsealed; a sealed form-"1" row is never redacted.
- `redacted_seq` is a JSON number only in an `AUDIT_ROW_REDACTED` row's
  `detail`. In any other code's `detail` it stays a string, so the redactor's
  value checks still see it.
- Test for #92: two `SqliteStore`s on one file and one node get seqs 1..N.

### Changed: C++ seq, request ids, tenant_id on sys rows, `/audit` errors (#138)

- **Breaking for existing callers** who read these values:
  - `emit()` returns `monotonic_seq` 0 instead of a process counter that
    started at 1 on every run (spec §2.1, §8). The store allocates the seq.
  - `scheduler::job_run()` mints `sched-<id>`, not `scheduler-<id>`.
  - Sys rows carry the engine's `tenant_id`.
  - An `/audit` 500 answers `internal error` and logs the error type; it
    returned the store's message.

### Fixed: C++ drainer shutdown race, seq, request ids, reader scope (#138)

- `put()` could pass the stopped check and then use a store handle that a
  concurrent re-`init()` had just freed. put, stats and flush are now counted
  while they use the handle. `shutdown()` closes the core drainer first, which
  wakes a `put()` blocked on a full queue and drains the rest, then waits for
  those calls before freeing the handle. A row put on a stopped drainer
  (including one the sink puts during the drain), or refused by the core, is
  reported once as `audit_drain_abandoned`, and `emit()` stores it
  synchronously, logging `audit_drain_stored_inline` when the sink takes it;
  it used to vanish.
- `init()` builds its settings first and publishes them under one lock, which
  every reader takes, so a re-init no longer races an emit or a log line on
  another thread for the ids, the strategy or the redact config.
- `SqliteStore` and `PostgresStore` allocate the node's next seq in the
  insert's transaction (Postgres under the same advisory lock as the other
  SDKs), using a new `(source_node_id, monotonic_seq)` index. `PostgresStore`
  runs its schema setup under the Python store's bootstrap advisory lock, so
  stores opening an existing table at once no longer fail creating the index. `SqliteStore`
  waits up to 5 s for a lock held elsewhere, and rolls back when a statement
  or COMMIT fails, so the next insert can run.
- Timestamps use the canonical form with six fractional digits (§4.3).
- Sys rows always carry a `request_id`: the one in scope, else a
  `boot-<service>-<id>` sentinel until the first real id, else a fresh
  `orphan-<service>-<id>` one (persistent-streams §7).
- The JSON decoder writes `\uXXXX` escapes (and surrogate pairs) as UTF-8,
  and decodes `\b`, `\f` and `\/`; it used to keep the `u` and drop the
  backslash.
- The reader can be scoped to a tenant: `handle_sys/api/audit(params,
  tenant)`, `set_scoped_audit_query()`, `enforce_tenant_isolation()`, and a
  tenant resolver on the Simple-Web-Server adapter.
- New `Config::queue_drain_max_attempts` (spec §2, default 50).
- Tests cover drainer vectors V-1 to V-12. `sqlite_store_smoke` is built
  again: CMake looked for `SQLite3::SQLite3`, but FindSQLite3 names the
  target `SQLite::SQLite3`, so it was always skipped. CI runs
  `postgres_store_smoke` against a Postgres service; it used to skip.

### Fixed: JS async store errors, drainer stop and `PostgresStore` (#137)

- Raise mode with a store whose `insert` returns a promise (such as
  `PostgresStore`): `emit()` returns a promise for the row that rejects with
  `AuditStoreError`. It used to return normally, and the rejection ended the
  process as an `unhandledRejection`. A sync store still throws from `emit()`.
  The TypeScript return type is now `Row | Promise<Row>`.
- The queue-mode fallback with no drainer logs `audit_sync_fallback_failed`
  for a rejected async insert too.
- Stopping the drainer (re-`init()`, uninstall) no longer drops rows
  silently. It cuts any backoff short and gives each row still queued one
  more attempt (spec §10). A row that fails it, or is still unstored when the
  timeout (5 s) passes, is reported as `audit_drain_lost_at_stop`, as in Go
  and Python, and `stop(timeoutMs)` resolves false. `flush()` counts a
  dead-lettered or lost row as done.
- New `close(timeoutMs)` (and `Engine.close()`) for shutdown: it flushes for
  up to half the timeout, then stops the drainer, and resolves false if a row
  was lost. A second `close()` while one runs waits for the same result.
- `audit_drain_degraded` reports the backoff about to start in
  `in_backoff_seconds`; it was always 0.
- `emit()` no longer makes up `monotonic_seq` from a per-process counter that
  restarted at 1 (spec §2.1, §8). It returns `monotonic_seq: 0`, and
  `PostgresStore` allocates the node's next seq in the insert transaction
  under the same advisory lock as Python and Go, using a new
  `(source_node_id, monotonic_seq)` index. Rows are still unsealed;
  `init()` logs `audit_chain_unavailable` (error) once to say so (§8.1).
  The first start after upgrading builds that index while the column
  ALTERs hold the table's exclusive lock, so on a large table create it
  beforehand (for the default table: `CREATE INDEX CONCURRENTLY IF NOT EXISTS
  idx_audit_log_node_seq ON audit_log (source_node_id, monotonic_seq)`).
- Audit row timestamps and `shipped_at` use the canonical form (§4.3).
- `PostgresStore` can share a table with the Python and Go stores: it inserts
  with a column list, adds the chain columns (and `pii_in_detail` on a table
  Python made), writes `shipped_at` in the canonical form instead of `NOW()`,
  reads `TIMESTAMPTZ` columns back in that form with their microseconds, filters on `tenantId`, and
  orders `query()` by timestamp.
- A table the JS store creates has the Python store's column order (Python
  reads by position) and empty, not NULL, `detail_salt` / `detail_commitment`
  (Go reads them as strings). A table an older JS store created keeps its old
  column order, with `pii_in_detail` before `shipped_at`; Postgres can't move
  a column, so recreate it before pointing a Python store at it.
- JS CI runs the `PostgresStore` tests against Postgres; they were always
  skipped. Two purge tests that failed against a real database are fixed.

### Fixed: JS PII redaction (#124)

- `fasten.redactExpired({ before })` clears `detail` (to `null`) on rows of
  the PII codes (`piiCodes()`: `piiInDetail` or SHORT) older than `before`,
  as Python and Go do (spec §7). It writes an `AUDIT_ROW_REDACTED` row for
  each one first, straight to the store, then clears it. Rows are never
  deleted, and a row sealed under form "1" is left alone and counted in
  `pii_redaction_skipped_legacy_form`.
- `init({ retentionPii: '30d' })` or `FASTEN_RETENTION_PII` runs it on init
  and then hourly. A re-`init()` during a pass runs the new config once that
  pass ends.
- `PostgresStore` retries its table setup on the next call when it fails,
  such as when Postgres isn't up yet; it used to fail every call until a
  restart.
- `PostgresStore` has `listRedactionCandidates()` and `redactRows()`, and
  takes an advisory lock while it creates its table, so two stores starting
  on a new table no longer fail with a duplicate-key error.

### Fixed: log output goes through the redactor (JS, Swift, Python)

- JS and Swift log lines, and JS drainer lines on stderr, are redacted as a
  whole, the message included, as Go and Python already do.
- Python: the structlog processor redacts the event too, and `configure()`
  gives the stdlib bridge the same `extra_redact_keys`.
- JS `extraRedactKeys` are matched as case-insensitive literal substrings,
  as in the other SDKs, in `emit()` as well as logs. They were regexes, so a
  key like `^ssn$` or `card_?num` no longer matches; list the plain names.
- `fasten doctor` no longer prints the DSN: `--json` reports
  `detail.backend` where it reported `detail.dsn`. It opens stores
  read-only, so it no longer creates a missing SQLite file or runs
  CREATE/ALTER TABLE, and it does not open a libpq `key=value` DSN.

### Fixed: Go `/audit/doctor` tenant scope and 500 bodies (#150)

- `/audit/doctor` uses the resolved tenant. A scoped caller gets its own row
  count, no host `tenant_id`, and on a chain break the verdict without
  `first_break_at` or a `reason` naming another tenant's row.
- The row count uses `CountFiltered`, so the Postgres store reports `rows` too.
  A custom store with only `Count` still reports `rows` to an unscoped caller.
- The chain sample is the node's newest 50 rows by `monotonic_seq`, through the
  new `ChainTail` on both built-in stores. The timestamp-ordered sample skipped
  seqs after a clock step back and reported a break on a clean chain.
- Reader 500s answer `internal error` and log a `reader_query_failed` sys line
  with the request id and the error type. The doctor's `last_error` and chain
  `reason` carry fixed text and log a `doctor_check_failed` sys line.

### Changed: replication ingest refuses the receiving node's own rows (Python + Go)

- A node's own rows come from its emit path, so ingest now stops at the
  first row whose `source_node_id` is the receiving node and reports it as
  the break, unless an earlier break is found. As with a stored conflict,
  other nodes' rows from that seq on are left for the sender to resend.
- Python: `Engine.ingest_replicated` and `fasten.ingest_replicated` check
  against the engine's `node_id`, and raise if it is empty.
  `replication.ingest`, `SQLiteStore.ingest_replicated` and
  `PostgresStore.ingest_replicated` take an optional `local_node_id`.
- Go: `SQLiteStore.IngestReplicated` and `PostgresStore.IngestReplicated`
  are unchanged.

### Added: engine-level replication ingest (Go)

- `Engine.IngestReplicated` and `fasten.IngestReplicated` ingest into the
  engine's audit store and check against its `NodeID`.
- `SQLiteStore.IngestReplicatedFor(ctx, localNode, rows)` and the same on
  `PostgresStore`, behind the new `LocalIngester` interface. A local-node
  row with `MonotonicSeq` below 1 is an error, since `RejectedFromSeq` 0
  means no break.

### Changed: replication ingest checks the stored rows (Python + Go)

- `ingest` / `IngestReplicated` now check a batch against the rows the store
  already holds, and reject from the first row that disagrees, where they
  used to keep the stored version and report the row as inserted: a row
  whose id, or node and seq, is stored with other content; a row that does
  not link to the stored row before or after it; an id repeated within the
  batch, on one node or two. A row
  stored with the same hash is still a re-delivery.
- Go SQLite stores raise `busy_timeout` to 5 s only while they write, and put
  back the pool connection's own value afterwards.

### Fixed: Python audit DSN path and `/audit/doctor` (#135, items 1–3)

- `SQLiteStore.from_dsn` keeps `sqlite:////abs/path.db` absolute, as the
  stream store already did. It used to create the file under the working
  directory. A relative path is made absolute when the store is built, so a
  thread that opens its connection after an `os.chdir()` uses the same file.
- `/audit/doctor` samples the node's newest 50 rows by `monotonic_seq` through
  the new `chain_tail()` on both built-in stores. The timestamp-ordered sample
  skipped seqs after a clock step back and reported a break on a clean chain.
  A store without `chain_tail()` keeps the old sample. Both stores add a
  `(source_node_id, monotonic_seq)` index, which this sample and the seq
  allocation use; it is not unique, since unchained rows all sit at seq 0.
  On an existing table the first `init()` after upgrading builds the index
  while holding the write lock, a couple of seconds at a million SQLite rows,
  so a busy node may want to create it beforehand.
- A scoped caller no longer sees the host `tenant_id`, or the row a chain break
  is on. The doctor's `last_error` and chain `reason` carry fixed text and log
  a `doctor_check_failed` sys line with the error type.
- `init()` sets the chain-unavailable flag from the new store: a store without
  `allocate_and_insert_originated` reports `verified: false` from the start,
  not only after its first emit.

### Fixed: Python stores on a table the Go SDK created

- Rows without a salt (unsealed, or form "1") now store an empty
  `detail_salt` and `detail_commitment` instead of SQL NULL. Go creates both
  columns `NOT NULL`, so on Postgres these inserts failed, and on SQLite
  `INSERT OR IGNORE` dropped the row without an error. Both stores read an
  empty value back as `None`, so rows read the same as before.
- The Postgres store selects its columns by name instead of `SELECT *`. Go's
  table orders them differently, so reads on it read the wrong column for
  most fields.
- The Postgres store reads Go's `TIMESTAMPTZ` timestamp and `shipped_at`
  columns, and `sources()` returns them in the canonical form.

### Changed: Python and Go redact unsealed rows (spec §7.1)

- PII redaction now covers unsealed rows (an empty `hash`) as well as form
  "2" rows: no hash covers their `detail`, so destroying it breaks nothing.
  These are the rows the core, Rust, JS, C++ and Swift SDKs write to a shared
  table. Python and Go used to skip them and count them as legacy rows on
  every pass, so their personal data outlived the horizon.
- Sealed form "1" rows are still skipped, and are now the only rows counted in
  the `pii_redaction_skipped_legacy_form` event and the Python warning.
- Adopters relying on unsealed rows keeping their `detail` past the PII
  horizon: it is now set to null after an `AUDIT_ROW_REDACTED` record, as for
  form "2" rows.
- Python's `fasten.chain.redact()` accepts unsealed rows too, matching the
  stores; it still raises on a sealed form "1" row.
- Python redaction now writes an empty `detail_salt` instead of SQL NULL, as
  Go does. On a table the Go store created the column is `NOT NULL`, so the
  update failed after the redaction record was written: on Postgres every pass
  added another record and the row was never blanked, and on SQLite the
  connection stayed in its transaction and other writers got "database is
  locked". The SQLite store now rolls back when the update fails, and both
  stores read an empty salt back as `None`.

### Changed: chain verification (Python + Go)

- A row with no hash is skipped only below its node's first sealed row; one
  at or above it is a break. The sealed row right after an unsealed one must
  link to `"genesis"`.
- A row given more than once is checked once, with its sealed copy
  preferred over an unsealed one (a stdout capture has both). Two sealed
  copies must have the same hash, and each must verify.
- Go now walks each node's chain separately, as Python does, so rows from
  several nodes no longer break on interleaving. Both SDKs report a
  duplicate `monotonic_seq` on one node, and `first_break_at` is the lowest
  seq that breaks on any node.

### Fixed: `mark_shipped` no longer breaks a row's hash (#123, Python + Go)

- Every canonical form hashes `shipped_at` as null (spec §1.1). Setting it
  after sealing changed the hash, so `verify_chain` failed on untouched rows.
- Emit always sealed with `shipped_at` null, so existing hashes don't change.
  A row sealed by calling `seal()` or `allocate_and_insert_originated` with
  `shipped_at` already set still verifies, over its stored value.

### Fixed: Rust SDK store-assigned monotonic_seq and PII redaction (#124)

- **Breaking:** `emit()` returns `monotonic_seq: 0`. The per-engine counter
  restarted at 1, so two engines on one node wrote duplicate seqs (spec §2.1).
  `PostgresStore` now gives a seq-0 row the node's next seq in the insert
  transaction, under the same advisory lock as the Python, Go and JS stores.
  Rows are not sealed, and `init()` logs `audit_chain_unavailable` (error)
  once to say so (§8.1).
- **Breaking:** `Row` gains public fields `prev_hash` and `hash` (both empty),
  so `Row { .. }` literals that list every field stop compiling.
- **Breaking:** `timestamp` and `shipped_at` use the canonical form
  `YYYY-MM-DDTHH:MM:SS.ffffffZ` (§4.3) in `PostgresStore`, in `Row`'s serde
  output (stdout audit lines included) and in sys-line `timestamp`s, which
  were milliseconds.
- `PostgresStore` can share a table with the Python and Go stores: it inserts
  with a column list, adds the chain columns, writes `''` for `detail_salt` /
  `detail_commitment`, and writes into `TIMESTAMPTZ` columns, mixed-case
  table names included. Store bootstrap
  takes the same advisory lock as Python, so stores starting together no
  longer fail on concurrent `CREATE TABLE`. Bootstrap adds a non-unique
  `(source_node_id, monotonic_seq)` index so the next-seq lookup stays cheap.
- Index names for tables whose `idx_{table}_{suffix}` would pass 63 bytes
  (table names of about 50 characters or more) now cut the table part and add
  a hash of the full name. Postgres truncated the old names to one, so only
  the first index was made and the seq index was missing. Shorter names keep
  their index names.
- PII retention: set `Config::retention_pii` (or `FASTEN_RETENTION_PII`), e.g.
  `"30d"`. A background thread redacts expired rows whose code is in
  `pii_codes()` (`pii_in_detail` or retention class Short): `detail` becomes
  `null` and an `AUDIT_ROW_REDACTED` row is written first (§7). Rows are never
  deleted. `redact_expired()` runs it by hand. `AuditStore` gains
  `list_redaction_candidates` and `redact_rows`, which default to
  `Error::Unsupported`, and `count_skipped_legacy_form`, which defaults to 0.
  `Config` gains `retention_pii`, so `Config { .. }` literals without
  `..Default::default()` stop compiling.
- `PostgresStore` redacts unsealed rows (`hash = ''`) whatever their
  `canonical_form_id` (spec §7.1). A sealed form-`"1"` row is never redacted:
  its detail is inside the hash. Such rows past the cutoff are counted and
  logged as `pii_redaction_skipped_legacy_form` (warn).
- Stopping the purger (`init()` again, `reset_for_tests()`) waits at most 2 s.
  The purger stops after the row it is on. Dropping an `Engine` stops its
  purger too.
- **Breaking:** `Error` gains `Unsupported` and `InvalidRetention` and is now
  `#[non_exhaustive]`, so `match`es on `Error` need a wildcard arm. Later
  variants will not be breaking.

### Fixed: fasten-core stores keep the chain fields (#139, item 1)

- `SqliteStore` and `PostgresStore` store `prev_hash`, `hash`,
  `canonical_form_id`, `detail_salt` and `detail_commitment` and read them
  back. A sealed row passed to `fasten_store_insert` used to be stored without
  its hash, so every `fasten-core/bindings/*` package lost the chain.
  A row sent with `monotonic_seq: 0` gets a store-allocated seq and is stored
  unsealed: its chain fields are dropped, as Python and Go overwrite them on
  allocation, since a hash sealed over another seq could never verify.
- `Row` has these as typed optional fields instead of leaving them in
  `extra`. A row passed through the C interface or the drainer keeps an
  absent field absent. A row read back from a store carries `prev_hash` and
  `hash` (`""` when unsealed) and `canonical_form_id` (`"1"` by default), as
  Python's rows do; salt and commitment only on a form "2" row.
- Opening a store adds the five columns to a table an older fasten-core
  created. It checks the table first and only alters what is missing, so
  opening an up-to-date table takes no write lock (SQLite) and runs no
  `ALTER TABLE` (Postgres). Salt and commitment are written as `''` when absent, so a table the
  Go store created (NOT NULL there) accepts the row; both read back as absent.
- Every table now has the chain columns, so redaction always applies the
  spec §7.1 rule: unsealed and sealed form-"2" rows are redacted, sealed
  form-"1" rows are refused.

### Fixed: fasten-core stores assign monotonic_seq; PII redaction (#124)

- `SqliteStore` and `PostgresStore` now allocate `monotonic_seq` when a row
  arrives with `monotonic_seq: 0`: next seq for its `source_node_id`, in the
  insert transaction (`BEGIN IMMEDIATE` on SQLite, the shared
  `pg_advisory_xact_lock` on Postgres). Two handles on one store no longer
  write duplicate seqs (#92). Rows stay unsealed (spec §8.2). A non-zero seq
  is written as given, under the same lock on Postgres, so it cannot take
  the seq a concurrent seq-0 insert has just picked.
- **Breaking:** fresh tables get `UNIQUE (source_node_id, monotonic_seq)`.
  A row that reuses a node's seq there now fails with the new
  `Error::SeqClash`, and the drainer dead-letters a row with an explicit
  seq at once instead of retrying (a seq-0 row is retried, as it gets a
  fresh seq); before, the row was stored with the duplicate seq. A repeated
  `id` is still a no-op (`ON CONFLICT (id) DO NOTHING`).
- Opening a table created before this release adds a non-unique
  `idx_<table>_node_seq` index, so seq allocation does not scan the table.
  The first open builds it while holding the write lock (SQLite) or a
  `SHARE` lock on the table (Postgres); create it beforehand on a big,
  busy table. Opening a table that is already up to date runs no DDL and
  takes no write lock.
- PII retention by redaction (spec §7.1): `list_redaction_candidates` and
  `redact_rows` on the `Store` trait, exported as
  `fasten_store_list_redaction_candidates` / `fasten_store_redact_rows`.
  `detail` becomes JSON `null` (and `detail_salt`, when the table has one,
  `''`); rows are never deleted. On a table shared with a sealing SDK,
  sealed form-`"1"` rows are left alone and `list_redaction_candidates`
  reports how many it left out (`skipped`; the C export's `out_skipped`, may
  be NULL); sealed form-`"2"` rows are redacted. The SQLite store binds ids and codes
  in chunks of 500 inside one transaction, so long lists stay under SQLite's
  bound-variable limit.
- `PostgresStore` takes the `fasten.bootstrap.<table>` advisory lock (same key
  as Python) around its schema bootstrap, so stores opening a fresh database
  at once no longer fail on a duplicate `pg_type` key.
- Spec: §8.2 (allocation without sealing), §2 and §2.1 state `prev_hash`
  comes from the node's last sealed row, §2.1 makes the node-keyed
  `pg_advisory_xact_lock` the required Postgres lock, and §7.1 makes
  redacting unsealed rows the rule for every SDK.

### Changed: shared drainer stop, install and close (fasten-core C ABI)

- `fasten_drainer_install` on a handle that already has a drainer now
  flushes the old one (up to 5 s) before stopping it, and reports rows it
  could not write in an `audit_drain_install_incomplete` sys event.
- `fasten_drainer_close` and `fasten_store_close` wait for the drain thread,
  including a store callback in progress, and for an old drainer a
  concurrent install is still stopping. A slow stop emits
  `audit_drain_stop_slow` instead of returning early.
- `fasten_drainer_enqueue` returns the new `FASTEN_ERR_DRAINER_STOPPED` (10)
  when the drainer is stopping and the row was not queued.
- New `fasten_drainer_install_with_sys_log` sends sys events to a host
  callback instead of stderr.
- An insert callback can return `FASTEN_INSERT_REJECTED` (any negative code)
  for a row the store will never accept; it is dead-lettered at once
  instead of being retried for the whole retry budget.
- A row that fails its one attempt at stop is now reported with
  `audit_drain_lost_at_stop` (`error_type`, `row_id`) instead of
  `audit_drain_dead_letter`, and no longer counts in `dead_lettered_total`
  or the dead-letter ring. `audit_drain_install_incomplete` reports
  `unstored` (rows dead-lettered or lost at stop) in place of
  `dead_lettered`.
- The queue is no longer allocated up front, so a large `capacity` costs
  nothing until rows arrive.

### Changed: Python queue mode goes through the shared drainer

- In queue mode (the default), `emit()` now hands the row to the fasten-core
  drainer and returns it before it is stored: `monotonic_seq` is 0 and
  `hash` is empty, and the store seals the row when it lands. Use
  `audit_store_failure_strategy="raise"` to get the
  sealed row back.
- A failed insert is retried with backoff and dead-lettered after
  `queue_drain_max_attempts`, instead of being dropped after one try. A row
  the store rejects outright (DB-API `DataError` / `IntegrityError`) is
  dead-lettered at once.
- `emit()` blocks while the queue is full.
- A forked child (gunicorn `--preload`, Celery prefork) installs its own
  drainer. `fork()` waits up to 1 s for an in-flight store insert, so a
  child no longer stops storing after inheriting SQLite mid-insert, and an
  insert stuck on a database lock does not hold up `fork()`; the parent then
  emits `audit_drain_fork_during_insert`, stored from another thread so a
  stalled syslog store does not hold up `fork()` either. A failed reinstall
  in the child emits `audit_drain_reinstall_failed`.
- `fasten.close(timeout=5.0)` (and `Engine.close`) flushes for up to half
  of `timeout`, then stops the drainer and stores the rows it still holds.
  It returns within about `timeout`: no store call starts after that, one
  still running is left behind, and rows not stored are reported as
  `audit_drain_lost_at_stop`. It returns False only if a row was lost,
  including one an emit racing `close` failed to store inline, and every
  row counted lost is reported before it returns.
  Sys events past the deadline go to stderr and the ring but not the
  syslog store, which is then marked degraded. A row reported lost and
  stored later, by a left-behind call, retire or an inline emit, gets
  `audit_drain_recovered_at_stop`, unless the process exits first, so a
  row reported lost may still have been stored. The exit hook calls
  `close(5.0)`, so a hanging store no longer holds interpreter exit, and
  the process exits normally: exit status and other atexit hooks are
  unaffected. Emits after `close` are stored inline without an
  `audit_drain_abandoned` event.
- Re-`init` waits at most 10 s for the drainer it replaces (flushing it
  for up to 5 s, as before), and reports rows still held then as
  `audit_drain_lost_at_stop`, so a hanging store no longer blocks
  `fasten.init()`, and a store call stuck in the old store no longer holds
  up the new drainer's inserts. If the old drainer's flush timed out or a
  row it held was not stored, re-init emits `audit_drain_install_incomplete`
  (`flushed`, `unstored`). While it retires, `flush()` also waits for its
  rows, and `close()` waits for it within its own timeout and reports the
  rows it still holds then as lost. Rows the old drainer loses keep the engine's
  `audit_write_swallowed()` flag set when re-init builds a new store over
  the same database (the same SQLite file or Postgres DSN and table, as
  `FASTEN_AUDIT_DSN` does); only a different store clears it.
- The drainer's store calls run on a Python thread (`fasten-store`, one
  per drainer); fasten-core's drain thread waits for each. A store call
  left behind at exit can no longer abort the process during interpreter
  finalization (CPython before 3.14 on Linux).
- Drainer sys events are written to stderr before the syslog store, so a
  hung syslog store can't hold them back. The events fasten-core sends
  while a drainer stops (`audit_drain_stop_slow`, `audit_drain_abandoned`)
  go to stderr and the ring only, and the syslog store is marked degraded.
- A flush that fails in fasten-core is reported as
  `audit_drain_flush_failed` (and `flush()` returns False) instead of
  looking like a timeout.

### Changed: Go queue mode goes through the shared drainer

- In queue mode (the default), `Emit` now hands the row to the fasten-core
  drainer and returns it before it is stored: `MonotonicSeq` and `Hash`
  are zero, and the store seals the row when it lands. Use
  `AuditStoreFailureStrategy: "raise"` to get the sealed row back.
- A failed insert is retried with backoff and dead-lettered after
  `QueueDrainMaxAttempts`, instead of being dropped after one try. A row
  the store rejects outright (Postgres SQLSTATE class 22/23, a SQLite
  constraint) is dead-lettered at once.
- `Emit` blocks while the queue is full, and that wait does not observe
  `ctx`.
- New `fasten.Close(timeout)` flushes and stops the drainer; call it on
  shutdown instead of `Flush` so a row still being retried is stored or
  reported. It returns within about `timeout`, even when a store call
  ignores `ctx` (lib/pq waiting on a server that stopped answering);
  that call finishes in the background. It reports rows not stored by
  then as `audit_drain_lost_at_stop`, and returns false only if a row
  was lost. A second `Close` while one runs waits for it and returns the
  same result. Emits after `Close` are stored inline without an
  `audit_drain_abandoned` event.

### Fixed: C++ queue mode reads columns from the row, not from `detail` (#147)

- The drainer hands each row to the sink as JSON, and every column was found
  by a substring search over it. A `detail` key named like a column that is
  null or left out (`tenant_id` with no engine tenant, `shipped_at`) set that
  column on the stored row, and a `detail` key `pii_in_detail` could clear
  that flag. Columns are now read from the row's own members.
- `detail` is bounded by the same scan, so a value containing `}` no longer
  cuts it short (#138, point 1).

### Changed: reworded messages (all SDKs)

- Reader error bodies (Python and Go): `search requires sys persistence:
  configure a syslog store`, and the same shape for `requires api
  persistence` and `requires an audit store with a search method`. The
  em dash and the `(FR1)` suffix are gone.
- These errors read `x: y` where they read `x — y`: the catalog loaders,
  init, reader auth and table names; Go's unknown audit code at emit;
  Python's `requires an audit store` from `verify` and `redact`; the
  core's `sslmode` TLS error; and Java's not-implemented message. Others
  still use the dash, such as Go's `NewReader` tenant panic, the
  search-disabled and transport-not-initialised bodies, Python's
  durable-storage DSN error and Swift's `register` errors.
- Python `fasten.reader.router` and Go `NewReader` config errors drop
  their `P1-44` / `P1-45` references.
- JS: the `_clearRustRegistry` test hook is now `_clearCoreRegistry`.
- Spec: `drainer-conformance.md` now says a dip into the 50–80 % band
  re-arms neither threshold flag, which is what the drainer does; it said
  both.

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
