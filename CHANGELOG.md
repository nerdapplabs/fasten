# Changelog

All notable changes to fasten are documented here.
Format: [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning 2.0](https://semver.org/).

## [Unreleased]

### Changed: card numbers sent as numbers are redacted

- A detail value that is a number with no fractional part (an integer or a
  whole-number float such as `4111111111111111.0`) and that the card rule
  matches now becomes the string `"***CC***"`, as when it is sent as a
  string.

### Fixed: JS and Python DSN errors

- DSN errors name a scheme only when the DSN has one, that is when `//`
  follows it. A DSN such as `host:5432/db` or `user:password@host/db` gets
  `DSN form not recognised`; an unknown scheme such as `mysql://...` is
  still named.
- JS: a `FASTEN_API_DSN` or `FASTEN_SYSLOG_DSN` read as a file path that
  cannot be opened, such as `user@host/db`, fails with SQLite's error, as
  `FASTEN_AUDIT_DSN` does, instead of an error quoting the DSN.
- `fasten doctor` describes `FASTEN_AUDIT_DSN` as init opens it: a path
  such as `sub/my db=1.db` is a SQLite file, not a libpq keyword DSN.

### Changed: Python store DSNs (breaking for existing callers)

These DSNs opened a local SQLite file before and no longer do:

- `FASTEN_AUDIT_DSN` with a scheme other than `sqlite`, `postgres` or
  `postgresql`, such as `file:f.db` or `mysql://host/app`, which wrote to a
  file named after the URL path. It is refused, as `FASTEN_API_DSN` and
  `FASTEN_SYSLOG_DSN` refuse it, and `fasten doctor` reports it.
- `FASTEN_AUDIT_DSN` with `postgres` or `postgresql` in another case, such
  as `POSTGRES://...`. It opens Postgres, as the stream DSNs do, and
  `fasten doctor` describes it the same way.
- libpq's keyword form, such as `host=db dbname=app` or `tenant=blue.db`, in
  `FASTEN_AUDIT_DSN`, `FASTEN_API_DSN` and `FASTEN_SYSLOG_DSN`. It is
  refused, as JS, Rust and Go refuse it.

A DSN's scheme is read only at its start, as JS, Go and Rust read it:

- ` postgres://...` with a leading space or tab is a file path, not
  Postgres.
- On Python 3.10, `2026:a.db` opens that file instead of being refused.
- A bare path keeps a `;` or a tab: `a;b.db` opens `a;b.db`, not `a`.

### Added: Go stores from the environment

- `Init` opens the audit store from `FASTEN_AUDIT_DSN` when
  `Config.AuditStore` is nil, as Python, JS and Rust do: `postgres://` or
  `postgresql://`, `sqlite:///rel.db`, `sqlite:////abs.db` or a bare path,
  with `?table=` and `?wal=false`. `FASTEN_API_DSN` and `FASTEN_SYSLOG_DSN`
  take the same forms, now including Postgres. A Postgres DSN needs a
  `database/sql` driver registered as `postgres` (for example
  `import _ "github.com/lib/pq"`, or pgx's driver registered under that
  name); without one, `Init` says so. A store passed in `Config` still
  wins.
- `Init` checks every DSN, and everything else it can refuse, before
  opening any store. An unknown scheme, libpq's keyword form, a missing
  path or directory, or an invalid table name is an `Init` error naming the
  variable and no part of the DSN; a DSN error names a scheme only when
  `//` follows it. A store that cannot be opened is reported by the
  variable, scheme and error type; the stores that `Init` opened are closed
  again, and their files are left in place. A failed `Init` keeps the
  stores, retention and drainer it had.
- SQLite DSN paths, in `Init` and `OpenStreamStore`, are used as written:
  `%20` is not decoded, a lone `%` is accepted, and a `#fragment` is
  dropped, as in Python, JS and Rust.
- For existing `OpenStreamStore` callers: `?table=` and `?wal=false` on a
  bare path are now honoured (they used to be passed to the driver), and a
  DSN that starts like a scheme (`name:rest`) is refused, as in Python, JS
  and Rust. That includes a SQLite `file:` URI and a drive letter
  (`C:/x.db`); use `sqlite:///` or a bare path instead.
- `Init` again with the same DSN keeps its store; with another DSN, the old
  store is closed once the writes running on it have returned, and later
  rows go to the new store. A `SlogHandler` follows `Init` and `Close`: it
  writes to the stores of the latest `Init`, not those it was created with.
  `Init` can run while other goroutines emit and log.
- `Close` now also stops retention and closes the stores opened from the
  environment, within its timeout: a purge or write still running is left
  to finish, its stores are closed once it returns, and `Close` returns
  false. Emits do not wait for it, and a later `Close` waits for those
  stores up to its own timeout. Until the next `Init`, rows for those
  stores go to stdout or the in-memory rings only, and are not counted as
  store failures. Stores passed in `Config` are not closed and still
  receive rows.
- A set `FASTEN_*` variable named like a DSN that `Init` does not read (for
  example `FASTEN_AUDIT_DNS`) is reported once as `env_dsn_not_read`.

### Fixed: fasten tui

- The sys pane shows a row's `event` when the row has no `message`, as
  `fasten tail` does. Sys rows from every SDK carry `event`, so the column
  showed `—` before.

### Changed: JS (breaking for existing callers)

- `PostgresStore.query()` and `listUnshipped()` return rows with the wire's
  snake_case keys (`origin_id`, `monotonic_seq`, `source_node_id`,
  `tenant_id`, `pii_in_detail`, `shipped_at`, `prev_hash`, ...), the shape of
  `Row` and of what `insert()` returns, instead of camelCase. They also carry
  `wire_version`, `canonical_form_id`, `detail_salt` and
  `detail_commitment`, and `verifyChain` reads them.
- An integer in `detail` that a number cannot hold exactly reads back from
  `query()` as a `BigInt`. `JSON.stringify` throws on it without a replacer.
- `emit()` throws `ChainError` when `target` is not a string, or a row field
  is not a string or holds an unpaired surrogate, in both modes and before
  anything is written.
- A string `detail` given to `PostgresStore.insert()` must be JSON text of
  an object; other text is rejected with `AuditRowRejectedError`.
- `PostgresStore.insert()` and `insertSealed()` reject a row with its own
  `monotonic_seq` when another row holds that seq on its node.
- `AuditRepository.purge` is typed `purge({ before, respectUnshipped })`, as
  `PostgresStore` implements it.
- A failed write of the first stdout line is logged as
  `audit_stdout_failed`, not thrown.
- The drainer's `last_error`, `audit_drain_failed`, `audit_drain_degraded`
  and `audit_drain_dead_letter` record the error type only, as the other
  SDKs do. `audit_sync_fallback_failed` reports it as `error_type` (was
  `error`).
- `apiStore` is now used: it is the api stream's store (`StreamStore`). It
  was typed as an audit store and ignored; remove an audit store passed
  there.
- `init()` now opens the audit store from `FASTEN_AUDIT_DSN` when no
  `auditStore` is passed, so an app with that variable set starts writing
  to that store. An audit or stream DSN with an unknown scheme, or in
  libpq's keyword form, makes `init()` throw, naming the scheme only.
- `close()` waits for api and sys store writes and resolves false when they
  do not finish in its timeout, then closes the stores it opened from
  `FASTEN_*_DSN`.
- `init()` now reads `FASTEN_PERSIST_STREAMS`, `FASTEN_RETENTION_API` and
  `FASTEN_RETENTION_SYSLOG` when the matching option is not passed, and
  throws on a value it cannot use: a stream name other than `api` or
  `sys`, a stream named without a store or a store attached but not named,
  or a retention that is not a positive whole number of `s`, `m`, `h` or
  `d` (checked even when that stream has no store). A retention for a
  store without `purge()` throws too. An app with these variables set can
  now fail to start.

### Added: JS SQLite store, replication, reader and stored logs

- `SqliteStore` (`fasten-sdk/store/sqlite`), on Node's built-in
  `node:sqlite` with no new dependency, seals rows into the per-node hash
  chain as `PostgresStore` does, and shares one file with the Python, Go and
  Rust SQLite stores, adding the columns their tables lack. Its calls are
  synchronous and block the event loop while they run. `node:sqlite` is a
  release candidate from Node 24.15.0 and experimental before it.
- Replication on both stores: `ingestReplicated(rows, { localNodeId })`
  verifies a replicated batch, checks it against the stored rows, stores the
  verified prefix as it was sealed, and returns `{ inserted,
  rejectedFromSeq, reason }` (Python's and Go's `IngestResult`).
  `insertReplicated(row)` stores one sealed row.
  `listUnshipped(limit, { serviceId, sourceNodeId, exact })` can list only
  the rows an identity originated, with detail numbers exact for shipping.
  The engine adds `listUnshipped()`, `markShipped(ids)` and
  `ingestReplicated(rows)`, which throw `TypeError` without a store that
  has the method. A store's `listUnshipped` throws `TypeError` when only
  one of `serviceId` and `sourceNodeId` is given.
- HTTP reader (`fasten-sdk/reader`): `reader({ auth, ... })` serves
  `/audit`, `/audit/doctor`, `/correlate`, `/search`, `/sys`, `/api` and
  `/topology` with the Python and Go readers' parameters, responses and
  limits, over either store. `auth` is required (`{ bearer }`,
  `requireBearer()`, `{ verify }` or `"none"`), and `tenantScope` /
  `enforceTenantIsolation` scope every route.
- Stored sys and api logs: `PostgresStreamStore` and `SqliteStreamStore` on
  the stream tables the other SDKs use, `init({ apiStore, syslogStore,
  persistStreams, searchEnabled, retentionApi, retentionSyslog })`,
  `apiLogger()`, `writeApi`, `pushApi`, `pushSyslog`, `mintSentinel` and
  `isSentinel`. `SqliteStreamStore` methods return promises, and it creates
  its table on `init()` or first use.
- Both audit stores gain `search`, `sources`, `chainTail` and
  `query({ afterSeq })`. On SQLite, search folds ASCII letters only, as the
  Python and Go SQLite stores do.
- `init()` opens the audit, api and sys stores from `FASTEN_AUDIT_DSN`,
  `FASTEN_API_DSN` and `FASTEN_SYSLOG_DSN` when none is passed, with
  Python's DSN forms (`postgres://`, `postgresql://`, `sqlite:///rel.db`,
  `sqlite:////abs.db`, a bare path, `?table=`, `?wal=false`).
- `PostgresStore` and `PostgresStreamStore` recover when the database drops
  their connections: a dead idle connection no longer ends the process, and
  a read or transaction that meets one runs again on a new connection. A
  stream INSERT is not run again, so a lost connection cannot store a
  stream row twice; it counts as a failed write.
- `PostgresStore` takes a pg `Pool` as well as a DSN, so it can share one
  with `PostgresStreamStore`.
- `apiLogger({ path })` can rewrite the stored path. A request aborted
  before its response finished is recorded with status 499 and
  `aborted: true`. A request id that looks like a sentinel is not taken
  from the client.
- The reader matches the request path as sent, applies the tenant scope to
  every row it returns, and a scoped doctor reports only the caller's data.
  It resolves the tenant scope before reading query parameters, so a
  caller without a tenant gets 401, not 422.
  The doctor's chain block reports `sealed_rows` and gives `verified: null`
  when no sealed row was checked.
- `purge({ before })` on both audit stores takes a `Date` or a timestamp in
  any offset.
- `SqliteStreamStore` takes `busyTimeoutMs` (default 5000).
- A set `FASTEN_*` variable named like a DSN variable but not read is
  reported once at init (`env_dsn_not_read`).

### Added: the JS SDK seals and verifies rows

- The JS `PostgresStore` seals each row into the node's hash chain when it
  stores it, as Python, Go and Rust do. Writers in any of them share one
  chain per node on one table, and each verifies the others' rows.
- When the store returns a row with a hash, the engine writes it to stdout
  a second time, sealed; in raise mode `emit()` returns it. A retry of a
  stored id returns the stored row. A store whose `seals()` is true but
  that returns no hashed row is logged once as `audit_chain_row_unsealed`.
  `audit_chain_unavailable` is logged with no store, or a store whose
  `seals()` does not return true. A failed stdout write, or an `error`
  event on stdout, is logged as `audit_stdout_failed` with `error_code`.
- A row a store cannot seal as given is rejected with
  `AuditRowRejectedError` and dead-lettered at once; `AuditSealError`
  (retried) is left for other seal failures. When a COMMIT fails the store
  reads the row back once; `AuditOutcomeUnknownError` says it could not.
- `verifyChain(rows, {checkpoints, partial})` reports `sealedRows`,
  `checkpointsChecked` and the node of the first break. `seal`,
  `detailCommitment`, `canonicalJSON` and `parseJson` give the same bytes
  as the other SDKs; `parseJson` keeps each number as written.
- Checkpoints: `publishCheckpoints`, `FileCheckpointSink`,
  `HttpCheckpointSink`, `loadCheckpoints` and `checkpointsSince`, with the
  other SDKs' file format. `loadCheckpoints` throws `PartialLastLineError`,
  carrying the checkpoints read so far, when the last line was cut short.
- `PostgresStore` gains `chainRows`, `allChainRows`, `chainTips` and
  `insertSealed`, adds the columns a Python or Go table lacks, and has
  TypeScript types (`fasten-sdk/store/postgres`).
- A `BigInt` in `detail` keeps its digits.
- `spec/js-sealed-form2.json` and `spec/js-sealed-stdout.jsonl`, written by
  `scripts/gen_js_vectors.mjs` from the JS engine and store, hold sealed
  rows and the stdout lines for them; the Python and Go suites verify both.

### Added: Rust replication, recovery, stored logs, the HTTP reader and stores from the environment

- Replication in fasten-core and the Rust SDK: `ingest_replicated` verifies
  a batch of rows sealed on other nodes, checks it against the stored rows,
  stores the verified prefix exactly as sealed in one transaction, and
  reports the first break in `IngestResult { inserted, rejected_from_seq,
  reason }`, as the Python, Go and JS stores do; a custom store builds one
  with `IngestResult::stored` or `IngestResult::cut`, so the break's seq and
  reason are always set together. `list_unshipped_sealed` lists the rows an
  identity originated, `ReplicatedRow::to_json` and `from_json` carry them,
  and `mark_shipped` marks them. The engine has `fasten::list_unshipped`,
  `mark_shipped` and `ingest_replicated`, scoped to its service and node
  id; a row from its own node is a break. The SDK re-exports
  `ReplicatedRow`, `IngestResult` and `BatchError`.
- `insert_replicated`, the replicated insert of spec §5, on the stores.
- `purge(before, respect_unshipped)` on the Rust SDK stores. A failure is
  `Error::AuditStorePurge`. A purge is never run a second time on its own:
  when the connection is lost while it runs, the error says how many rows
  it deleted is unknown. The engine never purges audit rows; it purges only
  the sys and api stores, by `retention_api` and `retention_syslog`.
- `PostgresStore` (Rust SDK) connects again after losing its connection
  (SQLSTATE class 08 or 57 other than 57014, a socket error or a closed
  client) and runs a read or a whole transaction once more. A COMMIT cut
  short is never run again; an insert reads its row back once. A purge is
  not run again.
  `PostgresStreamStore` follows the same rule for reads and purges, and
  never runs an INSERT again.
- `init` opens the audit store from `FASTEN_AUDIT_DSN`, and the sys and api
  stores from `FASTEN_SYSLOG_DSN` and `FASTEN_API_DSN`, when the config has
  none, in the Python SDK's DSN forms. `init` again with the same DSN keeps
  the store it opened; with another one, the old store is closed.
  `fasten::close` releases the stores opened from DSNs, as the JS SDK's
  close does. `fasten::parse_dsn`, `audit_store_from_dsn` and
  `stream_store_from_dsn` are public. A set `FASTEN_*` variable named like
  a DSN that init does not read is reported once as `env_dsn_not_read`.
- DSN errors name a scheme only when the DSN has one (`//` follows it).
- A DSN that repeats `table` or `wal` uses the first value that is not
  empty, as Python's `parse_qs` does.
- Stored sys and api logs: `SqliteStreamStore` (`store-sqlite`) and
  `PostgresStreamStore` (`store-postgres`) on the table the Python, Go and
  JS stream stores use; `Config::api_store`, `syslog_store`,
  `persist_streams`, `retention_api`, `retention_syslog`,
  `search_enabled`; `FASTEN_PERSIST_STREAMS`, `FASTEN_RETENTION_API`,
  `FASTEN_RETENTION_SYSLOG`, `FASTEN_SEARCH_ENABLED`. Writes run in order on
  one thread per stream, at most 10,000 waiting; a failed write keeps the
  stdout line, marks the stream degraded and is reported by error type
  only.
- `fasten::log::api` for api rows, and `fasten::close`; `fasten::flush` also
  waits for stream writes. After `close`, log lines and api rows go to
  stdout only until the next `init`.
- A `limit` of 0 means no limit in every read: `StreamStore::query` and
  `search`, `AuditQuery::limit`, `AuditSearch::limit` and `list_unshipped`.
- HTTP reader, `fasten::reader`: `/audit`, `/audit/doctor`, `/correlate`,
  `/search`, `/sys`, `/api`, `/topology` from a plain request value, with a
  required auth choice (`Auth::bearer`, `require_bearer`, `Auth::verify`,
  `Auth::None`) and an optional tenant scope applied to every row. Where
  the Python and JS readers differ it follows JS; `rust/README.md` lists
  the differences. A `Response` carries `Content-Type` and leaves
  `Content-Length` to the server, and a `Request`'s `Debug` leaves out
  credential headers. No new dependency; `examples/reader.rs` runs it
  behind tiny_http.
- `AuditStore::query`, `count`, `search`, `sources`, `chain_tail` and
  `kind`, implemented by `SqliteStore` and `PostgresStore`.
- fasten-core: `store::stream`, `store::stream_sqlite::SqliteStreamStore`,
  `AuditQuery`, `AuditSearch`, `Source`, and the matching `SqliteStore` read
  methods. `ReplicatedRow`, `IngestResult`, `BatchError`, `Source`,
  `reader::Response`, `reader::Auth` and the `Dsn` variants are
  `#[non_exhaustive]`; `ReplicatedRow::new`, `Source::new` and
  `Response::new` build them. `AuditQuery`, `AuditSearch`,
  `StreamFilter` and `reader::Request` stay open to struct literals with
  `..Default::default()`.

### Changed: Rust and fasten-core

- `init` now opens a store when `FASTEN_AUDIT_DSN`, `FASTEN_API_DSN` or
  `FASTEN_SYSLOG_DSN` is set and the config has no store for it. An unknown
  scheme, a libpq keyword DSN, or a scheme whose store feature is not built
  makes `init` fail with `Error::InvalidConfig`, naming the variable and the
  scheme only, and leaves the stores of the last `init` as they were. So
  does a store from one of them that cannot be opened:
  `<variable>: cannot open the <scheme> store (<error type>)`, without the
  driver's text.
- A sys line without a request id now carries a sentinel id (`boot-…`, then
  `orphan-…`) instead of an empty string, as in Python and Go.
- After `init`, SDK sys events (such as `audit_chain_unavailable`) are also
  kept in the sys stream and its store.
- `insert_sealed` refuses a row whose `timestamp` or `shipped_at` is not an
  RFC 3339 timestamp the Python and Go stores can read, and stores both in
  the canonical form.
- fasten-core `mark_shipped` writes `shipped_at` with six fractional digits.
- fasten-core's `PostgresStore` treats SQLSTATE class 08 and 57 (other than
  57014) and socket errors as a lost connection, not only a closed client.
- fasten-core's drainer, which Python and Go use, records the error type in
  `last_error`, `audit_drain_failed`, `audit_drain_degraded` and
  `audit_drain_dead_letter`, not the error's text, as
  spec/drainer-conformance.md asks; a store error or row rejection that
  fasten-core builds itself is recorded as `Store` or `RowRejected`, and one
  that carries a type name, such as the Rust SDK's `AuditStoreRejected`,
  under that name. An insert callback's failure still reads
  `insert callback returned non-zero rc=<n>`.
- fasten-core's `PostgresStore::purge` is not run a second time after a
  lost connection; it returns a `Store` error saying the outcome is
  unknown.

### Added: the Rust SDK and fasten-core seal and verify rows

- The Rust SDK's `PostgresStore`, and a new `SqliteStore` behind the
  `store-sqlite` feature, seal each row into the node's hash chain when
  they store it, as Python and Go do. Rust, Python and Go writers on one
  table share one chain per node, and each verifies the others' rows.
- `fasten::verify_chain` checks a chain. Its result has `sealed_rows`, so
  a result with nothing sealed is visible, and the node and seq of the
  first break. The stores' `chain_rows` and `all_chain_rows` read rows
  with their detail exactly as stored; both load every row into memory.
- Chain checkpoints: `publish_checkpoints`, `FileCheckpointSink`,
  `load_checkpoints`, `checkpoints_since` and
  `verify_chain_with_checkpoints` (`CheckpointOptions::whole()` or
  `partial()`), with Python's and Go's file format and failure reasons.
  `load_checkpoints` returns `CheckpointFileError::PartialLastLine`, with
  the checkpoints read so far, when the last line was cut short. There is
  no HTTP sink yet; implement `CheckpointSink` for one.
- A stored row is written to stdout twice, unsealed and then sealed, and a
  synchronous `submit()` returns the sealed row. If the sealed line can't
  be written, `audit_stdout_failed` is logged and the row is still
  returned.
- A row with `monotonic_seq` 0 must have `origin_id` equal to `id`. A
  different row under an id that is already stored is rejected.
- `insert_sealed` stores a row sealed elsewhere with its detail text
  unchanged, so it keeps its hash. `seal_row` and `GENESIS` let an adopter
  store seal rows; such a store overrides both `AuditStore::seals` and
  `AuditStore::allocate_and_insert_originated`.
- New `Error` variants: `Seal`, `AuditStoreRead`, `Chain`,
  `CheckpointFile` and `Custom` (for a sink or store implementer's own
  errors). Read failures are no longer reported as insert failures.
- `PostgresStore::redact_rows` clears the salt to an empty string, where
  it wrote NULL before, as Python and Go do.
- Breaking: the Rust `Row` has three new public fields,
  `canonical_form_id`, `detail_salt` and `detail_commitment`. `Row` now
  implements `Default`, so a struct literal can end in
  `..Default::default()`.
- fasten-core: the `chain` and `checkpoint` modules give the same hashes
  as Python and Go, including detail holding lone surrogates, `NaN` or
  `Infinity`. `SqliteStore` and `PostgresStore` seal a row inserted with
  `monotonic_seq` 0, which also applies to `fasten_store_insert`; a row
  with its own sequence number is stored as given and stays unsealed
  unless it already carries a hash. New: `Store::insert_sealed`,
  `Store::chain_rows`, `Store::chain_tips` (returning `ChainTip`),
  `ChainRow::from_row` and `Error::Seal`.
- `spec/rust-sealed-form2.json` holds rows sealed by the Rust SDK; the
  Python, Go and Rust test suites verify it.
- A float exactly halfway between two shortest decimal forms, such as
  `1000000000000000.25`, is written with the even last digit, as CPython
  and Go write it.
- The core SQLite and Postgres stores open a table the Python SDK created,
  adding the `wire_version` and `pii_in_detail` columns it lacks.
- A row with its own seq at a node and seq another row already holds is
  rejected, also on tables without a unique `(source_node_id,
  monotonic_seq)` index such as those Python creates.

### Fixed: `spec/row-schema.json` accepts the rows five SDKs write

- The schema now lists `canonical_form_id`, `detail_salt`,
  `detail_commitment` and `pii_in_detail`, allows a `null` `detail` (a
  redacted row), and takes any non-empty `request_id`. Before, it rejected
  every sealed row and any row whose `request_id` was not 12 hex
  characters.
- Rows from the Python, Go, JS, Rust and C++ SDKs now pass. Swift rows
  still fail: Swift writes ids of `evt-` plus 16 hex characters where the
  schema has 20.
- The `timestamp` description says microseconds, as those five SDKs write.

### Fixed: JS keeps a detail key named `__proto__`

- A `__proto__` key in a detail parsed from JSON is kept and redacted like
  any other key. Before, redaction dropped it and its value.

### Fixed: Go reads rows with a NULL salt or commitment

- The Go SQLite and Postgres stores read a row whose `detail_salt` or
  `detail_commitment` is NULL as empty. Before, one such row made the whole
  query fail. Tables created by another SDK allow NULL there, and the Rust
  SDK writes it when it redacts a row.
- `NewPostgresStore` opens a table the Python SDK created. Before, it
  failed with `column "pii_in_detail" does not exist`, because it built an
  index on that column before adding the column.

### Added: Python wheels on the GitHub release

- Each `vX.Y.Z` GitHub release carries the Python wheels, for Linux (glibc
  2.34 or later, x86-64 and arm64) and macOS 11 or later. They are listed in
  `SHA256SUMS` and attested like the other release files. A beta is not on
  PyPI, so this is where its wheels are: download one and
  `pip install` the file. A wheel bundles `libfasten_core`.

### Fixed: Go keeps detail numbers exact

- A row read from the Go SQLite or Postgres store keeps each detail number
  as it was written. Before, `75.0` came back as `75`, so `VerifyChain`
  reported "detail does not match its commitment" on an unaltered row that
  Python had sealed, and an integer above 2^53 came back rounded.
- `Emit` stores and seals an integer above 2^53 with every digit. Before,
  `1234567890123456789` was sealed as `1234567890123456800`.
- Numbers in `Row.Detail` are now `json.Number` on rows returned by `Emit`
  and by the stores, as they already were on rows decoded from JSON. Code
  that asserts `float64` on a detail value needs `.Float64()` or `.Int64()`.

### Fixed: Python `Redactor` reports a missing `libfasten_core`

- `Redactor.redact()` raises `OSError` when `libfasten_core` can't be
  loaded. Before, it returned `{"_redact_failed": true}`, the marker for a
  value that can't be redacted, so a missing library looked like a
  redaction. `fasten.init()` already failed in this case; this covers a
  `Redactor` used on its own.
- Log calls still don't raise: the structlog processor and `fasten.log`
  before `init()` replace the values with `<unredactable>` as before, and
  now write one warning to stderr saying the library didn't load.

### Added: Rust request_id follows tokio tasks

- With the `async` feature, `fasten::scope_request_id(rid, fut)` keeps the
  request_id across every `.await`, and `fasten::spawn(fut)` carries the
  current id into a new task. Before, the id was thread-local only and was
  lost when a task moved threads.
- Inside a task, an id set by `with_request_id` wins over the task's id. An
  id the caller left on the thread does not.
- `with_request_id` restores the previous id when its closure panics. Before,
  the id stayed set on the thread.

### Changed: Rust SDK Postgres store supports TLS

- `PostgresStore` connects through native-tls, with `sslmode` working as in
  libpq: the default, `prefer`, uses TLS when the server offers it without
  checking the certificate; `sslmode=require` and `sslmode=verify-full`
  use TLS and check the certificate and host name; `sslmode=verify-ca`
  checks the certificate but not the host name; `sslmode=disable` uses
  plaintext.
- The `store-postgres` feature needs `pkg-config` and the OpenSSL headers
  on Linux.

### Changed: fasten-core Postgres store under `sslmode=prefer`

- With `sslmode` unset or `prefer`, the fasten-core store
  (`fasten_store_open`) now connects to a server whose certificate it can't
  verify, as libpq does, instead of refusing it. Use `sslmode=verify-full`
  (or `require`) to check the certificate and host name; `verify-full` is
  the value that is strict in every SDK.
- `sslmode=verify-ca` and `sslmode=verify-full` are accepted, as in libpq.
- A DSN with only `hostaddr` uses that address as the TLS host name, as
  libpq does, instead of failing the TLS handshake.

### Changed: store DSN errors

- Python, Go and C++ errors for an unsupported DSN scheme, a DSN with no
  path, or a Postgres connection string that can't be parsed name no part
  of the DSN. A Go sqlite DSN that can't be parsed as a URL gets a fixed
  message.
- The C++ fallback that calls the audit sink directly logs the first line
  of a store error.

### Fixed: Python verifies Go-sealed rows with small floats

- Go hashed `detail` numbers as Go's encoder writes them (`0.00005`, `1e-7`,
  `-0`), while Python, reading the stored row, hashes them as CPython renders
  them (`5e-05`, `1e-07`, `0`). Python then reported an untampered Go row as
  a commitment mismatch. Go now hashes every number as CPython renders it
  (spec `chain-replication.md` §1.3), so rows it seals from this release on
  verify in Python. Rows an older Go release sealed with such numbers still
  verify in Go, but not in Python.
- New cross-SDK vectors: `spec/go-sealed-numbers.json` (Go seals, Python
  verifies) and a `form2_numbers` case in `spec/python-sealed-forms.json`
  (Python seals, Go verifies).

### Fixed: `fasten tail`, `fasten-tui` and `fasten dump`

- `fasten tail` and the TUI send the reader token as `Authorization: Bearer`,
  which `fasten.reader.require_bearer` checks. They read it from
  `FASTEN_READER_TOKEN` or `--token`; `fasten tail` used `X-Fasten-Key`
  from `FASTEN_READER_KEY` / `--key`, and every request got a 401.
- A 401 says to set the token, instead of "reader unreachable" (tail) or an
  empty "(no rows)" table (TUI, which now shows fetch errors in its footer).
- The TUI draws its frame again: the key hints in its footer were read as
  markup and every frame failed to render. Its header and footer show their
  text instead of only a top border.
- `fasten dump --catalog PATH` loads a codes YAML file first. With no codes
  registered it exits 1 instead of printing nothing. A catalog that can't be
  read, isn't valid YAML or isn't UTF-8 is reported on one line.

### Fixed: C++ build and README

- Configuring with `-DSIMPLE_WEB_SERVER_DIR` no longer fails: the
  `reader_simplehttp` example target pointed at a file that doesn't exist,
  and is removed. Serve the reader with `fasten_reader_simplehttp.hpp`.
- `cmake_minimum_required` is 3.18, which `find_library(... REQUIRED)` needs.
- The README names the reader API (`fasten::reader::handle_*`), and
  `fasten_store_sqlite.hpp` names the right CMake target, `SQLite::SQLite3`.

### Fixed: Rust quickstart, severity on stdout, empty tenant

- The README quickstart compiles: `submit()?` now converts into
  `fasten::Error`.
- Audit rows on stdout carry `"severity": "info"`, lowercase like the store
  and `spec/row-schema.json`, not `"Info"`. Reading accepts either case.
- An empty `FASTEN_TENANT_ID` is treated as unset (null), as in Python.
  JS does the same.
- Removed the `store-sqlite` and `shim-tracing` features: they added
  dependencies (`sqlx`, `tracing`) but no code used them.

### Added: C++ `fasten::shutdown()` and `ShutdownGuard`

- `fasten::shutdown()` writes queued audit rows, stops the drainer, drops
  the audit sink and waits for sink calls still running on other threads.
  `fasten::ShutdownGuard` calls it at scope exit. The engine is a static,
  destroyed after `main()`'s locals, so a sink that writes to a store local
  to `main()` needs one of them before the store goes out of scope. Two
  `shutdown()` calls at once both wait for the drainer to stop.

### Fixed: closing a fasten-core store handle while it is in use

- `fasten_store_close` waits for calls running on other threads before it
  frees the handle. The caller still calls it once and starts no call once
  it has begun; a later call usually gets `FASTEN_ERR_NULL_ARG`.
- `fasten_store_from_callback` returns NULL, with an error, for a NULL
  callback.
- A string argument that isn't UTF-8 returns `FASTEN_ERR_NULL_ARG`; an
  invalid optional query filter used to be read as no filter.
- A redaction replacement that isn't UTF-8 is treated as unset (`***`) in
  fasten-core, so C++ and Go behave like Rust instead of failing every
  redaction.

### Fixed: C++ stores no longer drop rows while reporting success

- Row ids come from a generator seeded with 256 bits instead of one 32-bit
  `random_device` value, so two processes no longer draw the same ids. It
  is reseeded in a forked child, so the workers of a prefork server don't
  share ids either.
- The SQLite and PostgreSQL stores insert with `OR IGNORE` /
  `ON CONFLICT (id) DO NOTHING`. A different row whose id is already stored
  was dropped while the insert succeeded; it now throws
  `fasten::InsertRejected`. The same row inserted again still succeeds. On
  SQLite, a row another unique index refuses (such as a taken node seq) is
  rejected too, with a message saying so.
- Text with a NUL byte was stored cut at the NUL. The SQLite store now
  keeps it whole, as the Python, Go and fasten-core stores do; the
  PostgreSQL store, which can't store a NUL in text, throws
  `fasten::InsertRejected`.
- The PostgreSQL store throws `fasten::InsertRejected` for a row the server
  refuses (SQLSTATE class 22, 23 or 54), as the other SDKs dead-letter it.
- A SQLite error while checking a stored row (such as `SQLITE_BUSY`) is
  retried instead of rejecting the row.
- The drainer dead-letters a rejected row at once instead of retrying it.
- The SQLite store's next seq no longer falls back to 1 when its query
  fails; the insert fails instead.

### Fixed: fasten-core purge and mark_shipped

- `purge` reads the cutoff as an RFC 3339 timestamp (any offset) or a date
  (midnight UTC) and compares it in the stored UTC form. It was compared as
  given, as text: `"tomorrow"` sorted after every row and deleted the whole
  table, and an offset like `+05:30` or a lowercase `t` deleted rows up to a
  day newer than the cutoff. Any other cutoff, including a timestamp with
  no timezone, is now an error (`FASTEN_ERR_NULL_ARG` over the C ABI).
  The redaction cutoff is read the same way.
- `mark_shipped` takes any number of ids. It failed above 32,766 ids on
  SQLite and 65,535 on PostgreSQL.

### Fixed: C++ sys lines keep the SDK's own keys

- A log field named `shape`, `level`, `event`, `service_id` or `timestamp`
  is left out of the sys line and the sys ring, which hold the SDK's
  values. Before, the line could carry the key twice.
- A `request_id` field is the line's request_id, as in the other SDKs, and
  is written once.
- The engine's `tenant_id` wins over a `tenant_id` field; with no engine
  tenant, the field's tenant is used, as in Go and Python.
- Sys ring rows carry `service_id` and `timestamp`, as the line does.

### Changed: a row the database refuses is dead-lettered at once

- In queue mode, a store error that means the row itself can never be
  stored is no longer retried: Postgres SQLSTATE classes 22 (data
  exception), 23 (integrity violation) and 54 (program limit, such as a
  value too long for an index), and SQLite constraint and datatype-mismatch
  errors. The row is dead-lettered after one attempt, with the usual
  dead-letter event, and the rows behind it are stored. This applies to the
  fasten-core stores and to the Python, Go, JS and Rust SDKs; other errors,
  including class 42 (a revoked grant, a renamed table), are retried as
  before. The C++ PostgreSQL store rejects the same classes (see "C++
  stores no longer drop rows" above); Swift still retries a refused row.
- Rust: a custom `AuditStore` can return the new
  `Error::AuditStoreRejected` to say the same.
- Python: the Postgres stores reconnect only when the connection was lost,
  not on every `OperationalError`.
- Python and Go: `RequestIDMiddleware` / `RequestID` use a client's
  `X-Request-ID` only when it is 1 to 128 characters of letters, digits,
  `.`, `_` and `-`; otherwise the request gets a new id. The Python MQTT
  shim applies the same rule to `_req`.

### Changed: the Go and C++ readers need an auth choice

- Go: `NewReader` takes `WithAuth(middleware)`, which puts every reader
  route behind the middleware (for example `WithAuth(RequireBearer(""))`),
  or `WithoutAuth()` when the routes are authenticated outside the reader.
  With neither it panics. Code that calls `NewReader()` needs one of the
  two options.
- C++: `simplehttp::mount()` and `simplehttp::start()` no longer default
  the prefix and the auth function, and an empty auth function throws
  `std::invalid_argument`. `simplehttp::no_auth()` serves the routes
  without one.
- Python already requires `dependencies=` on the reader router.
- The Python FastAPI example has no default reader token: set
  `DEMO_READER_TOKEN`, or the reader answers 401.

### Docs: security scope and reader authentication

- `docs/security.md` and the README say which SDKs seal audit rows (Python
  and Go, with a bundled audit store), what verification detects, and what
  needs external checkpoints. Replication ingest is listed as a trust
  boundary, here and in `spec/chain-replication.md` §4.
- Reader authentication is documented for Go (`RequireBearer`) and C++ (the
  `simplehttp::start` auth function), with the routes each SDK serves.
- `SECURITY.md` says which dependency scans run in CI and which are run by
  hand.

### Changed: `pii_in_detail` codes behave the same in every SDK

- Swift: `emit` on a code with `piiInDetail` stores
  `{"_redacted": "***", "_pii_in_detail": true}` plus the keys in the new
  `Meta.detailPassthroughKeys`, as the other SDKs do.
- Go and JS: a code loaded from YAML with `pii_in_detail: true` is handled
  like one from `Register` / `register()`.
- YAML codes in every SDK that loads them (Python, Go, JS, Rust, C++) accept
  `detail_passthrough_keys`, a list of strings, and a `pii_in_detail` code
  is always short retention. Null, an empty value or a non-string item is a
  load error in all five.
- A passthrough key named `_redacted` or `_pii_in_detail` no longer replaces
  the marker.
- Swift: a `Meta` with `piiInDetail` is short retention, and a nested
  dictionary or array in `detail` is written as JSON instead of `null`.
- JS: `metaOf()` returns the same camelCase fields for a YAML code as for a
  registered one (`retentionClass`, `piiInDetail`, `highVolume`,
  `declaredUnused`, `detailPassthroughKeys`). Code that read
  `retention_class` from a YAML code's meta needs `retentionClass`.

### Changed: redaction covers more keys and value shapes

Every SDK now masks more by default, so values that were stored before may
be replaced now.

- Key names: `access-key` / `accessKey`, `session-id` / `sessionId`,
  `passphrase`, a key ending in `_pwd` or `-pwd`, and a key ending in `dsn`.
  A bare `key`, `auth` or `pwd` is not matched; add those with
  `extra_redact_keys`.
- Value shapes: encrypted PEM private keys, `github_pat_` tokens, Slack
  tokens, `scheme://user:password@` in a URL (`***URL_CREDENTIALS***`), and
  `Bearer` / `Basic` Authorization values (`***AUTH_HEADER***`).
- Card numbers are found anywhere in a string, unbroken or in a card layout
  (4-4-4-4 with an optional short tail, 4-6-5, 4-6-4) split by any
  whitespace or dashes. A number must start like a card (for example 3,
  4, 5 or 6, 2221-2720, 8600 or 9860), so a list of years or a dashed id
  is kept. A layout is tried only at the start or end of a run of digit
  groups, so a list of 4-digit values such as ports is kept.
- OpenAI keys match only when `sk-` is not part of a longer word, so an id
  such as `task-<uuid>` is kept.
- JS and Swift: a `detail` or log line over `FASTEN_MAX_DETAIL_BYTES`
  (default 64 KiB) is replaced by a truncation marker, as in Python and Go.

### Added: Python wheels with libfasten_core inside

- When fasten is published to PyPI (from the 1.0 release), PyPI gets one
  wheel per platform, each with `libfasten_core` in the package: Linux
  x86_64 and aarch64 (`manylinux_2_34`, glibc 2.34 or later, OpenSSL
  bundled by auditwheel) and macOS arm64 and x86_64 (11.0 or later).
  `pip install fasten-sdk` then needs no Rust build and no
  `FASTEN_CORE_LIB`. Other platforms get no wheel, so pip reports no
  matching distribution.

### Fixed: the Apache-2.0 licence ships with every package

- `LICENSE` now holds the full Apache-2.0 text; the copyright line moved to
  `NOTICE`. GitHub recognised the old file as no licence.
- The npm package, the wheel, both crates, the Go module and the GitHub
  release files include `LICENSE` and `NOTICE`.
- The npm package ships `src/` only, without `test/` and `examples/`.
- `fasten-core` has a README for its crates.io page.

### Fixed: Python `init()` fails when libfasten_core can't be loaded

- `fasten.init()` started without the core library when no drainer was
  needed (stdout-only, or a store with `audit_store_failure_strategy="raise"`),
  and every `fasten.log.*` line was then replaced by
  `{"_redact_failed": true, "_summary": "<unredactable>"}`, with no error.
  It now raises `OSError` saying how to install or build the library.
- A library that exists but can't be loaded (wrong platform, bad file, an
  older build missing a function) raises `OSError` naming its path.

### Changed: PyPI page shows the Python README

- `python/pyproject.toml` sets `readme = "README.md"`, so the PyPI page has
  a description. `twine check` no longer warns about it.
- `python/README.md` links point at github.com, since relative links lead
  nowhere on PyPI.

### Docs: C++ install steps

- `cpp/README.md` Install covers the release files (`fasten-cpp-vX.Y.Z.tar.gz`
  and the Linux x86_64 `fasten-core` library), a build from a clone, and a
  CMake project, with the compile and link flags each header needs.

### Changed: PyPI gets wheels only, no sdist

- An sdist would hold only the Python files: it installed, then the first
  `register()` or `emit()` failed with `libfasten_core not found`. Without
  one, pip on a platform with no wheel says there is no matching
  distribution.

### Docs: Go and Swift install steps

- `go/README.md`: `go get` alone does not build the Go SDK, since its cgo
  flags need `fasten-core` next to `go/`. The install section now clones the
  repo, builds `fasten-core`, and uses a `replace` directive.
- New `swift/README.md`: requirements, install as a local package
  (`.package(path: "../fasten/swift")`), and a quickstart.

### Changed: how releases ship

- A `vX.Y.Z` tag runs the Python, JS, Rust, C++ and Swift tests and the
  integration smokes, and a `go/vX.Y.Z` tag runs the Go tests, before
  anything is released.
- A beta tag such as `v1.0.0-beta.0` is a GitHub prerelease, with the
  release files below; PyPI, npm and crates.io get fasten from the 1.0
  release.
- Python versions follow PEP 440, so `v1.0.0-beta.0` is `1.0.0b0` in
  Python.
- On npm, a release goes under the `latest` dist-tag only when it is above
  every published release; a backport such as 1.0.1 after 1.1.0 goes under
  `release-1.0`.
- On npm, a release is staged by the workflow and becomes installable when
  a maintainer approves it with two-factor authentication.
- The Rust SDK needs Rust 1.90 (`rust-version`), as fasten-core does.

### Changed: Python, Rust and npm packages are named `fasten-sdk`

- `fasten` is taken on PyPI, crates.io and npm by unrelated projects, so
  the package has one name on all three: `pip install fasten-sdk`,
  `fasten-sdk = "..."` in `Cargo.toml`, `npm install fasten-sdk`.
- Python still imports `fasten`, Rust still uses `fasten::`, and the
  `fasten` and `fasten-tui` commands keep their names.
- JS imports change from `'@nerdapplabs/fasten'` to `'fasten-sdk'`, and
  the Postgres store from `'@nerdapplabs/fasten/store/postgres'` to
  `'fasten-sdk/store/postgres'`.
- Go (`github.com/nerdapplabs/fasten/go`) and `fasten-core` keep their
  names.

### Fixed: remaining log lines go through the redactor (Python, C++)

- Python: `fasten.log.*` before `init()` redacts the line before handing it
  to the stdlib logger. If libfasten_core can't load, the values are dropped.
- C++: the SDK's own sys lines on stderr are redacted, including the sink
  error text in `audit_sync_fallback_failed` and the core's message in
  `audit_drain_abandoned`.
- Python: fasten's own error log lines (drainer, retention, Postgres
  reconnect) give the exception type and traceback frames with the message
  redacted, instead of the raw message and traceback. The exceptions it was
  raised from are listed the same way. Drainer and retention lines use the
  engine's redaction settings; `start_purger()` takes a `redactor`.
- Python: before `init()`, the event is redacted on its own, so an
  oversize field doesn't drop it. An event that can't be redacted is
  replaced by the marker.

### Fixed: SQLite store files are created 0600 (Python, Go, Rust, C++, Swift)

- A new database file is now created owner-only (0600) instead of with the
  process umask: the Python `SQLiteStore` and `StreamStore`, Go
  `OpenStreamStore`, the fasten-core `SqliteStore` used by Rust, the C++
  `fasten_store_sqlite.hpp` `SqliteStore` and the Swift `SQLiteStore`. SQLite
  gives its -wal and -shm files the same mode. An existing file keeps its
  mode, and `:memory:` is left alone. A symlink to a missing file is
  followed, as SQLite follows it, and the file it names is created 0600.
- The stores that take a `file:` URI (Python `StreamStore`, Go
  `OpenStreamStore`, fasten-core, C++, Swift) treat the file it names the
  same way, unless it sets `mode=memory`, `mode=ro`, `mode=rw`, a true
  `immutable` or a `vfs`, or names another host. The path is decoded as
  SQLite decodes it, ending at a `%00`. These stores open a `file:` path as
  a URI even when SQLite is built without URI support, so the file SQLite
  opens is the one created 0600. Python `SQLiteStore` makes its path
  absolute, so it never reads a URI.
- Go `NewSQLiteStore` and `NewStreamStore` take a `*sql.DB` the caller opened,
  so the caller's driver creates that file.

### Fixed: an age purge no longer leaves a hole in a chain (all stores)

- `purge(before)` deletes, per `source_node_id`, only the rows below the
  lowest seq it keeps (a row at or after the cutoff, or an unshipped row when
  `respect_unshipped` is set). A row's timestamp is taken at emit and its seq
  at insert, so seq N+1 can be older than seq N; deleting by timestamp alone
  could remove N+1, keep N and N+2, and break `verify_chain` at N+2. An old
  row above a kept one now stays until that row ages out too (spec §2.3).
- Same SQL in the Python and Go SQLite and Postgres stores, the fasten-core
  stores (Rust, C++, Swift) and the JS `PostgresStore`.
- With `respect_unshipped`, a shipped row above an older unshipped row is no
  longer deleted.
- Rows at seq 0 (not chained) are still purged by age alone.
- A purge can now delete and report fewer rows than before. Each node's
  lowest kept seq is one walk up the (source_node_id, monotonic_seq) index,
  so the purge costs about what the old delete did.

### Added: chain checkpoints (Python + Go)

- A checkpoint records a node's latest sealed row (`source_node_id`,
  `monotonic_seq`, `hash`, `anchored_at`). Checked against checkpoints
  published earlier outside the store, verification now reports rows cut off
  the end of a chain and a chain re-sealed from genesis (spec §9).
- Python: `fasten.checkpoints` with `Checkpoint`, `FileCheckpointSink`,
  `HttpCheckpointSink`, `CheckpointStore`, `take_checkpoints`,
  `publish_checkpoints`, `load_checkpoints` and `checkpoints_since`, and
  `verify_chain(rows, checkpoints=..., partial=False)`. `SQLiteStore` and
  `PostgresStore` gain `chain_tips()`.
- Go: `Checkpoint`, `FileCheckpointSink`, `HTTPCheckpointSink`,
  `TakeCheckpoints`, `PublishCheckpoints`, `LoadCheckpoints`,
  `CheckpointsSince`, `ErrPartialLastLine`, `CheckpointOptions` and
  `VerifyChainWithCheckpoints`; `VerifyChain` is unchanged. `SQLiteStore`
  and `PostgresStore` gain `ChainTips`.
- A verify with checkpoints covers the whole chain by default: a
  checkpointed node with no rows, or whose rows start after or end before
  any of its checkpoints, fails. A partial verify (a page, one node) skips
  those checkpoints, so only a whole-chain verify detects a cut-off tail. With
  retention, pass only the checkpoints taken since the latest purge
  (`checkpoints_since` / `CheckpointsSince`): older ones fail.
- The file sinks drop an unfinished last line, left by a crash mid-append,
  before the next append, so the file keeps loading.
- The HTTP sinks send userinfo in the URL as Basic auth, treat a redirect
  as a failed publish, time out after 10 s by default, and leave userinfo
  and query out of error messages.
- `spec/checkpoint-vectors.json` holds cases both SDKs must agree on.

### Added: release provenance

- Each `vX.Y.Z` GitHub release carries Swift, C++ and Rust source archives
  and the fasten-core library for Linux x86_64; each `go/vX.Y.Z` release
  carries the Go module zip. Every file is listed in `SHA256SUMS` and has a
  GitHub artifact attestation. Only the highest
  `vX.Y.Z` tag is marked as the repo's latest release; `go/` tags,
  prereleases and backports are not.
- The source archives and the Go module zip are reproducible: rebuilding
  them from the tag with GNU tar, GNU gzip and the stock Python zlib gives
  the same bytes.
- PyPI uploads (from the 1.0 release) carry PEP 740 attestations.
- SECURITY.md lists the commands to verify a release for each SDK, including
  how to match the Go zip's `h1:` hash with `go.sum`.

### Fixed: ingest of repeated and unsealed rows, rows without a form id (Python, Go)

- A row sent twice in one batch on the same node, with the same hash, is a
  re-delivery: ingest stores it once instead of rejecting the batch from it.
- An unsealed row below a node's first sealed row, in the batch and in the
  store, is left out of the insert. Ingest no longer raises (Python) or fails
  the batch (Go) on it. One above a sealed row the store already holds for its
  node is a break at that row (spec §4).
- Python reads a sealed row with an empty or missing `canonical_form_id` as
  form "1" and stores it as "1", as Go does (spec §1.5), so it verifies in
  both SDKs. SQLite no longer skips such a row and Postgres no longer rejects it.

### Fixed: drainer stop, re-init and sys events (Swift)

- A row the drainer refuses because it has stopped (a re-init or `close()`
  raced the emit) is stored inline, with `audit_drain_abandoned` then
  `audit_drain_stored_inline`. Before, it was dropped without a log line.
- `configure()` on a running engine swaps in the new drainer under the engine
  lock before stopping the old one, so an emit during re-init always reaches a
  drainer. It logs `audit_drain_install_incomplete` when the old drainer's
  rows were not stored, counting from the swap, so a dead letter from
  earlier is not counted and one right after the swap is.
- New `Fasten.close(timeout:)` flushes for up to half the timeout, as Python,
  Go and JS do, then stops the drainer per spec §10. Queued rows get one
  attempt each, an insert in progress is waited for, and rows not stored are
  logged as `audit_drain_lost_at_stop` and make `close()` return false. It
  also stops old drainers a re-init is still retiring, all within the one
  timeout, and returns false if any of them lost a row, counting from before
  any of them stopped.
- An insert still running at the close deadline is reported lost but keeps
  running. If it then stores its row, `audit_drain_recovered_at_stop` with
  `row_ids` follows, as in Python. A lost report can be a false alarm; a
  loss is never missed. The drain thread keeps the drainer alive until that
  insert returns.
- The drainer now logs the spec §4 events: `audit_queue_high_water`,
  `audit_queue_near_full`, `audit_drain_failed`, `audit_drain_degraded`,
  `audit_drain_recovered`, `audit_drain_dead_letter` and
  `audit_drain_abandoned`, through the redacted log path.
- `flush()` counts dead-lettered and lost rows as settled (spec §6), so it no
  longer times out on a row that was dead-lettered while pending. It returns
  only after the row's event is logged and the depth is updated.
- `last_error` in the drainer stats is `"<ErrorType>: <message>"`.
- Rows and sys log lines read the service id, node id and redactor under
  the engine lock, so a concurrent `configure()` can't tear them.

### Fixed: queued rows, sys and log lines, re-init report (Rust)

- `submit()` stores a row inline when the drainer is stopping and refuses it,
  then emits `audit_drain_stored_inline`. If that insert fails too, it emits
  `audit_sync_fallback_failed {error_type, row_id}` and returns `Ok`, as
  Python and Go do. Before, such a row was dropped.
- With no drainer installed in queue mode, a failed inline insert also emits
  `audit_sync_fallback_failed` and returns `Ok`. Before, it returned the
  error with no sys event. Raise mode still returns the error.
- Redact sys and log lines (`fasten::log::*` included) with the configured
  extra keys and replacement, as the other SDKs do.
- SDK sys events (`audit_chain_unavailable`, `retention_purge_failed`,
  `pii_redaction_skipped_legacy_form`) go to stderr, as spec
  drainer-conformance §4 asks. `fasten::log::*` lines stay on stdout.
- Re-init emits `audit_drain_install_incomplete {flushed, unstored}` when the
  old drainer's flush timed out or rows it held were not stored (spec §10).
- A failed insert through the drainer is retried and reported by the store
  error's type (e.g. `AuditStoreInsert`) in `audit_drain_failed.error`,
  `audit_drain_dead_letter.last_error`, `audit_drain_lost_at_stop.error_type`
  and `queue_stats().last_error`. Before, it was reported as
  `InvalidTableName`.
- fasten-core: `Drainer::unstored_total` is now public, and the new
  `Error::Store(String)` is a store error that carries only its type. The
  drainer retries it, and it maps to `ErrBackend`. The C ABI is unchanged.
- `PostgresStore::redact_rows` returns only the ids it redacted.

### Fixed: `fasten doctor` absolute SQLite paths and structlog redaction after init (Python)

- `fasten doctor` reads the audit DSN path as the SQLite store does, so
  `sqlite:////abs/audit.db` and a bare `/abs/audit.db` are checked at that
  path instead of being reported as not found. The api DSN check takes its
  path from the same helper as the stream store, so a DSN such as
  `./api;v2.db` is checked at `./api`. The path it prints is the path it
  checks.
- `fasten.shim.structlog.configure()` uses the engine's current redactor for
  each event, so redaction settings from an `init()` that runs after
  `configure()` apply to structlog output and the stdlib bridge.

### Fixed: re-init drainer handoff and idle drainer (JS)

- Re-`init()` keeps the old drainer visible to `flush()` and `close()` until
  it has stopped. `close()` stops it within its own timeout and resolves
  false if it lost rows, and re-init emits `audit_drain_install_incomplete`
  when the old drainer's flush timed out or rows were not stored.
- A re-`init()` to raise mode, or with no store, flushes the old drainer for
  up to 5 s too, instead of giving a row in backoff one try. Rows it loses
  are reported with `audit_drain_lost_at_stop` and
  `audit_drain_install_incomplete`; a later `close()` reports only rows lost
  during that close, as in Python and Go.
- `resetForTests()` also stops the drainers a re-init is retiring, and
  resolves once they have stopped.
- An idle drainer waits for the next row instead of polling, so it no longer
  uses CPU or keeps the process from exiting.
- The phase-1 stdout audit line carries `prev_hash: ""` and `hash: ""`.
- `index.d.ts` adds `redactReplacement` and `queueDrainMaxAttempts` to
  `InitOptions`, the dead-letter and `capacity_semantics` fields to
  `QueueStats`, and `wire_version` to `Row`.

### Fixed: form-2 rows read back from stdout and the reader verify (Go)

- The sealed stdout line and the `/audit`, `/correlate` and `/search`
  responses now carry `detail_salt` and `detail_commitment`. Without them a
  form-2 row read back from either place failed `VerifyChain` in Go and
  Python and could not be ingested again.
- Canonical JSON writes DEL (0x7f) as `\u007f`, as Python's `json.dumps`
  does, so a row holding that byte hashes the same in Go and Python.
- Rows Go sealed earlier with DEL left raw still verify, in Go and Python:
  when the commitment or hash misses, the check is retried with DEL raw
  (spec §1.2).

### Fixed: redact values when the core can't parse the input (C++)

- Strings are now written as valid UTF-8 JSON: bytes that are not valid
  UTF-8 become U+FFFD, so the core can redact detail and log fields that
  contain them. Before, such fields were returned unredacted.
- If the core still returns an error, every value is replaced with the
  redaction token (keys are kept) and a `redact_failed` sys event with
  `error_type` is written to stderr and the sys ring.
- `fasten::flush()` during a re-init also waits for the drainer being
  replaced, not only the new one.
- The core drainer's sys events (`audit_drain_*`, `audit_queue_*`) now go
  through the SDK's sys log, redacted, so they reach `query_syslog()` as
  well as stderr. Their numbers and booleans stay JSON numbers and
  booleans on the stderr line.
- `fasten::flush()` with under 1 ms left, including `flush(0)`, no longer
  waits with no timeout: each drainer gets at least 1 ms, so it returns
  true at once when nothing is queued and false after 1 ms when rows are
  still pending.
- `fasten::flush()` while a re-init is stopping the old drainer waits for
  the stop to finish, and returns false if it does not finish in time.
- A re-init whose old drainer did not flush in time, or held rows that
  were not stored, emits `audit_drain_install_incomplete` with `flushed`
  and `unstored`.
- When the core returns an error, an `AUDIT_ROW_REDACTED` row keeps its
  numeric `redacted_seq`.

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
  target `SQLite::SQLite3`, so it was always skipped.

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

- `GET /api/v1/logs/audit/doctor` is now available in the Go reader
  (`NewReader`).
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

### Added: the SDKs

The API each SDK has had since before this changelog's first entry:

- **Python**: `init`, `emit`, `log.*`, `register`; SQLite and Postgres
  stores; the mountable reader; the `fasten` CLI and `fasten-tui`.
- **Go**: `Register`, `Init`, `Emit`, `LogInfo`/`LogWarn`/`LogError`/
  `LogDebug`, `RedactDetail`; SQLite and Postgres stores; the slog handler
  and the HTTP reader.
- **Node / TypeScript**: `init`, `emit`, `log.*`, `register`,
  `withRequestID`.
- **Rust**: `init`, `register`, `EmitBuilder`, `with_request_id`,
  `fasten::log::info`/`warn`/`error`/`debug`.
- **C++14**: `fasten::init`, `emit`, `log::*`, `RequestScope`; SQLite and
  Postgres stores; the reader.
- **Swift**: `Fasten.configure`, `emit`, `log.*`, `withRequestID`; the
  SQLite store.
- **Java**: a placeholder. The types compile; `emit` throws
  `UnsupportedOperationException`.

[Unreleased]: https://github.com/nerdapplabs/fasten/commits/main
