//! PostgreSQL-backed AuditStore (sync, `postgres` crate).
//! Enable with: fasten-sdk = { features = ["store-postgres"] }
//!
//! Uses the synchronous `postgres` crate (as `pg`), since `AuditStore` is a
//! sync trait. The client sits behind a `Mutex` so the drainer thread can
//! share the store.

use std::sync::Mutex;

use fasten_core::chain::{ChainRow, GENESIS};
use fasten_core::checkpoint::ChainTip;
use pg::types::ToSql;

// Table names must match ^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$
// (a name or schema.table).

fn is_valid_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn validate_table_name(table: &str) -> Result<(), crate::Error> {
    let (schema, bare) = match table.split_once('.') {
        Some((s, t)) => (Some(s), t),
        None => (None, table),
    };
    let ok = schema.is_none_or(is_valid_identifier) && is_valid_identifier(bare);
    if ok {
        Ok(())
    } else {
        Err(crate::Error::AuditStoreInsert(format!(
            "fasten: invalid table name {:?}; must match \
             ^[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)?$",
            table
        )))
    }
}

fn pg_err(e: pg::Error) -> crate::Error {
    let msg = match e.as_db_error() {
        Some(db) => format!("{e}: {}", db.message()),
        None => e.to_string(),
    };
    // Bad data, a constraint or a size limit: the row can never be stored.
    if e.code().is_some_and(|c| fasten_core::drainer::sqlstate_rejects_row(c.code())) {
        return crate::Error::AuditStoreRejected(msg);
    }
    crate::Error::AuditStoreInsert(msg)
}

// A failed read: never a reason to reject or retry a row.
fn pg_read_err(e: pg::Error) -> crate::Error {
    crate::Error::AuditStoreRead(match e.as_db_error() {
        Some(db) => format!("{e}: {}", db.message()),
        None => e.to_string(),
    })
}

fn differs(id: &str) -> crate::Error {
    crate::Error::AuditStoreRejected(format!("row {id}: differs from the stored row with that id"))
}

const NODE_LOCK: &str = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";

fn ensure_schema(client: &mut pg::Client, schema: &str) -> Result<(), crate::Error> {
    let sql = format!("CREATE SCHEMA IF NOT EXISTS {schema}");
    client.execute(&sql, &[]).map_err(pg_err)?;
    Ok(())
}

/// `idx_{bare}_{suffix}`, unless that passes Postgres's 63-byte identifier
/// limit, where long names truncate to one name and only the first index
/// gets made. Then the table part is cut and a hash of the full name added.
fn index_name(bare: &str, suffix: &str) -> String {
    const MAX: usize = 63;
    let name = format!("idx_{bare}_{suffix}");
    if name.len() <= MAX {
        return name;
    }
    // FNV-1a over the folded name: unquoted `Foo` and `foo` are one table.
    let mut h: u32 = 0x811c_9dc5;
    for b in bare.to_ascii_lowercase().bytes() {
        h = (h ^ u32::from(b)).wrapping_mul(0x0100_0193);
    }
    let keep = MAX - "idx___".len() - 8 - suffix.len();
    format!("idx_{}_{h:08x}_{suffix}", &bare[..keep])
}

// Column order follows the Python store, which reads rows by position.
// pii_in_detail and wire_version, which Python lacks, go last.
fn ensure_table(client: &mut pg::Client, table: &str, bare: &str) -> Result<(), crate::Error> {
    let create = format!(
        "CREATE TABLE IF NOT EXISTS {table} (
            id              TEXT        NOT NULL,
            origin_id       TEXT        NOT NULL,
            monotonic_seq   BIGINT      NOT NULL DEFAULT 0,
            timestamp       TEXT        NOT NULL,
            code            TEXT        NOT NULL,
            action          TEXT        NOT NULL DEFAULT '',
            severity        TEXT        NOT NULL DEFAULT 'info',
            service_id      TEXT        NOT NULL DEFAULT '',
            source_node_id  TEXT        NOT NULL DEFAULT '',
            tenant_id       TEXT,
            actor           TEXT        NOT NULL DEFAULT '',
            actor_kind      TEXT        NOT NULL DEFAULT '',
            target          TEXT        NOT NULL DEFAULT '',
            category        TEXT        NOT NULL DEFAULT '',
            domain          TEXT        NOT NULL DEFAULT '',
            method          TEXT        NOT NULL DEFAULT '',
            request_id      TEXT        NOT NULL DEFAULT '',
            detail          TEXT        NOT NULL DEFAULT '{{}}',
            shipped_at      TEXT,
            prev_hash       TEXT        NOT NULL DEFAULT 'genesis',
            hash            TEXT        NOT NULL DEFAULT '',
            canonical_form_id TEXT      NOT NULL DEFAULT '1',
            detail_salt       TEXT,
            detail_commitment TEXT,
            pii_in_detail   SMALLINT    NOT NULL DEFAULT 0,
            wire_version    TEXT        NOT NULL DEFAULT '1',
            PRIMARY KEY (id)
        )"
    );
    client.execute(&create, &[]).map_err(pg_err)?;

    // Columns a table made by another SDK, or an older Rust store, may lack.
    for col in [
        "pii_in_detail SMALLINT NOT NULL DEFAULT 0",
        "wire_version TEXT NOT NULL DEFAULT '1'",
        "prev_hash TEXT NOT NULL DEFAULT 'genesis'",
        "hash TEXT NOT NULL DEFAULT ''",
        "canonical_form_id TEXT NOT NULL DEFAULT '1'",
        "detail_salt TEXT",
        "detail_commitment TEXT",
    ] {
        let sql = format!("ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col}");
        client.execute(sql.as_str(), &[]).map_err(pg_err)?;
    }

    for (suffix, cols) in [
        ("req", "request_id"),
        ("code", "code"),
        ("ts", "timestamp"),
        ("svc", "service_id"),
        // Not unique: older Rust tables repeat seqs per node.
        ("node_seq", "source_node_id, monotonic_seq"),
    ] {
        let name = index_name(bare, suffix);
        let sql = format!("CREATE INDEX IF NOT EXISTS {name} ON {table} ({cols})");
        client.execute(sql.as_str(), &[]).map_err(pg_err)?;
    }
    Ok(())
}

/// How the existing table keeps timestamps: the Go store as TIMESTAMPTZ,
/// Python and this store as TEXT.
struct Columns {
    ts_cast: &'static str,
    shipped_cast: &'static str,
}

impl Columns {
    /// Selects `column` in the canonical timestamp form (spec §4.3), which
    /// is what the chain hashes.
    fn canonical(cast: &str, column: &str) -> String {
        if cast.is_empty() {
            column.to_string()
        } else {
            format!(r#"to_char({column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')"#)
        }
    }
}

fn inspect_columns(
    client: &mut pg::Client,
    schema: Option<&str>,
    bare: &str,
) -> Result<Columns, crate::Error> {
    // Unquoted identifiers fold to lowercase in Postgres.
    let schema = schema.map(str::to_ascii_lowercase);
    let bare = bare.to_ascii_lowercase();
    let rows = client
        .query(
            "SELECT column_name, data_type FROM information_schema.columns \
             WHERE table_schema = COALESCE($1::text, current_schema()) AND table_name = $2",
            &[&schema, &bare],
        )
        .map_err(pg_err)?;
    let mut cols = Columns { ts_cast: "", shipped_cast: "" };
    for r in rows {
        let name: &str = r.get(0);
        let dtype: &str = r.get(1);
        let cast = if dtype.starts_with("timestamp") { "::timestamptz" } else { "" };
        match name {
            "timestamp" => cols.ts_cast = cast,
            "shipped_at" => cols.shipped_cast = cast,
            _ => {}
        }
    }
    Ok(cols)
}

/// Synchronous PostgreSQL audit store backed by the `postgres` crate.
///
/// Obtain one via [`PostgresStore::new`] and wrap it in an `Arc` before
/// passing to [`crate::Config::audit_store`].
///
/// A row with `monotonic_seq` 0 (what `emit` builds) gets the node's next
/// seq and is sealed into the node's hash chain in the insert transaction,
/// under the same per-node advisory lock as the Python, Go and JS stores
/// (spec §2.1), so Rust, Python and Go writers on one table share one chain
/// per node. A row with a seq of its own is stored as given: unsealed
/// unless it already carries a hash. An unsealed row at or above a node's
/// sealed rows makes [`crate::verify_chain`] fail for that node, so do not
/// write rows with their own seqs on a node id this store seals for.
///
/// [`PostgresStore::chain_rows`] reads a node's rows back for
/// [`crate::verify_chain`], and [`PostgresStore::chain_tips`] each node's
/// latest sealed row for [`crate::publish_checkpoints`].
///
/// `sslmode` in the DSN works as in libpq, except that `require` also checks
/// the certificate and host name, like `verify-full`. The default, `prefer`,
/// uses TLS
/// when the server offers it, without checking the certificate, and
/// plaintext when it doesn't. `sslmode=verify-full` and `sslmode=require`
/// use TLS and check the certificate and host name; `sslmode=verify-ca`
/// checks the certificate but not the host name; `sslmode=disable` uses
/// plaintext.
///
/// ```no_run
/// use std::sync::Arc;
/// use fasten::{Config, PostgresStore};
///
/// let store = PostgresStore::new(
///     "host=localhost user=myapp dbname=audit",
///     "audit_logs",
/// ).expect("connect");
///
/// fasten::init(Config {
///     service_id: "my-service".into(),
///     node_id: "node-1".into(),
///     audit_store: Some(Arc::new(store)),
///     ..Default::default()
/// }).expect("init");
/// ```
pub struct PostgresStore {
    client: Mutex<pg::Client>,
    table: String,
    /// Table name without the schema prefix; the index names are built from it.
    #[allow(dead_code)]
    idx: String,
    cols: Columns,
}

impl PostgresStore {
    /// Connect to `dsn`, create the schema/table/indexes if absent, and
    /// return a ready-to-use store.
    ///
    /// `table` may be a plain name (`"audit_logs"`) or schema-qualified
    /// (`"audit.audit_logs"`).  Either form must match
    /// `^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`.
    pub fn new(dsn: &str, table: impl Into<String>) -> Result<Self, crate::Error> {
        let table = table.into();
        validate_table_name(&table)?;

        let (schema_opt, bare) = match table.split_once('.') {
            Some((s, t)) => (Some(s.to_owned()), t.to_owned()),
            None => (None, table.clone()),
        };

        // fasten-core's connect, for its sslmode handling (TLS by default,
        // checked under require, verify-ca and verify-full).
        let mut client = fasten_core::store::postgres::connect_client(dsn).map_err(|e| match e {
            fasten_core::error::Error::Postgres(e) => pg_err(e),
            other => crate::Error::AuditStoreInsert(other.to_string()),
        })?;

        // Serialise bootstrap across processes and SDKs: concurrent CREATE /
        // ALTER on one table deadlock or fail. Same key as the Python store.
        let lock_key = format!("fasten.bootstrap.{table}");
        client
            .execute("SELECT pg_advisory_lock(hashtextextended($1, 0))", &[&lock_key])
            .map_err(pg_err)?;
        let ddl = (|| {
            if let Some(ref schema) = schema_opt {
                ensure_schema(&mut client, schema)?;
            }
            ensure_table(&mut client, &table, &bare)
        })();
        let unlock = client
            .execute("SELECT pg_advisory_unlock(hashtextextended($1, 0))", &[&lock_key])
            .map_err(pg_err);
        ddl?;
        unlock?;

        let cols = inspect_columns(&mut client, schema_opt.as_deref(), &bare)?;

        Ok(Self {
            client: Mutex::new(client),
            table,
            idx: bare,
            cols,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, pg::Client> {
        self.client.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The rows of `source_node_id`, ordered by `monotonic_seq`, for
    /// [`crate::verify_chain`]. Each row's `detail` is parsed from the
    /// stored text, so its numbers are the tokens that were hashed, whichever
    /// SDK wrote the row.
    ///
    /// Every row of the node is read into memory in one query, with no
    /// paging, and the store's one connection is held until it returns, so
    /// inserts through this store wait meanwhile.
    pub fn chain_rows(&self, source_node_id: &str) -> Result<Vec<ChainRow>, crate::Error> {
        let sql = format!(
            "SELECT {} FROM {} WHERE source_node_id = $1 ORDER BY monotonic_seq",
            self.chain_columns(),
            self.table
        );
        self.chain_query(&sql, &[&source_node_id])
    }

    /// Every row in the table, ordered by node id and `monotonic_seq`: the
    /// whole chain, for [`crate::verify_chain_with_checkpoints`].
    ///
    /// The whole table is read into memory in one query, with no paging,
    /// and the store's one connection is held until it returns, so inserts
    /// through this store wait meanwhile. On a large table verify one node
    /// at a time with [`PostgresStore::chain_rows`] and
    /// `CheckpointOptions::partial()`, or read from a second
    /// `PostgresStore`.
    pub fn all_chain_rows(&self) -> Result<Vec<ChainRow>, crate::Error> {
        let sql = format!(
            "SELECT {} FROM {} ORDER BY source_node_id, monotonic_seq",
            self.chain_columns(),
            self.table
        );
        self.chain_query(&sql, &[])
    }

    /// Each node's latest sealed row (node id, seq and hash), ordered by
    /// node id, for [`crate::take_checkpoints`].
    pub fn chain_tips(&self) -> Result<Vec<ChainTip>, crate::Error> {
        let sql = fasten_core::store::chain_tips_sql(&self.table);
        self.lock()
            .query(&sql as &str, &[])
            .map_err(pg_read_err)?
            .iter()
            .map(|r| {
                let node: String = column(r, 0, "chain tip")?;
                let owner = format!("node '{node}'");
                let monotonic_seq = stored_seq(&owner, column(r, 1, &owner)?)?;
                Ok(ChainTip { source_node_id: node, monotonic_seq, hash: column(r, 2, &owner)? })
            })
            .collect()
    }

    /// Store a sealed row from elsewhere exactly as it was sealed, with
    /// `detail` written as the text of `row.detail`, so a number such as
    /// `-0` or a 30-digit integer reads back as it was hashed. A
    /// [`crate::Row`] cannot carry those; `insert` is for rows this process
    /// built. `pii_in_detail` is the row's flag, which a `ChainRow` does not
    /// hold.
    ///
    /// The row must have a hash and a non-zero `monotonic_seq`. Its hash is
    /// not verified here: run [`crate::verify_chain`] over the batch first.
    /// Storing the same row again is a no-op; a different row under a stored
    /// id is [`crate::Error::AuditStoreRejected`].
    pub fn insert_sealed(&self, row: &ChainRow, pii_in_detail: bool) -> Result<(), crate::Error> {
        let (columns, detail) = fasten_core::store::sealed_columns(row, pii_in_detail)
            .map_err(|e| crate::Error::AuditStoreRejected(e.to_string()))?;
        let mut guard = self.lock();
        let mut tx = guard.transaction().map_err(pg_err)?;
        tx.execute(NODE_LOCK, &[&row.source_node_id]).map_err(pg_err)?;
        let mut held = self.held(&mut tx, &row.id)?;
        if held.is_none() && self.insert_row(&mut tx, &columns, &detail)? == 0 {
            held = self.held(&mut tx, &row.id)?;
        }
        tx.commit().map_err(pg_err)?;
        match held {
            Some(held) if held.hash != row.hash => Err(differs(&row.id)),
            _ => Ok(()),
        }
    }

    /// The columns `chain_row` reads, with timestamps in the canonical form.
    fn chain_columns(&self) -> String {
        format!(
            "id, wire_version, origin_id, monotonic_seq, {ts}, code, action, severity, \
             service_id, source_node_id, tenant_id, actor, actor_kind, target, category, domain, \
             method, request_id, detail, {shipped}, canonical_form_id, prev_hash, hash, \
             detail_salt, detail_commitment",
            ts = Columns::canonical(self.cols.ts_cast, "timestamp"),
            shipped = Columns::canonical(self.cols.shipped_cast, "shipped_at"),
        )
    }

    fn chain_query(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<ChainRow>, crate::Error> {
        self.lock().query(sql, params).map_err(pg_read_err)?.iter().map(chain_row).collect()
    }

    /// The row stored under `id`, if there is one.
    fn held(&self, tx: &mut pg::Transaction<'_>, id: &str) -> Result<Option<ChainRow>, crate::Error> {
        let sql = format!("SELECT {} FROM {} WHERE id = $1", self.chain_columns(), self.table);
        tx.query_opt(&sql as &str, &[&id]).map_err(pg_err)?.as_ref().map(chain_row).transpose()
    }

    /// Insert `row` as it is on `tx`, with `detail` as the text of its detail
    /// column. Returns the rows written: 0 when the id was already stored.
    fn insert_row(
        &self,
        tx: &mut pg::Transaction<'_>,
        row: &fasten_core::Row,
        detail: &str,
    ) -> Result<u64, crate::Error> {
        let pii_in_detail: i16 = i16::from(row.pii_in_detail);
        let monotonic_seq = i64::try_from(row.monotonic_seq).map_err(|_| {
            crate::Error::AuditStoreRejected(format!(
                "row {}: monotonic_seq {} is out of range",
                row.id, row.monotonic_seq
            ))
        })?;
        let prev_hash = row.prev_hash.as_deref().unwrap_or("");
        let hash = row.hash.as_deref().unwrap_or("");
        let form = row.canonical_form_id.as_deref().unwrap_or("1");
        // '' rather than NULL: a table the Go store created declares them
        // NOT NULL.
        let salt = row.detail_salt.as_deref().unwrap_or("");
        let commitment = row.detail_commitment.as_deref().unwrap_or("");

        let sql = format!(
            "INSERT INTO {} \
             (id, wire_version, origin_id, monotonic_seq, timestamp, \
              code, action, severity, service_id, source_node_id, tenant_id, \
              actor, actor_kind, target, category, domain, method, \
              request_id, detail, pii_in_detail, shipped_at, \
              prev_hash, hash, canonical_form_id, detail_salt, detail_commitment) \
             VALUES \
             ($1, $2, $3, $4, $5::text{}, \
              $6, $7, $8, $9, $10, $11, \
              $12, $13, $14, $15, $16, $17, \
              $18, $19, $20, $21::text{}, \
              $22, $23, $24, $25, $26) \
             ON CONFLICT (id) DO NOTHING",
            self.table, self.cols.ts_cast, self.cols.shipped_cast
        );

        let tenant: Option<&str> = row.tenant_id.as_deref();
        let shipped: Option<&str> = row.shipped_at.as_deref();
        let params: &[&(dyn ToSql + Sync)] = &[
            &row.id,
            &row.wire_version,
            &row.origin_id,
            &monotonic_seq,
            &row.timestamp,
            &row.code,
            &row.action,
            &row.severity,
            &row.service_id,
            &row.source_node_id,
            &tenant,
            &row.actor,
            &row.actor_kind,
            &row.target,
            &row.category,
            &row.domain,
            &row.method,
            &row.request_id,
            &detail,
            &pii_in_detail,
            &shipped,
            &prev_hash,
            &hash,
            &form,
            &salt,
            &commitment,
        ];
        tx.execute(&sql as &str, params).map_err(pg_err)
    }
}

/// Column `idx` of `r`, which belongs to the row or node `owner` names. A
/// NULL or a value of another type is an error that names both.
fn column<'a, T: pg::types::FromSql<'a>>(r: &'a pg::Row, idx: usize, owner: &str) -> Result<T, crate::Error> {
    r.try_get(idx).map_err(|e| {
        let name = r.columns().get(idx).map_or("?", pg::Column::name);
        crate::Error::AuditStoreRead(format!("{owner}: column {name}: {e}"))
    })
}

/// A seq read from the BIGINT column. A negative one is not a seq.
fn stored_seq(owner: &str, seq: i64) -> Result<u64, crate::Error> {
    u64::try_from(seq)
        .map_err(|_| crate::Error::AuditStoreRead(format!("{owner}: monotonic_seq {seq} is negative")))
}

/// A row selected as `PostgresStore::chain_columns`.
fn chain_row(r: &pg::Row) -> Result<ChainRow, crate::Error> {
    let id: String = column(r, 0, "row")?;
    let owner = format!("row {id}");
    let text = |idx: usize| column::<String>(r, idx, &owner);
    let opt = |idx: usize| column::<Option<String>>(r, idx, &owner);
    let row = fasten_core::Row {
        id,
        wire_version: text(1)?,
        origin_id: text(2)?,
        monotonic_seq: stored_seq(&owner, column(r, 3, &owner)?)?,
        timestamp: text(4)?,
        code: text(5)?,
        action: text(6)?,
        severity: text(7)?,
        service_id: text(8)?,
        source_node_id: text(9)?,
        tenant_id: opt(10)?,
        actor: text(11)?,
        actor_kind: text(12)?,
        target: text(13)?,
        category: text(14)?,
        domain: text(15)?,
        method: text(16)?,
        request_id: text(17)?,
        shipped_at: opt(19)?,
        canonical_form_id: Some(text(20)?),
        prev_hash: Some(text(21)?),
        hash: Some(text(22)?),
        detail_salt: opt(23)?,
        detail_commitment: opt(24)?,
        ..Default::default()
    };
    ChainRow::from_row(&row, &text(18)?)
        .map_err(|e| crate::Error::AuditStoreRead(format!("{owner}: detail: {e}")))
}

impl crate::checkpoints::CheckpointStore for PostgresStore {
    fn chain_tips(&self) -> Result<Vec<ChainTip>, crate::Error> {
        PostgresStore::chain_tips(self)
    }
}

impl crate::AuditStore for PostgresStore {
    fn insert(&self, row: &crate::Row) -> Result<(), crate::Error> {
        self.allocate_and_insert_originated(row).map(|_| ())
    }

    fn seals(&self) -> bool {
        true
    }

    fn allocate_and_insert_originated(&self, row: &crate::Row) -> Result<crate::Row, crate::Error> {
        // `row` with the seq and chain fields of the row stored under its
        // id, once that row is checked to be the same event (and, for a row
        // with its own seq, at that seq with that hash).
        let as_held = |held: ChainRow| {
            let same = held.same_event(&ChainRow::from(&crate::engine::sdk_row_to_core(row)))
                && (row.monotonic_seq == 0
                    || (row.monotonic_seq == held.monotonic_seq && row.hash == held.hash));
            if !same {
                return Err(differs(&row.id));
            }
            Ok(crate::Row {
                monotonic_seq: held.monotonic_seq,
                prev_hash: held.prev_hash,
                hash: held.hash,
                canonical_form_id: held.canonical_form_id,
                detail_salt: held.detail_salt,
                detail_commitment: held.detail_commitment,
                ..row.clone()
            })
        };

        let mut guard = self.lock();
        let mut tx = guard.transaction().map_err(pg_err)?;
        // A row with its own seq takes the lock too, or it could take the
        // seq a seq-0 insert has just picked.
        tx.execute(NODE_LOCK, &[&row.source_node_id]).map_err(pg_err)?;
        // A retry of a row that already landed must not take a new seq; it
        // gets the chain fields the row was stored with.
        if let Some(held) = self.held(&mut tx, &row.id)? {
            tx.commit().map_err(pg_err)?;
            return as_held(held);
        }
        let stored = if row.monotonic_seq == 0 {
            // Sealed here, so it must be a row this node originated, as the
            // Python and Go stores require.
            if row.origin_id != row.id {
                return Err(crate::Error::AuditStoreRejected(format!(
                    "row {}: allocate_and_insert_originated requires origin_id == id (got origin_id {:?})",
                    row.id, row.origin_id
                )));
            }
            // The seq counts every row on the node, sealed or not; prev_hash
            // comes from the node's last sealed row.
            let next = tx
                .query_one(
                    &format!(
                        "SELECT COALESCE(MAX(monotonic_seq), 0) + 1 FROM {} \
                         WHERE source_node_id = $1",
                        self.table
                    ),
                    &[&row.source_node_id],
                )
                .map_err(pg_err)?;
            let owner = format!("node '{}'", row.source_node_id);
            let seq = stored_seq(&owner, column(&next, 0, &owner)?)?;
            let tip = tx
                .query_opt(
                    &format!(
                        "SELECT hash FROM {} WHERE source_node_id = $1 AND hash <> '' \
                         ORDER BY monotonic_seq DESC LIMIT 1",
                        self.table
                    ),
                    &[&row.source_node_id],
                )
                .map_err(pg_err)?;
            let tip: Option<String> = tip.as_ref().map(|r| column(r, 0, &owner)).transpose()?;
            crate::seal_row(tip.as_deref().unwrap_or(GENESIS), row, seq)?
        } else {
            row.clone()
        };
        let detail = serde_json::to_string(&stored.detail)?;
        if self.insert_row(&mut tx, &crate::engine::sdk_row_to_core(&stored), &detail)? == 0 {
            // The id was stored under another node's lock meanwhile.
            let held = self.held(&mut tx, &row.id)?.ok_or_else(|| {
                crate::Error::AuditStoreInsert(format!("row {}: not inserted and not stored", row.id))
            })?;
            tx.commit().map_err(pg_err)?;
            return as_held(held);
        }
        tx.commit().map_err(pg_err)?;
        Ok(stored)
    }

    // Unsealed rows (hash '') and form-"2" rows only. A sealed form-"1" row
    // hashes its detail, so redacting it would break the chain (spec §7.1).
    fn list_redaction_candidates(
        &self,
        before: chrono::DateTime<chrono::Utc>,
        codes: &[String],
    ) -> Result<Vec<crate::RedactionCandidate>, crate::Error> {
        if codes.is_empty() {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT id, monotonic_seq FROM {} \
             WHERE timestamp < $1::text{} AND code = ANY($2) AND detail <> 'null' \
             AND (hash = '' OR canonical_form_id = '2') \
             ORDER BY monotonic_seq",
            self.table, self.cols.ts_cast
        );
        let before = crate::canonical_ts(&before);
        let codes: Vec<&str> = codes.iter().map(String::as_str).collect();
        let rows = self.lock().query(&sql as &str, &[&before, &codes]).map_err(pg_read_err)?;
        rows.iter()
            .map(|r| {
                let id: String = column(r, 0, "redaction candidate")?;
                let owner = format!("row {id}");
                let monotonic_seq = stored_seq(&owner, column(r, 1, &owner)?)?;
                Ok(crate::RedactionCandidate { id, monotonic_seq })
            })
            .collect()
    }

    fn count_skipped_legacy_form(
        &self,
        before: chrono::DateTime<chrono::Utc>,
        codes: &[String],
    ) -> Result<u64, crate::Error> {
        if codes.is_empty() {
            return Ok(0);
        }
        let sql = format!(
            "SELECT COUNT(*) FROM {} \
             WHERE timestamp < $1::text{} AND code = ANY($2) AND detail <> 'null' \
             AND hash <> '' AND canonical_form_id <> '2'",
            self.table, self.cols.ts_cast
        );
        let before = crate::canonical_ts(&before);
        let codes: Vec<&str> = codes.iter().map(String::as_str).collect();
        let row = self.lock().query_one(&sql as &str, &[&before, &codes]).map_err(pg_read_err)?;
        let count: i64 = column(&row, 0, "skipped rows")?;
        Ok(count.unsigned_abs())
    }

    fn redact_rows(&self, ids: &[String]) -> Result<Vec<String>, crate::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        // '' rather than NULL for the salt, as the Python and Go stores
        // write it: a table the Go store created declares it NOT NULL.
        let sql = format!(
            "UPDATE {} SET detail = 'null', detail_salt = '' \
             WHERE id = ANY($1) AND (hash = '' OR canonical_form_id = '2') RETURNING id",
            self.table
        );
        let ids_ref: Vec<&str> = ids.iter().map(String::as_str).collect();
        let rows = self.lock().query(&sql as &str, &[&ids_ref]).map_err(pg_err)?;
        rows.iter().map(|r| column(r, 0, "redacted row")).collect()
    }
}

#[cfg(test)]
mod tests {
    /// A connection string that can't be parsed fails before connecting,
    /// with an error that quotes none of it.
    #[test]
    fn unparsable_dsn_error_quotes_none_of_it() {
        let err = super::PostgresStore::new("host=db password=s3cret port=notaport", "audit_logs")
            .err()
            .expect("must fail")
            .to_string();
        assert!(!err.contains("s3cret"), "{err}");
    }

    use super::*;
    use std::collections::HashMap;

    // The DSN of the test database. Without one the Postgres tests return
    // early, unless FASTEN_REQUIRE_POSTGRES=1 says they must run.
    fn dsn() -> Option<String> {
        let dsn = std::env::var("FASTEN_TEST_POSTGRES_DSN").ok();
        assert!(
            dsn.is_some() || std::env::var("FASTEN_REQUIRE_POSTGRES").as_deref() != Ok("1"),
            "FASTEN_REQUIRE_POSTGRES=1 but FASTEN_TEST_POSTGRES_DSN is not set"
        );
        dsn
    }

    fn make_row(id: &str, code: &str) -> crate::Row {
        use chrono::Utc;
        crate::Row {
            wire_version: "1".into(),
            id: id.into(),
            origin_id: id.into(),
            monotonic_seq: 1,
            timestamp: Utc::now(),
            code: code.into(),
            action: "test_action".into(),
            severity: crate::Severity::Info,
            service_id: "test-svc".into(),
            source_node_id: "node-1".into(),
            tenant_id: None,
            actor: "test-user".into(),
            actor_kind: "user".into(),
            target: "resource-42".into(),
            category: "test".into(),
            domain: "test".into(),
            method: "sdk".into(),
            request_id: "req-test-001".into(),
            detail: {
                let mut m = HashMap::new();
                m.insert("key".into(), serde_json::json!("value"));
                m
            },
            pii_in_detail: false,
            prev_hash: String::new(),
            hash: String::new(),
            canonical_form_id: String::new(),
            detail_salt: None,
            detail_commitment: None,
            shipped_at: None,
        }
    }

    fn fresh_store(dsn: &str, table: &str) -> PostgresStore {
        let mut c = pg::Client::connect(dsn, pg::NoTls).expect("connect");
        c.batch_execute(&format!("DROP TABLE IF EXISTS {table}")).expect("drop");
        PostgresStore::new(dsn, table).expect("PostgresStore::new")
    }

    fn uniq(prefix: &str) -> String {
        format!("{prefix}-{}", &uuid::Uuid::new_v4().simple().to_string()[..12])
    }

    #[test]
    fn test_insert_and_query() {
        let Some(dsn) = dsn() else { return };

        let store = PostgresStore::new(&dsn, "fasten_pg_test")
            .expect("PostgresStore::new");

        let row = make_row(&uniq("evt-insert-test"), "TEST_INSERT");

        crate::AuditStore::insert(&store, &row).expect("first insert");

        // Same id again: ON CONFLICT DO NOTHING.
        crate::AuditStore::insert(&store, &row).expect("idempotent insert");

        let mut guard = store.client.lock().unwrap();
        let rows = guard
            .query(
                "SELECT id, code FROM fasten_pg_test WHERE id = $1",
                &[&row.id],
            )
            .expect("query");
        assert_eq!(rows.len(), 1, "expected exactly one row after upsert");
        let returned_id: &str = rows[0].get(0);
        let returned_code: &str = rows[0].get(1);
        assert_eq!(returned_id, row.id);
        assert_eq!(returned_code, row.code);
    }

    #[test]
    fn test_schema_qualified_table() {
        let Some(dsn) = dsn() else { return };

        let store = PostgresStore::new(&dsn, "fasten_test_schema.audit_rows")
            .expect("PostgresStore::new with schema");

        let row = make_row(&uniq("evt-schema-test"), "TEST_SCHEMA");
        crate::AuditStore::insert(&store, &row).expect("insert into schema-qualified table");

        let mut guard = store.client.lock().unwrap();
        let rows = guard
            .query(
                "SELECT id FROM fasten_test_schema.audit_rows WHERE id = $1",
                &[&row.id],
            )
            .expect("query schema table");
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn test_nullable_columns() {
        let Some(dsn) = dsn() else { return };

        let store = PostgresStore::new(&dsn, "fasten_pg_test")
            .expect("PostgresStore::new");

        let mut row = make_row(&uniq("evt-nullable-test"), "TEST_NULLABLE");
        row.tenant_id = Some("tenant-abc".into());
        row.shipped_at = Some(chrono::Utc::now());

        crate::AuditStore::insert(&store, &row).expect("insert with nullable columns set");

        let mut guard = store.client.lock().unwrap();
        let rows = guard
            .query(
                "SELECT tenant_id, shipped_at FROM fasten_pg_test WHERE id = $1",
                &[&row.id],
            )
            .expect("query");
        assert_eq!(rows.len(), 1);
        let tid: Option<&str> = rows[0].get(0);
        assert_eq!(tid, Some("tenant-abc"));
        let sat: Option<&str> = rows[0].get(1);
        assert!(sat.is_some(), "shipped_at should be present");
    }

    #[test]
    fn test_pii_in_detail_flag() {
        let Some(dsn) = dsn() else { return };

        let store = PostgresStore::new(&dsn, "fasten_pg_test")
            .expect("PostgresStore::new");

        let mut row = make_row(&uniq("evt-pii-test"), "TEST_PII");
        row.pii_in_detail = true;

        crate::AuditStore::insert(&store, &row).expect("insert pii row");

        let mut guard = store.client.lock().unwrap();
        let rows = guard
            .query(
                "SELECT pii_in_detail FROM fasten_pg_test WHERE id = $1",
                &[&row.id],
            )
            .expect("query");
        assert_eq!(rows.len(), 1);
        let flag: i16 = rows[0].get(0);
        assert_eq!(flag, 1i16);
    }

    // Two stores on one table, one node, writing at the same time: seqs must
    // be exactly 1..N, with no duplicates or gaps, in one unbroken chain.
    #[test]
    fn test_two_stores_allocate_unique_seq() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_alloc_test";
        let a = std::sync::Arc::new(fresh_store(&dsn, table));
        let b = std::sync::Arc::new(PostgresStore::new(&dsn, table).expect("second store"));
        let node = uniq("node");
        const PER: usize = 25;

        // Both threads start inserting at once.
        let start = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [a, b]
            .into_iter()
            .map(|store| {
                let node = node.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    for _ in 0..PER {
                        let mut row = make_row(&uniq("evt"), "TEST_ALLOC");
                        row.origin_id = row.id.clone();
                        row.monotonic_seq = 0;
                        row.source_node_id = node.clone();
                        crate::AuditStore::insert(&*store, &row).expect("insert");
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("writer thread");
        }

        let mut c = pg::Client::connect(&dsn, pg::NoTls).expect("connect");
        let rows = c
            .query(
                &format!(
                    "SELECT monotonic_seq, hash, prev_hash FROM {table}                      WHERE source_node_id = $1 ORDER BY monotonic_seq"
                ),
                &[&node],
            )
            .expect("query");
        let seqs: Vec<i64> = rows.iter().map(|r| r.get(0)).collect();
        assert_eq!(seqs, (1..=(2 * PER) as i64).collect::<Vec<_>>());
        let mut prev = "genesis".to_string();
        for r in &rows {
            assert_eq!(r.get::<_, &str>(2), prev);
            prev = r.get(1);
            assert_eq!(prev.len(), 64);
        }
        assert_verifies(&PostgresStore::new(&dsn, table).expect("reader"), &node, 2 * PER);
    }

    fn assert_verifies(store: &PostgresStore, node: &str, rows: usize) {
        let chain = store.chain_rows(node).expect("chain_rows");
        assert_eq!(chain.len(), rows);
        let result = crate::verify_chain(&chain);
        assert!(result.ok, "{result:?}");
    }

    fn emit_row(node: &str, code: &str) -> crate::Row {
        let mut row = make_row(&uniq("evt"), code);
        row.monotonic_seq = 0;
        row.source_node_id = node.into();
        // Numbers the hash must render as Python does.
        row.detail.insert("setpoint".into(), serde_json::json!(75.0));
        row.detail.insert("small".into(), serde_json::json!(1e-7));
        row.detail.insert("big".into(), serde_json::json!(u64::MAX));
        row
    }

    // Two engines on one node, one in raise mode and one draining a queue,
    // each with its own connection, write one unbroken chain.
    #[test]
    fn test_two_engines_write_one_chain() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_chain_engines";
        drop(fresh_store(&dsn, table));
        crate::register(
            "pg_chain".into(),
            [("PG_CHAIN_EVENT".to_string(), crate::Meta { domain: "pg_chain".into(), ..Default::default() })],
        )
        .expect("register");
        let node = uniq("node");
        const PER: usize = 40;

        let engines: Vec<_> = ["raise", "queue"]
            .into_iter()
            .map(|strategy| {
                let engine = crate::Engine::new();
                engine
                    .init(crate::Config {
                        service_id: format!("svc-chain-{strategy}"),
                        node_id: node.clone(),
                        audit_store: Some(std::sync::Arc::new(
                            PostgresStore::new(&dsn, table).expect("PostgresStore::new"),
                        )),
                        audit_store_failure_strategy: Some(strategy.into()),
                        ..Default::default()
                    })
                    .expect("init");
                std::sync::Arc::new(engine)
            })
            .collect();
        // Both engines start emitting at once.
        let start = std::sync::Arc::new(std::sync::Barrier::new(engines.len()));
        let handles: Vec<_> = engines
            .iter()
            .map(|engine| {
                let engine = engine.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    let mut detail = HashMap::new();
                    detail.insert("setpoint".to_string(), serde_json::json!(75.0));
                    start.wait();
                    (0..PER)
                        .map(|_| {
                            crate::EmitBuilder::new("PG_CHAIN_EVENT", "t")
                                .detail(detail.clone())
                                .submit_to(&engine)
                                .expect("submit")
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let emitted: Vec<Vec<crate::Row>> =
            handles.into_iter().map(|h| h.join().expect("emitter thread")).collect();
        for engine in &engines {
            assert!(engine.flush(std::time::Duration::from_secs(20)));
            engine.reset_for_tests();
        }

        let reader = PostgresStore::new(&dsn, table).expect("reader");
        let chain = reader.chain_rows(&node).expect("chain_rows");
        let seqs: Vec<u64> = chain.iter().map(|r| r.monotonic_seq).collect();
        assert_eq!(seqs, (1..=(2 * PER) as u64).collect::<Vec<_>>());
        let mut prev = "genesis";
        for r in &chain {
            assert_eq!(r.prev_hash, prev, "seq {}", r.monotonic_seq);
            prev = &r.hash;
        }
        let result = crate::verify_chain(&chain);
        assert!(result.ok, "{result:?}");

        // Raise mode returned each row as stored; queue mode as built.
        for row in &emitted[0] {
            let stored = chain.iter().find(|r| r.id == row.id).expect("stored");
            assert_eq!((row.monotonic_seq, &row.hash), (stored.monotonic_seq, &stored.hash));
        }
        assert!(emitted[1].iter().all(|r| r.monotonic_seq == 0 && r.hash.is_empty()));
        // Each stored row went to stdout twice, the sealed line second.
        let stdout = crate::engine::AUDIT_STDOUT.lock().unwrap();
        for row in emitted.iter().flatten() {
            let lines: Vec<_> = stdout.iter().filter(|l| l["id"] == row.id.as_str()).collect();
            assert_eq!(lines.len(), 2, "{}", row.id);
            assert_eq!(lines[0]["hash"], "");
            let stored = chain.iter().find(|r| r.id == row.id).expect("stored");
            assert_eq!(lines[1]["hash"], stored.hash.as_str());
        }
    }

    // A new store on the table picks the chain up from the stored tip.
    #[test]
    fn test_restart_continues_the_chain() {
        use crate::AuditStore;
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_chain_restart";
        let node = uniq("node");
        let store = fresh_store(&dsn, table);
        let mut last = String::new();
        for _ in 0..3 {
            last = store.allocate_and_insert_originated(&emit_row(&node, "TEST_CHAIN")).expect("insert").hash;
        }
        drop(store);
        let store = PostgresStore::new(&dsn, table).expect("reopen");
        let next = store.allocate_and_insert_originated(&emit_row(&node, "TEST_CHAIN")).expect("insert");
        assert_eq!((next.monotonic_seq, &next.prev_hash), (4, &last));
        for _ in 0..2 {
            store.insert(&emit_row(&node, "TEST_CHAIN")).expect("insert");
        }
        assert_verifies(&store, &node, 6);
    }

    // A retried row comes back as it was stored, not sealed again.
    #[test]
    fn test_retry_returns_the_stored_seal() {
        use crate::AuditStore;
        let Some(dsn) = dsn() else { return };
        let store = fresh_store(&dsn, "fasten_pg_chain_retry");
        let node = uniq("node");
        let row = emit_row(&node, "TEST_CHAIN");
        let first = store.allocate_and_insert_originated(&row).expect("insert");
        let again = store.allocate_and_insert_originated(&row).expect("retry");
        assert_eq!(first.canonical_form_id, "2");
        assert_eq!(
            (again.monotonic_seq, &again.prev_hash, &again.hash, &again.detail_salt, &again.detail_commitment),
            (1, &first.prev_hash, &first.hash, &first.detail_salt, &first.detail_commitment)
        );
        assert_verifies(&store, &node, 1);
    }

    // Another row under a stored id is refused, not handed that row's seal.
    #[test]
    fn test_a_different_row_at_a_stored_id_is_refused() {
        use crate::AuditStore;
        let Some(dsn) = dsn() else { return };
        let store = fresh_store(&dsn, "fasten_pg_chain_differs");
        let node = uniq("node");
        let row = emit_row(&node, "TEST_CHAIN");
        let first = store.allocate_and_insert_originated(&row).expect("insert");
        let other = crate::Row { target: "resource-43".into(), ..row.clone() };
        let err = store.allocate_and_insert_originated(&other).unwrap_err();
        assert!(matches!(&err, crate::Error::AuditStoreRejected(m) if m.contains("differs")), "{err:?}");

        // A row with its own seq: the same row again is returned as stored,
        // and the id at another seq is refused. Nothing is written twice.
        let own = crate::Row { monotonic_seq: 9, ..emit_row(&node, "TEST_CHAIN") };
        let stored = store.allocate_and_insert_originated(&own).expect("own seq");
        assert_eq!((stored.monotonic_seq, stored.hash.as_str()), (9, ""));
        let again = store.allocate_and_insert_originated(&own).expect("same row again");
        assert_eq!((again.monotonic_seq, again.hash.as_str()), (9, ""));
        let moved = crate::Row { monotonic_seq: 10, ..own.clone() };
        let err = store.allocate_and_insert_originated(&moved).unwrap_err();
        assert!(matches!(err, crate::Error::AuditStoreRejected(_)), "{err:?}");
        // The stored id is not a new row for seq 0 either: no seq is taken.
        let as_new = crate::Row { monotonic_seq: 0, target: "resource-44".into(), ..own };
        assert!(store.allocate_and_insert_originated(&as_new).is_err());

        let chain = store.chain_rows(&node).expect("chain_rows");
        assert_eq!(chain.iter().map(|r| r.monotonic_seq).collect::<Vec<_>>(), [1, 9]);
        assert_eq!(chain[0].hash, first.hash);
    }

    // A row sealed here must be one this node originated, as in the Python
    // and Go stores. The refused row takes no seq.
    #[test]
    fn test_rejects_foreign_origin() {
        use crate::AuditStore;
        let Some(dsn) = dsn() else { return };
        let store = fresh_store(&dsn, "fasten_pg_chain_origin");
        let node = uniq("node");
        store.insert(&emit_row(&node, "TEST_CHAIN")).expect("insert");
        let foreign = crate::Row { origin_id: "evt-somewhere-else".into(), ..emit_row(&node, "TEST_CHAIN") };
        let err = store.allocate_and_insert_originated(&foreign).unwrap_err();
        assert!(matches!(&err, crate::Error::AuditStoreRejected(m) if m.contains("origin_id == id")), "{err:?}");
        let next = store.allocate_and_insert_originated(&emit_row(&node, "TEST_CHAIN")).expect("insert");
        assert_eq!(next.monotonic_seq, 2);
        assert_verifies(&store, &node, 2);
    }

    /// The rows of a vector file, as another SDK sealed them.
    fn vector_rows(file: &str, label: Option<&str>) -> Vec<ChainRow> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec").join(file);
        let file = crate::Json::parse(&std::fs::read_to_string(path).expect("vector")).expect("json");
        let rows: Vec<crate::Json> = match file.get("cases") {
            Some(cases) => cases
                .as_array()
                .expect("cases")
                .iter()
                .filter(|c| label.is_none() || c.get("label").and_then(crate::Json::as_str) == label)
                .map(|c| c.get("row").expect("row").clone())
                .collect(),
            None => file.as_array().expect("rows").to_vec(),
        };
        rows.iter().map(|r| ChainRow::from_value(r).expect("row")).collect()
    }

    /// Insert vector rows with plain SQL, as the SDK that sealed them would:
    /// `detail` is the text in the file. `ts_cast` is "::timestamptz" for a
    /// Go-shaped table.
    fn sql_insert(c: &mut pg::Client, table: &str, ts_cast: &str, rows: &[ChainRow]) {
        let sql = format!(
            "INSERT INTO {table} (id, wire_version, origin_id, monotonic_seq, timestamp, code, action, \
             severity, service_id, source_node_id, tenant_id, actor, actor_kind, target, category, domain, \
             method, request_id, detail, prev_hash, hash, canonical_form_id, detail_salt, detail_commitment) \
             VALUES ($1, $2, $3, $4, $5::text{ts_cast}, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
             $17, $18, $19, $20, $21, $22, $23, $24)"
        );
        for r in rows {
            let seq = r.monotonic_seq as i64;
            let detail = r.detail.to_string();
            let salt = r.detail_salt.clone().unwrap_or_default();
            let commitment = r.detail_commitment.clone().unwrap_or_default();
            c.execute(
                sql.as_str(),
                &[
                    &r.id, &r.wire_version, &r.origin_id, &seq, &r.timestamp, &r.code, &r.action,
                    &r.severity, &r.service_id, &r.source_node_id, &r.tenant_id, &r.actor, &r.actor_kind,
                    &r.target, &r.category, &r.domain, &r.method, &r.request_id, &detail, &r.prev_hash,
                    &r.hash, &r.canonical_form_id, &salt, &commitment,
                ],
            )
            .expect("insert vector row");
        }
    }

    /// Go's rows on node-1 and a Python row with numeric detail, then a row
    /// of ours: it takes the next seq and links to the Go tip.
    fn assert_extends_other_sdks(dsn: &str, store: &PostgresStore, table: &str, ts_cast: &str) {
        use crate::AuditStore;
        let mut c = pg::Client::connect(dsn, pg::NoTls).expect("connect");
        let go = vector_rows("go-sealed-form2.json", None);
        assert_eq!(go.len(), 2);
        sql_insert(&mut c, table, ts_cast, &go);
        let mine = store.allocate_and_insert_originated(&emit_row("node-1", "TEST_XSDK")).expect("insert");
        assert_eq!((mine.monotonic_seq, &mine.prev_hash), (3, &go[1].hash));
        let chain = store.chain_rows("node-1").expect("chain_rows");
        assert_eq!(chain[..2], go[..]);
        let result = crate::verify_chain(&chain);
        assert!(result.ok && result.sealed_rows == 3, "{result:?}");

        // Python's row is sealed for node-1 seq 1 too, so it gets a table of
        // its own chain: delete ours and Go's, then extend Python's.
        c.batch_execute(&format!("DELETE FROM {table}")).expect("clear");
        let python = vector_rows("python-sealed-forms.json", Some("form2_numbers"));
        assert_eq!(python.len(), 1);
        assert!(python[0].detail.to_string().contains("12345678901234567890"));
        sql_insert(&mut c, table, ts_cast, &python);
        let mine = store.allocate_and_insert_originated(&emit_row("node-1", "TEST_XSDK")).expect("insert");
        assert_eq!((mine.monotonic_seq, &mine.prev_hash), (2, &python[0].hash));
        let chain = store.chain_rows("node-1").expect("chain_rows");
        assert_eq!(chain[0], python[0]);
        let result = crate::verify_chain(&chain);
        assert!(result.ok && result.sealed_rows == 2, "{result:?}");
    }

    #[test]
    fn test_extends_a_go_and_a_python_chain() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_xsdk_text";
        let store = fresh_store(&dsn, table);
        assert_extends_other_sdks(&dsn, &store, table, "");
    }

    #[test]
    fn test_extends_a_go_and_a_python_chain_in_a_go_shaped_table() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_xsdk_go";
        let mut c = pg::Client::connect(&dsn, pg::NoTls).expect("connect");
        create_go_table(&mut c, table);
        let store = PostgresStore::new(&dsn, table).expect("PostgresStore::new");
        assert_extends_other_sdks(&dsn, &store, table, "::timestamptz");
    }

    // Rows sealed elsewhere over numbers a `Row` cannot hold keep their
    // hashes through `insert_sealed`.
    #[test]
    fn test_insert_sealed_keeps_the_detail_text() {
        let Some(dsn) = dsn() else { return };
        let store = fresh_store(&dsn, "fasten_pg_chain_exact");
        let node = uniq("node");
        let mut rows: Vec<ChainRow> = Vec::new();
        for (i, detail) in [r#"{"n":123456789012345678901234567890}"#, r#"{"n":-0}"#].iter().enumerate() {
            let line = serde_json::to_string(&crate::Row { monotonic_seq: i as u64 + 1, ..emit_row(&node, "TEST_X") })
                .expect("row json");
            let mut unsealed = ChainRow::from_json(&line).expect("chain row");
            unsealed.detail = crate::Json::parse(detail).expect("detail");
            let prev = rows.last().map_or(GENESIS.to_string(), |r| r.hash.clone());
            rows.push(fasten_core::chain::seal(&prev, &unsealed).expect("seal"));
        }
        for r in &rows {
            store.insert_sealed(r, true).expect("insert_sealed");
            store.insert_sealed(r, true).expect("the same row again");
        }
        let stored = store.chain_rows(&node).expect("chain_rows");
        assert_eq!(stored, rows);
        let result = crate::verify_chain(&stored);
        assert!(result.ok && result.sealed_rows == 2, "{result:?}");

        let other = ChainRow { hash: "ab".repeat(32), ..rows[0].clone() };
        let err = store.insert_sealed(&other, false).unwrap_err();
        assert!(matches!(&err, crate::Error::AuditStoreRejected(m) if m.contains("differs")), "{err:?}");
        let unsealed = ChainRow { hash: String::new(), id: uniq("evt"), ..rows[0].clone() };
        let err = store.insert_sealed(&unsealed, false).unwrap_err();
        assert!(matches!(err, crate::Error::AuditStoreRejected(_)), "{err:?}");
    }

    // A negative seq or a column of another type is a read error that names
    // the row and the column, not a panic.
    #[test]
    fn test_unreadable_rows_are_read_errors() {
        use crate::AuditStore;
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_chain_unreadable";
        let store = fresh_store(&dsn, table);
        let node = uniq("node");
        let row = store.allocate_and_insert_originated(&emit_row(&node, "TEST_CHAIN")).expect("insert");
        let mut c = pg::Client::connect(&dsn, pg::NoTls).expect("connect");
        c.batch_execute(&format!("UPDATE {table} SET monotonic_seq = -5")).expect("update");
        let err = store.chain_rows(&node).unwrap_err();
        assert!(matches!(&err, crate::Error::AuditStoreRead(m) if m.contains("monotonic_seq -5 is negative")), "{err:?}");
        let err = store.chain_tips().unwrap_err();
        assert!(matches!(err, crate::Error::AuditStoreRead(_)), "{err:?}");
        // Nothing is sealed over a negative next seq.
        assert!(store.allocate_and_insert_originated(&emit_row(&node, "TEST_CHAIN")).is_err());

        c.batch_execute(&format!(
            "UPDATE {table} SET monotonic_seq = 1; ALTER TABLE {table} ALTER COLUMN severity DROP DEFAULT, \
             ALTER COLUMN severity TYPE INT USING 1"
        ))
        .expect("alter");
        let err = store.chain_rows(&node).unwrap_err();
        let want = format!("row {}: column severity", row.id);
        assert!(matches!(&err, crate::Error::AuditStoreRead(m) if m.contains(&want)), "{err:?}");
    }

    // A changed field, a changed detail and a removed row each break the
    // chain at the row they touch.
    #[test]
    fn test_tampering_is_detected() {
        use crate::AuditStore;
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_chain_tamper";
        for (change, seq, reason) in [
            ("UPDATE {t} SET actor = 'mallory' WHERE monotonic_seq = 2", 2, "hash mismatch"),
            ("UPDATE {t} SET detail = '{\"key\":\"other\"}' WHERE monotonic_seq = 3", 3, "commitment"),
            ("DELETE FROM {t} WHERE monotonic_seq = 2", 3, "prev_hash does not match"),
        ] {
            let store = fresh_store(&dsn, table);
            let node = uniq("node");
            for _ in 0..4 {
                store.insert(&emit_row(&node, "TEST_CHAIN")).expect("insert");
            }
            assert_verifies(&store, &node, 4);
            store.lock().batch_execute(&change.replace("{t}", table)).expect("tamper");
            let result = crate::verify_chain(&store.chain_rows(&node).expect("chain_rows"));
            assert_eq!((result.ok, result.first_break_at), (false, Some(seq)), "{change}");
            assert!(result.reason.as_deref().unwrap_or("").contains(reason), "{change}: {result:?}");
        }
    }

    // Checkpoints of each node's tip show rows cut off the end of a chain,
    // which the chain alone does not.
    #[test]
    fn test_checkpoints_catch_a_cut_tail() {
        use crate::checkpoints::{
            load_checkpoints, publish_checkpoints, verify_chain_with_checkpoints, CheckpointOptions,
            FileCheckpointSink,
        };
        use crate::AuditStore;
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_checkpoints";
        let store = fresh_store(&dsn, table);
        let (a, b) = (uniq("node-a"), uniq("node-b"));
        for _ in 0..5 {
            store.insert(&emit_row(&a, "TEST_CHAIN")).expect("insert");
        }
        let mut tip_b = String::new();
        for _ in 0..3 {
            tip_b = store.allocate_and_insert_originated(&emit_row(&b, "TEST_CHAIN")).expect("insert").hash;
        }
        let tips: Vec<(String, u64, String)> = store
            .chain_tips()
            .expect("chain_tips")
            .into_iter()
            .map(|t| (t.source_node_id, t.monotonic_seq, t.hash))
            .collect();
        assert_eq!(tips.len(), 2);
        assert_eq!((tips[0].0.as_str(), tips[0].1), (a.as_str(), 5));
        assert_eq!(tips[1], (b.clone(), 3, tip_b));

        let file = std::env::temp_dir().join(format!("{}.jsonl", uniq("fasten-pg-checkpoints")));
        let published = publish_checkpoints(&store, &FileCheckpointSink::new(&file)).expect("publish");
        let checkpoints = load_checkpoints(&file).expect("load");
        let _ = std::fs::remove_file(&file);
        assert_eq!(checkpoints, published);
        let whole = CheckpointOptions::default();
        let rows = store.all_chain_rows().expect("all_chain_rows");
        assert_eq!(rows.len(), 8);
        let result = verify_chain_with_checkpoints(&rows, &checkpoints, whole);
        assert!(result.ok, "{result:?}");

        store
            .lock()
            .execute(&format!("DELETE FROM {table} WHERE source_node_id = $1 AND monotonic_seq > 3"), &[&a])
            .expect("cut");
        let rows = store.all_chain_rows().expect("all_chain_rows");
        assert!(crate::verify_chain(&rows).ok);
        let result = verify_chain_with_checkpoints(&rows, &checkpoints, whole);
        assert_eq!(result.first_break_at, Some(4));
        assert_eq!(
            result.reason,
            Some(format!("node '{a}': chain ends at seq 3 before checkpoint at seq 5"))
        );
        // One node's rows are a partial verify.
        let partial = CheckpointOptions::partial();
        assert!(verify_chain_with_checkpoints(&store.chain_rows(&b).expect("chain_rows"), &checkpoints, partial).ok);
    }

    // Rows an older Rust store wrote unsealed stay below the chain: the
    // first sealed row links to "genesis" and the node verifies.
    #[test]
    fn test_chain_starts_above_unsealed_rows() {
        use crate::AuditStore;
        let Some(dsn) = dsn() else { return };
        let store = fresh_store(&dsn, "fasten_pg_chain_legacy");
        let node = uniq("node");
        for seq in 1..=2 {
            let mut old = emit_row(&node, "TEST_CHAIN");
            old.monotonic_seq = seq;
            store.insert(&old).expect("insert unsealed");
        }
        let first = store.allocate_and_insert_originated(&emit_row(&node, "TEST_CHAIN")).expect("insert");
        assert_eq!((first.monotonic_seq, first.prev_hash.as_str()), (3, "genesis"));
        store.insert(&emit_row(&node, "TEST_CHAIN")).expect("insert");
        assert_verifies(&store, &node, 4);
    }

    // A retried insert of a row that already landed takes no new seq.
    #[test]
    fn test_retry_does_not_burn_seq() {
        let Some(dsn) = dsn() else { return };
        let store = PostgresStore::new(&dsn, "fasten_pg_test").expect("PostgresStore::new");
        let node = uniq("node");
        let mut first = make_row(&uniq("evt"), "TEST_RETRY");
        first.monotonic_seq = 0;
        first.source_node_id = node.clone();
        crate::AuditStore::insert(&store, &first).expect("insert");
        crate::AuditStore::insert(&store, &first).expect("retry");
        let mut second = make_row(&uniq("evt"), "TEST_RETRY");
        second.monotonic_seq = 0;
        second.source_node_id = node.clone();
        crate::AuditStore::insert(&store, &second).expect("insert second");

        let rows = store
            .lock()
            .query(
                "SELECT monotonic_seq FROM fasten_pg_test WHERE source_node_id = $1                  ORDER BY monotonic_seq",
                &[&node],
            )
            .expect("query");
        let seqs: Vec<i64> = rows.iter().map(|r| r.get(0)).collect();
        assert_eq!(seqs, vec![1, 2]);
    }

    // Timestamps are written in the canonical form the other SDKs write.
    #[test]
    fn test_canonical_timestamp() {
        let Some(dsn) = dsn() else { return };
        let store = PostgresStore::new(&dsn, "fasten_pg_test").expect("PostgresStore::new");
        let mut row = make_row(&uniq("evt"), "TEST_TS");
        row.timestamp = "2026-01-02T03:04:05Z".parse().unwrap();
        row.shipped_at = Some("2026-01-02T03:04:06.5Z".parse().unwrap());
        crate::AuditStore::insert(&store, &row).expect("insert");
        let r = store
            .lock()
            .query_one(
                "SELECT timestamp, shipped_at FROM fasten_pg_test WHERE id = $1",
                &[&row.id],
            )
            .expect("query");
        assert_eq!(r.get::<_, &str>(0), "2026-01-02T03:04:05.000000Z");
        assert_eq!(r.get::<_, Option<&str>>(1), Some("2026-01-02T03:04:06.500000Z"));
    }

    fn create_go_table(c: &mut pg::Client, table: &str) {
        c.batch_execute(&format!(
            "DROP TABLE IF EXISTS {table};
             CREATE TABLE {table} (
                id TEXT PRIMARY KEY, origin_id TEXT NOT NULL, monotonic_seq BIGINT NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL, code TEXT NOT NULL, action TEXT NOT NULL,
                severity TEXT NOT NULL, service_id TEXT NOT NULL, source_node_id TEXT NOT NULL,
                tenant_id TEXT, actor TEXT NOT NULL, actor_kind TEXT NOT NULL,
                target TEXT NOT NULL, category TEXT NOT NULL, domain TEXT NOT NULL,
                method TEXT NOT NULL, request_id TEXT NOT NULL, detail TEXT NOT NULL,
                pii_in_detail SMALLINT NOT NULL DEFAULT 0, shipped_at TIMESTAMPTZ,
                wire_version TEXT NOT NULL DEFAULT '1', hash TEXT NOT NULL DEFAULT '',
                prev_hash TEXT NOT NULL DEFAULT '', canonical_form_id TEXT NOT NULL DEFAULT '1',
                detail_salt TEXT NOT NULL DEFAULT '', detail_commitment TEXT NOT NULL DEFAULT '')"
        ))
        .expect("create go table");
    }

    // Rows go into a Go-shaped table: TIMESTAMPTZ timestamps, NOT NULL salt.
    #[test]
    fn test_insert_into_go_shaped_table() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_go_shape";
        let mut c = pg::Client::connect(&dsn, pg::NoTls).expect("connect");
        create_go_table(&mut c, table);
        let store = PostgresStore::new(&dsn, table).expect("PostgresStore::new");
        let mut row = make_row(&uniq("evt"), "TEST_GO");
        row.monotonic_seq = 0;
        row.shipped_at = Some(chrono::Utc::now());
        crate::AuditStore::insert(&store, &row).expect("insert");
        assert_verifies(&store, &row.source_node_id, 1);
        let codes = vec!["TEST_GO".to_string()];
        let later = chrono::Utc::now() + chrono::Duration::hours(1);
        let found = crate::AuditStore::list_redaction_candidates(&store, later, &codes)
            .expect("candidates");
        assert_eq!(found.len(), 1);
        crate::AuditStore::redact_rows(&store, &[row.id.clone()]).expect("redact");
        let r = c
            .query_one(
                &format!("SELECT monotonic_seq, detail, detail_salt FROM {table} WHERE id = $1"),
                &[&row.id],
            )
            .expect("query");
        assert_eq!(r.get::<_, i64>(0), 1);
        assert_eq!(r.get::<_, &str>(1), "null");
        assert_eq!(r.get::<_, &str>(2), "");
        assert_verifies(&store, &row.source_node_id, 1);
    }

    // A mixed-case name folds to lowercase, so the TIMESTAMPTZ cast still applies.
    #[test]
    fn test_insert_into_mixed_case_go_table() {
        let Some(dsn) = dsn() else { return };
        let table = "Fasten_Go_Mixed";
        let mut c = pg::Client::connect(&dsn, pg::NoTls).expect("connect");
        create_go_table(&mut c, table);
        let store = PostgresStore::new(&dsn, table).expect("PostgresStore::new");
        let mut row = make_row(&uniq("evt"), "TEST_GO_MIXED");
        row.monotonic_seq = 0;
        row.shipped_at = Some(chrono::Utc::now());
        crate::AuditStore::insert(&store, &row).expect("insert");
        let n: i64 = c
            .query_one(&format!("SELECT count(*) FROM {table} WHERE id = $1"), &[&row.id])
            .expect("query")
            .get(0);
        assert_eq!(n, 1);
    }

    #[test]
    fn test_node_seq_index_created() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_seq_index";
        let _store = fresh_store(&dsn, table);
        let mut c = pg::Client::connect(&dsn, pg::NoTls).expect("connect");
        let r = c
            .query_one(
                "SELECT indexdef FROM pg_indexes WHERE tablename = $1 AND indexname = $2",
                &[&table, &format!("idx_{table}_node_seq")],
            )
            .expect("index exists");
        let def: &str = r.get(0);
        assert!(def.contains("(source_node_id, monotonic_seq)"), "{def}");
        assert!(!def.contains("UNIQUE"), "{def}");
    }

    #[test]
    fn test_index_name_fits_identifier_limit() {
        assert_eq!(index_name("audit_logs", "node_seq"), "idx_audit_logs_node_seq");
        let long = "a".repeat(63);
        let names: std::collections::HashSet<String> = ["req", "code", "ts", "svc", "node_seq"]
            .iter()
            .map(|s| index_name(&long, s))
            .collect();
        assert_eq!(names.len(), 5);
        for n in &names {
            assert!(n.len() <= 63, "{n}");
        }
        let other = format!("{}b", "a".repeat(62));
        assert_ne!(index_name(&long, "node_seq"), index_name(&other, "node_seq"));
    }

    #[test]
    fn test_node_seq_index_created_for_long_table_name() {
        let Some(dsn) = dsn() else { return };
        let table = format!("fasten_pg_long_{}", "x".repeat(45));
        assert_eq!(table.len(), 60);
        let _store = fresh_store(&dsn, &table);
        let mut c = pg::Client::connect(&dsn, pg::NoTls).expect("connect");
        let defs: Vec<String> = c
            .query("SELECT indexdef FROM pg_indexes WHERE tablename = $1", &[&table])
            .expect("indexes")
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert!(
            defs.iter().any(|d| d.contains("(source_node_id, monotonic_seq)")),
            "{defs:?}"
        );
        // Five indexes plus the primary key.
        assert_eq!(defs.len(), 6, "{defs:?}");
    }

    #[test]
    fn test_redact_expired() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_redact_test";
        let store = std::sync::Arc::new(fresh_store(&dsn, table));

        crate::register(
            "pg_redact".into(),
            [
                (
                    "PG_REDACT_PII".to_string(),
                    crate::Meta {
                        domain: "pg_redact".into(),
                        severity: crate::Severity::Info,
                        pii_in_detail: true,
                        ..Default::default()
                    },
                ),
                (
                    "PG_REDACT_PLAIN".to_string(),
                    crate::Meta {
                        domain: "pg_redact".into(),
                        severity: crate::Severity::Info,
                        retention_class: crate::RetentionClass::Long,
                        ..Default::default()
                    },
                ),
            ],
        )
        .expect("register");

        let node = uniq("node");
        let old = chrono::Utc::now() - chrono::Duration::days(40);
        let mut pii = make_row(&uniq("evt"), "PG_REDACT_PII");
        let mut plain = make_row(&uniq("evt"), "PG_REDACT_PLAIN");
        for r in [&mut pii, &mut plain] {
            r.monotonic_seq = 0;
            r.source_node_id = node.clone();
            r.timestamp = old;
            crate::AuditStore::insert(&*store, r).expect("insert");
        }
        // A sealed form-"1" row: its detail is in the hash, so it stays.
        let sealed_id = uniq("evt");
        store
            .lock()
            .execute(
                &format!(
                    "INSERT INTO {table} (id, origin_id, monotonic_seq, timestamp, code,                      source_node_id, detail, prev_hash, hash, canonical_form_id)                      VALUES ($1, $1, 99, '2020-01-01T00:00:00.000000Z', 'PG_REDACT_PII',                      'other-node', '{{\"email\":\"a@b.c\"}}', 'genesis', 'abc123', '1')"
                ),
                &[&sealed_id],
            )
            .expect("insert sealed");

        let engine = crate::Engine::new();
        engine
            .init(crate::Config {
                service_id: "svc-redact".into(),
                node_id: node.clone(),
                audit_store: Some(store.clone()),
                audit_store_failure_strategy: Some("raise".into()),
                ..Default::default()
            })
            .expect("init");
        let cutoff = chrono::Utc::now() - chrono::Duration::days(30);
        let redacted = engine.redact_expired(cutoff, "pii-30d").expect("redact_expired");
        assert_eq!(redacted, vec![pii.id.clone()]);

        let mut c = pg::Client::connect(&dsn, pg::NoTls).expect("connect");
        let detail_of = |c: &mut pg::Client, id: &str| -> String {
            c.query_one(&format!("SELECT detail FROM {table} WHERE id = $1"), &[&id])
                .expect("query")
                .get(0)
        };
        assert_eq!(detail_of(&mut c, &pii.id), "null");
        assert_eq!(detail_of(&mut c, &plain.id), r#"{"key":"value"}"#);
        assert_eq!(detail_of(&mut c, &sealed_id), r#"{"email":"a@b.c"}"#);

        let events = c
            .query(
                &format!(
                    "SELECT target, detail, monotonic_seq FROM {table} WHERE code = $1"
                ),
                &[&crate::AUDIT_ROW_REDACTED],
            )
            .expect("query events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].get::<_, &str>(0), pii.id);
        let detail: serde_json::Value =
            serde_json::from_str(events[0].get::<_, &str>(1)).expect("detail json");
        assert_eq!(detail["redacted_id"], serde_json::json!(pii.id));
        assert_eq!(detail["redacted_seq"], serde_json::json!(1));
        assert_eq!(detail["reason"], serde_json::json!("pii-30d"));
        assert_eq!(events[0].get::<_, i64>(2), 3);

        // Nothing left to do on a second pass.
        assert!(engine.redact_expired(cutoff, "pii-30d").expect("again").is_empty());
        // The redacted row kept its hash, lost its salt, and the node's
        // chain, redaction record included, still verifies.
        let chain = store.chain_rows(&node).expect("chain_rows");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].detail, crate::Json::Null);
        assert_eq!(chain[0].detail_salt, None);
        assert_eq!(chain[2].code, crate::AUDIT_ROW_REDACTED);
        let result = crate::verify_chain(&chain);
        assert!(result.ok, "{result:?}");
        let salt: String = c
            .query_one(&format!("SELECT detail_salt FROM {table} WHERE id = $1"), &[&pii.id])
            .expect("query")
            .get(0);
        assert_eq!(salt, "");
        engine.reset_for_tests();
    }

    // A sealed form-"1" PII row past the cutoff is left alone and reported.
    #[test]
    fn test_redact_reports_sealed_form1() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_redact_form1";
        let store = std::sync::Arc::new(fresh_store(&dsn, table));
        crate::register(
            "pg_form1".into(),
            [(
                "PG_FORM1_PII".to_string(),
                crate::Meta {
                    domain: "pg_form1".into(),
                    severity: crate::Severity::Info,
                    pii_in_detail: true,
                    ..Default::default()
                },
            )],
        )
        .expect("register");
        let sealed_id = uniq("evt");
        store
            .lock()
            .execute(
                &format!(
                    "INSERT INTO {table} (id, origin_id, monotonic_seq, timestamp, code, \
                     source_node_id, detail, prev_hash, hash, canonical_form_id) \
                     VALUES ($1, $1, 1, '2020-01-01T00:00:00.000000Z', 'PG_FORM1_PII', \
                     'node-f1', '{{\"email\":\"a@b.c\"}}', 'genesis', 'abc123', '1')"
                ),
                &[&sealed_id],
            )
            .expect("insert sealed");

        let engine = crate::Engine::new();
        engine
            .init(crate::Config {
                service_id: "svc-redact-form1".into(),
                node_id: "node-f1".into(),
                audit_store: Some(store.clone()),
                audit_store_failure_strategy: Some("raise".into()),
                ..Default::default()
            })
            .expect("init");
        let cutoff = chrono::Utc::now() - chrono::Duration::days(30);
        let redacted = engine.redact_expired(cutoff, "pii-30d").expect("redact_expired");
        assert!(redacted.is_empty());

        let mut c = pg::Client::connect(&dsn, pg::NoTls).expect("connect");
        let detail: String = c
            .query_one(&format!("SELECT detail FROM {table} WHERE id = $1"), &[&sealed_id])
            .expect("query")
            .get(0);
        assert_eq!(detail, r#"{"email":"a@b.c"}"#);

        let lines: Vec<serde_json::Value> = crate::engine::SYS_CAPTURE
            .lock()
            .unwrap()
            .iter()
            .filter(|v| {
                v["service_id"] == "svc-redact-form1"
                    && v["event"] == "pii_redaction_skipped_legacy_form"
            })
            .cloned()
            .collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["level"], "warn");
        assert_eq!(lines[0]["rows"], 1);
        engine.reset_for_tests();
    }

    // Only the rows the UPDATE matched come back.
    #[test]
    fn test_redact_rows_returns_matched_ids() {
        use crate::AuditStore;
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_redact_rows_ids";
        let store = fresh_store(&dsn, table);
        let unsealed = uniq("evt");
        store.insert(&make_row(&unsealed, "PG_RR")).expect("insert");
        let sealed = uniq("evt");
        store
            .lock()
            .execute(
                &format!(
                    "INSERT INTO {table} (id, origin_id, monotonic_seq, timestamp, code, \
                     source_node_id, detail, prev_hash, hash, canonical_form_id) \
                     VALUES ($1, $1, 2, '2020-01-01T00:00:00.000000Z', 'PG_RR', \
                     'node-1', '{{}}', 'genesis', 'abc123', '1')"
                ),
                &[&sealed],
            )
            .expect("insert sealed");
        let ids = vec![unsealed.clone(), sealed, uniq("missing")];
        assert_eq!(store.redact_rows(&ids).expect("redact_rows"), vec![unsealed]);
    }

    #[test]
    fn test_invalid_table_name_returns_error() {
        // Validation runs before connecting, so no DSN is needed.
        let result = PostgresStore::new("host=localhost user=test", "bad-name!");
        assert!(
            result.is_err(),
            "expected error for invalid table name, got Ok"
        );
    }

    #[test]
    fn test_connection_error_maps_to_audit_store_error() {
        let result =
            PostgresStore::new("host=127.0.0.1 port=1 user=nobody dbname=nobody", "audit");
        assert!(result.is_err(), "expected error for unreachable host");
    }
}
