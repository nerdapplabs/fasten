//! PostgreSQL-backed AuditStore (sync, `postgres` crate).
//! Enable with: fasten = { features = ["store-postgres"] }
//!
//! Uses the synchronous `postgres` crate (aliased as `pg`) so the impl
//! satisfies the sync `AuditStore` trait without requiring a Tokio runtime.
//! The inner `postgres::Client` is wrapped in a `Mutex` to satisfy `Send +
//! Sync` and allow shared use across the drainer thread.

use std::sync::Mutex;

use pg::types::ToSql;

// ── Table name validation ─────────────────────────────────────────────────
//
// Accept: identifier  OR  schema.table
// Pattern: ^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$
//
// We hand-roll the check to avoid pulling in the `regex` crate.

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
    let ok = schema.map_or(true, is_valid_identifier) && is_valid_identifier(bare);
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

// ── Schema + table bootstrap ──────────────────────────────────────────────

fn pg_err(e: pg::Error) -> crate::Error {
    let msg = match e.as_db_error() {
        Some(db) => format!("{e}: {}", db.message()),
        None => e.to_string(),
    };
    crate::Error::AuditStoreInsert(msg)
}

fn ensure_schema(client: &mut pg::Client, schema: &str) -> Result<(), crate::Error> {
    let sql = format!("CREATE SCHEMA IF NOT EXISTS {schema}");
    client.execute(&sql, &[]).map_err(pg_err)?;
    Ok(())
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

    for sql in &[
        format!("CREATE INDEX IF NOT EXISTS idx_{bare}_req  ON {table} (request_id)"),
        format!("CREATE INDEX IF NOT EXISTS idx_{bare}_code ON {table} (code)"),
        format!("CREATE INDEX IF NOT EXISTS idx_{bare}_ts   ON {table} (timestamp)"),
        format!("CREATE INDEX IF NOT EXISTS idx_{bare}_svc  ON {table} (service_id)"),
    ] {
        client.execute(sql.as_str(), &[]).map_err(pg_err)?;
    }
    Ok(())
}

/// What the existing table's columns allow. The Go store keeps timestamps as
/// TIMESTAMPTZ and detail_salt as NOT NULL; Python keeps TEXT and nullable.
struct Columns {
    ts_cast: &'static str,
    shipped_cast: &'static str,
    salt_nullable: bool,
}

fn inspect_columns(
    client: &mut pg::Client,
    schema: Option<&str>,
    bare: &str,
) -> Result<Columns, crate::Error> {
    let rows = client
        .query(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns \
             WHERE table_schema = COALESCE($1::text, current_schema()) AND table_name = $2",
            &[&schema, &bare],
        )
        .map_err(pg_err)?;
    let mut cols = Columns { ts_cast: "", shipped_cast: "", salt_nullable: true };
    for r in rows {
        let name: &str = r.get(0);
        let dtype: &str = r.get(1);
        let nullable: &str = r.get(2);
        let cast = if dtype.starts_with("timestamp") { "::timestamptz" } else { "" };
        match name {
            "timestamp" => cols.ts_cast = cast,
            "shipped_at" => cols.shipped_cast = cast,
            "detail_salt" => cols.salt_nullable = nullable == "YES",
            _ => {}
        }
    }
    Ok(cols)
}

// ── PostgresStore ─────────────────────────────────────────────────────────

/// Synchronous PostgreSQL audit store backed by the `postgres` crate.
///
/// Obtain one via [`PostgresStore::new`] and wrap it in an `Arc` before
/// passing to [`crate::Config::audit_store`].
///
/// A row with `monotonic_seq` 0 (what `emit` returns) gets the node's next
/// seq in the insert transaction, under the same per-node advisory lock as
/// the Python, Go and JS stores (spec §2.1). Rows are not sealed: `hash` and
/// `prev_hash` are empty.
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
    /// Bare table name (without schema prefix), used to name indexes.
    /// Exposed for reader implementations that need to reference index names.
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

        let mut client = pg::Client::connect(dsn, pg::NoTls).map_err(pg_err)?;

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
}

impl crate::AuditStore for PostgresStore {
    fn insert(&self, row: &crate::Row) -> Result<(), crate::Error> {
        let detail_json = serde_json::to_string(&row.detail)?;
        let timestamp = crate::canonical_ts(&row.timestamp);
        let shipped_at = row.shipped_at.as_ref().map(crate::canonical_ts);
        let pii_in_detail: i16 = if row.pii_in_detail { 1 } else { 0 };
        let severity = row.severity.to_string();

        // detail_salt / detail_commitment are '' rather than NULL: the Go
        // store reads them as strings.
        let sql = format!(
            "INSERT INTO {} \
             (id, wire_version, origin_id, monotonic_seq, timestamp, \
              code, action, severity, service_id, source_node_id, tenant_id, \
              actor, actor_kind, target, category, domain, method, \
              request_id, detail, pii_in_detail, shipped_at, \
              prev_hash, hash, detail_salt, detail_commitment) \
             VALUES \
             ($1, $2, $3, $4, $5::text{}, \
              $6, $7, $8, $9, $10, $11, \
              $12, $13, $14, $15, $16, $17, \
              $18, $19, $20, $21::text{}, \
              $22, $23, '', '') \
             ON CONFLICT (id) DO NOTHING",
            self.table, self.cols.ts_cast, self.cols.shipped_cast
        );

        let tenant: Option<&str> = row.tenant_id.as_deref();
        let shipped: Option<&str> = shipped_at.as_deref();

        let mut guard = self.lock();
        let mut tx = guard.transaction().map_err(pg_err)?;

        let mut monotonic_seq = row.monotonic_seq as i64;
        if monotonic_seq == 0 {
            tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&row.source_node_id],
            )
            .map_err(pg_err)?;
            // A retry of a row that already landed must not take a new seq.
            let exists = tx
                .query_opt(&format!("SELECT 1 FROM {} WHERE id = $1", self.table), &[&row.id])
                .map_err(pg_err)?;
            if exists.is_some() {
                return tx.commit().map_err(pg_err);
            }
            monotonic_seq = tx
                .query_one(
                    &format!(
                        "SELECT COALESCE(MAX(monotonic_seq), 0) + 1 FROM {} \
                         WHERE source_node_id = $1",
                        self.table
                    ),
                    &[&row.source_node_id],
                )
                .map_err(pg_err)?
                .get(0);
        }

        let params: &[&(dyn ToSql + Sync)] = &[
            &row.id,
            &row.wire_version,
            &row.origin_id,
            &monotonic_seq,
            &timestamp,
            &row.code,
            &row.action,
            &severity,
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
            &detail_json,
            &pii_in_detail,
            &shipped,
            &row.prev_hash,
            &row.hash,
        ];
        tx.execute(&sql as &str, params).map_err(pg_err)?;
        tx.commit().map_err(pg_err)
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
        let rows = self.lock().query(&sql as &str, &[&before, &codes]).map_err(pg_err)?;
        Ok(rows
            .iter()
            .map(|r| crate::RedactionCandidate {
                id: r.get(0),
                monotonic_seq: r.get::<_, i64>(1) as u64,
            })
            .collect())
    }

    fn redact_rows(&self, ids: &[String]) -> Result<Vec<String>, crate::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let salt = if self.cols.salt_nullable { "NULL" } else { "''" };
        let sql = format!(
            "UPDATE {} SET detail = 'null', detail_salt = {salt} \
             WHERE id = ANY($1) AND (hash = '' OR canonical_form_id = '2')",
            self.table
        );
        let ids_ref: Vec<&str> = ids.iter().map(String::as_str).collect();
        self.lock().execute(&sql as &str, &[&ids_ref]).map_err(pg_err)?;
        Ok(ids.to_vec())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn dsn() -> Option<String> {
        std::env::var("FASTEN_TEST_POSTGRES_DSN").ok()
    }

    /// Build a minimal Row for testing; fields not exercised here are set
    /// to sensible defaults.
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

    // ── insert + idempotency ──────────────────────────────────────────────

    #[test]
    fn test_insert_and_query() {
        let Some(dsn) = dsn() else { return };

        let store = PostgresStore::new(&dsn, "fasten_pg_test")
            .expect("PostgresStore::new");

        let row = make_row("evt-insert-test-00001", "TEST_INSERT");

        // First insert must succeed.
        crate::AuditStore::insert(&store, &row).expect("first insert");

        // Second insert of the same id must be idempotent (ON CONFLICT DO NOTHING).
        crate::AuditStore::insert(&store, &row).expect("idempotent insert");

        // Verify the row landed by querying directly through the Mutex'd client.
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

    // ── schema-qualified table name ───────────────────────────────────────

    #[test]
    fn test_schema_qualified_table() {
        let Some(dsn) = dsn() else { return };

        let store = PostgresStore::new(&dsn, "fasten_test_schema.audit_rows")
            .expect("PostgresStore::new with schema");

        let row = make_row("evt-schema-test-00001", "TEST_SCHEMA");
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

    // ── tenant_id + shipped_at (nullable columns) ─────────────────────────

    #[test]
    fn test_nullable_columns() {
        let Some(dsn) = dsn() else { return };

        let store = PostgresStore::new(&dsn, "fasten_pg_test")
            .expect("PostgresStore::new");

        let mut row = make_row("evt-nullable-test-00001", "TEST_NULLABLE");
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

    // ── pii_in_detail stored as SMALLINT 1 ───────────────────────────────

    #[test]
    fn test_pii_in_detail_flag() {
        let Some(dsn) = dsn() else { return };

        let store = PostgresStore::new(&dsn, "fasten_pg_test")
            .expect("PostgresStore::new");

        let mut row = make_row("evt-pii-test-00001", "TEST_PII");
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

    // ── seq allocation (spec §2.1, #92) ──────────────────────────────────

    // Two stores on one table, one node, writing at the same time: seqs must
    // be exactly 1..N, with no duplicates or gaps.
    #[test]
    fn test_two_stores_allocate_unique_seq() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_alloc_test";
        let a = std::sync::Arc::new(fresh_store(&dsn, table));
        let b = std::sync::Arc::new(PostgresStore::new(&dsn, table).expect("second store"));
        let node = uniq("node");
        const PER: usize = 25;

        let handles: Vec<_> = [a, b]
            .into_iter()
            .map(|store| {
                let node = node.clone();
                std::thread::spawn(move || {
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
        for r in &rows {
            assert_eq!(r.get::<_, &str>(1), "");
            assert_eq!(r.get::<_, &str>(2), "");
        }
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

    // Rows go into a Go-shaped table: TIMESTAMPTZ timestamps, NOT NULL salt.
    #[test]
    fn test_insert_into_go_shaped_table() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_pg_go_shape";
        let mut c = pg::Client::connect(&dsn, pg::NoTls).expect("connect");
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
        let store = PostgresStore::new(&dsn, table).expect("PostgresStore::new");
        let mut row = make_row(&uniq("evt"), "TEST_GO");
        row.monotonic_seq = 0;
        row.shipped_at = Some(chrono::Utc::now());
        crate::AuditStore::insert(&store, &row).expect("insert");
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
    }

    // ── PII redaction (spec §7) ───────────────────────────────────────────

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
        engine.reset_for_tests();
    }

    // ── error mapping ─────────────────────────────────────────────────────

    #[test]
    fn test_invalid_table_name_returns_error() {
        // No DSN needed — validation happens before connecting.
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
