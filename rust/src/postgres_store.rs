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
    crate::Error::AuditStoreInsert(e.to_string())
}

fn ensure_schema(client: &mut pg::Client, schema: &str) -> Result<(), crate::Error> {
    let sql = format!("CREATE SCHEMA IF NOT EXISTS {schema}");
    client.execute(&sql, &[]).map_err(pg_err)?;
    Ok(())
}

fn ensure_table(client: &mut pg::Client, table: &str, bare: &str) -> Result<(), crate::Error> {
    let create = format!(
        "CREATE TABLE IF NOT EXISTS {table} (
            id              TEXT        NOT NULL,
            wire_version    TEXT        NOT NULL DEFAULT '1',
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
            pii_in_detail   SMALLINT    NOT NULL DEFAULT 0,
            shipped_at      TEXT,
            PRIMARY KEY (id)
        )"
    );
    client.execute(&create, &[]).map_err(pg_err)?;

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

// ── PostgresStore ─────────────────────────────────────────────────────────

/// Synchronous PostgreSQL audit store backed by the `postgres` crate.
///
/// Obtain one via [`PostgresStore::new`] and wrap it in an `Arc` before
/// passing to [`crate::Config::audit_store`].
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

        if let Some(ref schema) = schema_opt {
            ensure_schema(&mut client, schema)?;
        }
        ensure_table(&mut client, &table, &bare)?;

        Ok(Self {
            client: Mutex::new(client),
            table,
            idx: bare,
        })
    }
}

impl crate::AuditStore for PostgresStore {
    fn insert(&self, row: &crate::Row) -> Result<(), crate::Error> {
        let detail_json = serde_json::to_string(&row.detail)?;
        let timestamp = row.timestamp.to_rfc3339();
        let shipped_at = row.shipped_at.as_ref().map(|t| t.to_rfc3339());
        let pii_in_detail: i16 = if row.pii_in_detail { 1 } else { 0 };
        let monotonic_seq = row.monotonic_seq as i64;
        let severity = row.severity.to_string();

        let sql = format!(
            "INSERT INTO {} \
             (id, wire_version, origin_id, monotonic_seq, timestamp, \
              code, action, severity, service_id, source_node_id, tenant_id, \
              actor, actor_kind, target, category, domain, method, \
              request_id, detail, pii_in_detail, shipped_at) \
             VALUES \
             ($1, $2, $3, $4, $5, \
              $6, $7, $8, $9, $10, $11, \
              $12, $13, $14, $15, $16, $17, \
              $18, $19, $20, $21) \
             ON CONFLICT (id) DO NOTHING",
            self.table
        );

        // Collect params as trait objects. Option<String> must be referenced
        // so we bind the local variable before constructing the slice.
        let tenant: Option<&str> = row.tenant_id.as_deref();
        let shipped: Option<&str> = shipped_at.as_deref();

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
        ];

        let mut guard = self
            .client
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        guard
            .execute(&sql as &str, params)
            .map(|_| ())
            .map_err(|e| crate::Error::AuditStoreInsert(e.to_string()))
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
            shipped_at: None,
        }
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
