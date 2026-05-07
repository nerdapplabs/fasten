use std::sync::Mutex;

use pg::types::ToSql;

use crate::{
    error::Error,
    row::Row,
    validate::{split_table, validate_table_name},
};

use super::Store;

// ── Connection holder ─────────────────────────────────────────────────────────
//
// Holds the live connection + the pre-prepared INSERT statement.  When the
// connection is lost, the entire Inner is replaced via `reconnect`.
//
// Why prepared statements at all?  On PG 15+ with pg_stat_statements enabled,
// named prepared statements appear in pg_prepared_statements and their query
// text is fingerprinted, giving free per-query stats without any tracing.  For
// high-frequency audit logging (~1 k rows/s per service) the repeated parse +
// plan step is worth eliminating.

struct Inner {
    client: pg::Client,
    stmt: pg::Statement,
}

impl Inner {
    fn connect(dsn: &str, insert_sql: &str) -> Result<Self, Error> {
        // Pure-Rust wire protocol; no libpq, no C dependency.
        let mut client = pg::Client::connect(dsn, pg::NoTls)?;
        let stmt = client.prepare(insert_sql)?;
        Ok(Self { client, stmt })
    }
}

// ── PostgresStore ─────────────────────────────────────────────────────────────

pub struct PostgresStore {
    inner: Mutex<Inner>,
    table: String,
    bare: String,          // bare name used for index identifiers
    schema: Option<String>,
    dsn: String,           // retained for reconnect
    insert_sql: String,    // retained for re-prepare after reconnect
}

impl PostgresStore {
    /// Connect to PostgreSQL at `dsn`, auto-create the schema (if schema-
    /// qualified), create the audit table + indexes, and prepare the INSERT
    /// statement.
    ///
    /// `dsn`   — libpq-style connection string or `postgresql://` URI.
    ///           For PG 15+ TLS, use `sslmode=require` in the DSN.
    ///           For read-only replicas, add `target_session_attrs=read-write`
    ///           so the driver rejects replica endpoints automatically.
    ///           Example: `"host=db.prod.example.com user=audit dbname=audit
    ///                      sslmode=require application_name=fasten_store_core"`
    ///
    /// `table` — plain name (`"audit_log"`) or schema-qualified
    ///           (`"audit.audit_log"`).  Both parts must match
    ///           `[A-Za-z_][A-Za-z0-9_]*`.
    pub fn connect(dsn: &str, table: &str) -> Result<Self, Error> {
        validate_table_name(table)?;

        let (schema_opt, bare) = split_table(table);
        let schema = schema_opt.map(str::to_owned);
        let bare = bare.to_owned();
        let insert_sql = build_insert_sql(table);

        let mut client = pg::Client::connect(dsn, pg::NoTls)?;
        migrate(&mut client, table, &bare, schema.as_deref())?;
        let stmt = client.prepare(&insert_sql)?;

        Ok(Self {
            inner: Mutex::new(Inner { client, stmt }),
            table: table.to_owned(),
            bare,
            schema,
            dsn: dsn.to_owned(),
            insert_sql,
        })
    }

    /// Attempt an insert; on a closed connection, reconnect once and retry.
    fn insert_with_reconnect(&self, row: &Row) -> Result<(), Error> {
        let detail_str = serde_json::to_string(&row.detail)?;
        let seq: i64 = row.monotonic_seq as i64;
        let pii: i16 = row.pii_in_detail as i16;
        let tenant: Option<&str> = row.tenant_id.as_deref();
        let shipped: Option<&str> = row.shipped_at.as_deref();

        let params: &[&(dyn ToSql + Sync)] = &[
            &row.id,             // $1  id
            &row.wire_version,   // $2  wire_version
            &row.origin_id,      // $3  origin_id
            &seq,                // $4  monotonic_seq (BIGINT)
            &row.timestamp,      // $5  timestamp
            &row.code,           // $6  code
            &row.action,         // $7  action
            &row.severity,       // $8  severity
            &row.service_id,     // $9  service_id
            &row.source_node_id, // $10 source_node_id
            &tenant,             // $11 tenant_id     (NULL when None)
            &row.actor,          // $12 actor
            &row.actor_kind,     // $13 actor_kind
            &row.target,         // $14 target
            &row.category,       // $15 category
            &row.domain,         // $16 domain
            &row.method,         // $17 method
            &row.request_id,     // $18 request_id
            &detail_str,         // $19 detail
            &pii,                // $20 pii_in_detail (SMALLINT)
            &shipped,            // $21 shipped_at    (NULL when None)
        ];

        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        match guard.client.execute(&guard.stmt, params) {
            Ok(_) => Ok(()),
            Err(e) if e.is_closed() => {
                // Connection lost (DB restart, network partition). Reconnect
                // and retry once. A second failure is a hard error.
                *guard = Inner::connect(&self.dsn, &self.insert_sql)?;
                guard.client.execute(&guard.stmt, params).map(|_| ())?;
                Ok(())
            }
            Err(e) => Err(Error::Postgres(e)),
        }
    }
}

impl Store for PostgresStore {
    fn insert(&self, row: &Row) -> Result<(), Error> {
        self.insert_with_reconnect(row)
    }

    fn ping(&self) -> Result<(), Error> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Reconnect if needed before the health check.
        if guard.client.is_closed() {
            *guard = Inner::connect(&self.dsn, &self.insert_sql)?;
        }
        guard.client.execute("SELECT 1", &[]).map(|_| ())?;
        Ok(())
    }
}

// ── Schema bootstrap ──────────────────────────────────────────────────────────

fn pg_exec(client: &mut pg::Client, sql: &str) -> Result<(), Error> {
    client.execute(sql, &[]).map(|_| ()).map_err(Error::Postgres)
}

fn migrate(
    client: &mut pg::Client,
    table: &str,
    bare: &str,
    schema: Option<&str>,
) -> Result<(), Error> {
    if let Some(s) = schema {
        pg_exec(client, &format!("CREATE SCHEMA IF NOT EXISTS {s}"))?;
    }

    pg_exec(
        client,
        &format!(
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
        ),
    )?;

    for sql in &[
        format!("CREATE INDEX IF NOT EXISTS idx_{bare}_req  ON {table} (request_id)"),
        format!("CREATE INDEX IF NOT EXISTS idx_{bare}_code ON {table} (code)"),
        format!("CREATE INDEX IF NOT EXISTS idx_{bare}_ts   ON {table} (timestamp)"),
        format!("CREATE INDEX IF NOT EXISTS idx_{bare}_svc  ON {table} (service_id)"),
    ] {
        pg_exec(client, sql)?;
    }

    Ok(())
}

// ── SQL builder ───────────────────────────────────────────────────────────────

fn build_insert_sql(table: &str) -> String {
    format!(
        "INSERT INTO {table} \
         (id, wire_version, origin_id, monotonic_seq, timestamp, \
          code, action, severity, service_id, source_node_id, tenant_id, \
          actor, actor_kind, target, category, domain, method, \
          request_id, detail, pii_in_detail, shipped_at) \
         VALUES \
         ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) \
         ON CONFLICT (id) DO NOTHING"
    )
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dsn() -> Option<String> {
        std::env::var("FASTEN_TEST_POSTGRES_DSN").ok()
    }

    fn make_row(id: &str, code: &str) -> Row {
        Row {
            wire_version: "1".into(),
            id: id.into(),
            origin_id: id.into(),
            monotonic_seq: 42,
            timestamp: "2026-05-07T00:00:00.000Z".into(),
            code: code.into(),
            action: "test".into(),
            severity: "info".into(),
            service_id: "svc".into(),
            source_node_id: "node-1".into(),
            tenant_id: None,
            actor: "tester".into(),
            actor_kind: "user".into(),
            target: "res-1".into(),
            category: "test".into(),
            domain: "test".into(),
            method: "sdk".into(),
            request_id: "req-001".into(),
            detail: serde_json::json!({"k": "v"}),
            pii_in_detail: false,
            shipped_at: None,
        }
    }

    #[test]
    fn invalid_table_rejected_before_connect() {
        let result = PostgresStore::connect("host=localhost user=nobody", "bad-name!");
        assert!(matches!(result.unwrap_err(), Error::InvalidTableName(_)));
    }

    #[test]
    fn unreachable_host_returns_error() {
        let result = PostgresStore::connect(
            "host=127.0.0.1 port=1 user=nobody dbname=nobody connect_timeout=1",
            "audit_log",
        );
        assert!(result.is_err());
    }

    #[test]
    fn insert_and_idempotent() {
        let Some(dsn) = dsn() else { return };
        let store = PostgresStore::connect(&dsn, "fasten_sc_pg_test").unwrap();
        let row = make_row("evt-sc-pg-001", "TEST");
        store.insert(&row).unwrap();
        store.insert(&row).unwrap(); // ON CONFLICT DO NOTHING
    }

    #[test]
    fn schema_qualified_table() {
        let Some(dsn) = dsn() else { return };
        let store =
            PostgresStore::connect(&dsn, "fasten_sc_test_schema.audit_rows").unwrap();
        store.insert(&make_row("evt-sc-schema-001", "TEST")).unwrap();
    }

    #[test]
    fn ping_ok() {
        let Some(dsn) = dsn() else { return };
        let store = PostgresStore::connect(&dsn, "fasten_sc_pg_test").unwrap();
        store.ping().unwrap();
    }
}
