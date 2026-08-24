use std::sync::Mutex;

use pg::types::ToSql;

use crate::{
    error::Error,
    row::Row,
    store::Filter,
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
        let mut client = connect_client(dsn)?;
        let stmt = client.prepare(insert_sql)?;
        Ok(Self { client, stmt })
    }
}

// ── Connector selection ─────────────────────────────────────────────────────
//
// `postgres-tls` feature ON  → native-tls connector, honours sslmode=require.
// `postgres-tls` feature OFF → NoTls; a DSN with sslmode=require|verify-* is
// refused up-front rather than being silently downgraded to plaintext (the
// exact fault P1-43 documents — the DSN said TLS, the client type was NoTls,
// negotiation completed in clear and no error was raised).

#[cfg(feature = "postgres-tls")]
fn connect_client(dsn: &str) -> Result<pg::Client, Error> {
    let tls = native_tls::TlsConnector::builder()
        .build()
        .map_err(|e| Error::TlsConnector(e.to_string()))?;
    let connector = postgres_native_tls::MakeTlsConnector::new(tls);
    Ok(pg::Client::connect(dsn, connector)?)
}

#[cfg(not(feature = "postgres-tls"))]
fn connect_client(dsn: &str) -> Result<pg::Client, Error> {
    if requires_tls(dsn) {
        return Err(Error::TlsUnavailable(
            "DSN requests TLS (sslmode=require|verify-ca|verify-full) but \
             fasten-core was built without the `postgres-tls` feature. \
             Rebuild with `--features postgres-tls` (on by default), or \
             remove the sslmode param to accept plaintext explicitly."
                .to_string(),
        ));
    }
    Ok(pg::Client::connect(dsn, pg::NoTls)?)
}

// requires_tls: crude DSN scan for sslmode requesting encryption. Matches
// libpq's rule set — the three sslmode values that MUST fail if TLS isn't
// available are `require`, `verify-ca`, `verify-full` (`prefer` allows
// fallback, `allow` allows fallback, `disable` is explicit plaintext).
// #[allow(dead_code)]: only the `#[cfg(not(feature = "postgres-tls"))]`
// arm of connect_client calls this at runtime; the test module below
// exercises it under every feature set so the sslmode semantics don't
// silently drift.
#[allow(dead_code)]
fn requires_tls(dsn: &str) -> bool {
    // Cover both URL form (?sslmode=require) and keyword form (sslmode=require).
    for part in dsn.split(|c: char| c == '?' || c == '&' || c.is_whitespace()) {
        let mut kv = part.splitn(2, '=');
        let k = kv.next().unwrap_or("").trim().to_ascii_lowercase();
        let v = kv.next().unwrap_or("").trim().to_ascii_lowercase();
        if k == "sslmode" && (v == "require" || v == "verify-ca" || v == "verify-full") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tls_tests {
    use super::requires_tls;
    #[test]
    fn requires_tls_matches_libpq_ssl_semantics() {
        // Positive: every "must-be-encrypted" sslmode.
        assert!(requires_tls("host=db user=x sslmode=require"));
        assert!(requires_tls("host=db user=x sslmode=verify-ca"));
        assert!(requires_tls("host=db user=x sslmode=verify-full"));
        assert!(requires_tls("postgres://u:p@db/x?sslmode=require"));
        assert!(requires_tls("postgres://u:p@db/x?sslmode=verify-full&application_name=a"));
        // Case-insensitive.
        assert!(requires_tls("host=db sslmode=REQUIRE"));
        // Negative: fallback-allowing modes.
        assert!(!requires_tls("host=db user=x sslmode=prefer"));
        assert!(!requires_tls("host=db user=x sslmode=allow"));
        assert!(!requires_tls("host=db user=x sslmode=disable"));
        assert!(!requires_tls("host=db user=x"));
        assert!(!requires_tls(""));
        // A key that only contains "sslmode" as a substring must not match.
        assert!(!requires_tls("host=db user=x sslmodex=require"));
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

impl std::fmt::Debug for PostgresStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresStore").field("table", &self.table).finish_non_exhaustive()
    }
}

impl PostgresStore {
    /// Connect to PostgreSQL at `dsn`, auto-create the schema (if schema-
    /// qualified), create the audit table + indexes, and prepare the INSERT
    /// statement.
    ///
    /// `dsn`   — libpq-style connection string or `postgresql://` URI.
    ///           TLS: `sslmode=require|verify-ca|verify-full` in the DSN
    ///           actually negotiates TLS when the crate is built with the
    ///           `postgres-tls` feature (ON by default). Without that
    ///           feature the connect **fails loudly** rather than silently
    ///           downgrading to plaintext — the P1-43 fault, where the docs
    ///           described a protection the code did not deliver.
    ///           For read-only replicas, add `target_session_attrs=read-write`
    ///           so the driver rejects replica endpoints automatically.
    ///           Example: `"host=db.prod.example.com user=audit dbname=audit
    ///                      sslmode=require application_name=fasten_core"`
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

        let mut client = connect_client(dsn)?;
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

    /// Run `f` against the live connection; reconnect once on a closed
    /// connection and retry.  Removes the per-method reconnect boilerplate.
    fn with_reconnect<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: Fn(&mut Inner) -> Result<R, Error>,
    {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match f(&mut *guard) {
            Err(Error::Postgres(ref e)) if e.is_closed() => {
                *guard = Inner::connect(&self.dsn, &self.insert_sql)?;
                f(&mut *guard)
            }
            other => other,
        }
    }

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

        self.with_reconnect(|inner| {
            inner
                .client
                .execute(&inner.stmt, params)
                .map(|_| ())
                .map_err(Error::Postgres)
        })
    }
}

impl Store for PostgresStore {
    fn insert(&self, row: &Row) -> Result<(), Error> {
        self.insert_with_reconnect(row)
    }

    fn ping(&self) -> Result<(), Error> {
        self.with_reconnect(|inner| {
            inner
                .client
                .execute("SELECT 1", &[])
                .map(|_| ())
                .map_err(Error::Postgres)
        })
    }

    fn query(&self, filter: &Filter) -> Result<Vec<Row>, Error> {
        let (where_clause, mut all_params) = build_filter_where(filter);
        let mut sql = format!(
            "SELECT id,wire_version,origin_id,monotonic_seq,timestamp,\
             code,action,severity,service_id,source_node_id,tenant_id,\
             actor,actor_kind,target,category,domain,method,\
             request_id,detail,pii_in_detail,shipped_at \
             FROM {}{} ORDER BY monotonic_seq ASC",
            self.table, where_clause
        );
        if filter.limit > 0 {
            let n = all_params.len() + 1;
            sql.push_str(&format!(" LIMIT ${n}"));
            all_params.push(Box::new(i64::from(filter.limit)));
            if filter.offset > 0 {
                let n = all_params.len() + 1;
                sql.push_str(&format!(" OFFSET ${n}"));
                all_params.push(Box::new(i64::from(filter.offset)));
            }
        }
        let params_refs: Vec<&(dyn ToSql + Sync)> =
            all_params.iter().map(|p| p.as_ref()).collect();

        self.with_reconnect(|inner| {
            let rows = inner
                .client
                .query(sql.as_str(), &params_refs)
                .map_err(Error::Postgres)?;
            Ok(rows.iter().map(row_from_pg).collect())
        })
    }

    fn count(&self, filter: &Filter) -> Result<u64, Error> {
        let (where_clause, all_params) = build_filter_where(filter);
        let sql = format!("SELECT COUNT(*) FROM {}{}", self.table, where_clause);
        let params_refs: Vec<&(dyn ToSql + Sync)> =
            all_params.iter().map(|p| p.as_ref()).collect();

        self.with_reconnect(|inner| {
            let rows = inner
                .client
                .query(sql.as_str(), &params_refs)
                .map_err(Error::Postgres)?;
            let n: i64 = rows.first().map(|r| r.get(0)).unwrap_or(0);
            Ok(n.unsigned_abs())
        })
    }

    fn list_unshipped(&self, limit: u32) -> Result<Vec<Row>, Error> {
        let effective: i64 = if limit == 0 { i64::MAX } else { i64::from(limit) };
        let sql = format!(
            "SELECT id,wire_version,origin_id,monotonic_seq,timestamp,\
             code,action,severity,service_id,source_node_id,tenant_id,\
             actor,actor_kind,target,category,domain,method,\
             request_id,detail,pii_in_detail,shipped_at \
             FROM {} WHERE shipped_at IS NULL ORDER BY monotonic_seq ASC LIMIT $1",
            self.table
        );
        self.with_reconnect(|inner| {
            let rows = inner
                .client
                .query(sql.as_str(), &[&effective as &(dyn ToSql + Sync)])
                .map_err(Error::Postgres)?;
            Ok(rows.iter().map(row_from_pg).collect())
        })
    }

    fn mark_shipped(&self, ids: &[String]) -> Result<(), Error> {
        if ids.is_empty() {
            return Ok(());
        }
        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        // $1 = shipped_at; $2 .. $N = IDs.
        let placeholders: String = (2..=ids.len() + 1)
            .map(|i| format!("${i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "UPDATE {} SET shipped_at = $1 WHERE id IN ({})",
            self.table, placeholders
        );

        let mut all_params: Vec<Box<(dyn ToSql + Sync)>> = Vec::with_capacity(ids.len() + 1);
        all_params.push(Box::new(now));
        for id in ids {
            all_params.push(Box::new(id.clone()));
        }
        let params_refs: Vec<&(dyn ToSql + Sync)> =
            all_params.iter().map(|p| p.as_ref()).collect();

        self.with_reconnect(|inner| {
            inner
                .client
                .execute(sql.as_str(), &params_refs)
                .map(|_| ())
                .map_err(Error::Postgres)
        })
    }

    fn purge(&self, before: &str, respect_unshipped: bool) -> Result<u64, Error> {
        let sql = if respect_unshipped {
            format!(
                "DELETE FROM {} WHERE timestamp < $1 AND shipped_at IS NOT NULL",
                self.table
            )
        } else {
            format!("DELETE FROM {} WHERE timestamp < $1", self.table)
        };
        self.with_reconnect(|inner| {
            inner
                .client
                .execute(sql.as_str(), &[&before as &(dyn ToSql + Sync)])
                .map_err(Error::Postgres)
        })
    }

    fn max_monotonic_seq(&self) -> Result<u64, Error> {
        let sql = format!(
            "SELECT COALESCE(MAX(monotonic_seq), 0) FROM {}",
            self.table
        );
        self.with_reconnect(|inner| {
            let rows = inner
                .client
                .query(sql.as_str(), &[])
                .map_err(Error::Postgres)?;
            let seq: i64 = rows.first().map(|r| r.get(0)).unwrap_or(0);
            Ok(seq.unsigned_abs())
        })
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

    // ARCH #3 (deferred): the canonical schema in spec/audit_log.postgres.sql
    // uses TIMESTAMPTZ + carries the hash-chain columns (hash, prev_hash,
    // canonical_form_id). This Rust core postgres store still writes/reads
    // TEXT timestamps and does not know the hash-chain columns yet — a
    // wholesale switch needs coordinated changes to build_insert_sql,
    // build_select_all, and the row-mapping code. Kept inline for now so
    // this DDL refactor doesn't ship a read-path regression; queued as a
    // follow-up commit.
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

// ── SQL builders ──────────────────────────────────────────────────────────────

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

/// Build `" WHERE col = $1 AND ..."` and matching params for the Postgres
/// extended-query protocol.  Params are assigned `$N` starting at 1.
fn build_filter_where(f: &Filter) -> (String, Vec<Box<(dyn ToSql + Sync)>>) {
    let mut parts: Vec<String> = Vec::new();
    let mut params: Vec<Box<(dyn ToSql + Sync)>> = Vec::new();
    let mut n: u32 = 1;

    if let Some(ref v) = f.request_id {
        parts.push(format!("request_id = ${n}"));
        params.push(Box::new(v.clone()));
        n += 1;
    }
    if let Some(ref v) = f.code {
        parts.push(format!("code = ${n}"));
        params.push(Box::new(v.clone()));
        n += 1;
    }
    if let Some(ref v) = f.domain {
        parts.push(format!("domain = ${n}"));
        params.push(Box::new(v.clone()));
        n += 1;
    }
    if let Some(ref v) = f.source_node_id {
        parts.push(format!("source_node_id = ${n}"));
        params.push(Box::new(v.clone()));
        n += 1;
    }
    if let Some(ref v) = f.since {
        parts.push(format!("timestamp >= ${n}"));
        params.push(Box::new(v.clone()));
        n += 1;
    }
    if let Some(ref v) = f.until {
        parts.push(format!("timestamp <= ${n}"));
        params.push(Box::new(v.clone()));
        n += 1;
    }
    let _ = n;

    let clause = if parts.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", parts.join(" AND "))
    };
    (clause, params)
}

// ── Row mapper ────────────────────────────────────────────────────────────────

fn row_from_pg(r: &pg::Row) -> Row {
    let detail_str: String = r.get(18);
    let detail = serde_json::from_str(&detail_str).unwrap_or(serde_json::Value::Null);
    let pii: i16 = r.get(19);
    let seq: i64 = r.get(3);
    Row {
        id:             r.get(0),
        wire_version:   r.get(1),
        origin_id:      r.get(2),
        monotonic_seq:  seq.unsigned_abs(),
        timestamp:      r.get(4),
        code:           r.get(5),
        action:         r.get(6),
        severity:       r.get(7),
        service_id:     r.get(8),
        source_node_id: r.get(9),
        tenant_id:      r.get(10),
        actor:          r.get(11),
        actor_kind:     r.get(12),
        target:         r.get(13),
        category:       r.get(14),
        domain:         r.get(15),
        method:         r.get(16),
        request_id:     r.get(17),
        detail,
        pii_in_detail:  pii != 0,
        shipped_at:     r.get(20),
        ..Default::default()
    }
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
            ..Default::default()
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

    #[test]
    fn query_with_code_filter() {
        let Some(dsn) = dsn() else { return };
        let store = PostgresStore::connect(&dsn, "fasten_sc_pg_qtest").unwrap();
        store.insert(&make_row("evt-pgq-001", "MATCH")).unwrap();
        store.insert(&make_row("evt-pgq-002", "OTHER")).unwrap();
        let rows = store
            .query(&Filter { code: Some("MATCH".into()), ..Default::default() })
            .unwrap();
        assert!(rows.iter().any(|r| r.code == "MATCH"));
    }

    #[test]
    fn list_unshipped_and_mark_shipped() {
        let Some(dsn) = dsn() else { return };
        let store = PostgresStore::connect(&dsn, "fasten_sc_pg_shiptest").unwrap();
        store.insert(&make_row("evt-pgship-001", "TEST")).unwrap();
        store.mark_shipped(&["evt-pgship-001".into()]).unwrap();
        // After marking, it should not appear in list_unshipped.
        let unshipped = store.list_unshipped(100).unwrap();
        assert!(!unshipped.iter().any(|r| r.id == "evt-pgship-001"));
    }

    #[test]
    fn max_monotonic_seq_is_positive() {
        let Some(dsn) = dsn() else { return };
        let store = PostgresStore::connect(&dsn, "fasten_sc_pg_seqtest").unwrap();
        store.insert(&make_row("evt-pgseq-001", "TEST")).unwrap();
        assert!(store.max_monotonic_seq().unwrap() >= 42);
    }
}
