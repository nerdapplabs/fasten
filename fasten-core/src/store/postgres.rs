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
             remove the sslmode param to accept plaintext explicitly. \
             NOTE: use `sslmode=require` — the driver accepts only \
             disable|prefer|require, and `require` with native-tls already \
             verifies the certificate chain AND the hostname."
                .to_string(),
        ));
    }
    Ok(pg::Client::connect(dsn, pg::NoTls)?)
}

// requires_tls: crude DSN scan for sslmode requesting encryption. Matches
// libpq's rule set — the three sslmode values that MUST fail if TLS isn't
// available are `require`, `verify-ca`, `verify-full` (`prefer` allows
// fallback, `allow` allows fallback, `disable` is explicit plaintext).
//
// IMPORTANT, and the reason this list differs from what you should WRITE in a
// DSN: tokio-postgres's Config parser accepts only `disable | prefer |
// require`. `verify-ca` / `verify-full` are REJECTED at connect time. We still
// match them here so a DSN carrying one fails closed rather than silently
// connecting in plaintext — but the value to document and use is `require`,
// which with native-tls already verifies both the certificate chain and the
// hostname. Recommending verify-* leads users to a connect error they then
// "fix" by dropping to `prefer`, which is exactly the plaintext fallback
// P1-43 closed.
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
    /// The driver accepts only disable|prefer|require. verify-ca/verify-full
    /// are rejected at connect time, so they must never be RECOMMENDED even
    /// though requires_tls() matches them (fail-closed). Pins the documented
    /// value so the guidance can't drift back.
    #[test]
    fn documented_strict_sslmode_is_require() {
        assert!(requires_tls("host=db user=x sslmode=require"));
        // Still fail-closed on values the driver will reject:
        assert!(requires_tls("host=db user=x sslmode=verify-full"));
        // Fallback-permitting modes must NOT be treated as requiring TLS.
        assert!(!requires_tls("host=db user=x sslmode=prefer"));
        assert!(!requires_tls("host=db user=x sslmode=disable"));
    }

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
    ///           TLS: use `sslmode=require` in the DSN. The driver rejects
    ///           `verify-ca`/`verify-full`; `require` + native-tls already
    ///           verifies the chain and the hostname.
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

        if row.monotonic_seq != 0 {
            return self.with_reconnect(|inner| {
                inner
                    .client
                    .execute(&inner.stmt, params)
                    .map(|_| ())
                    .map_err(Error::Postgres)
            });
        }

        let exists_sql = format!("SELECT 1 FROM {} WHERE id = $1", self.table);
        let seq_sql = format!(
            "SELECT COALESCE(MAX(monotonic_seq), 0) + 1 FROM {} WHERE source_node_id = $1",
            self.table
        );
        self.with_reconnect(|inner| {
            let Inner { client, stmt } = inner;
            let mut tx = client.transaction()?;
            // A retry after a lost commit ack must not take a new seq.
            if tx.query_opt(exists_sql.as_str(), &[&row.id])?.is_some() {
                tx.commit()?;
                return Ok(());
            }
            // Same lock key as the Python and Go stores, so every writer for
            // this node serialises here. An advisory lock rather than
            // FOR UPDATE: an empty node has no tip row to lock.
            tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&row.source_node_id],
            )?;
            let seq: i64 = tx.query_one(seq_sql.as_str(), &[&row.source_node_id])?.get(0);
            let mut p = params.to_vec();
            p[3] = &seq; // $4 monotonic_seq
            tx.execute(&*stmt, &p)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// `" AND hash = ''"` when the table has a `hash` column, else `""`.
    /// See the SQLite store.
    fn unsealed_gate(&self, client: &mut pg::Client) -> Result<&'static str, Error> {
        let row = client.query_one(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = COALESCE($1, current_schema()) \
             AND table_name = $2 AND column_name = 'hash'",
            &[&self.schema, &self.bare],
        )?;
        let n: i64 = row.get(0);
        Ok(if n > 0 { " AND hash = ''" } else { "" })
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

    fn list_redaction_candidates(
        &self,
        before: &str,
        codes: &[String],
    ) -> Result<Vec<(String, u64)>, Error> {
        if codes.is_empty() {
            return Ok(vec![]);
        }
        self.with_reconnect(|inner| {
            let gate = self.unsealed_gate(&mut inner.client)?;
            let sql = format!(
                "SELECT id, monotonic_seq FROM {} \
                 WHERE timestamp < $1 AND code = ANY($2) \
                 AND detail <> 'null'{gate} ORDER BY monotonic_seq",
                self.table
            );
            let rows = inner.client.query(sql.as_str(), &[&before, &codes])?;
            Ok(rows
                .iter()
                .map(|r| (r.get::<_, String>(0), r.get::<_, i64>(1).unsigned_abs()))
                .collect())
        })
    }

    fn redact_rows(&self, ids: &[String]) -> Result<Vec<String>, Error> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        self.with_reconnect(|inner| {
            let gate = self.unsealed_gate(&mut inner.client)?;
            // 'null' is the JSON literal; see the SQLite store.
            let sql = format!(
                "UPDATE {} SET detail = 'null' WHERE id = ANY($1){gate}",
                self.table
            );
            inner.client.execute(sql.as_str(), &[&ids])?;
            Ok(ids.to_vec())
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
                PRIMARY KEY (id),
                -- Same name as the Go store's index, so Go skips creating it.
                CONSTRAINT uq_{bare}_node_seq UNIQUE (source_node_id, monotonic_seq)
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
            monotonic_seq: 0,
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
        assert!(store.max_monotonic_seq().unwrap() >= 1);
    }

    /// A fresh, empty table per test run so seqs start at 1.
    fn fresh(dsn: &str, table: &str) -> PostgresStore {
        let mut c = connect_client(dsn).unwrap();
        c.execute(&format!("DROP TABLE IF EXISTS {table}"), &[]).unwrap();
        PostgresStore::connect(dsn, table).unwrap()
    }

    fn row_on(id: &str, node: &str) -> Row {
        let mut r = make_row(id, "TEST");
        r.source_node_id = node.into();
        r
    }

    fn seqs(store: &PostgresStore, node: &str) -> Vec<u64> {
        let f = Filter { source_node_id: Some(node.into()), ..Default::default() };
        store.query(&f).unwrap().iter().map(|r| r.monotonic_seq).collect()
    }

    #[test]
    fn seq_zero_is_allocated_per_node() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_alloc");
        store.insert(&row_on("evt-a1", "node-a")).unwrap();
        store.insert(&row_on("evt-a2", "node-a")).unwrap();
        store.insert(&row_on("evt-b1", "node-b")).unwrap();
        let mut r = row_on("evt-rep", "node-a");
        r.monotonic_seq = 7;
        store.insert(&r).unwrap();
        store.insert(&row_on("evt-a3", "node-a")).unwrap();
        assert_eq!(seqs(&store, "node-a"), vec![1, 2, 7, 8]);
        assert_eq!(seqs(&store, "node-b"), vec![1]);
    }

    #[test]
    fn retried_id_does_not_take_a_seq() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_retry");
        let r = row_on("evt-retry-1", "node-a");
        store.insert(&r).unwrap();
        store.insert(&r).unwrap();
        store.insert(&row_on("evt-retry-2", "node-a")).unwrap();
        assert_eq!(seqs(&store, "node-a"), vec![1, 2]);
    }

    #[test]
    fn duplicate_node_seq_is_rejected() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_dup");
        let mut a = row_on("evt-dup-1", "node-a");
        a.monotonic_seq = 3;
        let mut b = row_on("evt-dup-2", "node-a");
        b.monotonic_seq = 3;
        store.insert(&a).unwrap();
        assert!(store.insert(&b).is_err());
    }

    /// #92: several stores, one node, inserting at once.
    #[test]
    fn concurrent_stores_allocate_contiguous_seqs() {
        let Some(dsn) = dsn() else { return };
        drop(fresh(&dsn, "fasten_sc_pg_conc"));
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let dsn = dsn.clone();
                std::thread::spawn(move || {
                    let store = PostgresStore::connect(&dsn, "fasten_sc_pg_conc").unwrap();
                    for i in 0..25 {
                        store.insert(&row_on(&format!("evt-{t}-{i}"), "node-1")).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let store = PostgresStore::connect(&dsn, "fasten_sc_pg_conc").unwrap();
        assert_eq!(seqs(&store, "node-1"), (1..=100).collect::<Vec<u64>>());
    }

    fn days_ago(days: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::days(days))
            .format("%Y-%m-%dT%H:%M:%S%.6fZ")
            .to_string()
    }

    fn detail_of(store: &PostgresStore, id: &str) -> serde_json::Value {
        let rows = store.query(&Filter::default()).unwrap();
        rows.into_iter().find(|r| r.id == id).unwrap().detail
    }

    #[test]
    fn redaction_blanks_only_expired_pii_rows() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_redact");
        let mut pii = make_row("evt-pii-old", "USER_LOGIN");
        pii.timestamp = days_ago(40);
        let mut ops = make_row("evt-ops-old", "JOB_RAN");
        ops.timestamp = days_ago(40);
        store.insert(&pii).unwrap();
        store.insert(&ops).unwrap();

        let codes = vec!["USER_LOGIN".to_string()];
        let cutoff = days_ago(30);
        let found = store.list_redaction_candidates(&cutoff, &codes).unwrap();
        assert_eq!(found, vec![("evt-pii-old".to_string(), 1)]);
        let ids: Vec<String> = found.into_iter().map(|(id, _)| id).collect();
        assert_eq!(store.redact_rows(&ids).unwrap(), ids);

        assert_eq!(detail_of(&store, "evt-pii-old"), serde_json::Value::Null);
        assert_eq!(detail_of(&store, "evt-ops-old"), serde_json::json!({"k": "v"}));
        assert_eq!(store.count(&Filter::default()).unwrap(), 2);

        assert!(store.list_redaction_candidates(&cutoff, &codes).unwrap().is_empty());
        assert_eq!(store.redact_rows(&ids).unwrap(), ids);
        assert_eq!(detail_of(&store, "evt-pii-old"), serde_json::Value::Null);
        assert_eq!(store.count(&Filter::default()).unwrap(), 2);
    }

    #[test]
    fn redaction_skips_sealed_rows() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_redact_sealed");
        let mut c = connect_client(&dsn).unwrap();
        c.batch_execute(
            "ALTER TABLE fasten_sc_pg_redact_sealed ADD COLUMN hash TEXT NOT NULL DEFAULT ''",
        )
        .unwrap();
        for id in ["evt-sealed", "evt-unsealed"] {
            let mut r = make_row(id, "USER_LOGIN");
            r.timestamp = days_ago(40);
            store.insert(&r).unwrap();
        }
        c.batch_execute("UPDATE fasten_sc_pg_redact_sealed SET hash = 'abc' WHERE id = 'evt-sealed'")
            .unwrap();

        let codes = vec!["USER_LOGIN".to_string()];
        let found = store.list_redaction_candidates(&days_ago(30), &codes).unwrap();
        assert_eq!(found, vec![("evt-unsealed".to_string(), 2)]);
        store
            .redact_rows(&["evt-sealed".to_string(), "evt-unsealed".to_string()])
            .unwrap();
        assert_eq!(detail_of(&store, "evt-sealed"), serde_json::json!({"k": "v"}));
        assert_eq!(detail_of(&store, "evt-unsealed"), serde_json::Value::Null);
    }
}
