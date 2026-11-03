use std::sync::Mutex;

use pg::types::ToSql;

use crate::{
    error::Error,
    row::Row,
    store::Filter,
    validate::{split_table, validate_table_name},
};

use super::{non_empty, unsealed, RedactGate, RedactionCandidates, Store, CHAIN_COLUMNS, SELECT_COLUMNS};

// The live connection and its prepared INSERT. When the connection is lost,
// `with_reconnect` replaces the whole Inner. The INSERT is prepared once per
// connection so hot audit paths skip the parse and plan step.

struct Inner {
    client: pg::Client,
    stmt: pg::Statement,
}

impl Inner {
    fn connect(dsn: &str, insert_sql: &str) -> Result<Self, Error> {
        let mut client = connect_client(dsn)?;
        let stmt = client.prepare(insert_sql)?;
        Ok(Self { client, stmt })
    }
}

// With `postgres-tls`, connect through native-tls so sslmode=require is
// honoured. Without it, connect with NoTls and refuse a DSN that asks for
// TLS (sslmode=require|verify-*) instead of connecting in plaintext.

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
             NOTE: use `sslmode=require`: the driver accepts only \
             disable|prefer|require, and `require` with native-tls already \
             verifies the certificate chain AND the hostname."
                .to_string(),
        ));
    }
    Ok(pg::Client::connect(dsn, pg::NoTls)?)
}

// True if the DSN's sslmode requires encryption. As in libpq, those are
// `require`, `verify-ca` and `verify-full`; `prefer` and `allow` may fall back
// and `disable` is plaintext.
//
// The driver's config parser accepts only `disable | prefer | require` and
// rejects `verify-*` at connect time. We still match `verify-*` here so such
// a DSN fails closed, but `require` is the value to document: with native-tls
// it already verifies the certificate chain and the hostname. Pointing users
// at `verify-*` gets them a connect error they tend to "fix" with `prefer`,
// which allows plaintext.
//
// Only the non-TLS connect_client calls this; tests cover it under every
// feature set, hence allow(dead_code).
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
    /// The driver accepts only disable|prefer|require and rejects
    /// verify-ca/verify-full at connect time, so `require` is the documented
    /// value; requires_tls() still matches verify-* so they fail closed.
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

pub struct PostgresStore {
    inner: Mutex<Inner>,
    table: String,
    bare: String,          // bare name used for index identifiers
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
    /// `dsn`:   libpq-style connection string or `postgresql://` URI.
    ///           For TLS use `sslmode=require`; the driver rejects
    ///           `verify-ca`/`verify-full`, and `require` with native-tls
    ///           already verifies the chain and the hostname. TLS needs the
    ///           `postgres-tls` feature (on by default); without it a DSN
    ///           that asks for TLS fails to connect.
    ///           Add `target_session_attrs=read-write` to have the driver
    ///           reject read-only replica endpoints.
    ///           Example: `"host=db.prod.example.com user=audit dbname=audit
    ///                      sslmode=require application_name=fasten_core"`
    ///
    /// `table`: plain name (`"audit_log"`) or schema-qualified
    ///           (`"audit.audit_log"`).  Both parts must match
    ///           `[A-Za-z_][A-Za-z0-9_]*`.
    pub fn connect(dsn: &str, table: &str) -> Result<Self, Error> {
        validate_table_name(table)?;

        let (schema, bare) = split_table(table);
        let insert_sql = build_insert_sql(table);

        let mut client = connect_client(dsn)?;
        migrate(&mut client, table, bare, schema)?;
        let stmt = client.prepare(&insert_sql)?;

        Ok(Self {
            inner: Mutex::new(Inner { client, stmt }),
            table: table.to_owned(),
            bare: bare.to_owned(),
            dsn: dsn.to_owned(),
            insert_sql,
        })
    }

    /// Run `f` against the live connection; if the connection is closed,
    /// reconnect once and retry.
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
        let cleared;
        let row = if row.monotonic_seq == 0 {
            cleared = unsealed(row);
            &cleared
        } else {
            row
        };
        let detail_str = serde_json::to_string(&row.detail)?;
        let seq: i64 = row.monotonic_seq as i64;
        let pii: i16 = row.pii_in_detail as i16;
        let tenant: Option<&str> = row.tenant_id.as_deref();
        let shipped: Option<&str> = row.shipped_at.as_deref();
        let prev_hash = row.prev_hash.as_deref().unwrap_or("");
        let hash = row.hash.as_deref().unwrap_or("");
        let form = row.canonical_form_id.as_deref().unwrap_or("1");
        let salt = row.detail_salt.as_deref().unwrap_or("");
        let commitment = row.detail_commitment.as_deref().unwrap_or("");

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
            &prev_hash,          // $22 prev_hash
            &hash,               // $23 hash
            &form,               // $24 canonical_form_id
            &salt,               // $25 detail_salt
            &commitment,         // $26 detail_commitment
        ];

        let bare = self.bare.as_str();
        // Same lock key as the Python and Go stores, so every writer for
        // this node serialises here. An advisory lock rather than
        // FOR UPDATE: an empty node has no tip row to lock.
        let node_lock = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";
        if row.monotonic_seq != 0 {
            // Locked too, or this row could take the seq a seq-0 insert
            // has just picked and make that insert fail.
            return self.with_reconnect(|inner| {
                let Inner { client, stmt } = inner;
                let mut tx = client.transaction()?;
                tx.execute(node_lock, &[&row.source_node_id])?;
                tx.execute(&*stmt, params).map_err(|e| seq_clash(e, bare))?;
                tx.commit()?;
                Ok(())
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
            tx.execute(node_lock, &[&row.source_node_id])?;
            let seq: i64 = tx.query_one(seq_sql.as_str(), &[&row.source_node_id])?.get(0);
            let mut p = params.to_vec();
            p[3] = &seq; // $4 monotonic_seq
            tx.execute(&*stmt, &p).map_err(|e| seq_clash(e, bare))?;
            tx.commit()?;
            Ok(())
        })
    }

    fn redact_gate(&self, client: &mut pg::Client) -> Result<RedactGate, Error> {
        // Unquoted identifiers fold to lower case.
        let (schema, bare) = split_table(&self.table);
        let bare = bare.to_lowercase();
        let schema = schema.map(str::to_lowercase);
        let cols: Vec<String> = client
            .query(
                "SELECT column_name::text FROM information_schema.columns \
                 WHERE table_schema = COALESCE($1, current_schema()) AND table_name = $2",
                &[&schema, &bare],
            )?
            .iter()
            .map(|r| r.get(0))
            .collect();
        Ok(RedactGate::from_columns(&cols))
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
            "SELECT {SELECT_COLUMNS} FROM {}{} ORDER BY monotonic_seq ASC",
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
            "SELECT {SELECT_COLUMNS} FROM {} \
             WHERE shipped_at IS NULL ORDER BY monotonic_seq ASC LIMIT $1",
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
    ) -> Result<RedactionCandidates, Error> {
        if codes.is_empty() {
            return Ok(RedactionCandidates::default());
        }
        self.with_reconnect(|inner| {
            let gate = self.redact_gate(&mut inner.client)?;
            let base = format!(
                "FROM {} WHERE timestamp < $1 AND code = ANY($2) AND detail <> 'null'",
                self.table
            );
            let allowed = gate.allowed();
            // REPEATABLE READ so the list and the count see the same rows.
            let mut tx = inner
                .client
                .build_transaction()
                .isolation_level(pg::IsolationLevel::RepeatableRead)
                .read_only(true)
                .start()?;
            let rows = tx.query(
                format!("SELECT id, monotonic_seq {base}{allowed} ORDER BY monotonic_seq").as_str(),
                &[&before, &codes],
            )?;
            let skipped: i64 = if let Some(refused) = gate.refused() {
                tx.query_one(
                    format!("SELECT COUNT(*) {base}{refused}").as_str(),
                    &[&before, &codes],
                )?
                .get(0)
            } else {
                0
            };
            tx.commit()?;
            Ok(RedactionCandidates {
                rows: rows
                    .iter()
                    .map(|r| (r.get::<_, String>(0), r.get::<_, i64>(1).unsigned_abs()))
                    .collect(),
                skipped: skipped.unsigned_abs(),
            })
        })
    }

    fn redact_rows(&self, ids: &[String]) -> Result<Vec<String>, Error> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        self.with_reconnect(|inner| {
            let gate = self.redact_gate(&mut inner.client)?;
            // ids go in one array parameter, so there is no per-id bind limit
            // here.
            let sql = format!(
                "UPDATE {} SET {} WHERE id = ANY($1){}",
                self.table,
                gate.set(),
                gate.allowed()
            );
            inner.client.execute(sql.as_str(), &[&ids])?;
            Ok(ids.to_vec())
        })
    }
}

/// A unique violation on `uq_<bare>_node_seq`. A repeated id never gets
/// here: the insert is `ON CONFLICT (id) DO NOTHING`.
fn seq_clash(e: pg::Error, bare: &str) -> Error {
    let clash = e.as_db_error().is_some_and(|db| {
        *db.code() == pg::error::SqlState::UNIQUE_VIOLATION
            && db.constraint().is_some_and(|c| c.eq_ignore_ascii_case(&format!("uq_{bare}_node_seq")))
    });
    if clash {
        Error::SeqClash(e.to_string())
    } else {
        Error::Postgres(e)
    }
}

fn pg_exec(client: &mut pg::Transaction<'_>, sql: &str) -> Result<(), Error> {
    client.execute(sql, &[]).map(|_| ()).map_err(Error::Postgres)
}

fn migrate(
    client: &mut pg::Client,
    table: &str,
    bare: &str,
    schema: Option<&str>,
) -> Result<(), Error> {
    // Probe first, so opening an up-to-date table runs no DDL and waits on
    // no lock.
    if schema_missing(client, bare, schema)?.is_nothing() {
        return Ok(());
    }

    // Concurrent CREATE ... IF NOT EXISTS on a fresh database can fail with a
    // duplicate key on pg_type. Same lock key as the Python store; the xact
    // lock is released on commit, or on rollback when `tx` drops on error.
    let mut tx = client.transaction()?;
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
        &[&format!("fasten.bootstrap.{table}")],
    )?;
    let client = &mut tx;

    if let Some(s) = schema {
        pg_exec(client, &format!("CREATE SCHEMA IF NOT EXISTS {s}"))?;
    }

    let chain: String = CHAIN_COLUMNS
        .iter()
        .map(|(name, def)| format!("{name} {def},\n                "))
        .collect();
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
                {chain}PRIMARY KEY (id),
                -- Same name as the Go store's index, so Go skips creating it.
                CONSTRAINT uq_{bare}_node_seq UNIQUE (source_node_id, monotonic_seq)
            )"
        ),
    )?;

    let missing = schema_missing(client, bare, schema)?;
    // A table an older fasten-core created has no chain columns. IF NOT
    // EXISTS: an opener that names the table differently (`t`, `public.t`)
    // takes a different bootstrap lock and may have just added them.
    for (name, def) in missing.columns {
        pg_exec(client, &format!("ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {name} {def}"))?;
    }

    for sql in &[
        format!("CREATE INDEX IF NOT EXISTS idx_{bare}_req  ON {table} (request_id)"),
        format!("CREATE INDEX IF NOT EXISTS idx_{bare}_code ON {table} (code)"),
        format!("CREATE INDEX IF NOT EXISTS idx_{bare}_ts   ON {table} (timestamp)"),
        format!("CREATE INDEX IF NOT EXISTS idx_{bare}_svc  ON {table} (service_id)"),
    ] {
        pg_exec(client, sql)?;
    }

    // A table created before the UNIQUE constraint has no node-seq index and
    // may already repeat seqs on a node, so this one is not unique.
    if missing.node_seq_index {
        pg_exec(
            client,
            &format!(
                "CREATE INDEX IF NOT EXISTS idx_{bare}_node_seq \
                 ON {table} (source_node_id, monotonic_seq)"
            ),
        )?;
    }

    tx.commit()?;
    Ok(())
}

struct Missing {
    indexes: bool,
    node_seq_index: bool,
    columns: Vec<(&'static str, &'static str)>,
}

impl Missing {
    fn is_nothing(&self) -> bool {
        !self.indexes && !self.node_seq_index && self.columns.is_empty()
    }
}

/// What `migrate` still has to create on the table. A missing table lacks
/// everything.
fn schema_missing(
    client: &mut impl pg::GenericClient,
    bare: &str,
    schema: Option<&str>,
) -> Result<Missing, Error> {
    // Unquoted identifiers fold to lower case.
    let bare = bare.to_lowercase();
    let schema = schema.map(str::to_lowercase);
    let names: Vec<String> = client
        .query(
            "SELECT indexname FROM pg_indexes \
             WHERE schemaname = COALESCE($1, current_schema()) AND tablename = $2",
            &[&schema, &bare],
        )?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let have: Vec<String> = client
        .query(
            "SELECT column_name::text FROM information_schema.columns \
             WHERE table_schema = COALESCE($1, current_schema()) AND table_name = $2",
            &[&schema, &bare],
        )?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let has = |n: String| names.contains(&n);
    Ok(Missing {
        indexes: !["req", "code", "ts", "svc"].iter().all(|s| has(format!("idx_{bare}_{s}"))),
        node_seq_index: !has(format!("uq_{bare}_node_seq")) && !has(format!("idx_{bare}_node_seq")),
        columns: CHAIN_COLUMNS
            .into_iter()
            .filter(|(name, _)| !have.iter().any(|h| h == name))
            .collect(),
    })
}

fn build_insert_sql(table: &str) -> String {
    format!(
        "INSERT INTO {table} \
         (id, wire_version, origin_id, monotonic_seq, timestamp, \
          code, action, severity, service_id, source_node_id, tenant_id, \
          actor, actor_kind, target, category, domain, method, \
          request_id, detail, pii_in_detail, shipped_at, \
          prev_hash, hash, canonical_form_id, detail_salt, detail_commitment) \
         VALUES \
         ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,\
          $22,$23,$24,$25,$26) \
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
        prev_hash:         r.get(21),
        hash:              r.get(22),
        canonical_form_id: r.get(23),
        detail_salt:       non_empty(r.get(24)),
        detail_commitment: non_empty(r.get(25)),
        ..Default::default()
    }
}

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
        assert!(matches!(store.insert(&b), Err(Error::SeqClash(_))));
    }

    /// A replayed row keeps its id and seq, so storing it again is a no-op;
    /// another row on that node and seq is a clash.
    #[test]
    fn replayed_explicit_seq_row_is_stored_once() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_replay");
        let mut r = row_on("evt-replay-1", "node-a");
        r.monotonic_seq = 7;
        store.insert(&r).unwrap();
        store.insert(&r).unwrap();
        assert_eq!(store.count(&Filter::default()).unwrap(), 1);
        let mut other = row_on("evt-replay-2", "node-a");
        other.monotonic_seq = 7;
        assert!(matches!(store.insert(&other), Err(Error::SeqClash(_))));
        assert_eq!(store.count(&Filter::default()).unwrap(), 1);
        assert_eq!(seqs(&store, "node-a"), vec![7]);
    }

    /// A table from before the UNIQUE constraint already repeats seqs, so
    /// it gets a plain index.
    #[test]
    fn old_table_gets_a_non_unique_node_seq_index() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_sc_pg_old";
        let mut c = connect_client(&dsn).unwrap();
        c.batch_execute(&format!(
            "DROP TABLE IF EXISTS {table};
             CREATE TABLE {table} (
                id TEXT PRIMARY KEY, wire_version TEXT NOT NULL DEFAULT '1',
                origin_id TEXT NOT NULL, monotonic_seq BIGINT NOT NULL DEFAULT 0,
                timestamp TEXT NOT NULL, code TEXT NOT NULL,
                action TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT 'info',
                service_id TEXT NOT NULL DEFAULT '', source_node_id TEXT NOT NULL DEFAULT '',
                tenant_id TEXT, actor TEXT NOT NULL DEFAULT '',
                actor_kind TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '',
                method TEXT NOT NULL DEFAULT '', request_id TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '{{}}', pii_in_detail SMALLINT NOT NULL DEFAULT 0,
                shipped_at TEXT);
             INSERT INTO {table} (id, origin_id, monotonic_seq, timestamp, code, source_node_id)
             VALUES ('a', 'a', 1, 't', 'C', 'node-a'), ('b', 'b', 1, 't', 'C', 'node-a');"
        ))
        .unwrap();
        drop(PostgresStore::connect(&dsn, table).unwrap());
        let def: String = c
            .query_one(
                "SELECT indexdef FROM pg_indexes WHERE indexname = $1",
                &[&format!("idx_{table}_node_seq")],
            )
            .unwrap()
            .get(0);
        assert!(!def.contains("UNIQUE"), "{def}");
        assert!(schema_missing(&mut c, table, None).unwrap().is_nothing());
    }

    /// Opening an up-to-date table runs no DDL, so it does not wait for the
    /// bootstrap lock another opener holds.
    #[test]
    fn opening_an_up_to_date_table_skips_the_bootstrap() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_sc_pg_current";
        drop(fresh(&dsn, table));
        let mut holder = connect_client(&dsn).unwrap();
        holder
            .execute(
                "SELECT pg_advisory_lock(hashtextextended($1, 0))",
                &[&format!("fasten.bootstrap.{table}")],
            )
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let opener = std::thread::spawn(move || {
            tx.send(PostgresStore::connect(&dsn, table).is_ok()).unwrap();
        });
        let opened = rx.recv_timeout(std::time::Duration::from_secs(5));
        holder.batch_execute("SELECT pg_advisory_unlock_all()").unwrap();
        opener.join().unwrap();
        assert_eq!(opened, Ok(true));
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

    /// One writer picks its own seqs (MAX + 1, like another SDK) while
    /// others insert seq 0 on the same node. A seq-0 row never clashes; the
    /// explicit writer retries when its pick was taken first.
    #[test]
    fn explicit_and_allocated_seqs_on_one_node() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_sc_pg_mixed";
        drop(fresh(&dsn, table));
        let explicit = {
            let dsn = dsn.clone();
            std::thread::spawn(move || {
                let store = PostgresStore::connect(&dsn, table).unwrap();
                for i in 0..200 {
                    let mut r = row_on(&format!("evt-x-{i}"), "node-1");
                    loop {
                        r.monotonic_seq = store.max_monotonic_seq().unwrap() + 1;
                        match store.insert(&r) {
                            Ok(()) => break,
                            Err(Error::SeqClash(_)) => continue,
                            Err(e) => panic!("{e}"),
                        }
                    }
                }
            })
        };
        let allocating: Vec<_> = (0..3)
            .map(|t| {
                let dsn = dsn.clone();
                std::thread::spawn(move || {
                    let store = PostgresStore::connect(&dsn, table).unwrap();
                    for i in 0..200 {
                        store.insert(&row_on(&format!("evt-{t}-{i}"), "node-1")).unwrap();
                    }
                })
            })
            .collect();
        explicit.join().unwrap();
        for h in allocating {
            h.join().unwrap();
        }
        let store = PostgresStore::connect(&dsn, table).unwrap();
        assert_eq!(seqs(&store, "node-1"), (1..=800).collect::<Vec<u64>>());
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
        assert_eq!(found.rows, vec![("evt-pii-old".to_string(), 1)]);
        assert_eq!(found.skipped, 0);
        let ids: Vec<String> = found.rows.into_iter().map(|(id, _)| id).collect();
        assert_eq!(store.redact_rows(&ids).unwrap(), ids);

        assert_eq!(detail_of(&store, "evt-pii-old"), serde_json::Value::Null);
        assert_eq!(detail_of(&store, "evt-ops-old"), serde_json::json!({"k": "v"}));
        assert_eq!(store.count(&Filter::default()).unwrap(), 2);

        assert_eq!(
            store.list_redaction_candidates(&cutoff, &codes).unwrap(),
            RedactionCandidates::default()
        );
        assert_eq!(store.redact_rows(&ids).unwrap(), ids);
        assert_eq!(detail_of(&store, "evt-pii-old"), serde_json::Value::Null);
        assert_eq!(store.count(&Filter::default()).unwrap(), 2);
    }

    #[test]
    fn redaction_skips_sealed_rows() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_redact_sealed");
        for id in ["evt-sealed", "evt-unsealed"] {
            let mut r = make_row(id, "USER_LOGIN");
            r.timestamp = days_ago(40);
            if id == "evt-sealed" {
                r.monotonic_seq = 1;
                r.hash = Some("abc".into());
            }
            store.insert(&r).unwrap();
        }

        let codes = vec!["USER_LOGIN".to_string()];
        let found = store.list_redaction_candidates(&days_ago(30), &codes).unwrap();
        assert_eq!(found.rows, vec![("evt-unsealed".to_string(), 2)]);
        assert_eq!(found.skipped, 1);
        store
            .redact_rows(&["evt-sealed".to_string(), "evt-unsealed".to_string()])
            .unwrap();
        assert_eq!(detail_of(&store, "evt-sealed"), serde_json::json!({"k": "v"}));
        assert_eq!(detail_of(&store, "evt-unsealed"), serde_json::Value::Null);
    }

    /// The store picks the seq, so a hash sealed over another one is dropped.
    #[test]
    fn allocating_insert_drops_chain_fields() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_alloc_chain");
        let mut row = make_row("evt-alloc", "TEST");
        row.prev_hash = Some("genesis".into());
        row.hash = Some("h1".into());
        row.canonical_form_id = Some("2".into());
        row.detail_salt = Some("salt".into());
        row.detail_commitment = Some("commit".into());
        store.insert(&row).unwrap();
        let got = &store.query(&Filter::default()).unwrap()[0];
        assert_eq!(got.monotonic_seq, 1);
        assert_eq!(
            [got.prev_hash.as_deref(), got.hash.as_deref(), got.canonical_form_id.as_deref()],
            [Some(""), Some(""), Some("1")]
        );
        assert_eq!((got.detail_salt.as_deref(), got.detail_commitment.as_deref()), (None, None));
    }

    /// #139: a sealed row came back without its hash.
    #[test]
    fn chain_fields_round_trip() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_chain");
        let mut row = make_row("evt-sealed", "TEST");
        row.monotonic_seq = 1;
        row.prev_hash = Some("genesis".into());
        row.hash = Some("h1".into());
        row.canonical_form_id = Some("2".into());
        row.detail_salt = Some("salt".into());
        row.detail_commitment = Some("commit".into());
        store.insert(&row).unwrap();
        store.insert(&make_row("evt-plain", "TEST")).unwrap();
        let got = store.query(&Filter::default()).unwrap();
        let chain = |r: &Row| {
            [
                r.prev_hash.clone(),
                r.hash.clone(),
                r.canonical_form_id.clone(),
                r.detail_salt.clone(),
                r.detail_commitment.clone(),
            ]
        };
        assert_eq!(chain(&got[0]), chain(&row));
        let s = |v: &str| Some(v.to_string());
        assert_eq!(chain(&got[1]), [s(""), s(""), s("1"), None, None]);
    }

    /// A table the Go store created declares salt and commitment NOT NULL.
    #[test]
    fn writes_into_a_go_shaped_table() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_sc_pg_goshape";
        let mut c = connect_client(&dsn).unwrap();
        c.batch_execute(&format!(
            "DROP TABLE IF EXISTS {table};
             CREATE TABLE {table} (
                id TEXT PRIMARY KEY, wire_version TEXT NOT NULL DEFAULT '1',
                origin_id TEXT NOT NULL, monotonic_seq BIGINT NOT NULL,
                timestamp TEXT NOT NULL, code TEXT NOT NULL, action TEXT NOT NULL,
                severity TEXT NOT NULL, service_id TEXT NOT NULL,
                source_node_id TEXT NOT NULL, tenant_id TEXT, actor TEXT NOT NULL,
                actor_kind TEXT NOT NULL, target TEXT NOT NULL, category TEXT NOT NULL,
                domain TEXT NOT NULL, method TEXT NOT NULL, request_id TEXT NOT NULL,
                detail TEXT NOT NULL, pii_in_detail SMALLINT NOT NULL DEFAULT 0,
                shipped_at TEXT, hash TEXT NOT NULL DEFAULT '',
                prev_hash TEXT NOT NULL DEFAULT '',
                canonical_form_id TEXT NOT NULL DEFAULT '1',
                detail_salt TEXT NOT NULL DEFAULT '',
                detail_commitment TEXT NOT NULL DEFAULT '')"
        ))
        .unwrap();
        let store = PostgresStore::connect(&dsn, table).unwrap();
        store.insert(&make_row("evt-go", "TEST")).unwrap();
        let got = store.query(&Filter::default()).unwrap();
        assert_eq!(got[0].detail_salt, None);
        assert_eq!(got[0].hash.as_deref(), Some(""));
    }

    /// A table an older fasten-core created gets the chain columns on connect.
    #[test]
    fn connect_adds_chain_columns_to_an_old_table() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_sc_pg_oldshape";
        let mut c = connect_client(&dsn).unwrap();
        create_pre_chain_table(&mut c, table);
        c.execute(
            &format!(
                "INSERT INTO {table} (id, origin_id, timestamp, code, monotonic_seq) \
                 VALUES ('evt-old', 'evt-old', '2026-05-07T00:00:00.000000Z', 'TEST', 1)"
            ),
            &[],
        )
        .unwrap();
        let store = PostgresStore::connect(&dsn, table).unwrap();
        let mut row = make_row("evt-new", "TEST");
        row.monotonic_seq = 2;
        row.hash = Some("h2".into());
        store.insert(&row).unwrap();
        let got = store.query(&Filter::default()).unwrap();
        assert_eq!(got[0].hash.as_deref(), Some(""));
        assert_eq!(got[0].canonical_form_id.as_deref(), Some("1"));
        assert_eq!(got[1].hash.as_deref(), Some("h2"));
    }

    /// Two stores upgrading one old table, one naming it `t` and the other
    /// `public.t`, take different bootstrap locks.
    #[test]
    fn old_table_upgraded_under_two_names_at_once() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_sc_pg_twonames";
        let mut c = connect_client(&dsn).unwrap();
        for _ in 0..10 {
            create_pre_chain_table(&mut c, table);
            let start = std::sync::Arc::new(std::sync::Barrier::new(2));
            let openers: Vec<_> = [table.to_string(), format!("public.{table}")]
                .into_iter()
                .map(|name| {
                    let (dsn, start) = (dsn.clone(), start.clone());
                    std::thread::spawn(move || {
                        start.wait();
                        PostgresStore::connect(&dsn, &name).map(drop)
                    })
                })
                .collect();
            for h in openers {
                h.join().unwrap().unwrap();
            }
        }
    }

    /// The table shape from before the chain columns and the node-seq index.
    fn create_pre_chain_table(c: &mut pg::Client, table: &str) {
        c.batch_execute(&format!(
            "DROP TABLE IF EXISTS {table};
             CREATE TABLE {table} (
                id TEXT PRIMARY KEY, wire_version TEXT NOT NULL DEFAULT '1',
                origin_id TEXT NOT NULL, monotonic_seq BIGINT NOT NULL DEFAULT 0,
                timestamp TEXT NOT NULL, code TEXT NOT NULL,
                action TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT 'info',
                service_id TEXT NOT NULL DEFAULT '', source_node_id TEXT NOT NULL DEFAULT '',
                tenant_id TEXT, actor TEXT NOT NULL DEFAULT '',
                actor_kind TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '',
                method TEXT NOT NULL DEFAULT '', request_id TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '{{}}', pii_in_detail SMALLINT NOT NULL DEFAULT 0,
                shipped_at TEXT);"
        ))
        .unwrap();
    }

    /// Postgres folds unquoted names to lower case, so the column probe must
    /// too, or a mixed-case table looks hash-less and its sealed rows get
    /// redacted.
    #[test]
    fn redaction_skips_sealed_rows_in_mixed_case_table() {
        let Some(dsn) = dsn() else { return };
        let table = "FastenScMixed.AuditLog";
        let store = fresh(&dsn, table);
        let mut c = connect_client(&dsn).unwrap();
        c.batch_execute(&format!("ALTER TABLE {table} ADD COLUMN IF NOT EXISTS hash TEXT NOT NULL DEFAULT ''"))
            .unwrap();
        let mut r = make_row("evt-mixed-sealed", "USER_LOGIN");
        r.timestamp = days_ago(40);
        store.insert(&r).unwrap();
        c.batch_execute(&format!("UPDATE {table} SET hash = 'abc'")).unwrap();

        let codes = vec!["USER_LOGIN".to_string()];
        let found = store.list_redaction_candidates(&days_ago(30), &codes).unwrap();
        assert!(found.rows.is_empty());
        assert_eq!(found.skipped, 1);
        store.redact_rows(&["evt-mixed-sealed".to_string()]).unwrap();
        assert_eq!(detail_of(&store, "evt-mixed-sealed"), serde_json::json!({"k": "v"}));
    }

    /// A sealed form-"2" row hashes without its detail, so it is redacted
    /// like an unsealed one; only sealed form-"1" rows are refused.
    #[test]
    fn redaction_covers_sealed_form_2_rows() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_sc_pg_redact_form2";
        let store = fresh(&dsn, table);
        let mut c = connect_client(&dsn).unwrap();
        c.batch_execute(&format!(
            "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS hash TEXT NOT NULL DEFAULT '';
             ALTER TABLE {table} ADD COLUMN IF NOT EXISTS canonical_form_id TEXT NOT NULL DEFAULT '1';
             ALTER TABLE {table} ADD COLUMN IF NOT EXISTS detail_salt TEXT NOT NULL DEFAULT '';"
        ))
        .unwrap();
        for id in ["evt-form1", "evt-form2", "evt-unsealed"] {
            let mut r = make_row(id, "USER_LOGIN");
            r.timestamp = days_ago(40);
            store.insert(&r).unwrap();
        }
        c.batch_execute(&format!(
            "UPDATE {table} SET hash = 'abc' WHERE id = 'evt-form1';
             UPDATE {table} SET hash = 'def', canonical_form_id = '2', detail_salt = 'salt'
             WHERE id = 'evt-form2';"
        ))
        .unwrap();

        let codes = vec!["USER_LOGIN".to_string()];
        let found = store.list_redaction_candidates(&days_ago(30), &codes).unwrap();
        assert_eq!(
            found.rows,
            vec![("evt-form2".to_string(), 2), ("evt-unsealed".to_string(), 3)]
        );
        assert_eq!(found.skipped, 1);
        let all = vec!["evt-form1".to_string(), "evt-form2".to_string(), "evt-unsealed".to_string()];
        store.redact_rows(&all).unwrap();
        assert_eq!(detail_of(&store, "evt-form1"), serde_json::json!({"k": "v"}));
        assert_eq!(detail_of(&store, "evt-form2"), serde_json::Value::Null);
        assert_eq!(detail_of(&store, "evt-unsealed"), serde_json::Value::Null);
        let salt: String = c
            .query_one(&format!("SELECT detail_salt FROM {table} WHERE id = 'evt-form2'"), &[])
            .unwrap()
            .get(0);
        assert_eq!(salt, "");
    }
}
