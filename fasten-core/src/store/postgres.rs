use std::sync::Mutex;

use pg::types::ToSql;

use crate::{
    chain::ChainRow,
    checkpoint::ChainTip,
    error::Error,
    row::Row,
    store::Filter,
    validate::{split_table, validate_table_name},
};

use super::{
    chain_row, chain_tips_sql, check_originated, column_seq, non_empty, purge_cutoff, purge_sql, sealed_at,
    sealed_columns, stored_seq, tip_sql, Outcome, RedactGate, RedactionCandidates, Store, CHAIN_COLUMNS,
    SELECT_COLUMNS,
};

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

/// How a `require`-level DSN checks the server certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CertCheck {
    /// The chain and the host name: `require` and `verify-full`.
    Full,
    /// The chain only: `verify-ca`.
    ChainOnly,
}

#[allow(clippy::expect_used)]
static VERIFY_SSLMODE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(?i)(sslmode\s*=\s*)(verify-ca|verify-full)\b").expect("sslmode regex is valid")
});

// The driver accepts only sslmode disable, prefer and require. libpq's
// verify-ca and verify-full are rewritten to require, and the check they
// ask for is returned, so one strict value (verify-full) works in every SDK.
fn libpq_sslmode(dsn: &str) -> (std::borrow::Cow<'_, str>, CertCheck) {
    let mut check = CertCheck::Full;
    if let Some(c) = VERIFY_SSLMODE_RE.captures(dsn) {
        if c[2].eq_ignore_ascii_case("verify-ca") {
            check = CertCheck::ChainOnly;
        }
    }
    (VERIFY_SSLMODE_RE.replace_all(dsn, "${1}require"), check)
}

// Parse the DSN before connecting. The error names no part of the string;
// for a bad sslmode it names the option and the accepted values. A DSN with
// only hostaddr also gets it as host, as libpq uses it: TLS needs a host
// name to check, and the driver connects to hostaddr either way.
fn parse_dsn(dsn: &str) -> Result<pg::Config, Error> {
    let mut config = dsn.parse::<pg::Config>().map_err(|e| {
        // The Display text is generic; the cause (in Debug) names the option.
        Error::Store(if format!("{e:?}").contains("\"sslmode\"") {
            "unsupported sslmode in the Postgres connection string: use disable, prefer, \
             require, verify-ca or verify-full"
                .to_owned()
        } else {
            "invalid Postgres connection string".to_owned()
        })
    })?;
    if config.get_hosts().is_empty() {
        let addrs: Vec<String> = config.get_hostaddrs().iter().map(ToString::to_string).collect();
        for a in addrs {
            config.host(&a);
        }
    }
    Ok(config)
}

/// Open a Postgres client for `dsn`.
///
/// With `postgres-tls`, `sslmode` works as in libpq:
/// - `prefer` (the default) uses TLS when the server offers it, without
///   checking the server certificate, and plaintext when it doesn't;
/// - `require` and `verify-full` use TLS and check the certificate and host
///   name;
/// - `verify-ca` uses TLS and checks the certificate but not the host name;
/// - `disable` uses plaintext.
///
/// `verify-full` is strict in every SDK; libpq's `require` (Python, C++)
/// does not check the certificate.
///
/// Without the feature, connects with NoTls and refuses a DSN that asks for
/// TLS instead of connecting in plaintext.
#[cfg(feature = "postgres-tls")]
pub fn connect_client(dsn: &str) -> Result<pg::Client, Error> {
    let (dsn, check) = libpq_sslmode(dsn);
    let config = parse_dsn(&dsn)?;
    let mut builder = native_tls::TlsConnector::builder();
    if !matches!(config.get_ssl_mode(), pg::config::SslMode::Require) {
        builder.danger_accept_invalid_certs(true).danger_accept_invalid_hostnames(true);
    } else if check == CertCheck::ChainOnly {
        builder.danger_accept_invalid_hostnames(true);
    }
    let tls = builder
        .build()
        .map_err(|e| Error::TlsConnector(e.to_string()))?;
    let connector = postgres_native_tls::MakeTlsConnector::new(tls);
    Ok(config.connect(connector)?)
}

/// Open a Postgres client for `dsn`; see the `postgres-tls` variant.
#[cfg(not(feature = "postgres-tls"))]
pub fn connect_client(dsn: &str) -> Result<pg::Client, Error> {
    let config = parse_dsn(&libpq_sslmode(dsn).0)?;
    if requires_tls(dsn) {
        return Err(Error::TlsUnavailable(
            "DSN requests TLS (sslmode=require|verify-ca|verify-full) but \
             fasten-core was built without the `postgres-tls` feature. \
             Rebuild with `--features postgres-tls` (on by default), or \
             remove the sslmode param to accept plaintext explicitly."
                .to_string(),
        ));
    }
    Ok(config.connect(pg::NoTls)?)
}

// True if the DSN's sslmode requires encryption. As in libpq, those are
// `require`, `verify-ca` and `verify-full`; `prefer` and `allow` may fall back
// and `disable` is plaintext.
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
    use super::{libpq_sslmode, parse_dsn, requires_tls, CertCheck};

    /// An sslmode nobody accepts gets an error naming the accepted ones.
    #[test]
    fn unsupported_sslmode_error_names_accepted_values() {
        let err = super::connect_client("host=db password=s3cret sslmode=bogus")
            .err()
            .expect("must fail to parse")
            .to_string();
        assert!(!err.contains("s3cret"), "{err}");
        assert!(err.contains("use disable, prefer, require, verify-ca or verify-full"), "{err}");
    }

    /// verify-full and verify-ca parse as require; verify-ca skips only the
    /// host name check. Other modes and the rest of the DSN are unchanged.
    #[test]
    fn libpq_verify_modes_map_to_require() {
        for (dsn, want, check) in [
            ("host=db sslmode=verify-full", "host=db sslmode=require", CertCheck::Full),
            ("host=db sslmode = VERIFY-CA user=x", "host=db sslmode = require user=x", CertCheck::ChainOnly),
            ("postgres://u:p@db/x?sslmode=verify-full&a=b", "postgres://u:p@db/x?sslmode=require&a=b", CertCheck::Full),
            ("host=db sslmode=require", "host=db sslmode=require", CertCheck::Full),
            ("host=db sslmode=prefer", "host=db sslmode=prefer", CertCheck::Full),
        ] {
            let (got, c) = libpq_sslmode(dsn);
            assert_eq!(got, want);
            assert_eq!(c, check, "{dsn}");
        }
        let cfg = parse_dsn(&libpq_sslmode("host=db sslmode=verify-full").0).expect("parses");
        assert!(matches!(cfg.get_ssl_mode(), pg::config::SslMode::Require));
    }

    /// A DSN with only hostaddr gets it as host too, so TLS has a host name.
    #[test]
    fn hostaddr_alone_becomes_the_host() {
        let cfg = parse_dsn("hostaddr=10.0.0.5 user=x").expect("parses");
        assert_eq!(cfg.get_hosts(), [pg::config::Host::Tcp("10.0.0.5".into())]);
        let cfg = parse_dsn("host=db.internal hostaddr=10.0.0.5 user=x").expect("parses");
        assert_eq!(cfg.get_hosts(), [pg::config::Host::Tcp("db.internal".into())]);
    }

    /// A connection string the driver can't parse gives an error that
    /// quotes none of it.
    #[test]
    fn unparsable_dsn_error_quotes_none_of_it() {
        for dsn in ["host=db password=s3cret port=notaport", "host=db password='s3cret"] {
            let err = super::connect_client(dsn).err().expect("must fail to parse").to_string();
            assert!(!err.contains("s3cret"), "{err}");
            assert_eq!(err, "invalid Postgres connection string");
        }
    }
    /// Without TLS, every mode that needs encryption fails closed.
    #[test]
    fn strict_sslmodes_require_tls() {
        assert!(requires_tls("host=db user=x sslmode=require"));
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
    ///           For TLS use `sslmode=verify-full`, which checks the
    ///           certificate and host name (`require` does the same here;
    ///           `verify-ca` skips the host name). See [`connect_client`].
    ///           TLS needs the `postgres-tls` feature (on by default);
    ///           without it a DSN that asks for TLS fails to connect.
    ///           Add `target_session_attrs=read-write` to have the driver
    ///           reject read-only replica endpoints.
    ///           Example: `"host=db.prod.example.com user=audit dbname=audit
    ///                      sslmode=verify-full application_name=fasten_core"`
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

    /// Insert `row` as [`Store::insert`] does and return it as stored: with
    /// the seq and chain fields the store gave it. A row with a seq of its
    /// own is returned as given.
    ///
    /// When a row with this id is already stored, nothing is written. If
    /// the stored row is the same event (and, for a row with its own seq,
    /// at that seq with that hash), `row` comes back with the stored seq
    /// and chain fields; otherwise the error is `RowRejected`.
    pub fn insert_stored(&self, row: &Row) -> Result<Row, Error> {
        self.put(row, None)?.stored(row)
    }

    /// Write `row`, with `detail` as the text of its detail column or, when
    /// `None`, `row.detail` as `serde_json` renders it. A stored id is left
    /// as it is.
    fn put(&self, row: &Row, detail: Option<&str>) -> Result<Outcome, Error> {
        let rendered;
        let detail = match detail {
            Some(text) => text,
            None => {
                rendered = serde_json::to_string(&row.detail)?;
                &rendered
            }
        };
        let bare = self.bare.as_str();
        // Same lock key as the Python and Go stores, so every writer for
        // this node serialises here. An advisory lock rather than
        // FOR UPDATE: an empty node has no tip row to lock. A row with its
        // own seq takes it too, or it could take the seq a seq-0 insert
        // has just picked and make that insert fail.
        let node_lock = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";
        let held_sql = format!("SELECT {SELECT_COLUMNS} FROM {} WHERE id = $1", self.table);
        let seq_sql = format!(
            "SELECT COALESCE(MAX(monotonic_seq), 0) + 1 FROM {} WHERE source_node_id = $1",
            self.table
        );
        let tip_sql = tip_sql(&self.table, "$1");
        self.with_reconnect(|inner| {
            let Inner { client, stmt } = inner;
            let mut tx = client.transaction()?;
            tx.execute(node_lock, &[&row.source_node_id])?;
            // A retry after a lost commit ack must not take a new seq.
            if let Some(held) = held_row(&mut tx, &held_sql, &row.id)? {
                tx.commit()?;
                return Ok(held);
            }
            let stored = if row.monotonic_seq == 0 {
                check_originated(row)?;
                let seq: i64 = tx.query_one(seq_sql.as_str(), &[&row.source_node_id])?.try_get(0)?;
                // The seq counts every row on the node; the tip is its last
                // sealed one.
                let tip: Option<String> = match tx.query_opt(tip_sql.as_str(), &[&row.source_node_id])? {
                    Some(r) => Some(r.try_get(0)?),
                    None => None,
                };
                sealed_at(row, seq, tip.as_deref().unwrap_or(crate::chain::GENESIS))?
            } else {
                row.clone()
            };
            let written = execute_insert(&mut tx, stmt, &stored, column_seq(&stored)?, detail, bare)?;
            if written == 0 {
                // The id was stored under another node's lock meanwhile.
                let held = held_row(&mut tx, &held_sql, &row.id)?
                    .ok_or_else(|| Error::Store(format!("row {}: not inserted and not stored", row.id)))?;
                tx.commit()?;
                return Ok(held);
            }
            tx.commit()?;
            Ok(Outcome::Inserted(stored))
        })
    }

    /// The rows matching `filter`, ordered by `order`.
    fn select(&self, filter: &Filter, order: &str) -> Result<Vec<pg::Row>, Error> {
        let (where_clause, mut all_params) = build_filter_where(filter);
        let mut sql = format!(
            "SELECT {SELECT_COLUMNS} FROM {}{} ORDER BY {order}",
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
            inner.client.query(sql.as_str(), &params_refs).map_err(Error::Postgres)
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
        self.put(row, None).map(|_| ())
    }

    fn insert_sealed(&self, row: &ChainRow, pii_in_detail: bool) -> Result<(), Error> {
        let (columns, detail) = sealed_columns(row, pii_in_detail)?;
        self.put(&columns, Some(&detail))?.sealed(row)
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
        self.select(filter, "monotonic_seq ASC")?.iter().map(row_from_pg).collect()
    }

    fn chain_rows(&self, filter: &Filter) -> Result<Vec<ChainRow>, Error> {
        self.select(filter, "source_node_id, monotonic_seq")?.iter().map(chain_row_from_pg).collect()
    }

    fn chain_tips(&self) -> Result<Vec<ChainTip>, Error> {
        let sql = chain_tips_sql(&self.table);
        self.with_reconnect(|inner| inner.client.query(sql.as_str(), &[]).map_err(Error::Postgres))?
            .iter()
            .map(|r| {
                let node: String = column(r, 0, "chain tip")?;
                let owner = format!("node '{node}'");
                let seq: i64 = column(r, 1, &owner)?;
                let seq = u64::try_from(seq)
                    .map_err(|_| Error::Store(format!("{owner}: monotonic_seq {seq} is negative")))?;
                let hash = column(r, 2, &owner)?;
                Ok(ChainTip { source_node_id: node, monotonic_seq: seq, hash })
            })
            .collect()
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
            rows.iter().map(row_from_pg).collect()
        })
    }

    fn mark_shipped(&self, ids: &[String]) -> Result<(), Error> {
        if ids.is_empty() {
            return Ok(());
        }
        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        // The ids go in one array parameter: Postgres caps a statement at
        // 65,535 parameters.
        let sql = format!(
            "UPDATE {} SET shipped_at = $1 WHERE id = ANY($2)",
            self.table
        );
        self.with_reconnect(|inner| {
            inner
                .client
                .execute(sql.as_str(), &[&now as &(dyn ToSql + Sync), &ids])
                .map(|_| ())
                .map_err(Error::Postgres)
        })
    }

    fn purge(&self, before: &str, respect_unshipped: bool) -> Result<u64, Error> {
        let before = purge_cutoff(before)?;
        let sql = purge_sql(&self.table, "$1", respect_unshipped, true);
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
        let before = purge_cutoff(before)?;
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
            let rows = rows
                .iter()
                .map(|r| {
                    let id: String = column(r, 0, "redaction candidate")?;
                    let seq = stored_seq(&id, column(r, 1, &format!("row {id}"))?)?;
                    Ok((id, seq))
                })
                .collect::<Result<_, Error>>()?;
            Ok(RedactionCandidates { rows, skipped: skipped.unsigned_abs() })
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

/// The row stored under `id`, if there is one.
fn held_row(tx: &mut pg::Transaction<'_>, held_sql: &str, id: &str) -> Result<Option<Outcome>, Error> {
    match tx.query_opt(held_sql, &[&id])? {
        Some(r) => Ok(Some(Outcome::Held(row_from_pg(&r)?, column(&r, 18, &format!("row {id}"))?))),
        None => Ok(None),
    }
}

/// Run the prepared INSERT for `row` on `tx`, at `seq` and with `detail` as
/// the text of its detail column. Returns the rows written: 0 when the id
/// was already stored.
fn execute_insert(
    tx: &mut pg::Transaction<'_>,
    stmt: &pg::Statement,
    row: &Row,
    seq: i64,
    detail_str: &str,
    bare: &str,
) -> Result<u64, Error> {
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
    tx.execute(stmt, params).map_err(|e| seq_clash(e, bare))
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

/// Column `idx` of `r`, which belongs to the row or node `owner` names. A
/// NULL or a value of another type is an error that names both.
fn column<'a, T: pg::types::FromSql<'a>>(r: &'a pg::Row, idx: usize, owner: &str) -> Result<T, Error> {
    r.try_get(idx).map_err(|e| {
        let name = r.columns().get(idx).map_or("?", pg::Column::name);
        Error::Store(format!("{owner}: column {name}: {e}"))
    })
}

fn row_from_pg(r: &pg::Row) -> Result<Row, Error> {
    let id: String = column(r, 0, "row")?;
    let owner = format!("row {id}");
    let col_str = |idx: usize| column::<String>(r, idx, &owner);
    let col_opt = |idx: usize| column::<Option<String>>(r, idx, &owner);
    let detail_str = col_str(18)?;
    let detail = serde_json::from_str(&detail_str).unwrap_or(serde_json::Value::Null);
    let pii: i16 = column(r, 19, &owner)?;
    let seq = stored_seq(&id, column(r, 3, &owner)?)?;
    Ok(Row {
        wire_version:   col_str(1)?,
        origin_id:      col_str(2)?,
        monotonic_seq:  seq,
        timestamp:      col_str(4)?,
        code:           col_str(5)?,
        action:         col_str(6)?,
        severity:       col_str(7)?,
        service_id:     col_str(8)?,
        source_node_id: col_str(9)?,
        tenant_id:      col_opt(10)?,
        actor:          col_str(11)?,
        actor_kind:     col_str(12)?,
        target:         col_str(13)?,
        category:       col_str(14)?,
        domain:         col_str(15)?,
        method:         col_str(16)?,
        request_id:     col_str(17)?,
        detail,
        pii_in_detail:  pii != 0,
        shipped_at:     col_opt(20)?,
        prev_hash:         col_opt(21)?,
        hash:              col_opt(22)?,
        canonical_form_id: col_opt(23)?,
        detail_salt:       non_empty(col_opt(24)?),
        detail_commitment: non_empty(col_opt(25)?),
        id,
        ..Default::default()
    })
}

/// A selected row for verification, its `detail` parsed from the column text.
fn chain_row_from_pg(r: &pg::Row) -> Result<ChainRow, Error> {
    let row = row_from_pg(r)?;
    let detail: String = column(r, 18, &format!("row {}", row.id))?;
    chain_row(&row, &detail)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn purge_deletes_only_a_seq_prefix() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_purge");
        // Seq 2 is newer than the cutoff and seq 3 older: a timestamp-only
        // delete takes 3 and keeps 2 and 4, and the chain breaks at 4.
        for (id, node, ts) in [
            ("evt-a1", "node-a", "2020-01-01"),
            ("evt-a2", "node-a", "2020-01-03"),
            ("evt-a3", "node-a", "2020-01-02"),
            ("evt-a4", "node-a", "2020-01-04"),
            ("evt-b1", "node-b", "2020-01-01"),
            ("evt-b2", "node-b", "2020-01-02"),
        ] {
            let mut r = row_on(id, node);
            r.timestamp = format!("{ts}T00:00:00.000Z");
            store.insert(&r).unwrap();
        }
        assert_eq!(store.purge("2020-01-02T12:00:00.000Z", false).unwrap(), 3);
        assert_eq!(seqs(&store, "node-a"), vec![2, 3, 4]);
        assert!(seqs(&store, "node-b").is_empty());
    }

    #[test]
    fn purge_keeps_rows_above_an_unshipped_row() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_purge_unshipped");
        for (id, ts) in [("evt-u1", "2020-01-01"), ("evt-u2", "2020-01-02"), ("evt-u3", "2020-01-03")] {
            let mut r = row_on(id, "node-a");
            r.timestamp = format!("{ts}T00:00:00.000Z");
            store.insert(&r).unwrap();
        }
        store.mark_shipped(&["evt-u1".to_string(), "evt-u3".to_string()]).unwrap();
        assert_eq!(store.purge("2021-01-01T00:00:00.000Z", true).unwrap(), 1);
        assert_eq!(seqs(&store, "node-a"), vec![2, 3]);
    }

    #[test]
    fn purge_rejects_a_cutoff_that_is_not_a_timestamp() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_purge_cutoff");
        store.insert(&row_on("evt-c1", "node-a")).unwrap();
        assert!(matches!(store.purge("tomorrow", false), Err(Error::InvalidTimestamp(_))));
        assert_eq!(seqs(&store, "node-a"), vec![1]);
    }

    #[test]
    fn purge_normalizes_the_cutoff() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_purge_norm");
        for (id, ts) in [("evt-n1", "2025-12-31T23:00:00.000Z"), ("evt-n2", "2026-01-01T03:00:00.000Z")] {
            let mut r = row_on(id, "node-a");
            r.timestamp = ts.into();
            store.insert(&r).unwrap();
        }
        assert_eq!(store.purge("2026-01-01T05:30:00+05:30", false).unwrap(), 1);
        assert_eq!(seqs(&store, "node-a"), vec![2]);
    }

    // More ids than Postgres's 65,535 parameters.
    #[test]
    fn mark_shipped_takes_any_number_of_ids() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_ship_many");
        store.insert(&row_on("evt-m1", "node-a")).unwrap();
        store.insert(&row_on("evt-m2", "node-a")).unwrap();
        let mut ids: Vec<String> = (0..70_000).map(|i| format!("evt-none-{i}")).collect();
        ids.push("evt-m1".into());
        ids.insert(0, "evt-m2".into());
        store.mark_shipped(&ids).unwrap();
        assert!(store.list_unshipped(0).unwrap().is_empty());
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
            // Explicit seqs, so the rows are stored as given.
            if id == "evt-sealed" {
                r.monotonic_seq = 1;
                r.hash = Some("abc".into());
            } else {
                r.monotonic_seq = 2;
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

    /// The store picks the seq, so a hash sealed over another one is
    /// replaced by the store's own seal.
    #[test]
    fn allocating_insert_replaces_chain_fields() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_sc_pg_alloc_chain");
        let mut row = make_row("evt-alloc", "TEST");
        row.prev_hash = Some("elsewhere".into());
        row.hash = Some("h1".into());
        row.canonical_form_id = Some("2".into());
        row.detail_salt = Some("salt".into());
        row.detail_commitment = Some("commit".into());
        store.insert(&row).unwrap();
        let got = &store.query(&Filter::default()).unwrap()[0];
        assert_eq!(got.monotonic_seq, 1);
        assert_eq!(got.prev_hash.as_deref(), Some("genesis"));
        assert_eq!(got.canonical_form_id.as_deref(), Some("2"));
        assert_eq!(got.hash.as_deref().map(str::len), Some(64));
        assert_ne!(got.detail_salt.as_deref(), Some("salt"));
        assert_ne!(got.detail_commitment.as_deref(), Some("commit"));
        let rows = store.chain_rows(&Filter::default()).unwrap();
        assert!(crate::chain::verify_chain(&rows).ok);
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
        // The allocated row links to the stored one.
        assert_eq!(got[1].prev_hash.as_deref(), Some("h1"));
        assert_eq!(got[1].canonical_form_id.as_deref(), Some("2"));
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
        let got = store.chain_rows(&Filter::default()).unwrap();
        assert_eq!(got[0].prev_hash, "genesis");
        assert!(got[0].detail_salt.is_some());
        assert!(crate::chain::verify_chain(&got).ok);
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
        c.batch_execute(&format!("UPDATE {table} SET hash = 'abc', canonical_form_id = '1'")).unwrap();

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
            "UPDATE {table} SET hash = 'abc', canonical_form_id = '1' WHERE id = 'evt-form1';
             UPDATE {table} SET hash = '' WHERE id = 'evt-unsealed';"
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
