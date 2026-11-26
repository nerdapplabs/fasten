//! PostgreSQL store for the api or sys stream (sync `postgres` crate).
//! Enable with: fasten-sdk = { features = ["store-postgres"] }

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use fasten_core::store::postgres::connection_lost;
use fasten_core::store::stream::{
    ddl, insert_sql, lifted_status, lifted_text, like_pattern, parse_payload, payload_text, StreamParam,
};
use pg::types::ToSql;

use crate::pg_runtime::{off_runtime, Conn};

use crate::streams::{StreamFilter, StreamRow, StreamStore};
use crate::Error;

/// One stream's table in Postgres, the same table the Python, Go and JS
/// Postgres stream stores use (spec persistent-streams.md §2), so any SDK
/// reads and appends to what another wrote.
///
/// The store holds one connection. A connection found closed is opened
/// again before the next call. A read or purge that loses its connection
/// (by the rule of [`crate::PostgresStore`]: a socket error, a closed
/// client, or SQLSTATE class 08 or 57 other than 57014) runs once more on a
/// new one. An INSERT is never run again, since it may have committed: the
/// write fails and the stream counts it.
///
/// ```no_run
/// use std::sync::Arc;
/// use fasten::{Config, PostgresStreamStore};
///
/// let dsn = "host=localhost user=app dbname=logs";
/// let api = PostgresStreamStore::new(dsn, "api_log").expect("connect");
/// let syslog = PostgresStreamStore::new(dsn, "syslog").expect("connect");
/// fasten::init(Config {
///     service_id: "my-service".into(),
///     node_id: "node-1".into(),
///     api_store: Some(Arc::new(api)),
///     syslog_store: Some(Arc::new(syslog)),
///     ..Default::default()
/// }).expect("init");
/// ```
pub struct PostgresStreamStore {
    dsn: String,
    table: String,
    insert_sql: String,
    client: Mutex<Option<Conn>>,
    write_failures: AtomicU64,
}

impl std::fmt::Debug for PostgresStreamStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresStreamStore").field("table", &self.table).finish_non_exhaustive()
    }
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn db_err(e: &pg::Error) -> Error {
    Error::StreamStore(match e.as_db_error() {
        Some(db) => format!("{e}: {}", db.message()),
        None => e.to_string(),
    })
}

fn connect(dsn: &str) -> Result<pg::Client, Error> {
    fasten_core::store::postgres::connect_client(dsn).map_err(|e| match e {
        fasten_core::Error::Postgres(e) => db_err(&e),
        other => Error::StreamStore(other.to_string()),
    })
}

/// A client to replace a lost or closed one. A failed reconnect is reported
/// by error type, since the driver's message can name the user.
fn reconnect(dsn: &str) -> Result<pg::Client, Error> {
    connect(dsn).map_err(|e| Error::StreamStore(format!("cannot connect again ({})", crate::retention::error_type(&e))))
}

fn params(values: &[StreamParam]) -> Vec<Box<dyn ToSql + Sync>> {
    values
        .iter()
        .map(|v| match v {
            StreamParam::Text(s) => Box::new(s.clone()) as Box<dyn ToSql + Sync>,
            StreamParam::Int(n) => Box::new(*n),
        })
        .collect()
}

impl PostgresStreamStore {
    /// Connect to `dsn` and create the schema, table and indexes if absent.
    /// `table` may be schema-qualified (`"logs.syslog"`); it is required, so
    /// api rows cannot land in the syslog table. Use `"api_log"` or
    /// `"syslog"` to share tables with the other SDKs. `sslmode` is handled
    /// as in [`crate::PostgresStore`].
    pub fn new(dsn: &str, table: &str) -> Result<Self, Error> {
        off_runtime(|| Self::open(dsn, table))
    }

    fn open(dsn: &str, table: &str) -> Result<Self, Error> {
        let (schema, bare) = match table.split_once('.') {
            Some((s, t)) => (Some(s), t),
            None => (None, table),
        };
        if table.is_empty() {
            return Err(Error::InvalidConfig(
                "fasten PostgresStreamStore: table name is required (no default: pass \"api_log\" or \"syslog\")".into(),
            ));
        }
        if !(schema.is_none_or(is_identifier) && is_identifier(bare)) {
            return Err(Error::InvalidConfig(format!(
                "fasten PostgresStreamStore: table name {table:?} is not a valid SQL identifier. Use only letters, digits, underscores, and an optional 'schema.' prefix."
            )));
        }
        let ddl = ddl(table, bare, true).map_err(|e| Error::InvalidConfig(format!("fasten PostgresStreamStore: {e}")))?;
        let insert_sql =
            insert_sql(table, |n| format!("${n}")).map_err(|e| Error::InvalidConfig(format!("fasten PostgresStreamStore: {e}")))?;
        let mut client = connect(dsn)?;
        bootstrap(&mut client, table, schema, &ddl).map_err(|e| db_err(&e))?;
        Ok(Self {
            dsn: dsn.to_string(),
            table: table.to_string(),
            insert_sql,
            client: Mutex::new(Some(Conn(Some(client)))),
            write_failures: AtomicU64::new(0),
        })
    }

    /// Failed writes that were dropped.
    pub fn write_failures(&self) -> u64 {
        self.write_failures.load(Ordering::Relaxed)
    }

    /// Run `f` on the connection, opening one first when there is none or it
    /// has closed. With `retry`, a call that loses its connection runs once
    /// more on a new one. Runs off a tokio runtime thread, as
    /// [`crate::PostgresStore`] does.
    fn call<T: Send>(&self, retry: bool, f: impl Fn(&mut pg::Client) -> Result<T, pg::Error> + Sync) -> Result<T, Error> {
        off_runtime(|| self.call_here(retry, &f))
    }

    fn call_here<T>(&self, retry: bool, f: impl Fn(&mut pg::Client) -> Result<T, pg::Error>) -> Result<T, Error> {
        let mut guard = self.client.lock().unwrap_or_else(|e| e.into_inner());
        for attempt in 0..2 {
            if guard.as_deref().is_none_or(pg::Client::is_closed) {
                *guard = None;
                *guard = Some(Conn(Some(reconnect(&self.dsn)?)));
            }
            let Some(client) = guard.as_deref_mut() else { break };
            match f(client) {
                Ok(v) => return Ok(v),
                Err(e) => {
                    let lost = connection_lost(&e) || client.is_closed();
                    if lost {
                        *guard = None;
                    }
                    if !(lost && retry && attempt == 0) {
                        return Err(db_err(&e));
                    }
                }
            }
        }
        Err(Error::StreamStore("connection lost".into()))
    }

    fn rows(&self, sql: &str, values: &[StreamParam]) -> Result<Vec<StreamRow>, Error> {
        let boxed = params(values);
        let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(AsRef::as_ref).collect();
        let texts: Vec<String> =
            self.call(true, |c| c.query(sql, &refs).map(|rows| rows.iter().map(|r| r.get(0)).collect()))?;
        texts.iter().map(|t| parse_payload(t).map_err(Error::from)).collect()
    }
}

fn bootstrap(client: &mut pg::Client, table: &str, schema: Option<&str>, ddl: &[String]) -> Result<(), pg::Error> {
    let mut tx = client.transaction()?;
    // Stores starting together on a new table race on CREATE TABLE.
    tx.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", &[&format!("fasten.bootstrap.{table}")])?;
    if let Some(schema) = schema {
        tx.batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {schema}"))?;
    }
    for stmt in ddl {
        tx.batch_execute(stmt)?;
    }
    tx.commit()
}

impl StreamStore for PostgresStreamStore {
    fn insert(&self, row: &StreamRow) -> Result<(), Error> {
        let text: Vec<Option<String>> =
            ["request_id", "timestamp", "level", "service_id", "event", "method", "path"].iter().map(|f| lifted_text(row, f)).collect();
        let status = lifted_status(row);
        let payload = payload_text(row);
        self.call(false, |c| {
            c.execute(
                self.insert_sql.as_str(),
                &[&text[0], &text[1], &text[2], &text[3], &text[4], &text[5], &text[6], &status, &payload],
            )
        })
        .map(|_| ())
    }

    fn query(&self, filter: &StreamFilter, limit: u32) -> Result<Vec<StreamRow>, Error> {
        let (clause, values) = filter.where_clause(|n| format!("${n}"));
        // LIMIT is an integer, so writing it into the SQL is safe.
        let limit = fasten_core::store::sql_limit(limit);
        self.rows(&format!("SELECT payload FROM {}{clause} ORDER BY seq DESC LIMIT {limit}", self.table), &values)
    }

    fn count_matching(&self, filter: &StreamFilter) -> Result<u64, Error> {
        let (clause, values) = filter.where_clause(|n| format!("${n}"));
        let boxed = params(&values);
        let refs: Vec<&(dyn ToSql + Sync)> = boxed.iter().map(AsRef::as_ref).collect();
        let sql = format!("SELECT COUNT(*) FROM {}{clause}", self.table);
        let n: i64 = self.call(true, |c| c.query_one(sql.as_str(), &refs).map(|r| r.get(0)))?;
        Ok(n.unsigned_abs())
    }

    fn search(&self, q: &str, since: &str, until: Option<&str>, limit: u32) -> Result<Vec<StreamRow>, Error> {
        // E'\\' is one backslash whatever standard_conforming_strings says.
        let mut conds = vec!["COALESCE(timestamp, '') >= $1", "payload ILIKE $2 ESCAPE E'\\\\'"];
        let mut values = vec![StreamParam::Text(since.to_string()), StreamParam::Text(like_pattern(q))];
        if let Some(u) = until.filter(|u| !u.is_empty()) {
            conds.push("COALESCE(timestamp, '') <= $3");
            values.push(StreamParam::Text(u.to_string()));
        }
        let limit = fasten_core::store::sql_limit(limit);
        let sql = format!("SELECT payload FROM {} WHERE {} ORDER BY seq DESC LIMIT {limit}", self.table, conds.join(" AND "));
        self.rows(&sql, &values)
    }

    fn purge(&self, before: DateTime<Utc>) -> Result<u64, Error> {
        let cutoff = crate::canonical_ts(&before);
        let sql = format!("DELETE FROM {} WHERE timestamp < $1", self.table);
        // Run again after a lost connection it deletes what is left of the
        // same rows; the count is then the second run's. The retention
        // purger reads only the error.
        self.call(true, |c| c.execute(sql.as_str(), &[&cutoff]))
    }

    fn note_write_failure(&self) {
        self.write_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn degraded(&self) -> bool {
        self.write_failures() > 0
    }
}
