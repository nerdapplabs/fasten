//! `SQLite` store for the api or sys stream: the same table as the Python, Go
//! and JS `SQLite` stream stores (spec persistent-streams.md §2).

use std::sync::Mutex;
use std::time::Duration;

use rusqlite::types::ToSqlOutput;
use rusqlite::Connection;

use super::stream::{
    ddl, insert_sql, lifted_values, like_pattern, parse_payload, payload_text, StreamFilter, StreamParam,
    StreamRow,
};
use crate::error::Error;

/// One stream's table in a `SQLite` file. Rows come back newest first,
/// decoded from the stored JSON.
///
/// A file database uses WAL with `synchronous=NORMAL`, so a commit is a WAL
/// append without an fsync. A writer waits up to 5 s for another
/// connection's write lock.
pub struct SqliteStreamStore {
    conn: Mutex<Connection>,
    table: String,
    insert_sql: String,
}

impl std::fmt::Debug for SqliteStreamStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStreamStore").field("table", &self.table).finish_non_exhaustive()
    }
}

impl rusqlite::ToSql for StreamParam {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        match self {
            StreamParam::Text(s) => s.to_sql(),
            StreamParam::Int(n) => n.to_sql(),
        }
    }
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl SqliteStreamStore {
    /// Open the database at `path` (a file path, a `file:` URI or
    /// `":memory:"`) and create the table and its indexes if absent. A new
    /// file is created owner-only on Unix. `table` must match
    /// `^[A-Za-z_][A-Za-z0-9_]*$`.
    pub fn open(path: &str, table: &str, wal: bool) -> Result<Self, Error> {
        if !is_identifier(table) {
            return Err(Error::InvalidTableName(table.to_owned()));
        }
        super::sqlite::create_owner_only(path);
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        if wal && path != ":memory:" {
            conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        }
        for stmt in ddl(table, table, false)? {
            conn.execute_batch(&stmt)?;
        }
        Ok(Self { conn: Mutex::new(conn), table: table.to_owned(), insert_sql: insert_sql(table, |n| format!("?{n}"))? })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Store one row: the whole row as JSON in `payload`, the lifted fields
    /// in their columns.
    pub fn insert(&self, row: &StreamRow) -> Result<(), Error> {
        let mut values: Vec<Option<StreamParam>> = lifted_values(row);
        values.push(Some(StreamParam::Text(payload_text(row))));
        let refs: Vec<&dyn rusqlite::ToSql> = values.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
        self.lock().prepare_cached(&self.insert_sql)?.execute(refs.as_slice())?;
        Ok(())
    }

    fn rows(&self, sql: &str, params: &[StreamParam]) -> Result<Vec<StreamRow>, Error> {
        let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
        let guard = self.lock();
        let mut stmt = guard.prepare(sql)?;
        let texts = stmt
            .query_map(refs.as_slice(), |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        drop(guard);
        texts.iter().map(|t| parse_payload(t).map_err(Error::from)).collect()
    }

    /// Up to `limit` rows matching `filter`, newest first; 0 means no limit.
    pub fn query(&self, filter: &StreamFilter, limit: u32) -> Result<Vec<StreamRow>, Error> {
        let (clause, params) = filter.where_clause(|n| format!("?{n}"));
        // LIMIT is an integer, so writing it into the SQL is safe.
        let limit = super::sql_limit(limit);
        self.rows(&format!("SELECT payload FROM {}{clause} ORDER BY seq DESC LIMIT {limit}", self.table), &params)
    }

    /// How many rows match `filter`, with no limit.
    pub fn count_matching(&self, filter: &StreamFilter) -> Result<u64, Error> {
        let (clause, params) = filter.where_clause(|n| format!("?{n}"));
        let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
        let n: i64 = self
            .lock()
            .prepare(&format!("SELECT COUNT(*) FROM {}{clause}", self.table))?
            .query_row(refs.as_slice(), |r| r.get(0))?;
        Ok(n.unsigned_abs())
    }

    /// Case-insensitive substring search of the stored JSON within
    /// `[since, until]`, newest first, at most `limit` rows (0 for all). A
    /// linear `LIKE` scan; `%`, `_` and `\` in `q` match literally.
    pub fn search(&self, q: &str, since: &str, until: Option<&str>, limit: u32) -> Result<Vec<StreamRow>, Error> {
        let mut conds = vec!["COALESCE(timestamp, '') >= ?1", "lower(payload) LIKE ?2 ESCAPE '\\'"];
        let mut params = vec![StreamParam::Text(since.to_string()), StreamParam::Text(like_pattern(&q.to_lowercase()))];
        if let Some(u) = until.filter(|u| !u.is_empty()) {
            conds.push("COALESCE(timestamp, '') <= ?3");
            params.push(StreamParam::Text(u.to_string()));
        }
        let limit = super::sql_limit(limit);
        let sql = format!("SELECT payload FROM {} WHERE {} ORDER BY seq DESC LIMIT {limit}", self.table, conds.join(" AND "));
        self.rows(&sql, &params)
    }

    /// Delete rows with a timestamp before `before` and return how many.
    /// `before` is an RFC 3339 timestamp or a date, compared in the
    /// canonical form. Rows without a timestamp are kept.
    pub fn purge(&self, before: &str) -> Result<u64, Error> {
        let cutoff = super::purge_cutoff(before)?;
        let n = self.lock().execute(&format!("DELETE FROM {} WHERE timestamp < ?1", self.table), [cutoff])?;
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(v: serde_json::Value) -> StreamRow {
        match v {
            serde_json::Value::Object(m) => m,
            _ => unreachable!(),
        }
    }

    #[test]
    fn rows_round_trip_newest_first() {
        let s = SqliteStreamStore::open(":memory:", "syslog", true).unwrap();
        s.insert(&row(json!({"event": "a", "timestamp": "2026-01-01T00:00:00.000000Z", "n": 1}))).unwrap();
        s.insert(&row(json!({"event": "b", "timestamp": "2026-01-02T00:00:00.000000Z", "é": "ü"}))).unwrap();
        let got = s.query(&StreamFilter::default(), 10).unwrap();
        assert_eq!(got[0]["event"], "b");
        assert_eq!(got[1]["n"], 1);
        assert_eq!(s.count_matching(&StreamFilter { event: Some("a".into()), ..Default::default() }).unwrap(), 1);
        assert_eq!(s.search("Ü", "2026", None, 10).unwrap().len(), 1);
        assert_eq!(s.purge("2026-01-02T00:00:00Z").unwrap(), 1);
    }

    #[test]
    fn bad_table_names_are_refused() {
        assert!(SqliteStreamStore::open(":memory:", "a.b", true).is_err());
        assert!(SqliteStreamStore::open(":memory:", "x;drop", true).is_err());
    }

    // Python's SQLite stream DDL (python/fasten/store/stream.py); Go's has
    // the same columns and index names.
    #[test]
    fn reads_and_appends_to_a_table_python_created() {
        let path = std::env::temp_dir().join(format!("fasten-py-stream-{}.db", std::process::id()));
        let path = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);
        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS syslog (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT, timestamp TEXT, level TEXT,
                service_id TEXT, event TEXT, method TEXT, path TEXT, status INTEGER, payload TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS idx_syslog_req ON syslog(request_id);
             CREATE INDEX IF NOT EXISTS idx_syslog_ts  ON syslog(timestamp);
             INSERT INTO syslog (request_id, timestamp, level, service_id, event, payload)
               VALUES ('r-py', '2026-01-01T00:00:00.000000Z', 'info', 'py', 'started', '{\"request_id\": \"r-py\", \"event\": \"started\", \"n\": 1.0}');",
        )
        .unwrap();
        drop(c);
        let s = SqliteStreamStore::open(&path, "syslog", true).unwrap();
        s.insert(&row(json!({"request_id": "r-rust", "event": "started"}))).unwrap();
        let f = StreamFilter { event: Some("started".into()), ..Default::default() };
        let got = s.query(&f, 10).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0]["request_id"], "r-rust");
        assert_eq!(got[1]["n"], 1.0);
        let _ = std::fs::remove_file(&path);
    }
}
