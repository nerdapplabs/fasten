//! SQLite store for the api or sys stream, on fasten-core's.
//! Enable with: fasten-sdk = { features = ["store-sqlite"] }

use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};

use crate::streams::{StreamFilter, StreamRow, StreamStore};
use crate::Error;

/// One stream's table in a SQLite file, the same table the Python, Go and
/// JS SQLite stream stores use (spec persistent-streams.md §2).
///
/// A file database uses WAL with `synchronous=NORMAL`, so a commit does not
/// fsync, and a writer waits up to 5 s for another connection's write lock.
///
/// ```no_run
/// use std::sync::Arc;
/// use fasten::{Config, SqliteStreamStore};
///
/// let syslog = SqliteStreamStore::open("streams.db", "syslog").expect("open");
/// fasten::init(Config {
///     service_id: "my-service".into(),
///     node_id: "node-1".into(),
///     syslog_store: Some(Arc::new(syslog)),
///     ..Default::default()
/// }).expect("init");
/// ```
#[derive(Debug)]
pub struct SqliteStreamStore {
    inner: fasten_core::store::stream_sqlite::SqliteStreamStore,
    write_failures: AtomicU64,
}

fn err(e: fasten_core::Error) -> Error {
    Error::StreamStore(e.to_string())
}

impl SqliteStreamStore {
    /// Open the database at `path` (a file path or `":memory:"`) with WAL,
    /// creating the file (owner-only on Unix), the table and its indexes if
    /// absent. `table` must match `^[A-Za-z_][A-Za-z0-9_]*$`; use
    /// `"api_log"` or `"syslog"` to share tables with the other SDKs.
    pub fn open(path: &str, table: &str) -> Result<Self, Error> {
        Self::open_with(path, table, true)
    }

    /// [`SqliteStreamStore::open`], with WAL on or off.
    pub fn open_with(path: &str, table: &str, wal: bool) -> Result<Self, Error> {
        let inner = fasten_core::store::stream_sqlite::SqliteStreamStore::open(path, table, wal).map_err(|e| match e {
            fasten_core::Error::InvalidTableName(t) => Error::InvalidConfig(format!(
                "fasten SqliteStreamStore: table name {t:?} is not a valid SQL identifier. Use only letters, digits, and underscores."
            )),
            e => err(e),
        })?;
        Ok(Self { inner, write_failures: AtomicU64::new(0) })
    }

    /// Failed writes that were dropped.
    pub fn write_failures(&self) -> u64 {
        self.write_failures.load(Ordering::Relaxed)
    }
}

impl StreamStore for SqliteStreamStore {
    fn insert(&self, row: &StreamRow) -> Result<(), Error> {
        self.inner.insert(row).map_err(err)
    }

    fn query(&self, filter: &StreamFilter, limit: u32) -> Result<Vec<StreamRow>, Error> {
        self.inner.query(filter, limit).map_err(err)
    }

    fn count_matching(&self, filter: &StreamFilter) -> Result<u64, Error> {
        self.inner.count_matching(filter).map_err(err)
    }

    fn search(&self, q: &str, since: &str, until: Option<&str>, limit: u32) -> Result<Vec<StreamRow>, Error> {
        self.inner.search(q, since, until, limit).map_err(err)
    }

    fn purge(&self, before: DateTime<Utc>) -> Result<u64, Error> {
        self.inner.purge(&crate::canonical_ts(&before)).map_err(err)
    }

    fn note_write_failure(&self) {
        self.write_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn degraded(&self) -> bool {
        self.write_failures() > 0
    }
}
