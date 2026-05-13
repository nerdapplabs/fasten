use serde::{Deserialize, Serialize};

use crate::{error::Error, row::Row};

/// Query filter for read-path operations.
///
/// All string fields are exact-match predicates.  `since` / `until` are
/// ISO-8601 UTC timestamp bounds applied to the `timestamp` column.
/// A `None` field is ignored (no constraint).  `limit == 0` means no limit.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Filter {
    pub request_id:     Option<String>,
    pub code:           Option<String>,
    pub domain:         Option<String>,
    pub source_node_id: Option<String>,
    /// Lower bound (inclusive) for `timestamp`.
    pub since:          Option<String>,
    /// Upper bound (inclusive) for `timestamp`.
    pub until:          Option<String>,
    /// Maximum rows to return (0 = no limit).
    pub limit:          u32,
    /// Skip this many matching rows before returning results.
    pub offset:         u32,
}

/// Shared contract for all audit-store backends.
///
/// All methods must be thread-safe; implementations wrap internals in a
/// `Mutex` and implement `Send + Sync`.
pub trait Store: Send + Sync {
    // ── Write ─────────────────────────────────────────────────────────────────

    /// Persist `row`.  Duplicate IDs are silently ignored
    /// (`INSERT OR IGNORE` / `ON CONFLICT DO NOTHING`).
    fn insert(&self, row: &Row) -> Result<(), Error>;

    // ── Health ────────────────────────────────────────────────────────────────

    /// Verify the backend is reachable. A lightweight query (`SELECT 1`) is
    /// sufficient; on PostgreSQL, a lost connection is re-established first.
    fn ping(&self) -> Result<(), Error>;

    // ── Read path ─────────────────────────────────────────────────────────────

    /// Return rows matching `filter`, ordered by `monotonic_seq ASC`.
    fn query(&self, filter: &Filter) -> Result<Vec<Row>, Error>;

    /// Return the count of rows matching `filter`.
    fn count(&self, filter: &Filter) -> Result<u64, Error>;

    /// Return up to `limit` rows whose `shipped_at` is NULL, ordered by
    /// `monotonic_seq ASC`.  `limit == 0` returns all unshipped rows.
    fn list_unshipped(&self, limit: u32) -> Result<Vec<Row>, Error>;

    /// Set `shipped_at` to the current UTC time for all rows in `ids`.
    /// IDs that do not exist are silently ignored.
    fn mark_shipped(&self, ids: &[String]) -> Result<(), Error>;

    /// Delete rows whose `timestamp` is before `before_iso8601`.
    ///
    /// When `respect_unshipped` is `true`, rows with `shipped_at IS NULL` are
    /// preserved regardless of age.
    ///
    /// Returns the number of deleted rows.
    fn purge(&self, before: &str, respect_unshipped: bool) -> Result<u64, Error>;

    /// Return the maximum `monotonic_seq` across all stored rows, or `0` if
    /// the table is empty.
    fn max_monotonic_seq(&self) -> Result<u64, Error>;
}

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;
