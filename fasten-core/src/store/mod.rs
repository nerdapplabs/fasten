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

/// Result of [`Store::list_redaction_candidates`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RedactionCandidates {
    /// `(id, monotonic_seq)` ordered by `monotonic_seq`.
    pub rows: Vec<(String, u64)>,
    /// Matching rows left out because they are sealed (`hash <> ''`).
    /// Always 0 on a table without a `hash` column.
    pub skipped: u64,
}

/// Shared contract for all audit-store backends.
///
/// All methods must be thread-safe; implementations wrap internals in a
/// `Mutex` and implement `Send + Sync`.
pub trait Store: Send + Sync {
    // ── Write ─────────────────────────────────────────────────────────────────

    /// Persist `row`.  Duplicate IDs are silently ignored
    /// (`ON CONFLICT (id) DO NOTHING`).
    ///
    /// When `row.monotonic_seq` is 0 the store assigns the next seq for
    /// `row.source_node_id` inside the insert transaction (spec §2.1, §8.2).
    /// The row is not sealed. A non-zero seq is written as given.
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
    ///
    /// Table-wide, not per node. Kept for existing callers; do not use it to
    /// allocate a seq (insert a row with `monotonic_seq == 0` instead).
    fn max_monotonic_seq(&self) -> Result<u64, Error>;

    // ── Redaction (spec §7.1) ────────────────────────────────────────────────

    /// Rows with `timestamp < before`, `code` in `codes` and a `detail` not
    /// yet redacted. Sealed rows are never listed; they are counted in
    /// `skipped`.
    fn list_redaction_candidates(
        &self,
        _before: &str,
        _codes: &[String],
    ) -> Result<RedactionCandidates, Error> {
        Err(Error::Unsupported("list_redaction_candidates"))
    }

    /// Set `detail` to the JSON literal `null` on the unsealed rows in `ids`.
    /// Idempotent. Returns `ids`.
    fn redact_rows(&self, _ids: &[String]) -> Result<Vec<String>, Error> {
        Err(Error::Unsupported("redact_rows"))
    }
}

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;
