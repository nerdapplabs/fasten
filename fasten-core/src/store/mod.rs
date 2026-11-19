use serde::{Deserialize, Serialize};

use crate::{chain::ChainRow, error::Error, row::Row};

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
    /// Matching rows left out because they are sealed under form "1".
    pub skipped: u64,
}

/// Which rows redaction may touch, from the chain columns the table has
/// (spec §7.1). A sealed form-"2" row, which is what the stores write,
/// hashes without its detail and is redacted, as is an unsealed row; a sealed
/// form-"1" row is refused.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
#[derive(Debug, Default, Clone, Copy)]
struct RedactGate {
    hash: bool,
    form: bool,
    salt: bool,
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
impl RedactGate {
    /// From the table's column names, in any case.
    fn from_columns<S: AsRef<str>>(cols: &[S]) -> Self {
        let has = |name: &str| cols.iter().any(|c| c.as_ref().eq_ignore_ascii_case(name));
        RedactGate { hash: has("hash"), form: has("canonical_form_id"), salt: has("detail_salt") }
    }

    /// Appended to a WHERE clause: the rows redaction may touch.
    fn allowed(self) -> &'static str {
        match (self.hash, self.form) {
            (false, _) => "",
            (true, false) => " AND hash = ''",
            (true, true) => " AND (canonical_form_id = '2' OR hash = '')",
        }
    }

    /// Appended to a WHERE clause: the rows redaction refuses, or `None` when
    /// the table can hold none.
    fn refused(self) -> Option<&'static str> {
        match (self.hash, self.form) {
            (false, _) => None,
            (true, false) => Some(" AND hash <> ''"),
            (true, true) => Some(" AND canonical_form_id <> '2' AND hash <> ''"),
        }
    }

    /// The SET list of the redacting UPDATE. 'null' is the JSON literal:
    /// detail is NOT NULL, and it reads back as a null detail.
    fn set(self) -> &'static str {
        if self.salt {
            "detail = 'null', detail_salt = ''"
        } else {
            "detail = 'null'"
        }
    }
}

/// Shared contract for all audit-store backends.
///
/// Implementations must be `Send + Sync`; methods are called from several
/// threads.
pub trait Store: Send + Sync {
    /// Persist `row`.  Duplicate IDs are silently ignored
    /// (`ON CONFLICT (id) DO NOTHING`).
    ///
    /// When `row.monotonic_seq` is 0 the store assigns the next seq for
    /// `row.source_node_id` and seals the row after the node's last sealed
    /// row, all inside the insert transaction (spec §2.1). Chain fields the
    /// row carries are replaced.
    ///
    /// A non-zero seq is written as given, chain fields included: a sealed
    /// row replicated from elsewhere keeps its hash, and a row without one
    /// stays unsealed. A writer that picks its own seqs must not share a
    /// node id with rows sealed here (spec §8.2).
    fn insert(&self, row: &Row) -> Result<(), Error>;

    /// Verify the backend is reachable. A lightweight query (`SELECT 1`) is
    /// sufficient; on PostgreSQL, a lost connection is re-established first.
    fn ping(&self) -> Result<(), Error>;

    /// Return rows matching `filter`, ordered by `monotonic_seq ASC`.
    fn query(&self, filter: &Filter) -> Result<Vec<Row>, Error>;

    /// Rows matching `filter` as [`ChainRow`]s for
    /// [`crate::chain::verify_chain`], ordered by `monotonic_seq ASC`. Their
    /// `detail` is parsed from the stored text, so every number is the token
    /// that was hashed; `query` reads numbers into `serde_json` types, which
    /// can change them.
    fn chain_rows(&self, _filter: &Filter) -> Result<Vec<ChainRow>, Error> {
        Err(Error::Unsupported("chain_rows"))
    }

    /// Each node's sealed row with the highest `monotonic_seq`, ordered by
    /// node id, for [`crate::checkpoint::checkpoints_of`]. A node with no
    /// sealed row is left out.
    fn chain_tips(&self) -> Result<Vec<ChainRow>, Error> {
        Err(Error::Unsupported("chain_tips"))
    }

    /// Return the count of rows matching `filter`.
    fn count(&self, filter: &Filter) -> Result<u64, Error>;

    /// Return up to `limit` rows whose `shipped_at` is NULL, ordered by
    /// `monotonic_seq ASC`.  `limit == 0` returns all unshipped rows.
    fn list_unshipped(&self, limit: u32) -> Result<Vec<Row>, Error>;

    /// Set `shipped_at` to the current UTC time for all rows in `ids`, in
    /// one transaction however many ids there are.
    /// IDs that do not exist are silently ignored.
    fn mark_shipped(&self, ids: &[String]) -> Result<(), Error>;

    /// Delete rows whose `timestamp` is before `before_iso8601`, per node only
    /// a seq prefix (spec §2.3): rows above a kept row stay, so the rows left
    /// still verify.
    ///
    /// When `respect_unshipped` is `true`, rows with `shipped_at IS NULL` are
    /// preserved regardless of age, and so are the rows above them.
    ///
    /// Returns the number of deleted rows. `before` is an RFC 3339 timestamp
    /// (any offset) or a date, taken as midnight UTC; anything else is an
    /// `InvalidTimestamp` error and deletes nothing.
    fn purge(&self, before: &str, respect_unshipped: bool) -> Result<u64, Error>;

    /// Return the maximum `monotonic_seq` across all stored rows, or `0` if
    /// the table is empty.
    ///
    /// Table-wide, not per node. Kept for existing callers; do not use it to
    /// allocate a seq (insert a row with `monotonic_seq == 0` instead).
    fn max_monotonic_seq(&self) -> Result<u64, Error>;

    // ── Redaction (spec §7.1) ────────────────────────────────────────────────

    /// Rows with `timestamp < before`, `code` in `codes` and a `detail` not
    /// yet redacted. Sealed form-"1" rows are never listed; they are counted
    /// in `skipped`.
    fn list_redaction_candidates(
        &self,
        _before: &str,
        _codes: &[String],
    ) -> Result<RedactionCandidates, Error> {
        Err(Error::Unsupported("list_redaction_candidates"))
    }

    /// Set `detail` to the JSON literal `null` (and `detail_salt`, when the
    /// table has one, to `''`) on the rows in `ids` that are not sealed
    /// form-"1" rows. Idempotent. Returns `ids`.
    fn redact_rows(&self, _ids: &[String]) -> Result<Vec<String>, Error> {
        Err(Error::Unsupported("redact_rows"))
    }
}

/// `row` as an allocating insert stores it: at `seq`, sealed after
/// `prev_hash`. Chain fields the caller set are dropped first: the store
/// picks the seq, so a hash sealed over another seq could never verify.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn sealed_at(row: &Row, seq: u64, prev_hash: &str) -> Result<Row, Error> {
    let row = Row {
        monotonic_seq: seq,
        prev_hash: None,
        hash: None,
        canonical_form_id: None,
        detail_salt: None,
        detail_commitment: None,
        ..row.clone()
    };
    crate::chain::seal_row(prev_hash, &row).map_err(|e| Error::Store(e.to_string()))
}

/// Selects the hash of a node's sealed row with the highest seq, which its
/// next row links to; no row means "genesis" (spec §2.1).
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn tip_sql(table: &str, param: &str) -> String {
    format!(
        "SELECT hash FROM {table} WHERE source_node_id = {param} AND hash <> '' \
         ORDER BY monotonic_seq DESC LIMIT 1"
    )
}

/// Selects each node's sealed row with the highest seq, as `columns` of
/// `table`, ordered by node id. It walks the (source_node_id, monotonic_seq)
/// index: the next node id after the last, then that node's sealed row with
/// the highest seq. The same in SQLite and Postgres, and the query the Python
/// and Go stores run.
pub fn chain_tips_sql(table: &str, columns: &str) -> String {
    format!(
        "SELECT {columns} FROM {table} JOIN (\
         WITH RECURSIVE nodes(node) AS (SELECT MIN(source_node_id) FROM {table} UNION ALL \
         SELECT (SELECT MIN(source_node_id) FROM {table} WHERE source_node_id > node) \
         FROM nodes WHERE node IS NOT NULL) \
         SELECT node, (SELECT monotonic_seq FROM {table} WHERE source_node_id = node \
         AND hash <> '' ORDER BY monotonic_seq DESC LIMIT 1) AS seq \
         FROM nodes WHERE node IS NOT NULL) AS tip \
         ON source_node_id = tip.node AND monotonic_seq = tip.seq \
         WHERE hash <> '' ORDER BY source_node_id, id"
    )
}

/// A stored row for verification: `row` as the row mapper read it, with
/// `detail` taken from the column text.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn chain_row(row: &Row, detail_text: &str) -> Result<ChainRow, Error> {
    let mut out = ChainRow::from(row);
    out.detail = crate::chain::Json::parse(detail_text)
        .map_err(|e| Error::Store(format!("row {}: detail: {e}", row.id)))?;
    Ok(out)
}

/// Chain columns (spec §1, §2), in table order. A table an older
/// fasten-core created lacks them; `migrate` adds them. `detail_salt` and
/// `detail_commitment` are written as `''` when absent, since a table the Go
/// store created declares them NOT NULL.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) const CHAIN_COLUMNS: [(&str, &str); 5] = [
    ("prev_hash", "TEXT NOT NULL DEFAULT ''"),
    ("hash", "TEXT NOT NULL DEFAULT ''"),
    ("canonical_form_id", "TEXT NOT NULL DEFAULT '1'"),
    ("detail_salt", "TEXT"),
    ("detail_commitment", "TEXT"),
];

/// Every column a store reads back, in the order the row mappers expect.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) const SELECT_COLUMNS: &str = "id,wire_version,origin_id,monotonic_seq,timestamp,\
     code,action,severity,service_id,source_node_id,tenant_id,\
     actor,actor_kind,target,category,domain,method,\
     request_id,detail,pii_in_detail,shipped_at,\
     prev_hash,hash,canonical_form_id,detail_salt,detail_commitment";

/// `''` and NULL both mean "no salt / commitment" (form "1").
#[cfg(any(feature = "sqlite", feature = "postgres"))]
/// The age purge (spec §2.3). Per node it deletes only the rows below the
/// lowest seq it keeps, a row at or after the cutoff or, with
/// `respect_unshipped`, an unshipped row, so what is left is a seq suffix.
/// Rows at seq 0 are not chained and go by age alone. `param` is the
/// cutoff's placeholder.
///
/// Each node's lowest kept seq is one walk up the (source_node_id,
/// monotonic_seq) index, and the LIMIT keeps the planner from repeating it
/// per row. Postgres deletes with USING; SQLite has no USING, so it matches
/// ids.
pub(crate) fn purge_sql(table: &str, param: &str, respect_unshipped: bool, postgres: bool) -> String {
    let (unshipped, shipped) = if respect_unshipped {
        (" OR shipped_at IS NULL", " AND d.shipped_at IS NOT NULL")
    } else {
        ("", "")
    };
    let max = i64::MAX;
    let bound = format!(
        "WITH RECURSIVE nodes(node) AS (SELECT MIN(source_node_id) FROM {table} UNION ALL \
         SELECT (SELECT MIN(source_node_id) FROM {table} WHERE source_node_id > node) \
         FROM nodes WHERE node IS NOT NULL), \
         bound AS (SELECT node, COALESCE((SELECT monotonic_seq FROM {table} WHERE source_node_id = node \
         AND monotonic_seq > 0 AND (timestamp >= {param}{unshipped}) ORDER BY monotonic_seq LIMIT 1), \
         {max}) AS keep_from FROM nodes WHERE node IS NOT NULL LIMIT {max}) "
    );
    let matches = format!(
        "d.source_node_id = bound.node AND d.monotonic_seq < bound.keep_from \
         AND d.timestamp < {param}{shipped}"
    );
    if postgres {
        format!("{bound}DELETE FROM {table} AS d USING bound WHERE {matches}")
    } else {
        format!("DELETE FROM {table} WHERE id IN ({bound}SELECT d.id FROM bound, {table} AS d WHERE {matches})")
    }
}

/// The purge or redaction cutoff as a canonical UTC timestamp (spec §4.3),
/// which the stores compare with `timestamp` as text. Takes an RFC 3339 timestamp
/// with any offset, or a date (midnight UTC); anything else is an
/// InvalidTimestamp error. As given, an offset or a lowercase `t` sorts
/// differently from the stored form and deletes too much, and a string
/// like "tomorrow" sorts after every row.
pub(crate) fn purge_cutoff(before: &str) -> Result<String, Error> {
    let bad = || Error::InvalidTimestamp(before.to_string());
    let utc = match chrono::DateTime::parse_from_rfc3339(before) {
        Ok(t) => t.with_timezone(&chrono::Utc),
        Err(_) => chrono::NaiveDate::parse_from_str(before, "%Y-%m-%d")
            .map_err(|_| bad())?
            .and_hms_opt(0, 0, 0)
            .ok_or_else(bad)?
            .and_utc(),
    };
    Ok(utc.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
}

pub(crate) fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.is_empty())
}

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;
