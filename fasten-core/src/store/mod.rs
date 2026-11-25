use serde::{Deserialize, Serialize};

use crate::{
    chain::ChainRow,
    checkpoint::ChainTip,
    error::Error,
    replication::{IngestResult, ReplicatedRow},
    row::Row,
};

/// Query filter for read-path operations.
///
/// All string fields are exact-match predicates.  `since` / `until` are
/// ISO-8601 UTC timestamp bounds applied to the `timestamp` column.
/// A `None` field is ignored (no constraint).  `limit == 0` means no limit.
/// Every key may be left out of the JSON form (`fasten_core.h`), so a
/// missing `limit` or `offset` is 0.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
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

/// Filters for the reader's audit reads, which return rows newest first
/// (timestamp, then `monotonic_seq`), as the Python and Go stores do.
///
/// A `None` or empty text filter is ignored, except `tenant_id`: an empty
/// tenant matches only rows stored with an empty tenant, so a blank scope
/// never widens a read to every tenant. `since` and `until` are canonical
/// timestamps (spec §4.3), inclusive. `after_seq`, when above 0, keeps rows
/// with a lower `monotonic_seq`: the cursor of the next page.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AuditQuery {
    pub request_id:     Option<String>,
    pub code:           Option<String>,
    pub domain:         Option<String>,
    pub source_node_id: Option<String>,
    pub tenant_id:      Option<String>,
    pub actor:          Option<String>,
    pub target:         Option<String>,
    pub since:          Option<String>,
    pub until:          Option<String>,
    /// Maximum rows to return; 0 means no limit.
    pub limit:          u32,
    pub offset:         u64,
    pub after_seq:      u64,
}

impl AuditQuery {
    /// The WHERE conditions and their values, `limit`, `offset` and
    /// `after_seq` left out. `placeholder(n)` renders the n-th parameter.
    /// `node` is the expression for `source_node_id`.
    #[doc(hidden)]
    pub fn conditions(&self, node: &str, ts: impl Fn(usize) -> String, placeholder: impl Fn(usize) -> String) -> (Vec<String>, Vec<String>) {
        let mut conds = Vec::new();
        let mut params: Vec<String> = Vec::new();
        let text = |v: &Option<String>| v.as_deref().filter(|s| !s.is_empty()).map(str::to_string);
        for (col, v) in [
            ("request_id", text(&self.request_id)),
            ("code", text(&self.code)),
            ("domain", text(&self.domain)),
            (node, text(&self.source_node_id)),
            ("tenant_id", self.tenant_id.clone()),
            ("actor", text(&self.actor)),
            ("target", text(&self.target)),
        ] {
            if let Some(v) = v {
                params.push(v);
                conds.push(format!("{col} = {}", placeholder(params.len())));
            }
        }
        for (v, op) in [(text(&self.since), ">="), (text(&self.until), "<=")] {
            if let Some(v) = v {
                params.push(v);
                conds.push(format!("timestamp {op} {}", ts(params.len())));
            }
        }
        (conds, params)
    }
}

/// A free-text search of audit `detail` (spec §9): a case-insensitive
/// substring match within `[since, until]`, newest first. `%`, `_` and `\`
/// in `q` match literally. `tenant_id` scopes it to one tenant.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AuditSearch {
    pub q:         String,
    pub since:     String,
    pub until:     Option<String>,
    /// Maximum rows to return; 0 means no limit.
    pub limit:     u32,
    pub tenant_id: Option<String>,
}

impl AuditQuery {
    /// `limit` as a SQL LIMIT value: 0, no limit, is the largest BIGINT.
    #[doc(hidden)]
    pub fn sql_limit(&self) -> i64 {
        sql_limit(self.limit)
    }
}

impl AuditSearch {
    /// `limit` as a SQL LIMIT value: 0, no limit, is the largest BIGINT.
    #[doc(hidden)]
    pub fn sql_limit(&self) -> i64 {
        sql_limit(self.limit)
    }
}

/// A read's `limit` as a SQL LIMIT value: 0, no limit, is the largest
/// BIGINT, which SQLite and Postgres both take. For the SDK's stores; not a
/// stable API.
#[doc(hidden)]
pub fn sql_limit(limit: u32) -> i64 {
    if limit == 0 { i64::MAX } else { i64::from(limit) }
}

/// Rows written per `(source_node_id, service_id, tenant_id)`, for the
/// reader's `/topology`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Source {
    pub source_node_id: String,
    pub service_id:     String,
    pub tenant_id:      Option<String>,
    pub rows:           u64,
    pub first_seen:     Option<String>,
    pub last_seen:      Option<String>,
}

impl Source {
    /// `rows` rows from one node, service and tenant, first and last seen
    /// at the given canonical timestamps.
    pub fn new(
        source_node_id: String,
        service_id: String,
        tenant_id: Option<String>,
        rows: u64,
        first_seen: Option<String>,
        last_seen: Option<String>,
    ) -> Self {
        Self { source_node_id, service_id, tenant_id, rows, first_seen, last_seen }
    }
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
    /// Persist `row`. A row whose id is already stored is left as it is and
    /// the call succeeds, whatever the new row holds.
    ///
    /// When `row.monotonic_seq` is 0 the store assigns the next seq for
    /// `row.source_node_id` and seals the row after the node's last sealed
    /// row, all inside the insert transaction (spec §2.1). Chain fields the
    /// row carries are replaced. The row must be one this node originated:
    /// an `origin_id` other than `id` is `RowRejected`.
    ///
    /// A non-zero seq is written as given, chain fields included, so a row
    /// without a hash is stored unsealed. An unsealed row at or above a
    /// node's sealed rows makes `verify_chain` fail for that node, so a
    /// writer that picks its own seqs must not share a node id with rows
    /// sealed here (spec §8.2).
    ///
    /// `detail` is written as `serde_json` renders `row.detail`. That keeps
    /// the hash of a row this process built, but not always of a row sealed
    /// elsewhere: a `Row` cannot hold `-0`, an integer past 64 bits, `NaN` or
    /// an unpaired surrogate as its writer hashed them. Store those with
    /// [`Store::insert_sealed`].
    fn insert(&self, row: &Row) -> Result<(), Error>;

    /// Persist a sealed row from elsewhere exactly as it was sealed: every
    /// field as given, and `detail` as the text of `row.detail`
    /// ([`crate::chain::Json`]'s `Display`), so each number token and string
    /// reads back as it was hashed. `pii_in_detail` is the row's flag, which
    /// a `ChainRow` does not carry.
    ///
    /// The row must have a hash and a non-zero `monotonic_seq`; anything
    /// else is `RowRejected`. The hash is not verified here: verify the
    /// batch with `verify_chain` first. Storing the same row again is a
    /// no-op; a different row under a stored id is `RowRejected`, and a
    /// clash on `(source_node_id, monotonic_seq)` is `SeqClash`.
    fn insert_sealed(&self, _row: &ChainRow, _pii_in_detail: bool) -> Result<(), Error> {
        Err(Error::Unsupported("insert_sealed"))
    }

    /// The replicated insert of spec §5: [`Store::insert_sealed`] for a
    /// row shipped from another node, with its flag. The caller has
    /// verified the chain; [`Store::ingest_replicated`] verifies a batch
    /// and checks it against the stored rows first.
    fn insert_replicated(&self, row: &ReplicatedRow) -> Result<(), Error> {
        self.insert_sealed(&row.row, row.pii_in_detail)
    }

    /// Verify the backend is reachable. A lightweight query (`SELECT 1`) is
    /// sufficient; on `PostgreSQL`, a lost connection is re-established first.
    fn ping(&self) -> Result<(), Error>;

    /// Return rows matching `filter`, ordered by `monotonic_seq ASC`.
    fn query(&self, filter: &Filter) -> Result<Vec<Row>, Error>;

    /// Rows matching `filter` as [`ChainRow`]s for
    /// [`crate::chain::verify_chain`], ordered by `source_node_id`, then
    /// `monotonic_seq`. Their `detail` is parsed from the stored text, so
    /// every number is the token that was hashed; `query` reads numbers into
    /// `serde_json` types, which can change them.
    ///
    /// Every matching row is read into memory in one query, and the store's
    /// connection is held until it returns, so inserts wait meanwhile.
    /// `filter.limit` and `filter.offset` page through a large table; a page
    /// is a partial chain (see `CheckpointOptions::partial`).
    fn chain_rows(&self, _filter: &Filter) -> Result<Vec<ChainRow>, Error> {
        Err(Error::Unsupported("chain_rows"))
    }

    /// Each node's sealed row with the highest `monotonic_seq`, ordered by
    /// node id, for [`crate::checkpoint::checkpoints_of`]. A node with no
    /// sealed row is left out.
    fn chain_tips(&self) -> Result<Vec<ChainTip>, Error> {
        Err(Error::Unsupported("chain_tips"))
    }

    /// Return the count of rows matching `filter`.
    fn count(&self, filter: &Filter) -> Result<u64, Error>;

    /// Return up to `limit` rows whose `shipped_at` is NULL, ordered by
    /// `monotonic_seq ASC`.  `limit == 0` returns all unshipped rows.
    fn list_unshipped(&self, limit: u32) -> Result<Vec<Row>, Error>;

    /// Unshipped rows exactly as they were sealed, for shipping to another
    /// node (spec §5), ordered by `monotonic_seq`. `limit == 0` returns all.
    ///
    /// With `origin`, `(service_id, source_node_id)`, only the rows that
    /// identity originated (`origin_id == id`), so rows it ingested from
    /// other nodes are not shipped again. Without it, every unshipped row.
    fn list_unshipped_sealed(
        &self,
        _limit: u32,
        _origin: Option<(&str, &str)>,
    ) -> Result<Vec<ReplicatedRow>, Error> {
        Err(Error::Unsupported("list_unshipped_sealed"))
    }

    /// Set `shipped_at` to the current UTC time for all rows in `ids`, in
    /// one transaction however many ids there are.
    /// IDs that do not exist are silently ignored.
    fn mark_shipped(&self, ids: &[String]) -> Result<(), Error>;

    /// Verify a batch of rows sealed on other nodes and store its verified
    /// prefix in one transaction (spec §4), as the Python, Go and JS stores
    /// do.
    /// A break is reported in the result, not as an error. An error
    /// normally means nothing of the batch was stored, but an error after a
    /// lost connection can leave it stored; sending the batch again is
    /// safe, as a re-delivered row is skipped.
    fn ingest_replicated(
        &self,
        _rows: &[ReplicatedRow],
        _local_node_id: Option<&str>,
    ) -> Result<IngestResult, Error> {
        Err(Error::Unsupported("ingest_replicated"))
    }

    /// Delete rows whose `timestamp` is before `before_iso8601`, per node only
    /// a seq prefix (spec §2.3): rows above a kept row stay, so the rows left
    /// still verify.
    ///
    /// When `respect_unshipped` is `true`, rows with `shipped_at IS NULL` are
    /// preserved regardless of age, and so are the rows above them.
    ///
    /// Returns the number of deleted rows. `before` is an RFC 3339 timestamp
    /// (any offset) or a date, taken as midnight UTC; anything else is an
    /// `InvalidTimestamp` error and deletes nothing. It is never run a
    /// second time on its own: when the connection is lost while it runs,
    /// the Postgres store returns a `Store` error saying the outcome is
    /// unknown.
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

/// `row` as an allocating insert stores it: at `seq`, the next one the
/// store read for the node, sealed after `prev_hash`. Chain fields the caller
/// set are dropped first: the store picks the seq, so a hash sealed over
/// another seq could never verify.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn sealed_at(row: &Row, seq: i64, prev_hash: &str) -> Result<Row, Error> {
    // The hash covers the seq, so it must be the number the column holds.
    let seq = u64::try_from(seq).map_err(|_| {
        Error::Store(format!("node '{}': next monotonic_seq {seq} is negative", row.source_node_id))
    })?;
    let row = Row {
        monotonic_seq: seq,
        prev_hash: None,
        hash: None,
        canonical_form_id: None,
        detail_salt: None,
        detail_commitment: None,
        ..row.clone()
    };
    crate::chain::seal_row(prev_hash, &row).map_err(|e| Error::Seal(e.to_string()))
}

/// The seq of a row with one of its own, as the BIGINT column takes it.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn column_seq(row: &Row) -> Result<i64, Error> {
    i64::try_from(row.monotonic_seq).map_err(|_| {
        Error::RowRejected(format!("row {}: monotonic_seq {} is out of range", row.id, row.monotonic_seq))
    })
}

/// A seq read from the BIGINT column. A negative one is not a seq.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn stored_seq(id: &str, seq: i64) -> Result<u64, Error> {
    u64::try_from(seq).map_err(|_| Error::Store(format!("row {id}: monotonic_seq {seq} is negative")))
}

/// A seq-0 row is one this node originated (`origin_id == id`), as the
/// Python and Go stores require of the rows they seal.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn check_originated(row: &Row) -> Result<(), Error> {
    if row.origin_id == row.id {
        return Ok(());
    }
    Err(Error::RowRejected(format!(
        "row {}: a row with monotonic_seq 0 is sealed here and requires origin_id == id (got origin_id {:?})",
        row.id, row.origin_id
    )))
}

/// A row with this id is already stored and is not the row being inserted.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn differs(id: &str) -> Error {
    Error::RowRejected(format!("row {id}: differs from the stored row with that id"))
}

/// Selects the id of a row at node `node` and seq `seq` (placeholders).
/// For the SDK's stores; not a stable API.
#[doc(hidden)]
pub fn at_seq_sql(table: &str, node: &str, seq: &str) -> String {
    format!("SELECT id FROM {table} WHERE source_node_id = {node} AND monotonic_seq = {seq} LIMIT 1")
}

/// Another row, `other_id`, is stored at `row`'s node and seq. For the
/// SDK's stores; not a stable API.
#[doc(hidden)]
pub fn seq_taken(row: &Row, other_id: &str) -> Error {
    Error::SeqClash(format!(
        "row {}: seq {} on node {:?} is stored as row {other_id}",
        row.id, row.monotonic_seq, row.source_node_id
    ))
}

/// What an insert found.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) enum Outcome {
    /// The row was written; this is it as stored.
    Inserted(Row),
    /// A row with this id was already stored and nothing was written: that
    /// row, and the text of its `detail` column.
    Held(Row, String),
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
impl Outcome {
    /// `row` as the store holds it. For a row already stored that is `row`
    /// with the stored seq and chain fields, once the stored row is checked
    /// to be the same event, at the same seq and hash when `row` has its
    /// own; a different row under that id is `RowRejected`.
    pub(crate) fn stored(self, row: &Row) -> Result<Row, Error> {
        let (held, detail) = match self {
            Outcome::Inserted(stored) => return Ok(stored),
            Outcome::Held(held, detail) => (held, detail),
        };
        let same = chain_row(&held, &detail)?.same_event(&ChainRow::from(row))
            && (row.monotonic_seq == 0
                || (row.monotonic_seq == held.monotonic_seq
                    && row.hash.as_deref().unwrap_or("") == held.hash.as_deref().unwrap_or("")));
        if !same {
            return Err(differs(&row.id));
        }
        Ok(Row {
            monotonic_seq: held.monotonic_seq,
            prev_hash: held.prev_hash,
            hash: held.hash,
            canonical_form_id: held.canonical_form_id,
            detail_salt: held.detail_salt,
            detail_commitment: held.detail_commitment,
            ..row.clone()
        })
    }

    /// The result of `insert_sealed` for `row`: a row already stored must
    /// have the same hash.
    pub(crate) fn sealed(self, row: &ChainRow) -> Result<(), Error> {
        match self {
            Outcome::Held(held, _) if held.hash.as_deref() != Some(row.hash.as_str()) => Err(differs(&row.id)),
            _ => Ok(()),
        }
    }
}

/// `row` as the columns `insert_sealed` writes, and the text of its detail.
/// The `Row`'s own `detail` is not written. For the SDK's stores; not a
/// stable API.
#[doc(hidden)]
pub fn sealed_columns(row: &ChainRow, pii_in_detail: bool) -> Result<(Row, String), Error> {
    if row.hash.is_empty() || row.monotonic_seq == 0 {
        return Err(Error::RowRejected(format!(
            "row {}: insert_sealed requires a sealed row (a hash and a non-zero monotonic_seq)",
            row.id
        )));
    }
    // Stored in the wire form, so the text compares as the other SDKs
    // write it; one the Python and Go stores cannot read is refused.
    let canonical = |field: &str, ts: &str| {
        crate::replication::canonical_timestamp(ts).ok_or_else(|| {
            Error::RowRejected(format!("row {}: {field} is not an RFC 3339 timestamp", row.id))
        })
    };
    let timestamp = canonical("timestamp", &row.timestamp)?;
    let shipped_at = row.shipped_at.as_deref().map(|s| canonical("shipped_at", s)).transpose()?;
    let columns = Row {
        wire_version: row.wire_version.clone(),
        id: row.id.clone(),
        origin_id: row.origin_id.clone(),
        monotonic_seq: row.monotonic_seq,
        timestamp,
        code: row.code.clone(),
        action: row.action.clone(),
        severity: row.severity.clone(),
        service_id: row.service_id.clone(),
        source_node_id: row.source_node_id.clone(),
        tenant_id: row.tenant_id.clone(),
        actor: row.actor.clone(),
        actor_kind: row.actor_kind.clone(),
        target: row.target.clone(),
        category: row.category.clone(),
        domain: row.domain.clone(),
        method: row.method.clone(),
        request_id: row.request_id.clone(),
        detail: serde_json::Value::Null,
        pii_in_detail,
        shipped_at,
        prev_hash: Some(row.prev_hash.clone()),
        hash: Some(row.hash.clone()),
        canonical_form_id: Some(row.canonical_form_id.clone()).filter(|f| !f.is_empty()),
        detail_salt: row.detail_salt.clone(),
        detail_commitment: row.detail_commitment.clone(),
        ..Default::default()
    };
    Ok((columns, row.detail.to_string()))
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

/// Selects `source_node_id, monotonic_seq, hash` of each node's sealed row
/// with the highest seq, ordered by node id. It walks the (source_node_id,
/// monotonic_seq) index: the next node id after the last, then that node's
/// sealed row with the highest seq. The same in SQLite and Postgres, and the
/// query the Python and Go stores run. For the SDK's stores; not a stable
/// API.
#[doc(hidden)]
pub fn chain_tips_sql(table: &str) -> String {
    format!(
        "SELECT source_node_id, monotonic_seq, hash FROM {table} JOIN (\
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
    ChainRow::from_row(row, detail_text).map_err(|e| Error::Store(format!("row {}: detail: {e}", row.id)))
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
/// For the SDK's stores; not a stable API.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
#[doc(hidden)]
pub fn purge_sql(table: &str, param: &str, respect_unshipped: bool, postgres: bool) -> String {
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
/// `InvalidTimestamp` error. As given, an offset or a lowercase `t` sorts
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

/// `''` and NULL both mean "no salt" or "no commitment".
pub(crate) fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.is_empty())
}

pub mod stream;

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "sqlite")]
pub mod stream_sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(test)]
mod tests {
    use super::Filter;

    /// Every key is optional in the JSON form, `limit` and `offset` included.
    #[test]
    fn filter_keys_are_all_optional() {
        let f: Filter = serde_json::from_str(r#"{"code":"X"}"#).unwrap();
        assert_eq!(f.code.as_deref(), Some("X"));
        assert_eq!((f.limit, f.offset), (0, 0));
        let f: Filter = serde_json::from_str("{}").unwrap();
        assert!(f.code.is_none() && f.limit == 0);
    }
}
