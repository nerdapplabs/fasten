//! Replication (spec/chain-replication.md §4, §5): the rows a node ships,
//! and the ingest of a batch of rows sealed on other nodes.
//!
//! Ingest verifies the batch per node, checks it against what the store
//! already holds, and stores the verified prefix exactly as it was sealed,
//! in one transaction. It stops at the first break and reports it, so the
//! sender can resync from there. The steps are those of the Python
//! (`store/repo.py`), Go (`ingest.go`) and JS (`replication.js`) SDKs, and
//! the result has the same fields.
//!
//! The stores run the steps on their own transactions through `IngestTx`
//! and `ingest`, which are for the stores of this crate and the SDK, not a
//! stable API.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::LazyLock;

use crate::chain::{verify_chain, ChainError, ChainRow, Json, JsonString};

/// A sealed row as one node ships it to another: the row as it was hashed,
/// with its detail number tokens exact, and its `pii_in_detail` flag, which
/// the chain does not hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicatedRow {
    pub row: ChainRow,
    pub pii_in_detail: bool,
}

impl From<ChainRow> for ReplicatedRow {
    fn from(row: ChainRow) -> Self {
        Self { row, pii_in_detail: false }
    }
}

impl ReplicatedRow {
    /// Parse one wire-format row, as [`ChainRow::from_json`] does, with its
    /// `pii_in_detail` flag (`true`, `false`, `1` or `0`; missing is false).
    pub fn from_json(text: &str) -> Result<Self, ChainError> {
        Self::from_value(&Json::parse(text)?)
    }

    /// Build from a parsed wire-format row; see [`ReplicatedRow::from_json`].
    pub fn from_value(v: &Json) -> Result<Self, ChainError> {
        let pii_in_detail = match v.get("pii_in_detail") {
            None | Some(Json::Null) => false,
            Some(Json::Bool(b)) => *b,
            Some(Json::Number(n)) if n == "0" => false,
            Some(Json::Number(n)) if n == "1" => true,
            Some(_) => return Err(ChainError::Field("pii_in_detail", "not a boolean")),
        };
        Ok(Self { row: ChainRow::from_value(v)?, pii_in_detail })
    }

    /// The row as a wire-format JSON object, which [`ReplicatedRow::from_json`]
    /// and the other SDKs read back to the same row. `detail` keeps its
    /// number tokens; a missing salt or commitment is left out.
    pub fn to_value(&self) -> Json {
        let r = &self.row;
        let text = |s: &str| Json::String(s.into());
        let opt = |s: &Option<String>| s.as_deref().map_or(Json::Null, text);
        let mut m: BTreeMap<JsonString, Json> = [
            ("wire_version", text(&r.wire_version)),
            ("id", text(&r.id)),
            ("origin_id", text(&r.origin_id)),
            ("monotonic_seq", Json::Number(r.monotonic_seq.to_string())),
            ("timestamp", text(&r.timestamp)),
            ("code", text(&r.code)),
            ("action", text(&r.action)),
            ("severity", text(&r.severity)),
            ("service_id", text(&r.service_id)),
            ("source_node_id", text(&r.source_node_id)),
            ("tenant_id", opt(&r.tenant_id)),
            ("actor", text(&r.actor)),
            ("actor_kind", text(&r.actor_kind)),
            ("target", text(&r.target)),
            ("category", text(&r.category)),
            ("domain", text(&r.domain)),
            ("method", text(&r.method)),
            ("request_id", text(&r.request_id)),
            ("detail", r.detail.clone()),
            ("pii_in_detail", Json::Bool(self.pii_in_detail)),
            ("shipped_at", opt(&r.shipped_at)),
            ("canonical_form_id", text(&r.canonical_form_id)),
            ("prev_hash", text(&r.prev_hash)),
            ("hash", text(&r.hash)),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v))
        .collect();
        if let Some(salt) = &r.detail_salt {
            m.insert("detail_salt".into(), text(salt));
        }
        if let Some(commitment) = &r.detail_commitment {
            m.insert("detail_commitment".into(), text(commitment));
        }
        Json::Object(m)
    }

    /// [`ReplicatedRow::to_value`] as one line of JSON text.
    pub fn to_json(&self) -> String {
        self.to_value().to_string()
    }
}

/// Result of an ingest, with the field names the Python, Go and JS SDKs
/// use. Build one with [`IngestResult::stored`] or [`IngestResult::cut`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct IngestResult {
    /// The verified rows the call stored or found already stored (a
    /// re-delivery).
    pub inserted: usize,
    /// When the batch broke, the `monotonic_seq` of the first row not
    /// stored; the rows from that seq on, on every node, are left for the
    /// sender to resend. Set together with `reason`: both are `None` when
    /// the whole batch was stored.
    pub rejected_from_seq: Option<u64>,
    /// Why the batch broke at `rejected_from_seq`; set together with it.
    pub reason: Option<String>,
}

impl IngestResult {
    /// The whole batch was stored: `inserted` rows, no break.
    pub fn stored(inserted: usize) -> Self {
        Self { inserted, rejected_from_seq: None, reason: None }
    }

    /// `inserted` rows were stored, and the batch broke at `seq` for
    /// `reason`.
    pub fn cut(inserted: usize, seq: u64, reason: impl Into<String>) -> Self {
        Self { inserted, rejected_from_seq: Some(seq), reason: Some(reason.into()) }
    }

    /// `inserted` rows, and the break, if any, as `(seq, reason)`.
    fn with_break(inserted: usize, cut: Option<(u64, String)>) -> Self {
        match cut {
            Some((seq, reason)) => Self::cut(inserted, seq, reason),
            None => Self::stored(inserted),
        }
    }
}

/// A row of the batch whose timestamp the stores cannot hold. The whole
/// batch is refused and nothing is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BatchError {
    /// The row's index in the batch.
    pub index: usize,
    pub id: String,
    /// `timestamp` or `shipped_at`.
    pub field: &'static str,
}

impl fmt::Display for BatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rows[{}] (row {}): {} is not an RFC 3339 timestamp", self.index, self.id, self.field)
    }
}

impl std::error::Error for BatchError {}

#[allow(clippy::expect_used)]
static RFC3339: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-](\d{2}):(\d{2}))$")
        .expect("timestamp regex is valid")
});

/// `ts` in the wire form (spec §4.3), `YYYY-MM-DDTHH:MM:SS.ffffffZ` in UTC,
/// or `None` when it is not an RFC 3339 timestamp the Python and Go stores
/// can read back: year 0, a second of 60, an offset above 23:59, or a UTC
/// year outside 1 to 9999 once the offset is applied. Digits past the
/// sixth are dropped. For the stores of this crate and the SDK; not a
/// stable API.
#[doc(hidden)]
pub fn canonical_timestamp(ts: &str) -> Option<String> {
    let c = RFC3339.captures(ts)?;
    let num = |i: usize| c.get(i).map_or(0, |m| m.as_str().parse::<u32>().unwrap_or(u32::MAX));
    let (year, hour, minute, second) = (num(1), num(4), num(5), num(6));
    let (off_h, off_m) = (num(9), num(10));
    if year == 0 || hour > 23 || minute > 59 || second > 59 || off_h > 23 || off_m > 59 {
        return None;
    }
    let t = chrono::DateTime::parse_from_rfc3339(ts).ok()?.with_timezone(&chrono::Utc);
    if !(1..=9999).contains(&chrono::Datelike::year(&t)) {
        return None;
    }
    Some(t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
}

/// What a store holds at a node and seq. For the stores of this crate and
/// the SDK; not a stable API.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StoredRow {
    pub id: String,
    pub hash: String,
    pub prev_hash: String,
}

impl StoredRow {
    pub fn new(id: String, hash: String, prev_hash: String) -> Self {
        Self { id, hash, prev_hash }
    }
}

/// The reads and the insert ingest makes, all on one transaction of the
/// store, which holds each batch node's advisory lock, or the database's
/// write lock, from before the first read. For the stores of this crate and
/// the SDK; not a stable API.
#[doc(hidden)]
pub trait IngestTx {
    type Error;

    /// The hash of the row stored under `id`, if there is one.
    fn by_id(&mut self, id: &str) -> Result<Option<String>, Self::Error>;

    /// The row stored at `node` and `seq`, if there is one.
    fn at_seq(&mut self, node: &str, seq: u64) -> Result<Option<StoredRow>, Self::Error>;

    /// Whether a sealed row is stored on `node` below `seq`.
    fn sealed_below(&mut self, node: &str, seq: u64) -> Result<bool, Self::Error>;

    /// Insert `row` exactly as it was sealed, with `detail` as the text of
    /// `row.row.detail`, unless its id is stored. Returns the rows written.
    fn insert(&mut self, row: &ReplicatedRow) -> Result<u64, Self::Error>;
}

/// A batch after verification: its longest verified run of sealed rows
/// from each chain's start, and the unsealed rows below the first break.
/// For the stores of this crate and the SDK; not a stable API.
#[doc(hidden)]
#[derive(Debug, Clone, Default)]
pub struct Verified {
    prefix: Vec<ReplicatedRow>,
    unsealed: Vec<ReplicatedRow>,
    /// The first break, as its seq and why.
    cut: Option<(u64, String)>,
}

impl Verified {
    /// The nodes the store must lock, sorted, so two ingests take them in
    /// the same order.
    pub fn nodes(&self) -> Vec<&str> {
        let nodes: BTreeSet<&str> =
            self.prefix.iter().chain(&self.unsealed).map(|r| r.row.source_node_id.as_str()).collect();
        nodes.into_iter().collect()
    }

    fn nothing_to_store(&self) -> IngestResult {
        IngestResult::with_break(0, self.cut.clone())
    }
}

/// Verify `rows`: sorted by seq, the sealed rows below the first break,
/// each identical copy once, and the unsealed rows below it, which are
/// checked against the store but not stored.
fn verify_batch(rows: &[ReplicatedRow]) -> Verified {
    let mut sorted: Vec<&ReplicatedRow> = rows.iter().collect();
    sorted.sort_by_key(|r| r.row.monotonic_seq);
    let chain: Vec<ChainRow> = sorted.iter().map(|r| r.row.clone()).collect();
    let result = verify_chain(&chain);
    let cut = result.first_break_at.zip(result.reason);
    let break_at = cut.as_ref().map(|(seq, _)| *seq);
    let below = |r: &ReplicatedRow| break_at.is_none_or(|b| r.row.monotonic_seq < b);
    let mut seen = HashSet::new();
    let mut prefix = Vec::new();
    let mut unsealed = Vec::new();
    for r in sorted {
        if !below(r) {
            continue;
        }
        if r.row.hash.is_empty() {
            unsealed.push(r.clone());
        } else if seen.insert((&r.row.id, &r.row.source_node_id, &r.row.hash)) {
            prefix.push(r.clone());
        }
    }
    Verified { prefix, unsealed, cut }
}

/// The first row that disagrees with what the store holds (spec §4), as
/// its seq and why. A row already stored with the same hash is a
/// re-delivery, not a conflict.
fn stored_conflict<T: IngestTx>(tx: &mut T, v: &Verified) -> Result<Option<(u64, String)>, T::Error> {
    // The stored neighbours are checked even when the batch holds one too:
    // the batch neighbour may be cut by a later break, and if both are kept
    // they must agree anyway.
    let mut ordered: Vec<&ChainRow> = v.prefix.iter().chain(&v.unsealed).map(|r| &r.row).collect();
    ordered.sort_by(|a, b| (a.monotonic_seq, &a.source_node_id).cmp(&(b.monotonic_seq, &b.source_node_id)));
    let mut seen: HashMap<&str, &ChainRow> = HashMap::new();
    for row in ordered {
        let (node, seq) = (row.source_node_id.as_str(), row.monotonic_seq);
        if row.hash.is_empty() {
            if tx.sealed_below(node, seq)? {
                return Ok(Some((seq, format!("row {}: no hash after the node's chain started", row.id))));
            }
            continue;
        }
        // id is unique, so the store could keep only one row with it.
        if let Some(first) = seen.insert(&row.id, row) {
            return Ok(Some((
                seq,
                format!(
                    "row {}: also in this batch at seq {} on node '{}'",
                    row.id, first.monotonic_seq, first.source_node_id
                ),
            )));
        }
        if let Some(held) = tx.by_id(&row.id)? {
            if held != row.hash {
                return Ok(Some((seq, format!("row {}: differs from the stored row with that id", row.id))));
            }
            continue;
        }
        if let Some(other) = tx.at_seq(node, seq)? {
            return Ok(Some((seq, format!("row {}: seq {seq} on node '{node}' is stored as row {}", row.id, other.id))));
        }
        if let Some(prev_seq) = seq.checked_sub(1) {
            if let Some(before) = tx.at_seq(node, prev_seq)? {
                // After an unsealed row the store links to "genesis" (spec §2).
                let link = if before.hash.is_empty() { crate::chain::GENESIS } else { before.hash.as_str() };
                if row.prev_hash != link {
                    return Ok(Some((
                        seq,
                        format!("row {}: prev_hash does not match stored row {}", row.id, before.id),
                    )));
                }
            }
        }
        if let Some(next_seq) = seq.checked_add(1) {
            if let Some(after) = tx.at_seq(node, next_seq)? {
                if after.prev_hash != row.hash {
                    return Ok(Some((seq, format!("row {}: stored row {} does not link to it", row.id, after.id))));
                }
            }
        }
    }
    Ok(None)
}

/// Check `v` against the store on `tx` and insert the rows that agree.
/// `Ok(None)` means another writer stored one of the ids after the checks
/// ran: roll back and run it again. On an error, roll back; nothing of the
/// batch may be committed. For the stores of this crate and the SDK; not a
/// stable API.
#[doc(hidden)]
pub fn ingest_on<T: IngestTx>(tx: &mut T, v: &Verified) -> Result<Option<IngestResult>, T::Error> {
    let mut cut = v.cut.clone();
    let mut prefix: Vec<&ReplicatedRow> = v.prefix.iter().collect();
    if let Some((seq, why)) = stored_conflict(tx, v)? {
        prefix.retain(|r| r.row.monotonic_seq < seq);
        cut = Some((seq, why));
    }
    for row in &prefix {
        // Skipped: fine for a re-delivery, not for any other row.
        if tx.insert(row)? == 0 && tx.by_id(&row.row.id)?.as_deref() != Some(row.row.hash.as_str()) {
            return Ok(None);
        }
    }
    Ok(Some(IngestResult::with_break(prefix.len(), cut)))
}

/// How many times ingest runs when other writers keep storing its ids.
const ATTEMPTS: usize = 3;

/// The message of the error `ingest` returns when other writers kept
/// storing the batch's ids between its checks and its inserts. For the
/// stores of this crate and the SDK; not a stable API.
#[doc(hidden)]
pub const STORED_MEANWHILE: &str = "ingest_replicated: rows kept being stored by another writer";

/// Ingest `rows` with `attempt`, which runs [`ingest_on`] on a new
/// transaction of the store, locks taken, and commits when it returns a
/// result. `attempt` runs again, at most three times in all, while it
/// returns `Ok(None)`; then `exhausted()` is the error.
///
/// Every row's `timestamp` and `shipped_at` must be one
/// [`canonical_timestamp`] accepts, or the batch is refused with a
/// [`BatchError`] and nothing is stored.
///
/// With `local_node_id`, a row from that node is a break: the rows below
/// the lowest-seq one are ingested, and that row is reported unless an
/// earlier break is found. A node's own rows come from its emit path, never
/// from replication. An empty or absent `local_node_id` skips the check.
///
/// For the stores of this crate and the SDK; not a stable API.
#[doc(hidden)]
pub fn ingest<E: From<BatchError>>(
    rows: &[ReplicatedRow],
    local_node_id: Option<&str>,
    mut attempt: impl FnMut(&Verified) -> Result<Option<IngestResult>, E>,
    exhausted: impl FnOnce() -> E,
) -> Result<IngestResult, E> {
    for (index, r) in rows.iter().enumerate() {
        let bad = |field| BatchError { index, id: r.row.id.clone(), field };
        if canonical_timestamp(&r.row.timestamp).is_none() {
            return Err(bad("timestamp").into());
        }
        if r.row.shipped_at.as_deref().is_some_and(|s| canonical_timestamp(s).is_none()) {
            return Err(bad("shipped_at").into());
        }
    }
    let local = local_node_id.filter(|n| !n.is_empty());
    let first_local = rows
        .iter()
        .filter(|r| local.is_some_and(|n| r.row.source_node_id == n))
        .min_by_key(|r| r.row.monotonic_seq);
    let kept: Vec<ReplicatedRow> = match first_local {
        Some(first) => rows.iter().filter(|r| r.row.monotonic_seq < first.row.monotonic_seq).cloned().collect(),
        None => rows.to_vec(),
    };
    let v = verify_batch(&kept);
    let mut result = None;
    if v.prefix.is_empty() && v.unsealed.is_empty() {
        result = Some(v.nothing_to_store());
    } else {
        for _ in 0..ATTEMPTS {
            if let Some(r) = attempt(&v)? {
                result = Some(r);
                break;
            }
        }
    }
    let Some(result) = result else {
        return Err(exhausted());
    };
    match (first_local, result.rejected_from_seq) {
        (Some(first), None) => Ok(IngestResult::cut(
            result.inserted,
            first.row.monotonic_seq,
            format!("row {}: source_node_id '{}' is this node", first.row.id, local.unwrap_or_default()),
        )),
        _ => Ok(result),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_the_other_stores_can_read() {
        let ok = [
            ("2026-06-15T10:30:01Z", "2026-06-15T10:30:01.000000Z"),
            ("2026-06-15t10:30:01.1234567z", "2026-06-15T10:30:01.123456Z"),
            ("2026-06-15T10:30:01+05:30", "2026-06-15T05:00:01.000000Z"),
            ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00.000000Z"),
            ("9999-12-31T23:59:59.999999Z", "9999-12-31T23:59:59.999999Z"),
        ];
        for (ts, want) in ok {
            assert_eq!(canonical_timestamp(ts).as_deref(), Some(want), "{ts}");
        }
        let bad = [
            "",
            "2026-06-15",
            "2026-06-15 10:30:01Z",
            "0000-06-15T10:30:01Z",
            "2026-02-30T10:30:01Z",
            "2026-06-15T24:00:00Z",
            "2026-06-15T10:30:60Z",
            "2026-06-15T10:30:01+24:00",
            "2026-06-15T10:30:01+05:60",
            "2026-06-15T10:30:01",
            "0001-01-01T00:00:00+00:01",
            "9999-12-31T23:59:59-00:01",
            "tomorrow",
        ];
        for ts in bad {
            assert_eq!(canonical_timestamp(ts), None, "{ts}");
        }
    }

    /// A transaction on which another writer stores each row's id, with
    /// another hash, between the checks and the insert.
    struct Raced {
        held: HashMap<String, String>,
    }

    impl IngestTx for Raced {
        type Error = crate::Error;
        fn by_id(&mut self, id: &str) -> Result<Option<String>, crate::Error> {
            Ok(self.held.get(id).cloned())
        }
        fn at_seq(&mut self, _: &str, _: u64) -> Result<Option<StoredRow>, crate::Error> {
            Ok(None)
        }
        fn sealed_below(&mut self, _: &str, _: u64) -> Result<bool, crate::Error> {
            Ok(false)
        }
        fn insert(&mut self, row: &ReplicatedRow) -> Result<u64, crate::Error> {
            self.held.insert(row.row.id.clone(), "another".into());
            Ok(0)
        }
    }

    fn sealed(seq: u64) -> ReplicatedRow {
        let text = format!(
            r#"{{"id":"e{seq}","origin_id":"e{seq}","monotonic_seq":{seq},"timestamp":"2026-06-15T10:30:01Z","source_node_id":"n"}}"#
        );
        ReplicatedRow::from(crate::chain::seal("genesis", &ChainRow::from_json(&text).unwrap()).unwrap())
    }

    // A skipped insert of a row that is not the one stored means another
    // writer got there first: the attempt is dropped and run again, three
    // times at most, then the call fails.
    #[test]
    fn rows_stored_meanwhile_are_checked_again_a_bounded_number_of_times() {
        let rows = [sealed(1)];
        let mut attempts = 0;
        let err = ingest(
            &rows,
            None,
            |v| {
                attempts += 1;
                ingest_on(&mut Raced { held: HashMap::new() }, v)
            },
            || crate::Error::Store(STORED_MEANWHILE.into()),
        )
        .unwrap_err();
        assert_eq!(attempts, 3);
        assert!(matches!(err, crate::Error::Store(m) if m == STORED_MEANWHILE));

        // On the second attempt the checks see the stored row, and report it.
        let mut attempts = 0;
        let held: HashMap<String, String> = [("e1".to_string(), "another".to_string())].into();
        let result = ingest(
            &rows,
            None,
            |v| {
                attempts += 1;
                let held = if attempts == 1 { HashMap::new() } else { held.clone() };
                ingest_on(&mut Raced { held }, v)
            },
            || crate::Error::Store(STORED_MEANWHILE.into()),
        )
        .unwrap();
        assert_eq!(attempts, 2);
        assert_eq!(result.rejected_from_seq, Some(1));
        assert_eq!(result.reason.as_deref(), Some("row e1: differs from the stored row with that id"));
    }

    // Nothing to store means no transaction at all.
    #[test]
    fn an_empty_or_wholly_broken_batch_opens_no_transaction() {
        let mut broken = sealed(1);
        broken.row.target = "tampered".into();
        for rows in [vec![], vec![broken]] {
            let r = ingest(&rows, None, |_| -> Result<_, crate::Error> { panic!("no attempt") }, || unreachable!())
                .unwrap();
            assert_eq!(r.inserted, 0);
        }
    }

    fn sealed_on(node: &str, seq: u64) -> ReplicatedRow {
        let text = format!(
            r#"{{"id":"{node}-{seq}","origin_id":"{node}-{seq}","monotonic_seq":{seq},"timestamp":"2026-06-15T10:30:01Z","source_node_id":"{node}"}}"#
        );
        ReplicatedRow::from(crate::chain::seal("genesis", &ChainRow::from_json(&text).unwrap()).unwrap())
    }

    // Two ingests take the node locks in one order whatever order their
    // batches list the nodes in, so they cannot deadlock.
    #[test]
    fn the_nodes_to_lock_are_sorted_whatever_the_batch_order() {
        let a = [sealed_on("b", 1), sealed_on("a", 1), sealed_on("c", 1)];
        let b = [sealed_on("c", 1), sealed_on("a", 1), sealed_on("b", 1)];
        for rows in [&a[..], &b[..]] {
            assert_eq!(verify_batch(rows).nodes(), ["a", "b", "c"]);
        }
    }

    #[test]
    fn a_result_has_a_break_seq_and_a_reason_together() {
        assert_eq!(IngestResult::stored(3), IngestResult { inserted: 3, rejected_from_seq: None, reason: None });
        let cut = IngestResult::cut(1, 2, "why");
        assert_eq!((cut.inserted, cut.rejected_from_seq, cut.reason.as_deref()), (1, Some(2), Some("why")));
    }

    #[test]
    fn a_shipped_row_reads_back_as_it_was() {
        let line = r#"{"id":"e","origin_id":"e","monotonic_seq":3,"timestamp":"2026-06-15T10:30:01.000000Z","detail":{"n":1.50,"big":123456789012345678901234567890},"pii_in_detail":true,"hash":"h","prev_hash":"p","canonical_form_id":"2","detail_salt":"s","detail_commitment":"c","tenant_id":null}"#;
        let row = ReplicatedRow::from_json(line).unwrap();
        assert!(row.pii_in_detail);
        let back = ReplicatedRow::from_json(&row.to_json()).unwrap();
        assert_eq!(back, row);
        assert!(row.to_json().contains("123456789012345678901234567890"));
        assert!(row.to_json().contains("1.50"));
        let unflagged = ReplicatedRow::from_json(r#"{"monotonic_seq":1,"pii_in_detail":0}"#).unwrap();
        assert!(!unflagged.pii_in_detail);
        assert!(ReplicatedRow::from_json(r#"{"monotonic_seq":1,"pii_in_detail":"yes"}"#).is_err());
    }
}
