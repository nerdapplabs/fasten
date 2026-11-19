//! Chain checkpoints (spec/chain-replication.md §9).
//!
//! A checkpoint records a node's latest sealed row: its seq and hash.
//! Published somewhere the store's operator cannot rewrite, it lets
//! [`crate::chain::verify_chain_with_checkpoints`] detect a chain cut short
//! at the end, or re-sealed from genesis.

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::chain::{canonical_json, ChainRow, Json};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CheckpointError {
    /// The text is not a JSON object with exactly the four checkpoint fields.
    #[error("not a checkpoint: {0}")]
    NotACheckpoint(String),

    /// `anchored_at` is not in the canonical timestamp form (spec 4.3).
    #[error("checkpoint of node '{node}' at seq {seq}: not the canonical timestamp form: {anchored_at:?}")]
    AnchoredAt { node: String, seq: u64, anchored_at: String },
}

/// A node's latest sealed row at `anchored_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub source_node_id: String,
    pub monotonic_seq: u64,
    pub hash: String,
    /// When the checkpoint was taken: UTC, six fractional digits, "Z".
    pub anchored_at: String,
}

impl Checkpoint {
    /// Parse one line of a checkpoint file. The object must have exactly the
    /// four fields, each of its type; a repeated key keeps its last value.
    pub fn from_json(text: &str) -> Result<Self, CheckpointError> {
        let bad = || CheckpointError::NotACheckpoint(text.trim().to_string());
        let Ok(Json::Object(map)) = Json::parse(text) else {
            return Err(bad());
        };
        if map.len() != 4 {
            return Err(bad());
        }
        let string = |key: &str| map.get(key).and_then(Json::as_str).map(str::to_string).ok_or_else(bad);
        let monotonic_seq = match map.get("monotonic_seq") {
            Some(Json::Number(tok)) => tok.parse::<u64>().map_err(|_| bad())?,
            _ => return Err(bad()),
        };
        Ok(Self {
            source_node_id: string("source_node_id")?,
            monotonic_seq,
            hash: string("hash")?,
            anchored_at: string("anchored_at")?,
        })
    }

    /// The checkpoint as one line of a checkpoint file, without the newline.
    /// These are the bytes Python's `FileCheckpointSink` writes: keys sorted,
    /// `", "` and `": "` separators, non-ASCII escaped.
    pub fn to_json(&self) -> String {
        let string = |s: &str| canonical_json(&Json::String(s.to_string()));
        format!(
            r#"{{"anchored_at": {}, "hash": {}, "monotonic_seq": {}, "source_node_id": {}}}"#,
            string(&self.anchored_at),
            string(&self.hash),
            self.monotonic_seq,
            string(&self.source_node_id),
        )
    }
}

/// Options for [`crate::chain::verify_chain_with_checkpoints`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CheckpointOptions {
    /// The rows are a page, one node or a sample rather than the whole
    /// chain: a checkpoint below a node's oldest row or above its newest, or
    /// for a node with no rows, is then skipped. Only a whole-chain verify
    /// detects a cut-off tail.
    pub partial: bool,
}

/// One checkpoint per node, anchored at `anchored_at`. `tips` is each node's
/// sealed row with the highest seq, ordered by node id, as a store's
/// `chain_tips` returns them.
pub fn checkpoints_of(tips: &[ChainRow], anchored_at: DateTime<Utc>) -> Vec<Checkpoint> {
    let anchored_at = canonical_ts(anchored_at);
    let mut out: Vec<Checkpoint> = Vec::new();
    for tip in tips {
        // Two rows at one seq; verify_chain reports that.
        if out.last().is_some_and(|last| last.source_node_id == tip.source_node_id) {
            continue;
        }
        out.push(Checkpoint {
            source_node_id: tip.source_node_id.clone(),
            monotonic_seq: tip.monotonic_seq,
            hash: tip.hash.clone(),
            anchored_at: anchored_at.clone(),
        });
    }
    out
}

/// The checkpoints anchored at or after `cutoff`, in their order. An
/// `anchored_at` not in the canonical form is an error.
///
/// For a whole-chain verify of a store with retention, pass the time the
/// latest purge finished: a checkpoint taken before it can fall among the
/// rows it removed, or belong to a node with no rows left, and fails the
/// verify, while every node still in the store has a checkpoint from the
/// next publish. The retention period alone is not a safe cutoff, since a
/// node's last checkpoint can be taken just before its rows are purged.
pub fn checkpoints_since(
    checkpoints: &[Checkpoint],
    cutoff: DateTime<Utc>,
) -> Result<Vec<Checkpoint>, CheckpointError> {
    // The canonical form is fixed width, so text order is time order.
    let cutoff = canonical_ts(cutoff);
    let mut out = Vec::new();
    for cp in checkpoints {
        if !is_canonical_ts(&cp.anchored_at) {
            return Err(CheckpointError::AnchoredAt {
                node: cp.source_node_id.clone(),
                seq: cp.monotonic_seq,
                anchored_at: cp.anchored_at.clone(),
            });
        }
        if cp.anchored_at >= cutoff {
            out.push(cp.clone());
        }
    }
    Ok(out)
}

fn canonical_ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}

// Whether `s` is `YYYY-MM-DDTHH:MM:SS.ffffffZ` and a real date and time.
fn is_canonical_ts(s: &str) -> bool {
    const SHAPE: &[u8] = b"dddd-dd-ddTdd:dd:dd.ddddddZ";
    let b = s.as_bytes();
    b.len() == SHAPE.len()
        && b.iter().zip(SHAPE).all(|(c, shape)| if *shape == b'd' { c.is_ascii_digit() } else { c == shape })
        // chrono reads second 60 as a leap second; Python and Go reject it.
        && &s[17..19] != "60"
        && DateTime::parse_from_rfc3339(s).is_ok()
}

// One node's rows by seq, with the lowest and highest seq.
struct NodeIndex<'a> {
    by_seq: HashMap<u64, Vec<&'a ChainRow>>,
    lowest: u64,
    highest: u64,
}

impl<'a> NodeIndex<'a> {
    fn new(rows: &[&'a ChainRow]) -> Self {
        let mut by_seq: HashMap<u64, Vec<&ChainRow>> = HashMap::new();
        for row in rows {
            by_seq.entry(row.monotonic_seq).or_default().push(row);
        }
        let lowest = by_seq.keys().copied().min().unwrap_or(0);
        let highest = by_seq.keys().copied().max().unwrap_or(0);
        Self { by_seq, lowest, highest }
    }

    // Check the node's rows against one of its checkpoints, as
    // (monotonic_seq, reason); None if they agree. A checkpoint outside the
    // rows, below the oldest or above the newest, is skipped only in a
    // partial verify.
    fn mismatch(&self, cp: &Checkpoint, partial: bool) -> Option<(u64, String)> {
        let seq = cp.monotonic_seq;
        let node = &cp.source_node_id;
        if let Some(at) = self.by_seq.get(&seq) {
            if at.iter().any(|r| r.hash == cp.hash) {
                return None;
            }
            let id = at.iter().map(|r| r.id.as_str()).min().unwrap_or_default();
            return Some((seq, format!("row {id}: hash differs from checkpoint at seq {seq}")));
        }
        if seq > self.highest {
            // In a partial verify the batch ends earlier.
            return (!partial).then(|| {
                let highest = self.highest;
                (
                    highest.saturating_add(1),
                    format!("node '{node}': chain ends at seq {highest} before checkpoint at seq {seq}"),
                )
            });
        }
        if seq < self.lowest {
            // In a partial verify the batch starts later.
            return (!partial).then(|| {
                let lowest = self.lowest;
                (lowest, format!("node '{node}': rows start at seq {lowest}, after the checkpoint at seq {seq}"))
            });
        }
        Some((seq, format!("node '{node}': no row at checkpointed seq {seq}")))
    }
}

// Check each node's rows, one copy per id, against the checkpoints (spec
// 9.3) and return the break at the lowest seq as (monotonic_seq, reason).
// Checkpoints are taken by node, then seq, so every SDK reports the same
// break. Unless `partial`, every checkpoint must fall within its node's rows.
pub(crate) fn checkpoint_break(
    by_node: &BTreeMap<&str, Vec<&ChainRow>>,
    checkpoints: &[Checkpoint],
    partial: bool,
) -> Option<(u64, String)> {
    let mut newest: HashMap<&str, u64> = HashMap::new();
    for cp in checkpoints {
        let seq = newest.entry(&cp.source_node_id).or_insert(cp.monotonic_seq);
        *seq = (*seq).max(cp.monotonic_seq);
    }
    let index: HashMap<&str, NodeIndex> = newest
        .keys()
        .filter_map(|node| by_node.get(node).map(|rows| (*node, NodeIndex::new(rows))))
        .collect();
    let mut sorted: Vec<&Checkpoint> = checkpoints.iter().collect();
    sorted.sort_by(|a, b| (&a.source_node_id, a.monotonic_seq).cmp(&(&b.source_node_id, b.monotonic_seq)));

    let mut first: Option<(u64, String)> = None;
    for cp in sorted {
        let node = cp.source_node_id.as_str();
        let seq = cp.monotonic_seq;
        let found = match index.get(node) {
            Some(rows) => rows.mismatch(cp, partial),
            // A node with no rows breaks once, at its newest checkpoint.
            None if !partial && newest.get(node) == Some(&seq) => {
                Some((seq, format!("node '{node}': no rows, but checkpointed at seq {seq}")))
            }
            None => None,
        };
        if let Some(found) = found {
            if first.as_ref().is_none_or(|f| found.0 < f.0) {
                first = Some(found);
            }
        }
    }
    first
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_timestamps_only() {
        assert!(is_canonical_ts("2026-06-15T10:30:45.123456Z"));
        for bad in [
            "2026-06-15T10:30:45Z",
            "2026-06-15T10:30:45.123Z",
            "2026-06-15T10:30:45.123456+00:00",
            "2026-06-15 10:30:45.123456Z",
            "2026-06-15t10:30:45.123456z",
            "2026-13-15T10:30:45.123456Z",
            "2026-06-15T10:30:60.123456Z",
            "2026-06-15T10:30:45.123456Z\n",
            "",
        ] {
            assert!(!is_canonical_ts(bad), "{bad:?}");
        }
    }
}
