//! Chain checkpoints (spec chain-replication.md §9).
//!
//! A checkpoint records a node's latest sealed row: its seq and hash.
//! Published somewhere the store's operator cannot rewrite, it lets
//! [`verify_chain_with_checkpoints`] detect a chain cut short at the end, or
//! re-sealed from genesis:
//!
//! ```no_run
//! # fn run(store: &dyn fasten::CheckpointStore, rows: Vec<fasten::ChainRow>) -> Result<(), fasten::Error> {
//! use fasten::{load_checkpoints, publish_checkpoints, verify_chain_with_checkpoints};
//! use fasten::{CheckpointOptions, FileCheckpointSink};
//!
//! publish_checkpoints(store, &FileCheckpointSink::new("/mnt/worm/checkpoints.jsonl"))?;
//! // ...
//! let checkpoints = load_checkpoints("/mnt/worm/checkpoints.jsonl")?;
//! let result = verify_chain_with_checkpoints(&rows, &checkpoints, CheckpointOptions::default());
//! # Ok(()) }
//! ```
//!
//! `rows` there must be the whole chain; set `CheckpointOptions::partial` to
//! verify a page or one node. With retention, checkpoints taken before a
//! purge fail a whole-chain verify; pass only the checkpoints taken since the
//! latest purge finished (see [`checkpoints_since`]).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fasten_core::chain::{ChainRow, Json};
use fasten_core::checkpoint::checkpoints_of;

pub use fasten_core::chain::verify_chain_with_checkpoints;
pub use fasten_core::checkpoint::{checkpoints_since, Checkpoint, CheckpointError, CheckpointOptions};

use crate::Error;

/// Where checkpoints are published.
pub trait CheckpointSink {
    fn publish(&self, checkpoints: &[Checkpoint]) -> Result<(), Error>;
}

/// Appends one JSON line per checkpoint to a file and fsyncs it.
///
/// If the file ends in an unfinished line, as a crash mid-append leaves it,
/// that line is dropped before the append; a complete last line without a
/// newline gets one. One publisher per file: concurrent publishes to the
/// same file are not supported.
#[derive(Debug, Clone)]
pub struct FileCheckpointSink {
    path: PathBuf,
}

impl FileCheckpointSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl CheckpointSink for FileCheckpointSink {
    fn publish(&self, checkpoints: &[Checkpoint]) -> Result<(), Error> {
        if checkpoints.is_empty() {
            return Ok(());
        }
        let mut file = OpenOptions::new().read(true).append(true).create(true).open(&self.path)?;
        let mut out = end_last_line(&mut file)?.to_vec();
        for cp in checkpoints {
            out.extend_from_slice(cp.to_json().as_bytes());
            out.push(b'\n');
        }
        file.write_all(&out)?;
        file.sync_all()?;
        Ok(())
    }
}

/// Make `file` end at a line break, as `load_checkpoints` reads it: truncate
/// an unfinished last line (not valid JSON), or return the newline that a
/// complete one lacks.
fn end_last_line(file: &mut File) -> std::io::Result<&'static [u8]> {
    let end = file.seek(SeekFrom::End(0))?;
    let mut start = end;
    let mut chunk = [0u8; 4096];
    while start > 0 {
        let n = chunk.len().min(usize::try_from(start).unwrap_or(usize::MAX));
        let from = start - n as u64;
        file.seek(SeekFrom::Start(from))?;
        file.read_exact(&mut chunk[..n])?;
        if let Some(i) = chunk[..n].iter().rposition(|b| *b == b'\n') {
            start = from + i as u64 + 1;
            break;
        }
        start = from;
    }
    if start == end {
        return Ok(b"");
    }
    file.seek(SeekFrom::Start(start))?;
    let mut last = Vec::new();
    file.read_to_end(&mut last)?;
    if is_json(&last) {
        return Ok(b"\n");
    }
    file.set_len(start)?;
    Ok(b"")
}

fn is_json(text: &[u8]) -> bool {
    std::str::from_utf8(text).is_ok_and(|text| Json::parse(text).is_ok())
}

/// What [`take_checkpoints`] reads: each node's sealed row with the highest
/// `monotonic_seq`, ordered by node id. The bundled stores implement it.
pub trait CheckpointStore {
    fn chain_tips(&self) -> Result<Vec<ChainRow>, Error>;
}

impl<T: CheckpointStore + ?Sized> CheckpointStore for std::sync::Arc<T> {
    fn chain_tips(&self) -> Result<Vec<ChainRow>, Error> {
        (**self).chain_tips()
    }
}

/// One checkpoint per node in `store` with a sealed row, ordered by node id.
pub fn take_checkpoints<S: CheckpointStore + ?Sized>(store: &S) -> Result<Vec<Checkpoint>, Error> {
    Ok(checkpoints_of(&store.chain_tips()?, chrono::Utc::now()))
}

/// Take checkpoints of `store`, publish them to `sink` and return them.
pub fn publish_checkpoints<S, K>(store: &S, sink: &K) -> Result<Vec<Checkpoint>, Error>
where
    S: CheckpointStore + ?Sized,
    K: CheckpointSink + ?Sized,
{
    let checkpoints = take_checkpoints(store)?;
    sink.publish(&checkpoints)?;
    Ok(checkpoints)
}

/// Read back a file written by [`FileCheckpointSink`], or by the Python or
/// Go one. Blank lines are skipped.
///
/// A line that is not a checkpoint is an error, except an unfinished last
/// line (no trailing newline, not valid JSON), as a crash mid-append leaves
/// it: that one is skipped, with a `checkpoint_unfinished_last_line` warning
/// on stderr. Python logs a warning for it too; Go returns
/// `ErrPartialLastLine`.
pub fn load_checkpoints(path: impl AsRef<Path>) -> Result<Vec<Checkpoint>, Error> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)?;
    let mut lines: Vec<&str> = text.split('\n').collect();
    // The text after the last newline; empty when the file ends with one.
    let last = lines.pop().unwrap_or_default();
    let mut out = Vec::new();
    for line in lines.into_iter().filter(|line| !line.trim().is_empty()) {
        out.push(Checkpoint::from_json(line)?);
    }
    if !last.trim().is_empty() {
        if !is_json(last.as_bytes()) {
            crate::DEFAULT.sys_event(
                "warn",
                "checkpoint_unfinished_last_line",
                serde_json::json!({ "path": path.display().to_string() }),
            );
            return Ok(out);
        }
        out.push(Checkpoint::from_json(last)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_chain;
    use fasten_core::chain::seal;

    const WHOLE: CheckpointOptions = CheckpointOptions { partial: false };

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("fasten-checkpoints-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn file(&self) -> PathBuf {
            self.0.join("checkpoints.jsonl")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn chain(node: &str, n: u64, qty: u64) -> Vec<ChainRow> {
        let mut out: Vec<ChainRow> = Vec::new();
        for seq in 1..=n {
            let row = ChainRow::from_json(&format!(
                r#"{{"id": "evt-{node}-{seq}", "origin_id": "evt-{node}-{seq}", "monotonic_seq": {seq},
                    "timestamp": "2026-06-15T10:30:00.000000Z", "code": "ORDER_PLACED",
                    "action": "create", "severity": "info", "service_id": "gateway",
                    "source_node_id": "{node}", "actor": "alice", "actor_kind": "user",
                    "target": "order/{seq}", "category": "order", "domain": "sales",
                    "method": "http", "request_id": "req-{seq}", "detail": {{"qty": {qty}}}}}"#
            ))
            .unwrap();
            let prev = out.last().map_or("genesis", |r| r.hash.as_str()).to_string();
            out.push(seal(&prev, &row).unwrap());
        }
        out
    }

    /// A store holding the given rows, each node's in seq order.
    struct Rows(Vec<ChainRow>);

    impl CheckpointStore for Rows {
        fn chain_tips(&self) -> Result<Vec<ChainRow>, Error> {
            let mut tips: std::collections::BTreeMap<&str, &ChainRow> = Default::default();
            for row in self.0.iter().filter(|r| !r.hash.is_empty()) {
                tips.insert(&row.source_node_id, row);
            }
            Ok(tips.into_values().cloned().collect())
        }
    }

    fn cp(node: &str, seq: u64) -> Checkpoint {
        Checkpoint {
            source_node_id: node.into(),
            monotonic_seq: seq,
            hash: "ab".repeat(32),
            anchored_at: "2026-06-15T11:00:00.000000Z".into(),
        }
    }

    #[test]
    fn publish_appends_one_line_per_node_and_load_reads_them_back() {
        let dir = TempDir::new("publish");
        let sink = FileCheckpointSink::new(dir.file());
        let mut rows = chain("node-a", 3, 1);
        rows.extend(chain("node-b", 2, 1));
        // The store an engine holds is behind an Arc.
        let store = std::sync::Arc::new(Rows(rows.clone()));

        let first = publish_checkpoints(&store, &sink).unwrap();
        let tips: Vec<(&str, u64, &str)> =
            first.iter().map(|c| (c.source_node_id.as_str(), c.monotonic_seq, c.hash.as_str())).collect();
        assert_eq!(tips, [("node-a", 3, rows[2].hash.as_str()), ("node-b", 2, rows[4].hash.as_str())]);
        let second = publish_checkpoints(&store, &sink).unwrap();

        let text = std::fs::read_to_string(dir.file()).unwrap();
        assert_eq!(text.lines().count(), 4);
        assert!(text.ends_with('\n'));
        assert_eq!(text.lines().next().unwrap(), first[0].to_json());
        let loaded = load_checkpoints(dir.file()).unwrap();
        assert_eq!(loaded, [first, second].concat());
        assert!(verify_chain_with_checkpoints(&rows, &loaded, WHOLE).ok);
    }

    #[test]
    fn publishing_nothing_creates_no_file() {
        let dir = TempDir::new("nothing");
        let sink = FileCheckpointSink::new(dir.file());
        assert!(publish_checkpoints(&Rows(Vec::new()), &sink).unwrap().is_empty());
        assert!(!dir.file().exists());
    }

    #[test]
    fn a_cut_tail_and_a_resealed_chain_are_caught_from_the_file() {
        let dir = TempDir::new("caught");
        let sink = FileCheckpointSink::new(dir.file());
        let rows = chain("node-a", 8, 1);
        publish_checkpoints(&Rows(rows.clone()), &sink).unwrap();
        let checkpoints = load_checkpoints(dir.file()).unwrap();

        let cut = &rows[..5];
        assert!(verify_chain(cut).ok);
        let res = verify_chain_with_checkpoints(cut, &checkpoints, WHOLE);
        assert_eq!(res.first_break_at, Some(6));
        assert_eq!(
            res.reason.as_deref(),
            Some("node 'node-a': chain ends at seq 5 before checkpoint at seq 8")
        );
        assert!(verify_chain_with_checkpoints(cut, &checkpoints, CheckpointOptions { partial: true }).ok);

        let resealed = chain("node-a", 8, 2);
        assert!(verify_chain(&resealed).ok);
        let res = verify_chain_with_checkpoints(&resealed, &checkpoints, WHOLE);
        assert_eq!(res.first_break_at, Some(8));
        assert_eq!(res.reason.as_deref(), Some("row evt-node-a-8: hash differs from checkpoint at seq 8"));
    }

    #[test]
    fn a_cut_short_last_line_is_skipped_on_load_and_dropped_by_the_next_publish() {
        let dir = TempDir::new("cut-short");
        let sink = FileCheckpointSink::new(dir.file());
        sink.publish(&[cp("node-a", 1)]).unwrap();
        let whole = std::fs::read(dir.file()).unwrap();
        let cut = &cp("node-a", 2).to_json()[..40];
        std::fs::write(dir.file(), [whole.as_slice(), cut.as_bytes()].concat()).unwrap();

        assert_eq!(load_checkpoints(dir.file()).unwrap(), [cp("node-a", 1)]);
        sink.publish(&[cp("node-a", 3)]).unwrap();
        let text = std::fs::read_to_string(dir.file()).unwrap();
        assert_eq!(text, format!("{}\n{}\n", cp("node-a", 1).to_json(), cp("node-a", 3).to_json()));
        assert_eq!(load_checkpoints(dir.file()).unwrap(), [cp("node-a", 1), cp("node-a", 3)]);
    }

    #[test]
    fn a_file_that_is_one_cut_short_line_is_emptied_before_the_append() {
        let dir = TempDir::new("only-cut");
        // Longer than one read chunk, with no newline anywhere.
        let cut = format!(r#"{{"source_node_id": "{}"#, "n".repeat(9000));
        std::fs::write(dir.file(), &cut).unwrap();
        assert!(load_checkpoints(dir.file()).unwrap().is_empty());
        FileCheckpointSink::new(dir.file()).publish(&[cp("node-a", 1)]).unwrap();
        assert_eq!(std::fs::read_to_string(dir.file()).unwrap(), format!("{}\n", cp("node-a", 1).to_json()));
    }

    #[test]
    fn a_complete_last_line_without_a_newline_is_kept() {
        let dir = TempDir::new("no-newline");
        std::fs::write(dir.file(), cp("node-a", 1).to_json()).unwrap();
        assert_eq!(load_checkpoints(dir.file()).unwrap(), [cp("node-a", 1)]);
        FileCheckpointSink::new(dir.file()).publish(&[cp("node-a", 2)]).unwrap();
        let text = std::fs::read_to_string(dir.file()).unwrap();
        assert_eq!(text, format!("{}\n{}\n", cp("node-a", 1).to_json(), cp("node-a", 2).to_json()));
    }

    #[test]
    fn load_skips_blank_lines_and_rejects_other_lines() {
        let dir = TempDir::new("lines");
        let line = cp("node-a", 1).to_json();
        std::fs::write(dir.file(), format!("\n{line}\n  \n{line}\r\n")).unwrap();
        assert_eq!(load_checkpoints(dir.file()).unwrap().len(), 2);

        // An unfinished line that is not the last one fails the load.
        std::fs::write(dir.file(), format!("{}\n{line}\n", &line[..40])).unwrap();
        assert!(matches!(load_checkpoints(dir.file()), Err(Error::Checkpoint(_))));
        // So does a last line that is JSON but not a checkpoint.
        std::fs::write(dir.file(), format!("{line}\n{{\"hash\": \"h\"}}")).unwrap();
        assert!(matches!(load_checkpoints(dir.file()), Err(Error::Checkpoint(_))));
        std::fs::write(dir.file(), format!("{line}\n[1]\n")).unwrap();
        assert!(matches!(load_checkpoints(dir.file()), Err(Error::Checkpoint(_))));

        assert!(matches!(load_checkpoints(dir.0.join("absent.jsonl")), Err(Error::Io(_))));
    }

    #[test]
    fn checkpoints_since_drops_those_before_a_purge() {
        let rows = chain("node-a", 10, 1);
        let at = |row: &ChainRow, anchored_at: &str| Checkpoint {
            source_node_id: row.source_node_id.clone(),
            monotonic_seq: row.monotonic_seq,
            hash: row.hash.clone(),
            anchored_at: anchored_at.into(),
        };
        let checkpoints =
            [at(&rows[1], "2026-06-15T11:00:00.000000Z"), at(&rows[9], "2026-06-15T13:00:00.000000Z")];
        let kept = &rows[4..];
        assert!(!verify_chain_with_checkpoints(kept, &checkpoints, WHOLE).ok);
        let purged_at = "2026-06-15T12:00:00Z".parse().unwrap();
        let since = checkpoints_since(&checkpoints, purged_at).unwrap();
        assert_eq!(since, checkpoints[1..]);
        assert!(verify_chain_with_checkpoints(kept, &since, WHOLE).ok);
    }
}
