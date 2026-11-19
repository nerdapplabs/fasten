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
//! publish_checkpoints(store, &FileCheckpointSink::new("/var/lib/fasten/checkpoints.jsonl"))?;
//! // ...
//! let checkpoints = load_checkpoints("/var/lib/fasten/checkpoints.jsonl")?;
//! let result = verify_chain_with_checkpoints(&rows, &checkpoints, CheckpointOptions::whole());
//! # Ok(()) }
//! ```
//!
//! `rows` there must be the whole chain; pass `CheckpointOptions::partial()`
//! to verify a page or one node. With retention, checkpoints taken before a
//! purge fail a whole-chain verify; pass only the checkpoints taken since the
//! latest purge finished (see [`checkpoints_since`]).
//!
//! [`FileCheckpointSink`] reads the file's last line and may truncate it, so
//! it needs read and write access to the file. That rules out a path that
//! only accepts appends or forbids rewrites (a WORM mount): for one of those,
//! implement [`CheckpointSink`] over whatever API it offers. A plain file
//! protects the checkpoints only as far as the store's operator cannot write
//! to it, so keep it on another host or copy it away after each publish.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fasten_core::chain::Json;
use fasten_core::checkpoint::checkpoints_of;

pub use fasten_core::chain::verify_chain_with_checkpoints;
pub use fasten_core::checkpoint::{
    checkpoints_since, ChainTip, Checkpoint, CheckpointError, CheckpointOptions,
};

use crate::Error;

/// Why a checkpoint file could not be read or written. Every variant names
/// the file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckpointFileError {
    #[error("checkpoint file {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Line `line` (counted from 1) is not a checkpoint.
    #[error("checkpoint file {}, line {line}: {source}", path.display())]
    Line {
        path: PathBuf,
        line: usize,
        #[source]
        source: CheckpointError,
    },

    /// The last line is cut short: no newline after it and not valid JSON,
    /// as a crash in the middle of an append leaves it. `read` holds the
    /// checkpoints on the lines before it, which are whole; a caller that
    /// accepts the file without its last line takes them from here.
    #[error(
        "checkpoint file {}: line {line}, the last, is cut short ({} whole checkpoints before it)",
        path.display(),
        read.len()
    )]
    PartialLastLine { path: PathBuf, line: usize, read: Vec<Checkpoint> },
}

/// Where checkpoints are published.
///
/// An implementation returns its own failures as [`Error::Custom`] (see
/// [`Error::custom`]).
pub trait CheckpointSink {
    fn publish(&self, checkpoints: &[Checkpoint]) -> Result<(), Error>;
}

/// Appends one JSON line per checkpoint to a file and fsyncs it.
///
/// If the file ends in an unfinished line, as a crash mid-append leaves it,
/// that line is dropped before the append, with a
/// `checkpoint_unfinished_line_dropped` warning on stderr that gives the path
/// and the bytes dropped; a complete last line without a newline gets one.
/// The file is opened for reading and writing, and may be truncated. One
/// publisher per file: concurrent publishes to the same file are not
/// supported.
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

    fn append(&self, checkpoints: &[Checkpoint]) -> std::io::Result<()> {
        let mut file = OpenOptions::new().read(true).append(true).create(true).open(&self.path)?;
        let mut out = end_last_line(&mut file, &self.path)?.to_vec();
        for cp in checkpoints {
            out.extend_from_slice(cp.to_json().as_bytes());
            out.push(b'\n');
        }
        file.write_all(&out)?;
        file.sync_all()
    }
}

impl CheckpointSink for FileCheckpointSink {
    fn publish(&self, checkpoints: &[Checkpoint]) -> Result<(), Error> {
        if checkpoints.is_empty() {
            return Ok(());
        }
        self.append(checkpoints)
            .map_err(|source| CheckpointFileError::Io { path: self.path.clone(), source }.into())
    }
}

/// Make `file` end at a line break, as `load_checkpoints` reads it: truncate
/// an unfinished last line (not valid JSON), or return the newline that a
/// complete one lacks.
fn end_last_line(file: &mut File, path: &Path) -> std::io::Result<&'static [u8]> {
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
    crate::DEFAULT.sys_event(
        "warn",
        "checkpoint_unfinished_line_dropped",
        serde_json::json!({ "path": path.display().to_string(), "bytes_dropped": last.len() }),
    );
    file.set_len(start)?;
    Ok(b"")
}

fn is_json(text: &[u8]) -> bool {
    std::str::from_utf8(text).is_ok_and(|text| Json::parse(text).is_ok())
}

/// What [`take_checkpoints`] reads from a store. The bundled stores
/// implement it.
///
/// `chain_tips` returns, for each node that has a sealed row, that node's
/// sealed row with the highest `monotonic_seq`: its node id, seq and hash.
/// An unsealed row above it is not the tip. It should read the tips in one
/// query or one snapshot, so a row inserted meanwhile cannot leave two
/// nodes' tips taken at different times. The order does not matter and a
/// node given twice is reduced to its highest seq.
pub trait CheckpointStore {
    fn chain_tips(&self) -> Result<Vec<ChainTip>, Error>;
}

impl<T: CheckpointStore + ?Sized> CheckpointStore for std::sync::Arc<T> {
    fn chain_tips(&self) -> Result<Vec<ChainTip>, Error> {
        (**self).chain_tips()
    }
}

/// One checkpoint per node in `store` with a sealed row, ordered by node id.
pub fn take_checkpoints<S: CheckpointStore + ?Sized>(store: &S) -> Result<Vec<Checkpoint>, Error> {
    Ok(checkpoints_of(&store.chain_tips()?, chrono::Utc::now()))
}

/// Take checkpoints of `store`, publish them to `sink` and return them.
/// When reading the tips fails nothing is published.
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
/// Every failure is an [`Error::CheckpointFile`] that names the path. A line
/// that is not a checkpoint is [`CheckpointFileError::Line`]. An unfinished
/// last line (no trailing newline, not valid JSON), as a crash mid-append
/// leaves it, is [`CheckpointFileError::PartialLastLine`], which carries the
/// checkpoints read before it, as Go's `ErrPartialLastLine` does:
///
/// ```no_run
/// use fasten::{load_checkpoints, CheckpointFileError, Error};
///
/// let checkpoints = match load_checkpoints("checkpoints.jsonl") {
///     Ok(all) => all,
///     // Accept the file without its cut-short last line.
///     Err(Error::CheckpointFile(CheckpointFileError::PartialLastLine { read, .. })) => read,
///     Err(e) => panic!("{e}"),
/// };
/// ```
pub fn load_checkpoints(path: impl AsRef<Path>) -> Result<Vec<Checkpoint>, Error> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .map_err(|source| CheckpointFileError::Io { path: path.to_path_buf(), source })?;
    let mut lines: Vec<&str> = text.split('\n').collect();
    // The text after the last newline; empty when the file ends with one.
    let last = lines.pop().unwrap_or_default();
    let parse = |line: &str, number: usize| {
        Checkpoint::from_json(line)
            .map_err(|source| CheckpointFileError::Line { path: path.to_path_buf(), line: number, source })
    };
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate().filter(|(_, line)| !line.trim().is_empty()) {
        out.push(parse(line, i + 1)?);
    }
    if !last.trim().is_empty() {
        let number = lines.len() + 1;
        if !is_json(last.as_bytes()) {
            return Err(CheckpointFileError::PartialLastLine { path: path.to_path_buf(), line: number, read: out }
                .into());
        }
        out.push(parse(last, number)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{verify_chain, ChainRow};
    use fasten_core::chain::seal;

    const WHOLE: CheckpointOptions = CheckpointOptions::whole();

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

    // Every sealed row as a tip, newest first: take_checkpoints reduces
    // them to one per node.
    impl CheckpointStore for Rows {
        fn chain_tips(&self) -> Result<Vec<ChainTip>, Error> {
            Ok(self.0.iter().rev().filter(|r| !r.hash.is_empty()).map(tip).collect())
        }
    }

    fn tip(row: &ChainRow) -> ChainTip {
        ChainTip {
            source_node_id: row.source_node_id.clone(),
            monotonic_seq: row.monotonic_seq,
            hash: row.hash.clone(),
        }
    }

    fn cp(node: &str, seq: u64) -> Checkpoint {
        Checkpoint::new(node, seq, "ab".repeat(32), "2026-06-15T11:00:00.000000Z").unwrap()
    }

    fn file_error(res: Result<Vec<Checkpoint>, Error>) -> CheckpointFileError {
        match res {
            Err(Error::CheckpointFile(e)) => e,
            other => panic!("wanted a checkpoint file error, got {other:?}"),
        }
    }

    fn sys_lines(event: &str, path: &Path) -> Vec<serde_json::Value> {
        let path = path.display().to_string();
        crate::engine::SYS_CAPTURE
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v["event"] == event && v["path"] == path.as_str())
            .cloned()
            .collect()
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
        assert!(verify_chain_with_checkpoints(cut, &checkpoints, CheckpointOptions::partial()).ok);

        let resealed = chain("node-a", 8, 2);
        assert!(verify_chain(&resealed).ok);
        let res = verify_chain_with_checkpoints(&resealed, &checkpoints, WHOLE);
        assert_eq!(res.first_break_at, Some(8));
        assert_eq!(res.reason.as_deref(), Some("row evt-node-a-8: hash differs from checkpoint at seq 8"));
    }

    #[test]
    fn a_cut_short_last_line_fails_the_load_and_is_dropped_by_the_next_publish() {
        let dir = TempDir::new("cut-short");
        let sink = FileCheckpointSink::new(dir.file());
        sink.publish(&[cp("node-a", 1)]).unwrap();
        let whole = std::fs::read(dir.file()).unwrap();
        let cut = &cp("node-a", 2).to_json()[..40];
        std::fs::write(dir.file(), [whole.as_slice(), cut.as_bytes()].concat()).unwrap();

        // The load fails, and hands over the whole checkpoints before the cut.
        let err = file_error(load_checkpoints(dir.file()));
        let text = err.to_string();
        match err {
            CheckpointFileError::PartialLastLine { path, line, read } => {
                assert_eq!((path, line), (dir.file(), 2));
                assert_eq!(read, [cp("node-a", 1)]);
            }
            other => panic!("{other:?}"),
        }
        assert!(text.contains(&dir.file().display().to_string()) && text.contains("cut short"), "{text}");

        sink.publish(&[cp("node-a", 3)]).unwrap();
        let dropped = sys_lines("checkpoint_unfinished_line_dropped", &dir.file());
        assert_eq!(dropped.len(), 1);
        assert_eq!((&dropped[0]["level"], &dropped[0]["bytes_dropped"]), (&"warn".into(), &40.into()));
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
        // Not a clean, empty list of checkpoints.
        match file_error(load_checkpoints(dir.file())) {
            CheckpointFileError::PartialLastLine { line, read, .. } => assert_eq!((line, read), (1, vec![])),
            other => panic!("{other:?}"),
        }
        FileCheckpointSink::new(dir.file()).publish(&[cp("node-a", 1)]).unwrap();
        let dropped = sys_lines("checkpoint_unfinished_line_dropped", &dir.file());
        assert_eq!(dropped[0]["bytes_dropped"], cut.len());
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

        // An unfinished line that is not the last one fails the load, and
        // the error says which file and line.
        std::fs::write(dir.file(), format!("{line}\n\n{}\n{line}\n", &line[..40])).unwrap();
        let err = file_error(load_checkpoints(dir.file()));
        assert!(matches!(&err, CheckpointFileError::Line { line: 3, .. }), "{err:?}");
        assert!(err.to_string().contains(&format!("{}, line 3", dir.file().display())), "{err}");
        // So does a last line that is JSON but not a checkpoint.
        std::fs::write(dir.file(), format!("{line}\n{{\"hash\": \"h\"}}")).unwrap();
        assert!(matches!(file_error(load_checkpoints(dir.file())), CheckpointFileError::Line { line: 2, .. }));
        std::fs::write(dir.file(), format!("{line}\n[1]\n")).unwrap();
        assert!(matches!(file_error(load_checkpoints(dir.file())), CheckpointFileError::Line { line: 2, .. }));

        let absent = dir.0.join("absent.jsonl");
        let err = file_error(load_checkpoints(&absent));
        assert!(matches!(&err, CheckpointFileError::Io { path, .. } if *path == absent), "{err:?}");
        assert!(err.to_string().contains("absent.jsonl"), "{err}");
    }

    // A path that cannot be opened for writing: its parent is a file.
    #[test]
    fn publishing_to_an_unwritable_path_is_an_error_and_changes_nothing() {
        let dir = TempDir::new("unwritable");
        FileCheckpointSink::new(dir.file()).publish(&[cp("node-a", 1)]).unwrap();
        let before = std::fs::read(dir.file()).unwrap();

        let under_a_file = dir.file().join("checkpoints.jsonl");
        let err = FileCheckpointSink::new(&under_a_file).publish(&[cp("node-a", 2)]).unwrap_err();
        match err {
            Error::CheckpointFile(CheckpointFileError::Io { path, .. }) => assert_eq!(path, under_a_file),
            other => panic!("{other:?}"),
        }
        assert_eq!(std::fs::read(dir.file()).unwrap(), before);

        // A directory in place of the file.
        let err = FileCheckpointSink::new(&dir.0).publish(&[cp("node-a", 2)]).unwrap_err();
        assert!(matches!(err, Error::CheckpointFile(CheckpointFileError::Io { .. })), "{err:?}");
        assert_eq!(std::fs::read(dir.file()).unwrap(), before);
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    // A file that can be read but not written keeps its lines. Root ignores
    // file modes, so there the publish succeeds and this checks nothing more.
    #[cfg(unix)]
    #[test]
    fn publishing_to_a_read_only_file_leaves_its_lines() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("read-only");
        let sink = FileCheckpointSink::new(dir.file());
        sink.publish(&[cp("node-a", 1)]).unwrap();
        let before = std::fs::read(dir.file()).unwrap();
        std::fs::set_permissions(dir.file(), std::fs::Permissions::from_mode(0o400)).unwrap();
        let is_root = OpenOptions::new().append(true).open(dir.file()).is_ok();
        let res = sink.publish(&[cp("node-a", 2)]);
        if is_root {
            assert!(res.is_ok());
        } else {
            assert!(matches!(res, Err(Error::CheckpointFile(CheckpointFileError::Io { .. }))), "{res:?}");
            assert_eq!(std::fs::read(dir.file()).unwrap(), before);
        }
    }

    #[test]
    fn a_chain_tips_error_propagates_and_creates_no_file() {
        struct Down;
        impl CheckpointStore for Down {
            fn chain_tips(&self) -> Result<Vec<ChainTip>, Error> {
                Err(Error::AuditStoreRead("connection lost".into()))
            }
        }
        let dir = TempDir::new("tips-error");
        let sink = FileCheckpointSink::new(dir.file());
        let err = publish_checkpoints(&Down, &sink).unwrap_err();
        assert!(matches!(err, Error::AuditStoreRead(_)), "{err:?}");
        assert!(matches!(take_checkpoints(&Down), Err(Error::AuditStoreRead(_))));
        assert!(!dir.file().exists());
    }

    // A sink of the adopter's own returns its failure as Error::Custom.
    #[test]
    fn a_custom_sink_error_reaches_the_caller() {
        struct Refusing;
        impl CheckpointSink for Refusing {
            fn publish(&self, _: &[Checkpoint]) -> Result<(), Error> {
                Err(Error::custom("bucket is locked"))
            }
        }
        let err = publish_checkpoints(&Rows(chain("node-a", 2, 1)), &Refusing).unwrap_err();
        assert!(matches!(&err, Error::Custom(e) if e.to_string() == "bucket is locked"), "{err:?}");
    }

    #[test]
    fn checkpoints_since_drops_those_before_a_purge() {
        let rows = chain("node-a", 10, 1);
        let at = |row: &ChainRow, anchored_at: &str| {
            Checkpoint::new(row.source_node_id.as_str(), row.monotonic_seq, row.hash.as_str(), anchored_at).unwrap()
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
