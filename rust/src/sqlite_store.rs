//! SQLite-backed AuditStore: fasten-core's `SqliteStore`, with SQLite
//! compiled in.
//! Enable with: fasten-sdk = { features = ["store-sqlite"] }

use fasten_core::chain::ChainRow;
use fasten_core::checkpoint::ChainTip;
use fasten_core::replication::{IngestResult, ReplicatedRow};
use fasten_core::store::{Filter, Store};

/// SQLite audit store.
///
/// A row with `monotonic_seq` 0 (what `emit` builds) gets the node's next
/// seq and is sealed into the node's hash chain in the insert transaction
/// (spec §2.1). A row with a seq of its own is stored as given: unsealed
/// unless it already carries a hash. An unsealed row at or above a node's
/// sealed rows makes [`crate::verify_chain`] fail for that node, so do not
/// write rows with their own seqs on a node id this store seals for.
///
/// [`SqliteStore::chain_rows`] reads a node's rows back for
/// [`crate::verify_chain`], and [`SqliteStore::chain_tips`] each node's
/// latest sealed row for [`crate::publish_checkpoints`].
///
/// ```no_run
/// use std::sync::Arc;
/// use fasten::{Config, SqliteStore};
///
/// let store = SqliteStore::open("audit.db", "audit_logs").expect("open");
///
/// fasten::init(Config {
///     service_id: "my-service".into(),
///     node_id: "node-1".into(),
///     audit_store: Some(Arc::new(store)),
///     ..Default::default()
/// }).expect("init");
/// ```
#[derive(Debug)]
pub struct SqliteStore {
    inner: fasten_core::SqliteStore,
}

// A failed write. A row the store can never take is AuditStoreRejected.
fn write_err(e: fasten_core::Error, row: &fasten_core::Row) -> crate::Error {
    match e {
        fasten_core::Error::Seal(msg) => crate::Error::Seal(msg),
        e if fasten_core::drainer::rejected(&e, row) => crate::Error::AuditStoreRejected(e.to_string()),
        e => crate::Error::AuditStoreInsert(e.to_string()),
    }
}

// A failed write of a row sealed elsewhere: one the store refuses is
// AuditStoreRejected.
fn replicated_err(e: fasten_core::Error) -> crate::Error {
    match e {
        e @ (fasten_core::Error::RowRejected(_) | fasten_core::Error::SeqClash(_)) => {
            crate::Error::AuditStoreRejected(e.to_string())
        }
        e => write_err(e, &fasten_core::Row::default()),
    }
}

fn read_err(e: fasten_core::Error) -> crate::Error {
    crate::Error::AuditStoreRead(e.to_string())
}

impl SqliteStore {
    /// Open the database at `path`, a file path or `":memory:"`, creating
    /// the file (owner-only on Unix), the table and its indexes if absent.
    /// A file database uses WAL journal mode. `table` must match
    /// `^[A-Za-z_][A-Za-z0-9_]*$`.
    pub fn open(path: &str, table: &str) -> Result<Self, crate::Error> {
        Self::open_with_wal(path, table, true)
    }

    /// [`SqliteStore::open`], with WAL journal mode on or off, as a DSN's
    /// `?wal=false` asks.
    pub fn open_with_wal(path: &str, table: &str, wal: bool) -> Result<Self, crate::Error> {
        let inner = fasten_core::SqliteStore::open(path, table, wal)
            .map_err(|e| crate::Error::AuditStoreInsert(e.to_string()))?;
        Ok(Self { inner })
    }

    /// The unshipped rows, ordered by `monotonic_seq`, read as the
    /// [`crate::Row`] type holds them: a detail number `serde_json` cannot
    /// hold exactly is changed, and a redacted detail reads as empty. Ship
    /// [`crate::AuditStore::list_unshipped_sealed`] instead, which keeps
    /// each row as it was hashed. `limit == 0` returns all; `origin` is as
    /// there.
    pub fn list_unshipped(&self, limit: usize, origin: Option<(&str, &str)>) -> Result<Vec<crate::Row>, crate::Error> {
        let rows = crate::AuditStore::list_unshipped_sealed(self, limit, origin)?;
        Ok(rows.iter().map(crate::row_from_replicated).collect())
    }

    /// Verify a batch of rows sealed on other nodes and store its verified
    /// prefix; see [`crate::AuditStore::ingest_replicated`].
    pub fn ingest_replicated(
        &self,
        rows: &[ReplicatedRow],
        local_node_id: Option<&str>,
    ) -> Result<IngestResult, crate::Error> {
        crate::AuditStore::ingest_replicated(self, rows, local_node_id)
    }

    /// The rows of `source_node_id`, ordered by `monotonic_seq`, for
    /// [`crate::verify_chain`]. Each row's `detail` is parsed from the
    /// stored text, so its numbers are the tokens that were hashed.
    ///
    /// Every row of the node is read into memory in one query, with no
    /// paging, and the store's connection is held until it returns, so
    /// inserts through this store wait meanwhile.
    pub fn chain_rows(&self, source_node_id: &str) -> Result<Vec<ChainRow>, crate::Error> {
        let filter = Filter { source_node_id: Some(source_node_id.to_string()), ..Default::default() };
        self.inner.chain_rows(&filter).map_err(read_err)
    }

    /// Every row in the table, ordered by node id and `monotonic_seq`: the
    /// whole chain, for [`crate::verify_chain_with_checkpoints`].
    ///
    /// The whole table is read into memory in one query, with no paging,
    /// and the store's connection is held until it returns, so inserts
    /// through this store wait meanwhile. On a large table verify one node
    /// at a time with [`SqliteStore::chain_rows`] and
    /// `CheckpointOptions::partial()`.
    pub fn all_chain_rows(&self) -> Result<Vec<ChainRow>, crate::Error> {
        self.inner.chain_rows(&Filter::default()).map_err(read_err)
    }

    /// Each node's latest sealed row (node id, seq and hash), ordered by
    /// node id, for [`crate::take_checkpoints`].
    pub fn chain_tips(&self) -> Result<Vec<ChainTip>, crate::Error> {
        self.inner.chain_tips().map_err(read_err)
    }

    /// Store a sealed row from elsewhere exactly as it was sealed, with
    /// `detail` written as the text of `row.detail`, so a number such as
    /// `-0` or a 30-digit integer reads back as it was hashed. A
    /// [`crate::Row`] cannot carry those; `insert` is for rows this process
    /// built. `pii_in_detail` is the row's flag, which a `ChainRow` does not
    /// hold.
    ///
    /// The row must have a hash, a non-zero `monotonic_seq`, and timestamps
    /// the Python and Go stores can read back
    /// ([`crate::replication::canonical_timestamp`]); timestamps are stored
    /// in the canonical form. Its hash is not verified here: run
    /// [`crate::verify_chain`] over the batch first, or use
    /// [`SqliteStore::ingest_replicated`]. Storing the same row again is a
    /// no-op; a different row under a stored id, or another row at its node
    /// and seq, is [`crate::Error::AuditStoreRejected`].
    pub fn insert_sealed(&self, row: &ChainRow, pii_in_detail: bool) -> Result<(), crate::Error> {
        self.inner.insert_sealed(row, pii_in_detail).map_err(replicated_err)
    }
}

impl crate::checkpoints::CheckpointStore for SqliteStore {
    fn chain_tips(&self) -> Result<Vec<ChainTip>, crate::Error> {
        SqliteStore::chain_tips(self)
    }
}

impl crate::AuditStore for SqliteStore {
    fn insert(&self, row: &crate::Row) -> Result<(), crate::Error> {
        self.allocate_and_insert_originated(row).map(|_| ())
    }

    fn seals(&self) -> bool {
        true
    }

    fn allocate_and_insert_originated(&self, row: &crate::Row) -> Result<crate::Row, crate::Error> {
        let core = crate::engine::sdk_row_to_core(row);
        let stored = self.inner.insert_stored(&core).map_err(|e| write_err(e, &core))?;
        Ok(crate::Row {
            monotonic_seq: stored.monotonic_seq,
            prev_hash: stored.prev_hash.unwrap_or_default(),
            hash: stored.hash.unwrap_or_default(),
            canonical_form_id: stored.canonical_form_id.unwrap_or_default(),
            detail_salt: stored.detail_salt,
            detail_commitment: stored.detail_commitment,
            ..row.clone()
        })
    }

    fn list_redaction_candidates(
        &self,
        before: chrono::DateTime<chrono::Utc>,
        codes: &[String],
    ) -> Result<Vec<crate::RedactionCandidate>, crate::Error> {
        let found = self
            .inner
            .list_redaction_candidates(&crate::canonical_ts(&before), codes)
            .map_err(read_err)?;
        Ok(found
            .rows
            .into_iter()
            .map(|(id, monotonic_seq)| crate::RedactionCandidate { id, monotonic_seq })
            .collect())
    }

    fn count_skipped_legacy_form(
        &self,
        before: chrono::DateTime<chrono::Utc>,
        codes: &[String],
    ) -> Result<u64, crate::Error> {
        let found = self
            .inner
            .list_redaction_candidates(&crate::canonical_ts(&before), codes)
            .map_err(read_err)?;
        Ok(found.skipped)
    }

    fn redact_rows(&self, ids: &[String]) -> Result<Vec<String>, crate::Error> {
        self.inner.redact_rows(ids).map_err(|e| crate::Error::AuditStoreInsert(e.to_string()))
    }

    fn list_unshipped_sealed(
        &self,
        limit: usize,
        origin: Option<(&str, &str)>,
    ) -> Result<Vec<ReplicatedRow>, crate::Error> {
        let limit = u32::try_from(limit).unwrap_or(0);
        self.inner.list_unshipped_sealed(limit, origin).map_err(read_err)
    }

    fn mark_shipped(&self, ids: &[String]) -> Result<(), crate::Error> {
        self.inner.mark_shipped(ids).map_err(|e| crate::Error::AuditStoreInsert(e.to_string()))
    }

    fn ingest_replicated(
        &self,
        rows: &[ReplicatedRow],
        local_node_id: Option<&str>,
    ) -> Result<IngestResult, crate::Error> {
        self.inner.ingest_replicated(rows, local_node_id).map_err(replicated_err)
    }

    fn purge(&self, before: chrono::DateTime<chrono::Utc>, respect_unshipped: bool) -> Result<u64, crate::Error> {
        self.inner
            .purge(&crate::canonical_ts(&before), respect_unshipped)
            .map_err(|e| crate::Error::AuditStoreInsert(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoints::{
        load_checkpoints, publish_checkpoints, verify_chain_with_checkpoints, CheckpointOptions,
        FileCheckpointSink,
    };
    use crate::AuditStore;
    use std::collections::HashMap;

    fn row(id: &str, node: &str) -> crate::Row {
        crate::Row {
            wire_version: "1".into(),
            id: id.into(),
            origin_id: id.into(),
            monotonic_seq: 0,
            timestamp: chrono::Utc::now(),
            code: "USER_LOGIN".into(),
            action: "login".into(),
            severity: crate::Severity::Info,
            service_id: "test-svc".into(),
            source_node_id: node.into(),
            tenant_id: None,
            actor: "tester".into(),
            actor_kind: "user".into(),
            target: "res-1".into(),
            category: "test".into(),
            domain: "test".into(),
            method: "sdk".into(),
            request_id: "req-001".into(),
            detail: HashMap::from([
                ("setpoint".to_string(), serde_json::json!(75.0)),
                ("who".to_string(), serde_json::json!("é<&>")),
            ]),
            pii_in_detail: false,
            prev_hash: String::new(),
            hash: String::new(),
            canonical_form_id: String::new(),
            detail_salt: None,
            detail_commitment: None,
            shipped_at: None,
        }
    }

    fn memory() -> SqliteStore {
        SqliteStore::open(":memory:", "audit_logs").unwrap()
    }

    #[test]
    fn rows_are_sealed_into_a_chain_per_node() {
        let store = memory();
        assert!(store.seals());
        let first = store.allocate_and_insert_originated(&row("evt-a1", "node-a")).unwrap();
        let second = store.allocate_and_insert_originated(&row("evt-a2", "node-a")).unwrap();
        store.insert(&row("evt-b1", "node-b")).unwrap();
        assert_eq!((first.monotonic_seq, second.monotonic_seq), (1, 2));
        assert_eq!(first.prev_hash, "genesis");
        assert_eq!(second.prev_hash, first.hash);
        assert_eq!(second.canonical_form_id, "2");
        assert!(second.detail_salt.is_some() && second.detail_commitment.is_some());

        let chain = store.chain_rows("node-a").unwrap();
        assert_eq!(chain.iter().map(|r| r.hash.as_str()).collect::<Vec<_>>(), [&first.hash, &second.hash]);
        assert!(crate::verify_chain(&chain).ok);
        let all = store.all_chain_rows().unwrap();
        assert_eq!(all.len(), 3);
        assert!(crate::verify_chain(&all).ok);
    }

    #[test]
    fn a_retried_row_keeps_its_seq_and_hash() {
        let store = memory();
        let row = row("evt-1", "node-a");
        let first = store.allocate_and_insert_originated(&row).unwrap();
        let again = store.allocate_and_insert_originated(&row).unwrap();
        assert_eq!((again.monotonic_seq, &again.hash, &again.prev_hash), (1, &first.hash, &first.prev_hash));
        assert_eq!(again.detail_salt, first.detail_salt);
        assert_eq!(store.chain_rows("node-a").unwrap().len(), 1);

        // Another row under the stored id is not handed the stored row's
        // seal: it is refused, and can never be stored.
        let other = crate::Row { target: "res-2".into(), ..row.clone() };
        let err = store.allocate_and_insert_originated(&other).unwrap_err();
        assert!(matches!(&err, crate::Error::AuditStoreRejected(m) if m.contains("differs")), "{err:?}");
        assert!(crate::verify_chain(&store.chain_rows("node-a").unwrap()).ok);
    }

    // A row sealed here must be one this node originated, as in the Python
    // and Go stores. The refused row takes no seq.
    #[test]
    fn a_foreign_origin_is_refused() {
        let store = memory();
        store.insert(&row("evt-1", "node-a")).unwrap();
        let foreign = crate::Row { origin_id: "evt-somewhere-else".into(), ..row("evt-2", "node-a") };
        let err = store.allocate_and_insert_originated(&foreign).unwrap_err();
        assert!(matches!(&err, crate::Error::AuditStoreRejected(m) if m.contains("origin_id == id")), "{err:?}");
        let next = store.allocate_and_insert_originated(&row("evt-3", "node-a")).unwrap();
        assert_eq!(next.monotonic_seq, 2);
        assert!(crate::verify_chain(&store.chain_rows("node-a").unwrap()).ok);
    }

    // Rows sealed elsewhere over numbers a `Row` cannot hold keep their
    // hashes through `insert_sealed`.
    #[test]
    fn a_row_sealed_elsewhere_is_stored_as_sealed() {
        let store = memory();
        let mut rows: Vec<ChainRow> = Vec::new();
        for (i, detail) in [r#"{"n":123456789012345678901234567890}"#, r#"{"n":-0}"#].iter().enumerate() {
            let line = serde_json::to_string(&crate::Row { monotonic_seq: i as u64 + 1, ..row(&format!("evt-x{i}"), "node-x") })
                .unwrap();
            let mut unsealed = ChainRow::from_json(&line).unwrap();
            unsealed.detail = crate::Json::parse(detail).unwrap();
            let prev = rows.last().map_or(crate::GENESIS.to_string(), |r| r.hash.clone());
            rows.push(fasten_core::chain::seal(&prev, &unsealed).unwrap());
        }
        for r in &rows {
            store.insert_sealed(r, false).unwrap();
            store.insert_sealed(r, false).unwrap();
        }
        let stored = store.chain_rows("node-x").unwrap();
        assert_eq!(stored, rows);
        let result = crate::verify_chain(&stored);
        assert!(result.ok && result.sealed_rows == 2, "{result:?}");

        let unsealed = ChainRow { hash: String::new(), id: "evt-x9".into(), ..rows[0].clone() };
        let err = store.insert_sealed(&unsealed, false).unwrap_err();
        assert!(matches!(err, crate::Error::AuditStoreRejected(_)), "{err:?}");
        let other = ChainRow { hash: "ab".repeat(32), ..rows[0].clone() };
        let err = store.insert_sealed(&other, false).unwrap_err();
        assert!(matches!(err, crate::Error::AuditStoreRejected(_)), "{err:?}");
    }

    fn register_code(domain: &str, code: &str, pii: bool) {
        let meta = crate::Meta { domain: domain.into(), pii_in_detail: pii, ..Default::default() };
        crate::register(domain.into(), [(code.to_string(), meta)]).unwrap();
    }

    fn engine(service_id: &str, node: &str, store: std::sync::Arc<SqliteStore>, strategy: &str) -> crate::Engine {
        let engine = crate::Engine::new();
        engine
            .init(crate::Config {
                service_id: service_id.into(),
                node_id: node.into(),
                audit_store: Some(store),
                audit_store_failure_strategy: Some(strategy.into()),
                ..Default::default()
            })
            .unwrap();
        engine
    }

    fn audit_lines(service_id: &str) -> Vec<serde_json::Value> {
        let lines = crate::engine::AUDIT_STDOUT.lock().unwrap();
        lines.iter().filter(|v| v["service_id"] == service_id).cloned().collect()
    }

    // Numbers the hash renders as Python does, and text it escapes.
    fn numeric_detail() -> HashMap<String, serde_json::Value> {
        HashMap::from([
            ("setpoint".to_string(), serde_json::json!(75.0)),
            ("small".to_string(), serde_json::json!(1e-7)),
            ("max".to_string(), serde_json::json!(u64::MAX)),
            ("name".to_string(), serde_json::json!("café ✓ 日本")),
        ])
    }

    // What a log collector holds: every stdout line, two per row. The sealed
    // lines are a chain that verifies on its own, in raise and queue mode.
    #[test]
    fn captured_stdout_lines_verify() {
        register_code("sqlite_stdout", "SQLITE_STDOUT_EVENT", false);
        for strategy in ["raise", "queue"] {
            let service = format!("svc-sqlite-stdout-{strategy}");
            let store = std::sync::Arc::new(memory());
            let engine = engine(&service, "node-stdout", store.clone(), strategy);
            for _ in 0..3 {
                crate::EmitBuilder::new("SQLITE_STDOUT_EVENT", "t").detail(numeric_detail()).submit_to(&engine).unwrap();
            }
            assert!(engine.flush(std::time::Duration::from_secs(20)));
            engine.reset_for_tests();

            let lines = audit_lines(&service);
            assert_eq!(lines.len(), 6, "{strategy}");
            let captured: Vec<ChainRow> =
                lines.iter().map(|l| ChainRow::from_json(&l.to_string()).unwrap()).collect();
            let result = crate::verify_chain(&captured);
            assert!(result.ok, "{strategy}: {result:?}");
            assert_eq!((result.total_rows, result.sealed_rows), (6, 3), "{strategy}");
            // The sealed lines alone are the rows the store holds.
            let sealed: Vec<ChainRow> = captured.into_iter().filter(|r| !r.hash.is_empty()).collect();
            assert_eq!(sealed, store.chain_rows("node-stdout").unwrap(), "{strategy}");
            assert!(sealed[0].detail.to_string().contains("18446744073709551615"));

            // A changed number in a captured line is caught.
            let line = lines.iter().find(|l| l["hash"] == sealed[0].hash.as_str()).unwrap();
            let edited = line.to_string().replace("75.0", "76.0");
            let mut tampered = sealed.clone();
            tampered[0] = ChainRow::from_json(&edited).unwrap();
            assert!(!crate::verify_chain(&tampered).ok, "{strategy}");
        }
    }

    // redact_expired through the engine: the redaction record is a sealed
    // row of the same chain, written to stdout twice like any other.
    #[test]
    fn redact_expired_seals_its_record() {
        register_code("sqlite_pii", "SQLITE_PII_EVENT", true);
        let store = std::sync::Arc::new(memory());
        let engine = engine("svc-sqlite-redact", "node-redact", store.clone(), "raise");
        let pii = crate::EmitBuilder::new("SQLITE_PII_EVENT", "user/1").submit_to(&engine).unwrap();
        crate::EmitBuilder::new("SQLITE_PII_EVENT", "user/2").submit_to(&engine).unwrap();
        let before = pii.timestamp + chrono::Duration::microseconds(1);

        let redacted = engine.redact_expired(before, "pii-30d").unwrap();
        assert_eq!(redacted, [pii.id.clone()]);
        assert!(engine.redact_expired(before, "pii-30d").unwrap().is_empty());
        engine.reset_for_tests();

        let chain = store.chain_rows("node-redact").unwrap();
        assert_eq!(chain.len(), 3);
        let record = &chain[2];
        assert_eq!((record.code.as_str(), record.monotonic_seq), (crate::AUDIT_ROW_REDACTED, 3));
        assert_eq!(record.prev_hash, chain[1].hash);
        assert_eq!(record.hash.len(), 64);
        assert_eq!((&chain[0].detail, chain[0].detail_salt.as_deref()), (&crate::Json::Null, None));
        assert_eq!(chain[0].hash, pii.hash);
        let result = crate::verify_chain(&chain);
        assert!(result.ok && result.sealed_rows == 3, "{result:?}");

        let lines: Vec<serde_json::Value> =
            audit_lines("svc-sqlite-redact").into_iter().filter(|l| l["id"] == record.id.as_str()).collect();
        assert_eq!(lines.len(), 2);
        assert_eq!((&lines[0]["hash"], &lines[0]["monotonic_seq"]), (&"".into(), &0.into()));
        assert_eq!(lines[1]["hash"], record.hash.as_str());
        assert_eq!(lines[1]["detail"]["redacted_id"], pii.id.as_str());
    }

    // Engines on one database file, each with its own connection, emitting
    // at the same moment, write one unbroken chain.
    #[test]
    fn concurrent_engines_on_one_file_write_one_chain() {
        register_code("sqlite_conc", "SQLITE_CONC_EVENT", false);
        let dir = std::env::temp_dir().join(format!("fasten-sqlite-conc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("audit.db").to_str().unwrap().to_string();
        drop(SqliteStore::open(&db, "audit_logs").unwrap());

        const PER: usize = 25;
        let strategies = ["raise", "queue", "raise", "queue"];
        let start = std::sync::Arc::new(std::sync::Barrier::new(strategies.len()));
        let writers: Vec<_> = strategies
            .into_iter()
            .enumerate()
            .map(|(i, strategy)| {
                let (db, start) = (db.clone(), start.clone());
                std::thread::spawn(move || {
                    let store = std::sync::Arc::new(SqliteStore::open(&db, "audit_logs").unwrap());
                    let engine = engine(&format!("svc-sqlite-conc-{i}"), "node-conc", store, strategy);
                    start.wait();
                    for _ in 0..PER {
                        crate::EmitBuilder::new("SQLITE_CONC_EVENT", "t").submit_to(&engine).unwrap();
                    }
                    assert!(engine.flush(std::time::Duration::from_secs(30)));
                    engine.reset_for_tests();
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }

        let chain = SqliteStore::open(&db, "audit_logs").unwrap().chain_rows("node-conc").unwrap();
        assert_eq!(
            chain.iter().map(|r| r.monotonic_seq).collect::<Vec<_>>(),
            (1..=(strategies.len() * PER) as u64).collect::<Vec<_>>()
        );
        let result = crate::verify_chain(&chain);
        assert!(result.ok && result.sealed_rows == chain.len(), "{result:?}");
        // Every engine wrote: the chain interleaves all four services.
        let services: std::collections::BTreeSet<&str> = chain.iter().map(|r| r.service_id.as_str()).collect();
        assert_eq!(services.len(), strategies.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn vector_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/rust-sealed-form2.json")
    }

    /// The rows of spec/rust-sealed-form2.json, one JSON object per line.
    fn vector_lines() -> Vec<String> {
        let text = std::fs::read_to_string(vector_path()).unwrap();
        let rows: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
        // Each row as it stands in the file, numbers included.
        let lines: Vec<String> =
            text.lines().filter(|l| l.starts_with('{')).map(|l| l.trim_end_matches(',').to_string()).collect();
        assert_eq!(lines.len(), rows.len());
        lines
    }

    // spec/rust-sealed-form2.json is what this SDK seals: Python and Go
    // verify the same file. Each row is a `Row` as serde writes it, the
    // redacted one as the store holds it after `redact_rows`.
    #[test]
    fn rust_sealed_vector_is_this_sdks_output() {
        let lines = vector_lines();
        assert_eq!(lines.len(), 4);
        let mut chain = Vec::new();
        for line in &lines {
            let row = ChainRow::from_json(line).unwrap();
            if row.detail != crate::Json::Null {
                // The line is a Row: it parses as one and serialises back.
                let parsed: crate::Row = serde_json::from_str(line).unwrap();
                let written: serde_json::Value = serde_json::from_str(line).unwrap();
                assert_eq!(serde_json::to_value(&parsed).unwrap(), written);
            }
            chain.push(row);
        }
        let result = crate::verify_chain(&chain);
        assert!(result.ok && result.sealed_rows == 4, "{result:?}");
        assert_eq!(chain.iter().filter(|r| r.detail == crate::Json::Null && r.detail_salt.is_none()).count(), 1);
        let ties = fasten_core::chain::canonical_json(&chain[3].detail);
        assert!(ties.contains(r#""tie":1000000000000000.2,"tie_frac":87730252702983.62"#), "{ties}");
    }

    // Writes spec/rust-sealed-form2.json from a real engine and store:
    //   FASTEN_WRITE_RUST_SEALED_VECTOR=1 cargo test --features store-sqlite writes_the_rust_sealed_vector
    // The salts are random, so each run gives a new file; commit it and the
    // Rust, Python and Go tests that read it all move together.
    #[test]
    fn writes_the_rust_sealed_vector() {
        if std::env::var("FASTEN_WRITE_RUST_SEALED_VECTOR").as_deref() != Ok("1") {
            return;
        }
        register_code("vector", "VECTOR_EVENT", false);
        let store = std::sync::Arc::new(memory());
        let engine = engine("gateway", "node-rust", store.clone(), "raise");
        let nested = serde_json::json!({"list": [1, 2.5, {"x": 0.0001}], "ok": true, "none": null});
        let details: [HashMap<String, serde_json::Value>; 4] = [
            HashMap::from([
                ("setpoint".to_string(), serde_json::json!(75.0)),
                ("small".to_string(), serde_json::json!(1e-7)),
                ("max".to_string(), serde_json::json!(u64::MAX)),
                // A 30-digit integer, which a serde_json number holds as a float.
                ("big".to_string(), serde_json::json!(123_456_789_012_345_678_901_234_567_890_f64)),
            ]),
            HashMap::from([
                ("name".to_string(), serde_json::json!("café ✓ 日本")),
                ("del".to_string(), serde_json::json!("a\u{7f}b")),
                ("nested".to_string(), nested),
            ]),
            HashMap::from([("note".to_string(), serde_json::json!("to be redacted"))]),
            HashMap::from([
                ("neg".to_string(), serde_json::json!(-1.5)),
                ("count".to_string(), serde_json::json!(7)),
                // Halfway between two shortest forms: Python writes the even
                // one, 1000000000000000.2 and 87730252702983.62.
                ("tie".to_string(), serde_json::json!(1_000_000_000_000_000.25_f64)),
                ("tie_frac".to_string(), serde_json::json!(87_730_252_702_983.625_f64)),
            ]),
        ];
        let mut rows: Vec<serde_json::Value> = Vec::new();
        for (i, detail) in details.into_iter().enumerate() {
            let row = crate::EmitBuilder::new("VECTOR_EVENT", format!("sensor/{i}"))
                .detail(detail)
                .submit_to(&engine)
                .unwrap();
            // The row as serde writes it is the sealed stdout line.
            let mut line = audit_lines("gateway").into_iter().rfind(|l| l["id"] == row.id.as_str()).unwrap();
            line.as_object_mut().unwrap().remove("shape");
            assert_eq!(serde_json::to_value(&row).unwrap(), line);
            rows.push(line);
        }
        engine.reset_for_tests();

        // The third row as the store holds it once redacted.
        let id = rows[2]["id"].as_str().unwrap().to_string();
        assert_eq!(crate::AuditStore::redact_rows(&*store, std::slice::from_ref(&id)).unwrap(), [id]);
        let redacted = rows[2].as_object_mut().unwrap();
        redacted.insert("detail".into(), serde_json::Value::Null);
        redacted.remove("detail_salt");

        let lines: Vec<String> = rows.iter().map(|r| r.to_string()).collect();
        let chain: Vec<ChainRow> = lines.iter().map(|l| ChainRow::from_json(l).unwrap()).collect();
        assert_eq!(chain, store.chain_rows("node-rust").unwrap());
        assert!(crate::verify_chain(&chain).ok);
        std::fs::write(vector_path(), format!("[\n{}\n]\n", lines.join(",\n"))).unwrap();
    }

    #[test]
    fn a_row_with_its_own_seq_is_stored_as_given() {
        let store = memory();
        let own = crate::Row { monotonic_seq: 5, ..row("evt-5", "node-a") };
        let stored = store.allocate_and_insert_originated(&own).unwrap();
        assert_eq!((stored.monotonic_seq, stored.hash.as_str()), (5, ""));
        // Another row at that seq on the node can never be stored.
        let clash = crate::Row { monotonic_seq: 5, ..row("evt-other", "node-a") };
        let err = store.allocate_and_insert_originated(&clash).unwrap_err();
        assert!(matches!(err, crate::Error::AuditStoreRejected(_)), "{err:?}");
    }

    // An engine in raise mode and then one draining a queue write one chain.
    #[test]
    fn engines_write_one_sealed_chain() {
        let store = std::sync::Arc::new(memory());
        crate::register(
            "sqlite_chain".into(),
            [("SQLITE_CHAIN_EVENT".to_string(), crate::Meta { domain: "sqlite_chain".into(), ..Default::default() })],
        )
        .unwrap();
        const PER: usize = 20;
        let mut emitted = Vec::new();
        for strategy in ["raise", "queue"] {
            let engine = crate::Engine::new();
            engine
                .init(crate::Config {
                    service_id: format!("svc-sqlite-{strategy}"),
                    node_id: "node-sqlite".into(),
                    audit_store: Some(store.clone()),
                    audit_store_failure_strategy: Some(strategy.into()),
                    ..Default::default()
                })
                .unwrap();
            let rows: Vec<crate::Row> = (0..PER)
                .map(|_| crate::EmitBuilder::new("SQLITE_CHAIN_EVENT", "t").submit_to(&engine).unwrap())
                .collect();
            assert!(engine.flush(std::time::Duration::from_secs(20)));
            engine.reset_for_tests();
            emitted.push(rows);
        }

        let chain = store.chain_rows("node-sqlite").unwrap();
        assert_eq!(
            chain.iter().map(|r| r.monotonic_seq).collect::<Vec<_>>(),
            (1..=(2 * PER) as u64).collect::<Vec<_>>()
        );
        let result = crate::verify_chain(&chain);
        assert!(result.ok, "{result:?}");
        // Raise mode returned each row as stored; queue mode as built.
        for (row, stored) in emitted[0].iter().zip(&chain) {
            assert_eq!((&row.id, row.monotonic_seq, &row.hash), (&stored.id, stored.monotonic_seq, &stored.hash));
        }
        assert!(emitted[1].iter().all(|r| r.monotonic_seq == 0 && r.hash.is_empty()));
        let tips = store.chain_tips().unwrap();
        assert_eq!((tips.len(), &tips[0].hash), (1, &chain[2 * PER - 1].hash));
    }

    #[test]
    fn redaction_keeps_the_chain_valid() {
        let store = memory();
        let old = crate::Row {
            timestamp: chrono::Utc::now() - chrono::Duration::days(40),
            ..row("evt-old", "node-a")
        };
        store.insert(&old).unwrap();
        store.insert(&row("evt-new", "node-a")).unwrap();
        let before = chrono::Utc::now() - chrono::Duration::days(30);
        let codes = ["USER_LOGIN".to_string()];

        let found = store.list_redaction_candidates(before, &codes).unwrap();
        let ids: Vec<String> = found.iter().map(|c| c.id.clone()).collect();
        assert_eq!(ids, ["evt-old"]);
        assert_eq!(found[0].monotonic_seq, 1);
        assert_eq!(store.count_skipped_legacy_form(before, &codes).unwrap(), 0);
        assert_eq!(store.redact_rows(&ids).unwrap(), ids);

        let chain = store.chain_rows("node-a").unwrap();
        assert_eq!(chain[0].detail, fasten_core::chain::Json::Null);
        assert_eq!(chain[0].detail_salt, None);
        assert!(crate::verify_chain(&chain).ok);
        assert!(store.list_redaction_candidates(before, &codes).unwrap().is_empty());
    }

    #[test]
    fn checkpoints_catch_a_cut_tail_and_a_resealed_chain() {
        let dir = std::env::temp_dir().join(format!("fasten-sqlite-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("audit.db");
        let file = dir.join("checkpoints.jsonl");
        let whole = CheckpointOptions::default();
        let partial = CheckpointOptions::partial();

        let store = SqliteStore::open(db.to_str().unwrap(), "audit_logs").unwrap();
        for i in 0..6 {
            store.insert(&row(&format!("evt-a{i}"), "node-a")).unwrap();
        }
        for i in 0..3 {
            store.insert(&row(&format!("evt-b{i}"), "node-b")).unwrap();
        }
        // An unsealed row above a node's sealed ones is not its tip.
        store.insert(&crate::Row { monotonic_seq: 9, ..row("evt-b9", "node-b") }).unwrap();
        let tips: Vec<(String, u64)> =
            store.chain_tips().unwrap().into_iter().map(|t| (t.source_node_id, t.monotonic_seq)).collect();
        assert_eq!(tips, [("node-a".to_string(), 6), ("node-b".to_string(), 3)]);

        let published = publish_checkpoints(&store, &FileCheckpointSink::new(&file)).unwrap();
        let checkpoints = load_checkpoints(&file).unwrap();
        assert_eq!(checkpoints, published);
        let rows: Vec<ChainRow> =
            store.all_chain_rows().unwrap().into_iter().filter(|r| r.id != "evt-b9").collect();
        assert!(verify_chain_with_checkpoints(&rows, &checkpoints, whole).ok);
        assert!(verify_chain_with_checkpoints(&store.chain_rows("node-a").unwrap(), &checkpoints, partial).ok);

        // Rows cut off the end of node-a still verify on their own.
        let cut: Vec<ChainRow> =
            rows.iter().filter(|r| r.source_node_id != "node-a" || r.monotonic_seq <= 4).cloned().collect();
        assert!(crate::verify_chain(&cut).ok);
        let res = verify_chain_with_checkpoints(&cut, &checkpoints, whole);
        assert_eq!(res.first_break_at, Some(5));
        assert_eq!(
            res.reason.as_deref(),
            Some("node 'node-a': chain ends at seq 4 before checkpoint at seq 6")
        );
        assert!(verify_chain_with_checkpoints(&cut, &checkpoints, partial).ok);

        // The same rows sealed again in a new table verify on their own too.
        let resealed = SqliteStore::open(db.to_str().unwrap(), "audit_resealed").unwrap();
        for i in 0..6 {
            resealed.insert(&row(&format!("evt-a{i}"), "node-a")).unwrap();
        }
        let again = resealed.chain_rows("node-a").unwrap();
        assert!(crate::verify_chain(&again).ok);
        let res = verify_chain_with_checkpoints(&again, &checkpoints, partial);
        assert_eq!(res.first_break_at, Some(6));
        assert_eq!(res.reason.as_deref(), Some("row evt-a5: hash differs from checkpoint at seq 6"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
