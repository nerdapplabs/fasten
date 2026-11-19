//! SQLite-backed AuditStore: fasten-core's `SqliteStore`, with SQLite
//! compiled in.
//! Enable with: fasten-sdk = { features = ["store-sqlite"] }

use fasten_core::chain::ChainRow;
use fasten_core::store::{Filter, Store};

/// SQLite audit store.
///
/// A row with `monotonic_seq` 0 (what `emit` builds) gets the node's next
/// seq and is sealed into the node's hash chain in the insert transaction
/// (spec §2.1). A row with a seq of its own is stored as given.
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

fn store_err(e: fasten_core::Error) -> crate::Error {
    crate::Error::AuditStoreInsert(e.to_string())
}

impl SqliteStore {
    /// Open the database at `path`, a file path or `":memory:"`, creating
    /// the file (owner-only on Unix), the table and its indexes if absent.
    /// A file database uses WAL journal mode. `table` must match
    /// `^[A-Za-z_][A-Za-z0-9_]*$`.
    pub fn open(path: &str, table: &str) -> Result<Self, crate::Error> {
        let inner = fasten_core::SqliteStore::open(path, table, true).map_err(store_err)?;
        Ok(Self { inner })
    }

    /// The rows of `source_node_id`, ordered by `monotonic_seq`, for
    /// [`crate::verify_chain`]. Each row's `detail` is parsed from the
    /// stored text, so its numbers are the tokens that were hashed.
    pub fn chain_rows(&self, source_node_id: &str) -> Result<Vec<ChainRow>, crate::Error> {
        let filter = Filter { source_node_id: Some(source_node_id.to_string()), ..Default::default() };
        self.inner.chain_rows(&filter).map_err(store_err)
    }

    /// Every row in the table: the whole chain, for
    /// [`crate::verify_chain_with_checkpoints`].
    pub fn all_chain_rows(&self) -> Result<Vec<ChainRow>, crate::Error> {
        self.inner.chain_rows(&Filter::default()).map_err(store_err)
    }

    /// Each node's sealed row with the highest `monotonic_seq`, ordered by
    /// node id, for [`crate::take_checkpoints`].
    pub fn chain_tips(&self) -> Result<Vec<ChainRow>, crate::Error> {
        self.inner.chain_tips().map_err(store_err)
    }
}

impl crate::checkpoints::CheckpointStore for SqliteStore {
    fn chain_tips(&self) -> Result<Vec<ChainRow>, crate::Error> {
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
        let stored = self.inner.insert_stored(&core).map_err(|e| {
            // A constraint or a clashing seq: the row can never be stored.
            if fasten_core::drainer::rejected(&e, &core) {
                crate::Error::AuditStoreRejected(e.to_string())
            } else {
                store_err(e)
            }
        })?;
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
            .map_err(store_err)?;
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
            .map_err(store_err)?;
        Ok(found.skipped)
    }

    fn redact_rows(&self, ids: &[String]) -> Result<Vec<String>, crate::Error> {
        self.inner.redact_rows(ids).map_err(store_err)
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
        let first = store.allocate_and_insert_originated(&row("evt-1", "node-a")).unwrap();
        let again = store.allocate_and_insert_originated(&row("evt-1", "node-a")).unwrap();
        assert_eq!((again.monotonic_seq, &again.hash, &again.prev_hash), (1, &first.hash, &first.prev_hash));
        assert_eq!(again.detail_salt, first.detail_salt);
        assert_eq!(store.chain_rows("node-a").unwrap().len(), 1);
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

    // An engine in raise mode and one draining a queue write one chain.
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
        let partial = CheckpointOptions { partial: true };

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
