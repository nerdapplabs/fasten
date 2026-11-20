//! Replication on the core stores (spec/chain-replication.md §4, §5):
//! ingest stores the verified prefix of a batch exactly as it was sealed and
//! reports the first break; the rows a node originated are listed for
//! shipping. The Postgres store connects again after losing its connection.
//!
//! The Postgres tests need `FASTEN_TEST_POSTGRES_DSN`. Without it they
//! return early, unless `FASTEN_REQUIRE_POSTGRES=1`, which makes them fail.

#![cfg(feature = "sqlite")]

use std::collections::HashMap;

use fasten_core::chain::{seal, verify_chain, ChainRow, Json};
use fasten_core::replication::{IngestResult, ReplicatedRow};
use fasten_core::{Error, Filter, Row, SqliteStore, Store};

fn wire(seq: u64, id: &str, node: &str) -> ChainRow {
    let v = serde_json::json!({
        "id": id, "origin_id": id, "monotonic_seq": seq,
        "timestamp": format!("2026-06-15T10:30:{:02}.000000Z", seq % 60),
        "code": "USER_CREATED", "action": "create", "severity": "info", "service_id": "svc",
        "source_node_id": node, "actor": "a", "actor_kind": "user", "target": "u/1",
        "category": "account", "domain": "user", "method": "sdk", "request_id": "r",
        "detail": {"k": "v"},
    });
    ChainRow::from_json(&v.to_string()).unwrap()
}

fn chain(node: &str, seqs: &[u64], prefix: &str) -> Vec<ReplicatedRow> {
    let mut prev = "genesis".to_string();
    seqs.iter()
        .map(|&seq| {
            let sealed = seal(&prev, &wire(seq, &format!("{prefix}-{seq}"), node)).unwrap();
            prev.clone_from(&sealed.hash);
            ReplicatedRow::from(sealed)
        })
        .collect()
}

fn vector(file: &str) -> Vec<ReplicatedRow> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec").join(file);
    let parsed = Json::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
    let rows: Vec<Json> = match parsed.get("cases") {
        Some(cases) => cases.as_array().unwrap().iter().map(|c| c.get("row").unwrap().clone()).collect(),
        None => parsed.as_array().unwrap().to_vec(),
    };
    rows.iter().map(|r| ReplicatedRow::from_value(r).unwrap()).collect()
}

/// The batches of every SDK's vector file. Python's holds one row per case,
/// so each is a batch of its own.
fn vector_batches() -> Vec<Vec<ReplicatedRow>> {
    let mut out: Vec<Vec<ReplicatedRow>> = vector("python-sealed-forms.json").into_iter().map(|r| vec![r]).collect();
    for file in ["go-sealed-form2.json", "js-sealed-form2.json", "rust-sealed-form2.json"] {
        out.push(vector(file));
    }
    out
}

fn all_rows(store: &dyn Store) -> Vec<ChainRow> {
    store.chain_rows(&Filter::default()).unwrap()
}

fn got(r: &IngestResult) -> (usize, Option<u64>) {
    (r.inserted, r.rejected_from_seq)
}

struct TempDb(std::path::PathBuf);

impl TempDb {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("fasten-repl-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> String {
        self.0.join("audit.db").to_str().unwrap().to_string()
    }

    fn raw_details(&self) -> HashMap<String, String> {
        let conn = rusqlite::Connection::open(self.path()).unwrap();
        let mut stmt = conn.prepare("SELECT id, detail FROM audit_log").unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Each SDK's sealed rows are stored as they were sealed: they verify with
/// their hashes, and the detail column holds the sender's text.
fn check_vectors(store: &dyn Store, raw: &dyn Fn() -> HashMap<String, String>, clear: &dyn Fn()) {
    for batch in vector_batches() {
        clear();
        let r = store.ingest_replicated(&batch, None).unwrap();
        assert_eq!(got(&r), (batch.len(), None), "{:?}", r.reason);
        let back = all_rows(store);
        let v = verify_chain(&back);
        assert!(v.ok && v.sealed_rows == batch.len(), "{v:?}");
        let raw = raw();
        for sent in &batch {
            let stored = back.iter().find(|b| b.id == sent.row.id).unwrap();
            assert_eq!(stored.hash, sent.row.hash);
            assert_eq!(raw[&sent.row.id], sent.row.detail.to_string(), "{}", sent.row.id);
            assert_eq!(Json::parse(&raw[&sent.row.id]).unwrap(), sent.row.detail);
        }
        // Delivered again: nothing new, nothing refused.
        assert_eq!(got(&store.ingest_replicated(&batch, None).unwrap()), (batch.len(), None));
    }
}

#[test]
fn sqlite_ingests_every_sdks_sealed_rows_as_sealed() {
    let db = TempDb::new();
    let store = SqliteStore::open(&db.path(), "audit_log", true).unwrap();
    let clear = || rusqlite::Connection::open(db.path()).unwrap().execute_batch("DELETE FROM audit_log").unwrap();
    check_vectors(&store, &|| db.raw_details(), &clear);
}

/// The checks against stored rows and the local-node rule, on any store.
fn check_conflicts(store: &dyn Store) {
    let rows = chain("node-1", &[1, 2, 3, 4], "a");
    assert_eq!(got(&store.ingest_replicated(&rows[..2], None).unwrap()), (2, None));
    // Re-delivered with what follows.
    assert_eq!(got(&store.ingest_replicated(&rows, None).unwrap()), (4, None));
    // Another row at a stored seq.
    let other = chain("node-1", &[1], "x");
    let r = store.ingest_replicated(&other, None).unwrap();
    assert_eq!(got(&r), (0, Some(1)));
    assert_eq!(r.reason.as_deref(), Some("row x-1: seq 1 on node 'node-1' is stored as row a-1"));
    // A row that does not link to the stored row before it.
    let detached = {
        let s = seal(&"0".repeat(64), &wire(5, "a-5", "node-1")).unwrap();
        vec![ReplicatedRow::from(s)]
    };
    let r = store.ingest_replicated(&detached, None).unwrap();
    assert_eq!(r.reason.as_deref(), Some("row a-5: prev_hash does not match stored row a-4"));
    // The local node's rows.
    let r = store.ingest_replicated(&chain("node-2", &[1, 2], "l"), Some("node-2")).unwrap();
    assert_eq!(got(&r), (0, Some(1)));
    assert_eq!(r.reason.as_deref(), Some("row l-1: source_node_id 'node-2' is this node"));
    // A timestamp the other stores cannot read refuses the batch.
    let mut bad = wire(1, "t-1", "node-3");
    bad.timestamp = "0000-01-01T00:00:00Z".into();
    let err = store.ingest_replicated(&[ReplicatedRow::from(seal("genesis", &bad).unwrap())], None).unwrap_err();
    assert!(matches!(err, Error::RowRejected(_)), "{err:?}");
    // An insert error part-way stores nothing.
    let mut batch = chain("node-4", &[1, 2], "p");
    batch.push(ReplicatedRow::from(seal("genesis", &wire(1 << 63, "huge", "node-5")).unwrap()));
    assert!(store.ingest_replicated(&batch, None).is_err());
    let left = all_rows(store);
    assert!(left.iter().all(|r| r.source_node_id == "node-1"), "{left:?}");
    assert_eq!(left.len(), 4);
    assert!(verify_chain(&left).ok);
}

#[test]
fn sqlite_checks_a_batch_against_the_stored_rows() {
    check_conflicts(&SqliteStore::open(":memory:", "audit_log", true).unwrap());
}

fn originated(id: &str, node: &str, service: &str) -> Row {
    Row {
        wire_version: "1".into(),
        id: id.into(),
        origin_id: id.into(),
        timestamp: "2026-06-15T10:30:00.000000Z".into(),
        code: "C".into(),
        severity: "info".into(),
        service_id: service.into(),
        source_node_id: node.into(),
        detail: serde_json::json!({"n": 1.50}),
        pii_in_detail: true,
        ..Default::default()
    }
}

/// Only the rows the identity originated are listed for shipping; they ship
/// as JSON lines, another store ingests them, and shipped rows are not
/// listed again.
fn check_unshipped(store: &dyn Store) {
    for i in 1..=3 {
        store.insert(&originated(&format!("own-{i}"), "node-a", "svc-a")).unwrap();
    }
    store.insert(&originated("other-svc", "node-a", "svc-b")).unwrap();
    store.ingest_replicated(&chain("node-c", &[1, 2], "c"), None).unwrap();

    let ship = store.list_unshipped_sealed(0, Some(("svc-a", "node-a"))).unwrap();
    assert_eq!(ship.iter().map(|r| r.row.id.as_str()).collect::<Vec<_>>(), ["own-1", "own-2", "own-3"]);
    assert!(ship.iter().all(|r| r.pii_in_detail));
    assert_eq!(store.list_unshipped_sealed(2, Some(("svc-a", "node-a"))).unwrap().len(), 2);
    assert_eq!(store.list_unshipped_sealed(0, None).unwrap().len(), 6);

    let lines: Vec<String> = ship.iter().map(ReplicatedRow::to_json).collect();
    let received: Vec<ReplicatedRow> = lines.iter().map(|l| ReplicatedRow::from_json(l).unwrap()).collect();
    assert_eq!(received, ship);
    let aggregator = SqliteStore::open(":memory:", "audit_log", true).unwrap();
    assert_eq!(got(&aggregator.ingest_replicated(&received, None).unwrap()), (3, None));
    let v = verify_chain(&all_rows(&aggregator));
    assert!(v.ok && v.sealed_rows == 3, "{v:?}");
    assert!(aggregator.list_unshipped_sealed(0, None).unwrap().iter().all(|r| r.pii_in_detail));

    let ids: Vec<String> = ship.iter().map(|r| r.row.id.clone()).collect();
    store.mark_shipped(&ids).unwrap();
    assert!(store.list_unshipped_sealed(0, Some(("svc-a", "node-a"))).unwrap().is_empty());
    let shipped = all_rows(store);
    let at = shipped.iter().find(|r| r.id == "own-1").unwrap().shipped_at.clone().unwrap();
    assert_eq!(fasten_core::replication::canonical_timestamp(&at).as_deref(), Some(at.as_str()));
}

#[test]
fn sqlite_lists_what_a_node_originated_for_shipping() {
    check_unshipped(&SqliteStore::open(":memory:", "audit_log", true).unwrap());
}

/// Two threads ingest batches spanning two nodes, listing them in opposite
/// orders, while two threads allocate on a local node, each pair on its own
/// handle. Every call succeeds, nothing is refused, and every chain
/// verifies.
fn check_concurrent(stores: [&dyn Store; 2]) {
    let seqs: Vec<u64> = (1..=24).collect();
    let a = chain("node-a", &seqs, "ca");
    let b = chain("node-b", &seqs, "cb");
    std::thread::scope(|scope| {
        for (i, store) in stores.into_iter().enumerate() {
            let (a, b) = (&a, &b);
            scope.spawn(move || {
                for (ca, cb) in a.chunks(4).zip(b.chunks(4)) {
                    let batch = if i == 0 { [ca, cb].concat() } else { [cb, ca].concat() };
                    assert_eq!(got(&store.ingest_replicated(&batch, None).unwrap()), (batch.len(), None));
                }
            });
            scope.spawn(move || {
                for n in 0..15 {
                    store.insert(&originated(&format!("local-{i}-{n}"), "local", "svc")).unwrap();
                }
            });
        }
    });
    let rows = all_rows(stores[0]);
    assert_eq!(rows.len(), 24 * 2 + 30);
    let v = verify_chain(&rows);
    assert!(v.ok, "{v:?}");
    for (node, last) in [("node-a", 24), ("node-b", 24), ("local", 30)] {
        let seqs: Vec<u64> = rows.iter().filter(|r| r.source_node_id == node).map(|r| r.monotonic_seq).collect();
        assert_eq!(seqs, (1..=last).collect::<Vec<u64>>(), "{node}");
    }
}

#[test]
fn sqlite_concurrent_ingests_and_allocations_on_one_file() {
    let db = TempDb::new();
    let one = SqliteStore::open(&db.path(), "audit_log", true).unwrap();
    let two = SqliteStore::open(&db.path(), "audit_log", true).unwrap();
    check_concurrent([&one, &two]);
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use fasten_core::store::postgres::connect_client;
    use fasten_core::PostgresStore;

    fn dsn() -> Option<String> {
        let dsn = std::env::var("FASTEN_TEST_POSTGRES_DSN").ok().filter(|d| !d.is_empty());
        assert!(
            dsn.is_some() || std::env::var("FASTEN_REQUIRE_POSTGRES").as_deref() != Ok("1"),
            "FASTEN_REQUIRE_POSTGRES=1 but FASTEN_TEST_POSTGRES_DSN is not set"
        );
        dsn
    }

    struct Table {
        dsn: String,
        name: String,
    }

    impl Table {
        fn new(dsn: &str, prefix: &str) -> Self {
            let name = format!("{prefix}_{}", std::process::id() ^ rand_suffix());
            Self { dsn: dsn.to_string(), name }
        }

        fn sql(&self, sql: &str) -> Vec<pg::Row> {
            connect_client(&self.dsn).unwrap().query(sql, &[]).unwrap()
        }

        /// A store on this table whose connection is named after it.
        fn store(&self) -> PostgresStore {
            let sep = if self.dsn.contains('?') { '&' } else { '?' };
            PostgresStore::connect(&format!("{}{sep}application_name={}", self.dsn, self.name), &self.name).unwrap()
        }

        /// End the store's connection, as a server restart would.
        fn terminate(&self) -> usize {
            connect_client(&self.dsn)
                .unwrap()
                .query(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = $1",
                    &[&self.name],
                )
                .unwrap()
                .len()
        }
    }

    impl Drop for Table {
        fn drop(&mut self) {
            if let Ok(mut c) = connect_client(&self.dsn) {
                let _ = c.batch_execute(&format!("DROP TABLE IF EXISTS {}", self.name));
            }
        }
    }

    fn rand_suffix() -> u32 {
        use std::hash::{BuildHasher, Hasher};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(u64::from(std::process::id()));
        u32::try_from(h.finish() & 0x7fff_ffff).unwrap()
    }

    #[test]
    fn postgres_ingests_every_sdks_sealed_rows_as_sealed() {
        let Some(dsn) = dsn() else { return };
        let t = Table::new(&dsn, "repl_vectors");
        let store = t.store();
        let raw = || {
            t.sql(&format!("SELECT id, detail FROM {}", t.name)).iter().map(|r| (r.get(0), r.get(1))).collect()
        };
        let clear = || {
            t.sql(&format!("DELETE FROM {}", t.name));
        };
        check_vectors(&store, &raw, &clear);
    }

    #[test]
    fn postgres_checks_a_batch_against_the_stored_rows() {
        let Some(dsn) = dsn() else { return };
        let t = Table::new(&dsn, "repl_conflicts");
        check_conflicts(&t.store());
    }

    #[test]
    fn postgres_lists_what_a_node_originated_for_shipping() {
        let Some(dsn) = dsn() else { return };
        let t = Table::new(&dsn, "repl_unshipped");
        check_unshipped(&t.store());
    }

    // A lost connection, between calls or while a call waits on the node's
    // lock, is replaced and the call runs on the new one. No row is lost or
    // stored twice.
    #[test]
    fn postgres_connects_again_after_losing_its_connection() {
        let Some(dsn) = dsn() else { return };
        let t = Table::new(&dsn, "repl_recover");
        let store = std::sync::Arc::new(t.store());
        store.insert(&originated("r-1", "node-1", "svc")).unwrap();
        assert_eq!(t.terminate(), 1);
        store.insert(&originated("r-2", "node-1", "svc")).unwrap();
        assert_eq!(t.terminate(), 1);
        assert_eq!(store.ingest_replicated(&chain("node-2", &[1, 2], "i"), None).unwrap().inserted, 2);
        assert_eq!(t.terminate(), 1);
        assert_eq!(store.list_unshipped_sealed(0, None).unwrap().len(), 4);
        assert_eq!(t.terminate(), 1);
        store.ping().unwrap();

        // During a call: it waits on the node's lock when its connection ends.
        let mut holder = connect_client(&dsn).unwrap();
        holder.execute("SELECT pg_advisory_lock(hashtextextended($1, 0))", &[&"node-1"]).unwrap();
        let writer = {
            let store = store.clone();
            std::thread::spawn(move || store.insert_stored(&originated("r-3", "node-1", "svc")))
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let waiting = t.sql(&format!(
                "SELECT 1 FROM pg_stat_activity WHERE application_name = '{}' AND wait_event_type = 'Lock'",
                t.name
            ));
            if !waiting.is_empty() {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "the insert never waited on the lock");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(t.terminate(), 1);
        holder.execute("SELECT pg_advisory_unlock(hashtextextended($1, 0))", &[&"node-1"]).unwrap();
        assert_eq!(writer.join().unwrap().unwrap().monotonic_seq, 3);

        let rows = store.chain_rows(&Filter { source_node_id: Some("node-1".into()), ..Default::default() }).unwrap();
        assert_eq!(rows.iter().map(|r| r.monotonic_seq).collect::<Vec<_>>(), [1, 2, 3]);
        assert!(verify_chain(&rows).ok);
    }

    // A statement timeout comes over a live connection: the error is
    // returned and the connection kept.
    #[test]
    fn postgres_keeps_its_connection_after_a_statement_timeout() {
        let Some(dsn) = dsn() else { return };
        let t = Table::new(&dsn, "repl_timeout");
        let sep = if dsn.contains('?') { '&' } else { '?' };
        let timed = format!("{dsn}{sep}application_name={}&options=-c%20statement_timeout%3D300", t.name);
        let store = PostgresStore::connect(&timed, &t.name).unwrap();
        store.insert(&originated("s-1", "node-1", "svc")).unwrap();
        let pid = |t: &Table| -> Vec<i32> {
            t.sql(&format!("SELECT pid FROM pg_stat_activity WHERE application_name = '{}'", t.name))
                .iter()
                .map(|r| r.get(0))
                .collect()
        };
        let before = pid(&t);
        let mut holder = connect_client(&dsn).unwrap();
        holder.execute("SELECT pg_advisory_lock(hashtextextended($1, 0))", &[&"node-1"]).unwrap();
        let err = store.insert(&originated("s-2", "node-1", "svc")).unwrap_err();
        assert!(matches!(&err, Error::Postgres(e) if e.code().map(pg::error::SqlState::code) == Some("57014")), "{err:?}");
        assert_eq!(pid(&t), before);
        holder.execute("SELECT pg_advisory_unlock(hashtextextended($1, 0))", &[&"node-1"]).unwrap();
        store.insert(&originated("s-2", "node-1", "svc")).unwrap();
    }

    impl Table {
        /// Wait until the store's connection waits on a lock.
        fn wait_for_lock_wait(&self) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let waiting = self.sql(&format!(
                    "SELECT 1 FROM pg_stat_activity WHERE application_name = '{}' AND wait_event_type = 'Lock'",
                    self.name
                ));
                if !waiting.is_empty() {
                    return;
                }
                assert!(std::time::Instant::now() < deadline, "the store never waited on a lock");
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    fn node_rows(store: &PostgresStore, node: &str) -> Vec<ChainRow> {
        store.chain_rows(&Filter { source_node_id: Some(node.into()), ..Default::default() }).unwrap()
    }

    // Ingest takes the node lock allocation takes, so it waits for a writer
    // holding it. Ended while it waits, it runs again on a new connection
    // and stores each row once.
    #[test]
    fn postgres_ingest_takes_the_node_lock_allocation_takes() {
        let Some(dsn) = dsn() else { return };
        let t = Table::new(&dsn, "repl_lock");
        let store = std::sync::Arc::new(t.store());
        let lock = "SELECT pg_advisory_lock(hashtextextended($1, 0))";
        let unlock = "SELECT pg_advisory_unlock(hashtextextended($1, 0))";
        for (node, end_while_waiting) in [("node-l", false), ("node-m", true)] {
            let mut holder = connect_client(&dsn).unwrap();
            holder.execute(lock, &[&node]).unwrap();
            let batch = chain(node, &[1, 2, 3], node);
            let ingest = {
                let (store, batch) = (store.clone(), batch.clone());
                std::thread::spawn(move || store.ingest_replicated(&batch, None))
            };
            t.wait_for_lock_wait();
            assert!(!ingest.is_finished());
            if end_while_waiting {
                assert_eq!(t.terminate(), 1);
            }
            holder.execute(unlock, &[&node]).unwrap();
            let r = ingest.join().unwrap().unwrap();
            assert_eq!(got(&r), (3, None), "{node}");
            let rows = node_rows(&store, node);
            assert_eq!(rows.iter().map(|r| r.monotonic_seq).collect::<Vec<_>>(), [1, 2, 3], "{node}");
            assert!(verify_chain(&rows).ok, "{node}");
            // Allocation on the node continues the ingested chain.
            store.insert(&originated(&format!("{node}-own"), node, "svc")).unwrap();
            let rows = node_rows(&store, node);
            assert_eq!(rows.len(), 4, "{node}");
            assert!(verify_chain(&rows).ok, "{node}");
        }
    }

    #[test]
    fn postgres_concurrent_ingests_and_allocations() {
        let Some(dsn) = dsn() else { return };
        let t = Table::new(&dsn, "repl_conc");
        let (one, two) = (t.store(), t.store());
        check_concurrent([&one, &two]);
    }

    // A purge is not run a second time: ended while its DELETE waits, it
    // fails saying the outcome is unknown and deletes nothing; a connection
    // that ended while idle is replaced before the purge runs.
    #[test]
    fn postgres_purge_runs_once() {
        let Some(dsn) = dsn() else { return };
        let t = Table::new(&dsn, "repl_purge");
        let store = std::sync::Arc::new(t.store());
        let old = |id: &str| Row { timestamp: "2020-01-01T00:00:00.000000Z".into(), ..originated(id, "node-p", "svc") };
        store.insert(&old("p-1")).unwrap();
        store.insert(&old("p-2")).unwrap();
        assert_eq!(t.terminate(), 1);
        assert_eq!(store.purge("2021-01-01", false).unwrap(), 2);

        store.insert(&old("p-3")).unwrap();
        let mut holder = connect_client(&dsn).unwrap();
        holder.batch_execute(&format!("BEGIN; LOCK TABLE {} IN ACCESS EXCLUSIVE MODE", t.name)).unwrap();
        let purge = {
            let store = store.clone();
            std::thread::spawn(move || store.purge("2021-01-01", false))
        };
        t.wait_for_lock_wait();
        assert_eq!(t.terminate(), 1);
        let err = purge.join().unwrap().unwrap_err();
        holder.batch_execute("ROLLBACK").unwrap();
        assert!(matches!(&err, Error::Store(m) if m.contains("unknown")), "{err:?}");
        assert_eq!(node_rows(&store, "node-p").len(), 1);
        assert_eq!(store.purge("2021-01-01", false).unwrap(), 1);
    }
}
