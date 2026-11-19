//! The stores seal rows on insert (spec/chain-replication.md §2.1), and
//! `chain_rows` reads them back for `verify_chain`.
//!
//! The Postgres tests need `FASTEN_TEST_POSTGRES_DSN` and pass without it.

#![cfg(feature = "sqlite")]

use fasten_core::chain::{seal, verify_chain, ChainRow, ChainVerifyResult};
use fasten_core::{Filter, Row, SqliteStore, Store};

fn row(id: &str, node: &str) -> Row {
    Row {
        wire_version: "1".into(),
        id: id.into(),
        origin_id: id.into(),
        timestamp: "2026-05-07T00:00:00.000000Z".into(),
        code: "USER_LOGIN".into(),
        action: "login".into(),
        severity: "info".into(),
        service_id: "svc".into(),
        source_node_id: node.into(),
        actor: "tester".into(),
        actor_kind: "user".into(),
        target: "res-1".into(),
        category: "test".into(),
        domain: "test".into(),
        method: "sdk".into(),
        request_id: "req-001".into(),
        detail: serde_json::json!({"setpoint": 75.0, "small": 1e-7, "n": 7, "who": "é<&>"}),
        ..Default::default()
    }
}

fn node(node: &str) -> Filter {
    Filter { source_node_id: Some(node.into()), ..Default::default() }
}

fn verify(store: &dyn Store, n: &str) -> (Vec<ChainRow>, ChainVerifyResult) {
    let rows = store.chain_rows(&node(n)).unwrap();
    let result = verify_chain(&rows);
    (rows, result)
}

/// Every row is sealed, links to the one before it and has seqs 1..=n.
fn assert_unbroken(rows: &[ChainRow], n: u64) {
    assert_eq!(rows.iter().map(|r| r.monotonic_seq).collect::<Vec<_>>(), (1..=n).collect::<Vec<_>>());
    let mut prev = "genesis".to_string();
    for r in rows {
        assert_eq!(r.canonical_form_id, "2");
        assert_eq!(r.prev_hash, prev, "seq {}", r.monotonic_seq);
        assert_eq!(r.hash.len(), 64);
        prev.clone_from(&r.hash);
    }
}

struct TempDb(std::path::PathBuf);

impl TempDb {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("fasten-chain-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> String {
        self.0.join("audit.db").to_str().unwrap().to_string()
    }

    fn open(&self) -> SqliteStore {
        SqliteStore::open(&self.path(), "audit_log", true).unwrap()
    }

    fn sql(&self, sql: &str) {
        rusqlite::Connection::open(self.path()).unwrap().execute_batch(sql).unwrap();
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn sqlite_rows_are_sealed_per_node() {
    let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
    for i in 0..5 {
        store.insert(&row(&format!("evt-a{i}"), "node-a")).unwrap();
        store.insert(&row(&format!("evt-b{i}"), "node-b")).unwrap();
    }
    for n in ["node-a", "node-b"] {
        let (rows, result) = verify(&store, n);
        assert!(result.ok, "{result:?}");
        assert_unbroken(&rows, 5);
    }
    let all = store.chain_rows(&Filter::default()).unwrap();
    assert_eq!(verify_chain(&all), ChainVerifyResult { ok: true, total_rows: 10, first_break_at: None, reason: None });
}

/// A repeated id is stored once and takes no seq.
#[test]
fn sqlite_repeated_id_keeps_the_chain() {
    let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
    let first = row("evt-1", "node-a");
    store.insert(&first).unwrap();
    store.insert(&first).unwrap();
    store.insert(&row("evt-2", "node-a")).unwrap();
    let (rows, result) = verify(&store, "node-a");
    assert!(result.ok, "{result:?}");
    assert_unbroken(&rows, 2);
}

#[test]
fn sqlite_two_handles_write_one_chain() {
    let db = TempDb::new("conc");
    drop(db.open());
    let handles: Vec<_> = (0..4)
        .map(|t| {
            let store = db.open();
            std::thread::spawn(move || {
                for i in 0..50 {
                    store.insert(&row(&format!("evt-{t}-{i}"), "node-1")).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let (rows, result) = verify(&db.open(), "node-1");
    assert!(result.ok, "{result:?}");
    assert_unbroken(&rows, 200);
}

#[test]
fn sqlite_reopened_store_continues_the_chain() {
    let db = TempDb::new("restart");
    let store = db.open();
    for i in 0..3 {
        store.insert(&row(&format!("evt-{i}"), "node-1")).unwrap();
    }
    drop(store);
    let store = db.open();
    for i in 3..6 {
        store.insert(&row(&format!("evt-{i}"), "node-1")).unwrap();
    }
    let (rows, result) = verify(&store, "node-1");
    assert!(result.ok, "{result:?}");
    assert_unbroken(&rows, 6);
}

#[test]
fn sqlite_tampering_is_detected() {
    for (change, seq, reason) in [
        ("UPDATE audit_log SET actor = 'mallory' WHERE monotonic_seq = 2", 2, "hash mismatch"),
        ("UPDATE audit_log SET detail = '{\"n\":8}' WHERE monotonic_seq = 3", 3, "does not match its commitment"),
        ("DELETE FROM audit_log WHERE monotonic_seq = 2", 3, "prev_hash does not match"),
        ("UPDATE audit_log SET hash = '', prev_hash = '' WHERE monotonic_seq = 4", 4, "no hash after"),
    ] {
        let db = TempDb::new("tamper");
        let store = db.open();
        for i in 0..5 {
            store.insert(&row(&format!("evt-{i}"), "node-1")).unwrap();
        }
        assert!(verify(&store, "node-1").1.ok);
        db.sql(change);
        let (_, result) = verify(&store, "node-1");
        assert!(!result.ok, "{change}");
        assert_eq!(result.first_break_at, Some(seq), "{change}");
        assert!(result.reason.as_deref().unwrap_or("").contains(reason), "{change}: {result:?}");
    }
}

/// Redaction clears detail and salt and leaves the hash, so the chain
/// verifies before and after (spec §7.1).
#[test]
fn sqlite_redacted_row_still_verifies() {
    let db = TempDb::new("redact");
    let store = db.open();
    for i in 0..3 {
        store.insert(&row(&format!("evt-{i}"), "node-1")).unwrap();
    }
    let (before, result) = verify(&store, "node-1");
    assert!(result.ok);
    store.redact_rows(&["evt-1".to_string()]).unwrap();
    let (after, result) = verify(&store, "node-1");
    assert!(result.ok, "{result:?}");
    assert_eq!(after[1].detail, fasten_core::chain::Json::Null);
    assert_eq!(after[1].detail_salt, None);
    assert_eq!(after[1].hash, before[1].hash);
    assert_eq!(after[1].detail_commitment, before[1].detail_commitment);
    // Redacted rows are written the way the Python store writes them.
    let salt: String = rusqlite::Connection::open(db.path())
        .unwrap()
        .query_row("SELECT detail_salt FROM audit_log WHERE id = 'evt-1'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(salt, "");
    // The chain goes on after it.
    store.insert(&row("evt-3", "node-1")).unwrap();
    let (rows, result) = verify(&store, "node-1");
    assert!(result.ok, "{result:?}");
    assert_eq!(rows[3].prev_hash, rows[2].hash);
}

/// Rows stored unsealed before sealing started stay below the chain: the
/// first sealed row links to "genesis" and the chain verifies (spec §2).
#[test]
fn sqlite_unsealed_rows_below_the_chain_are_skipped() {
    let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
    for seq in 1..=3 {
        let mut old = row(&format!("evt-old-{seq}"), "node-1");
        old.monotonic_seq = seq;
        store.insert(&old).unwrap();
    }
    store.insert(&row("evt-new-1", "node-1")).unwrap();
    store.insert(&row("evt-new-2", "node-1")).unwrap();
    let (rows, result) = verify(&store, "node-1");
    assert!(result.ok, "{result:?}");
    assert_eq!(rows.iter().map(|r| r.hash.is_empty()).collect::<Vec<_>>(), [true, true, true, false, false]);
    assert_eq!((rows[3].monotonic_seq, rows[3].prev_hash.as_str()), (4, "genesis"));
    assert_eq!(rows[4].prev_hash, rows[3].hash);
}

/// A sealed row arriving with its own seq is stored as it is, and the next
/// allocated row links to it.
#[test]
fn sqlite_sealed_row_is_not_resealed() {
    let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
    let mut first = row("evt-1", "node-1");
    first.monotonic_seq = 1;
    let sealed = seal("genesis", &ChainRow::from(&first)).unwrap();
    sealed.stamp(&mut first);
    store.insert(&first).unwrap();
    store.insert(&row("evt-2", "node-1")).unwrap();
    let (rows, result) = verify(&store, "node-1");
    assert!(result.ok, "{result:?}");
    assert_eq!(rows[0].hash, sealed.hash);
    assert_eq!(rows[0].detail_salt, sealed.detail_salt);
    assert_eq!(rows[1].prev_hash, sealed.hash);
}

/// `chain_rows` hashes the detail text as stored. A row sealed elsewhere can
/// hold number tokens `serde_json` does not keep, which `query` loses.
#[test]
fn sqlite_chain_rows_keep_stored_number_tokens() {
    let db = TempDb::new("tokens");
    let store = db.open();
    let detail = r#"{"big": 123456789012345678901234567890, "neg": -0, "wide": 1.0E+2, "f": 75.0}"#;
    let mut stored = row("evt-1", "node-1");
    stored.monotonic_seq = 1;
    stored.detail = serde_json::json!({});
    // The wire row with the detail text spliced in.
    let mut wire = serde_json::to_value(&stored).unwrap();
    wire.as_object_mut().unwrap().remove("detail");
    let text = format!(r#"{{"detail":{detail},{}"#, &wire.to_string()[1..]);
    let sealed = seal("genesis", &ChainRow::from_json(&text).unwrap()).unwrap();
    sealed.stamp(&mut stored);
    store.insert(&stored).unwrap();
    rusqlite::Connection::open(db.path())
        .unwrap()
        .execute("UPDATE audit_log SET detail = ?1 WHERE id = 'evt-1'", [detail])
        .unwrap();

    let (rows, result) = verify(&store, "node-1");
    assert!(result.ok, "{result:?}");
    assert_eq!(rows[0].detail, fasten_core::chain::Json::parse(detail).unwrap());
    let lossy: Vec<ChainRow> = store.query(&node("node-1")).unwrap().iter().map(ChainRow::from).collect();
    assert!(!verify_chain(&lossy).ok);
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use fasten_core::store::postgres::connect_client;
    use fasten_core::PostgresStore;

    fn dsn() -> Option<String> {
        std::env::var("FASTEN_TEST_POSTGRES_DSN").ok()
    }

    fn fresh(dsn: &str, table: &str) -> PostgresStore {
        let mut c = connect_client(dsn).unwrap();
        c.batch_execute(&format!("DROP TABLE IF EXISTS {table}")).unwrap();
        PostgresStore::connect(dsn, table).unwrap()
    }

    #[test]
    fn rows_are_sealed_per_node() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_chain_pg_seal");
        for i in 0..5 {
            store.insert(&row(&format!("evt-a{i}"), "node-a")).unwrap();
            store.insert(&row(&format!("evt-b{i}"), "node-b")).unwrap();
        }
        // A repeated id is stored once and takes no seq.
        store.insert(&row("evt-a0", "node-a")).unwrap();
        for n in ["node-a", "node-b"] {
            let (rows, result) = verify(&store, n);
            assert!(result.ok, "{result:?}");
            assert_unbroken(&rows, 5);
        }
    }

    #[test]
    fn four_connections_write_one_chain() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_chain_pg_conc";
        drop(fresh(&dsn, table));
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let dsn = dsn.clone();
                std::thread::spawn(move || {
                    let store = PostgresStore::connect(&dsn, table).unwrap();
                    for i in 0..50 {
                        store.insert(&row(&format!("evt-{t}-{i}"), "node-1")).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let (rows, result) = verify(&PostgresStore::connect(&dsn, table).unwrap(), "node-1");
        assert!(result.ok, "{result:?}");
        assert_unbroken(&rows, 200);
    }

    #[test]
    fn reconnected_store_continues_the_chain() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_chain_pg_restart";
        let store = fresh(&dsn, table);
        for i in 0..3 {
            store.insert(&row(&format!("evt-{i}"), "node-1")).unwrap();
        }
        drop(store);
        let store = PostgresStore::connect(&dsn, table).unwrap();
        for i in 3..6 {
            store.insert(&row(&format!("evt-{i}"), "node-1")).unwrap();
        }
        let (rows, result) = verify(&store, "node-1");
        assert!(result.ok, "{result:?}");
        assert_unbroken(&rows, 6);
    }

    #[test]
    fn tampering_is_detected() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_chain_pg_tamper";
        for (change, seq, reason) in [
            ("UPDATE {t} SET actor = 'mallory' WHERE monotonic_seq = 2", 2, "hash mismatch"),
            ("UPDATE {t} SET detail = '{\"n\":8}' WHERE monotonic_seq = 3", 3, "does not match its commitment"),
            ("DELETE FROM {t} WHERE monotonic_seq = 2", 3, "prev_hash does not match"),
        ] {
            let store = fresh(&dsn, table);
            for i in 0..5 {
                store.insert(&row(&format!("evt-{i}"), "node-1")).unwrap();
            }
            assert!(verify(&store, "node-1").1.ok);
            connect_client(&dsn).unwrap().batch_execute(&change.replace("{t}", table)).unwrap();
            let (_, result) = verify(&store, "node-1");
            assert_eq!((result.ok, result.first_break_at), (false, Some(seq)), "{change}");
            assert!(result.reason.as_deref().unwrap_or("").contains(reason), "{change}: {result:?}");
        }
    }

    #[test]
    fn redacted_row_still_verifies() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_chain_pg_redact");
        for i in 0..3 {
            store.insert(&row(&format!("evt-{i}"), "node-1")).unwrap();
        }
        let (before, _) = verify(&store, "node-1");
        store.redact_rows(&["evt-1".to_string()]).unwrap();
        let (after, result) = verify(&store, "node-1");
        assert!(result.ok, "{result:?}");
        assert_eq!(after[1].detail, fasten_core::chain::Json::Null);
        assert_eq!(after[1].detail_salt, None);
        assert_eq!(after[1].hash, before[1].hash);
        store.insert(&row("evt-3", "node-1")).unwrap();
        assert!(verify(&store, "node-1").1.ok);
    }

    #[test]
    fn unsealed_rows_below_the_chain_are_skipped() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_chain_pg_head");
        for seq in 1..=3 {
            let mut old = row(&format!("evt-old-{seq}"), "node-1");
            old.monotonic_seq = seq;
            store.insert(&old).unwrap();
        }
        store.insert(&row("evt-new-1", "node-1")).unwrap();
        store.insert(&row("evt-new-2", "node-1")).unwrap();
        let (rows, result) = verify(&store, "node-1");
        assert!(result.ok, "{result:?}");
        assert_eq!((rows[3].monotonic_seq, rows[3].prev_hash.as_str()), (4, "genesis"));
        assert_eq!(rows[4].prev_hash, rows[3].hash);
    }
}
