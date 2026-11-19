//! The stores seal rows on insert (spec/chain-replication.md §2.1), and
//! `chain_rows` reads them back for `verify_chain`.
//!
//! The Postgres tests need `FASTEN_TEST_POSTGRES_DSN`. Without it they
//! return early, unless `FASTEN_REQUIRE_POSTGRES=1`, which makes them fail.

#![cfg(feature = "sqlite")]

use std::sync::{Arc, Barrier};

use fasten_core::chain::{seal, verify_chain, ChainRow, ChainVerifyResult, Json};
use fasten_core::{Error, Filter, Row, SqliteStore, Store};

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

/// The rows of a vector file, as another SDK sealed them.
fn vector_rows(path: &str) -> Vec<ChainRow> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(path);
    let file = Json::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
    let rows = match file.get("cases") {
        Some(cases) => cases.as_array().unwrap().iter().map(|c| c.get("row").unwrap().clone()).collect(),
        None => file.as_array().unwrap().to_vec(),
    };
    rows.iter().map(|r| ChainRow::from_value(r).unwrap()).collect()
}

const VECTOR_COLUMNS: &str = "id, wire_version, origin_id, monotonic_seq, timestamp, code, action, \
     severity, service_id, source_node_id, tenant_id, actor, actor_kind, target, category, domain, \
     method, request_id, detail, shipped_at, prev_hash, hash, canonical_form_id, detail_salt, \
     detail_commitment";

/// A vector row as the values of `VECTOR_COLUMNS`, the seq apart: what the
/// SDK that sealed it writes, with `detail` as the text in the file.
fn vector_values(r: &ChainRow) -> (Vec<Option<String>>, i64) {
    let some = |s: &str| Some(s.to_string());
    let values = vec![
        some(&r.id), some(&r.wire_version), some(&r.origin_id), None, some(&r.timestamp), some(&r.code),
        some(&r.action), some(&r.severity), some(&r.service_id), some(&r.source_node_id),
        r.tenant_id.clone(), some(&r.actor), some(&r.actor_kind), some(&r.target), some(&r.category),
        some(&r.domain), some(&r.method), some(&r.request_id), Some(r.detail.to_string()),
        r.shipped_at.clone(), some(&r.prev_hash), some(&r.hash), some(&r.canonical_form_id),
        Some(r.detail_salt.clone().unwrap_or_default()), Some(r.detail_commitment.clone().unwrap_or_default()),
    ];
    (values, i64::try_from(r.monotonic_seq).unwrap())
}

/// Insert vector rows into the SQLite table with plain SQL, as another SDK
/// on the same file would.
fn sql_insert(db: &TempDb, rows: &[ChainRow]) {
    let conn = rusqlite::Connection::open(db.path()).unwrap();
    let marks: Vec<String> = (1..=25).map(|i| format!("?{i}")).collect();
    let sql = format!("INSERT INTO audit_log ({VECTOR_COLUMNS}) VALUES ({})", marks.join(", "));
    for r in rows {
        let (values, seq) = vector_values(r);
        let params: Vec<&dyn rusqlite::ToSql> =
            values.iter().enumerate().map(|(i, v)| if i == 3 { &seq as &dyn rusqlite::ToSql } else { v }).collect();
        conn.execute(&sql, params.as_slice()).unwrap();
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
    let res = verify_chain(&all);
    assert!(res.ok, "{res:?}");
    assert_eq!((res.total_rows, res.sealed_rows), (10, 10));
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
    // Every thread starts inserting at once.
    let start = Arc::new(Barrier::new(4));
    let handles: Vec<_> = (0..4)
        .map(|t| {
            let store = db.open();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
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

fn python_numbers_id() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/python-sealed-forms.json");
    let file = Json::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = file.get("cases").unwrap().as_array().unwrap();
    let case = cases.iter().find(|c| c.get("label").and_then(Json::as_str) == Some("form2_numbers")).unwrap();
    case.get("row").unwrap().get("id").and_then(Json::as_str).unwrap().to_string()
}

/// Another SDK's sealed rows, put in the table with plain SQL: the next row
/// this store seals takes the next seq and links to their tip.
#[test]
fn sqlite_extends_a_go_chain() {
    let db = TempDb::new("go-chain");
    let store = db.open();
    let go = vector_rows("spec/go-sealed-form2.json");
    assert_eq!(go.len(), 2);
    sql_insert(&db, &go);

    let mine = store.insert_stored(&row("evt-rust-1", "node-1")).unwrap();
    assert_eq!((mine.monotonic_seq, mine.prev_hash.as_deref()), (3, Some(go[1].hash.as_str())));
    let (rows, result) = verify(&store, "node-1");
    assert!(result.ok, "{result:?}");
    assert_eq!((rows.len(), result.sealed_rows), (3, 3));
    // The Go rows read back as Go sealed them.
    assert_eq!(rows[..2], go[..]);
}

#[test]
fn sqlite_extends_a_python_chain_with_numeric_detail() {
    let db = TempDb::new("py-chain");
    let store = db.open();
    let python: Vec<ChainRow> =
        vector_rows("spec/python-sealed-forms.json").into_iter().filter(|r| r.id == python_numbers_id()).collect();
    assert_eq!(python.len(), 1);
    assert!(python[0].detail.to_string().contains("12345678901234567890"));
    sql_insert(&db, &python);

    let mine = store.insert_stored(&row("evt-rust-1", "node-1")).unwrap();
    assert_eq!((mine.monotonic_seq, mine.prev_hash.as_deref()), (2, Some(python[0].hash.as_str())));
    let (rows, result) = verify(&store, "node-1");
    assert!(result.ok, "{result:?}");
    assert_eq!((rows.len(), result.sealed_rows), (2, 2));
    assert_eq!(rows[0], python[0]);
}

/// A row sealed elsewhere over number tokens a `Row` cannot hold.
fn sealed_elsewhere(id: &str, seq: u64, prev: &str, detail: &str) -> ChainRow {
    let mut core = row(id, "node-x");
    core.monotonic_seq = seq;
    seal(prev, &ChainRow::from_row(&core, detail).unwrap()).unwrap()
}

const EXACT_DETAILS: [&str; 4] = [
    r#"{"n":123456789012345678901234567890}"#,
    r#"{"n":-0}"#,
    r#"{"f":1.0E+2,"nan":NaN,"name":"\udcff.txt"}"#,
    r#"{"plain":75.0}"#,
];

/// `insert_sealed` stores each detail as it was sealed, so the chain
/// verifies; `insert` of the same rows as `Row`s does not keep them all.
fn assert_exact_details(store: &dyn Store) {
    let mut rows: Vec<ChainRow> = Vec::new();
    for (i, detail) in EXACT_DETAILS.iter().enumerate() {
        let prev = rows.last().map_or("genesis".to_string(), |r| r.hash.clone());
        rows.push(sealed_elsewhere(&format!("evt-x{i}"), i as u64 + 1, &prev, detail));
    }
    assert!(verify_chain(&rows).ok);
    for r in &rows {
        store.insert_sealed(r, true).unwrap();
    }
    let (stored, result) = verify(store, "node-x");
    assert!(result.ok, "{result:?}");
    assert_eq!(stored, rows);
    assert_eq!(result.sealed_rows, 4);
    assert!(store.query(&node("node-x")).unwrap().iter().all(|r| r.pii_in_detail));

    // The same row again is a no-op; another row under its id is refused,
    // and so is a row that is not sealed.
    store.insert_sealed(&rows[1], true).unwrap();
    let other = sealed_elsewhere("evt-x1", 9, "genesis", r#"{"n":1}"#);
    assert!(matches!(store.insert_sealed(&other, false), Err(Error::RowRejected(_))));
    let clash = sealed_elsewhere("evt-x-clash", 2, "genesis", r#"{"n":1}"#);
    assert!(matches!(store.insert_sealed(&clash, false), Err(Error::SeqClash(_))));
    let unsealed = ChainRow { hash: String::new(), ..sealed_elsewhere("evt-x8", 8, "genesis", "{}") };
    assert!(matches!(store.insert_sealed(&unsealed, false), Err(Error::RowRejected(_))));
    let no_seq = sealed_elsewhere("evt-x0", 0, "genesis", "{}");
    assert!(matches!(store.insert_sealed(&no_seq, false), Err(Error::RowRejected(_))));
    assert_eq!(verify(store, "node-x").0, rows);

    // What `insert` writes for the first two: the text serde_json renders.
    for (i, r) in rows.iter().take(2).enumerate() {
        let mut core = row(&format!("evt-y{i}"), "node-y");
        core.monotonic_seq = r.monotonic_seq;
        core.detail = serde_json::from_str(EXACT_DETAILS[i]).unwrap();
        let mut again = r.clone();
        again.id.clone_from(&core.id);
        again.origin_id.clone_from(&core.id);
        again.source_node_id = "node-y".into();
        let prev = if i == 0 { "genesis".to_string() } else { verify(store, "node-y").0[0].hash.clone() };
        seal(&prev, &again).unwrap().stamp(&mut core);
        store.insert(&core).unwrap();
    }
    let (_, lossy) = verify(store, "node-y");
    assert!(!lossy.ok, "a Row kept a 30-digit integer and -0");
    assert!(lossy.reason.unwrap_or_default().contains("does not match its commitment"));
}

#[test]
fn sqlite_row_sealed_elsewhere_keeps_its_detail_text() {
    assert_exact_details(&SqliteStore::open(":memory:", "audit_log", false).unwrap());
}

/// A stored id: the same row comes back as stored, another row is refused.
fn assert_stored_ids(store: &dyn Store, insert_stored: &dyn Fn(&Row) -> Result<Row, Error>) {
    let first = insert_stored(&row("evt-1", "node-1")).unwrap();
    // A retry of the same row gets the stored seq and chain fields.
    let again = insert_stored(&row("evt-1", "node-1")).unwrap();
    let wire = |r: &Row| serde_json::to_value(r).unwrap();
    assert_eq!(wire(&again), wire(&first));
    // The same id with other content is not the stored row.
    let other = Row { target: "res-2".into(), ..row("evt-1", "node-1") };
    let err = insert_stored(&other).unwrap_err();
    assert!(matches!(&err, Error::RowRejected(m) if m.contains("row evt-1: differs")), "{err:?}");
    // `insert` keeps its contract: a stored id is left alone.
    store.insert(&other).unwrap();

    // A row with its own seq: stored once, the same row again is returned,
    // and the id at another seq or with another hash is refused.
    let own = Row { monotonic_seq: 7, ..row("evt-7", "node-1") };
    assert_eq!(wire(&insert_stored(&own).unwrap()), wire(&own));
    let stored = insert_stored(&own).unwrap();
    assert_eq!((stored.monotonic_seq, stored.hash.as_deref().unwrap_or("")), (7, ""));
    let moved = Row { monotonic_seq: 8, ..own.clone() };
    assert!(matches!(insert_stored(&moved), Err(Error::RowRejected(_))));
    let sealed = Row { hash: Some("ab".repeat(32)), ..own.clone() };
    assert!(matches!(insert_stored(&sealed), Err(Error::RowRejected(_))));
    // A stored id is not a new row for seq 0 either.
    let as_new = Row { monotonic_seq: 0, target: "res-9".into(), ..own };
    assert!(matches!(insert_stored(&as_new), Err(Error::RowRejected(_))));

    let seqs: Vec<u64> = store.query(&node("node-1")).unwrap().iter().map(|r| r.monotonic_seq).collect();
    assert_eq!(seqs, [1, 7]);
}

#[test]
fn sqlite_stored_id_is_returned_or_refused() {
    let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
    assert_stored_ids(&store, &|r: &Row| store.insert_stored(r));
}

/// A seq-0 row is sealed here, so it must be one this node originated.
fn assert_foreign_origin_refused(store: &dyn Store) {
    store.insert(&row("evt-1", "node-1")).unwrap();
    let foreign = Row { origin_id: "evt-somewhere-else".into(), ..row("evt-2", "node-1") };
    let err = store.insert(&foreign).unwrap_err();
    assert!(matches!(&err, Error::RowRejected(m) if m.contains("origin_id == id")), "{err:?}");
    // The refused row took no seq.
    store.insert(&row("evt-3", "node-1")).unwrap();
    let (rows, result) = verify(store, "node-1");
    assert!(result.ok, "{result:?}");
    assert_unbroken(&rows, 2);
    // With its own seq it is a replicated row and is stored as given.
    store.insert(&Row { monotonic_seq: 9, ..foreign }).unwrap();
}

#[test]
fn sqlite_foreign_origin_is_refused_and_takes_no_seq() {
    assert_foreign_origin_refused(&SqliteStore::open(":memory:", "audit_log", false).unwrap());
}

/// An insert that fails inside the transaction takes no seq: the next row
/// gets it and the chain has no gap.
#[test]
fn sqlite_failed_sealing_insert_takes_no_seq() {
    let db = TempDb::new("abort");
    let store = db.open();
    db.sql(
        "CREATE TRIGGER refuse_one BEFORE INSERT ON audit_log WHEN NEW.id = 'evt-refused'
         BEGIN SELECT RAISE(ABORT, 'refused by trigger'); END",
    );
    store.insert(&row("evt-0", "node-1")).unwrap();
    let err = store.insert(&row("evt-refused", "node-1")).unwrap_err();
    assert!(err.to_string().contains("refused by trigger"), "{err}");
    assert!(store.insert_stored(&row("evt-refused", "node-1")).is_err());
    let next = store.insert_stored(&row("evt-1", "node-1")).unwrap();
    assert_eq!(next.monotonic_seq, 2);

    let (rows, result) = verify(&store, "node-1");
    assert!(result.ok, "{result:?}");
    assert_unbroken(&rows, 2);
    assert_eq!(rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["evt-0", "evt-1"]);
}

/// A negative seq is not read as its absolute value.
#[test]
fn sqlite_negative_seq_is_an_error() {
    let db = TempDb::new("negative");
    let store = db.open();
    store.insert(&row("evt-1", "node-1")).unwrap();
    db.sql("UPDATE audit_log SET monotonic_seq = -5");
    for err in [
        store.chain_rows(&node("node-1")).unwrap_err(),
        store.query(&node("node-1")).unwrap_err(),
        store.chain_tips().unwrap_err(),
    ] {
        assert!(err.to_string().contains("monotonic_seq -5 is negative"), "{err}");
    }
    let err = store.chain_rows(&node("node-1")).unwrap_err().to_string();
    assert!(err.contains("row evt-1"), "{err}");
    // The next seq would be -4: nothing is sealed over it.
    let err = store.insert(&row("evt-2", "node-1")).unwrap_err();
    assert!(err.to_string().contains("next monotonic_seq -4 is negative"), "{err}");
    assert_eq!(store.count(&Filter::default()).unwrap(), 1);
}

/// `chain_rows` returns the table node by node, each in seq order.
#[test]
fn sqlite_chain_rows_are_ordered_by_node_then_seq() {
    let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
    for (id, n) in [("b1", "node-b"), ("a1", "node-a"), ("b2", "node-b"), ("a2", "node-a")] {
        store.insert(&row(id, n)).unwrap();
    }
    let order: Vec<(String, u64)> = store
        .chain_rows(&Filter::default())
        .unwrap()
        .into_iter()
        .map(|r| (r.source_node_id, r.monotonic_seq))
        .collect();
    let want = [("node-a", 1), ("node-a", 2), ("node-b", 1), ("node-b", 2)];
    assert_eq!(order, want.map(|(n, s)| (n.to_string(), s)));
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use fasten_core::store::postgres::connect_client;
    use fasten_core::PostgresStore;

    fn dsn() -> Option<String> {
        let dsn = std::env::var("FASTEN_TEST_POSTGRES_DSN").ok();
        assert!(
            dsn.is_some() || std::env::var("FASTEN_REQUIRE_POSTGRES").as_deref() != Ok("1"),
            "FASTEN_REQUIRE_POSTGRES=1 but FASTEN_TEST_POSTGRES_DSN is not set"
        );
        dsn
    }

    /// Insert vector rows with plain SQL, as another SDK on the table would.
    fn sql_insert(dsn: &str, table: &str, rows: &[ChainRow]) {
        let mut c = connect_client(dsn).unwrap();
        let marks: Vec<String> = (1..=25).map(|i| format!("${i}")).collect();
        let sql = format!("INSERT INTO {table} ({VECTOR_COLUMNS}) VALUES ({})", marks.join(", "));
        for r in rows {
            let (values, seq) = vector_values(r);
            let params: Vec<&(dyn pg::types::ToSql + Sync)> = values
                .iter()
                .enumerate()
                .map(|(i, v)| if i == 3 { &seq as &(dyn pg::types::ToSql + Sync) } else { v })
                .collect();
            c.execute(sql.as_str(), &params).unwrap();
        }
    }

    #[test]
    fn extends_a_go_chain_and_a_python_chain() {
        let Some(dsn) = dsn() else { return };
        let go = vector_rows("spec/go-sealed-form2.json");
        let python: Vec<ChainRow> = vector_rows("spec/python-sealed-forms.json")
            .into_iter()
            .filter(|r| r.id == python_numbers_id())
            .map(|r| ChainRow { source_node_id: "node-py".into(), ..r })
            .collect();
        let store = fresh(&dsn, "fasten_chain_pg_extend");
        sql_insert(&dsn, "fasten_chain_pg_extend", &go);
        let mine = store.insert_stored(&row("evt-rust-1", "node-1")).unwrap();
        assert_eq!((mine.monotonic_seq, mine.prev_hash.as_deref()), (3, Some(go[1].hash.as_str())));
        let (rows, result) = verify(&store, "node-1");
        assert!(result.ok, "{result:?}");
        assert_eq!((rows.len(), result.sealed_rows), (3, 3));
        assert_eq!(rows[..2], go[..]);

        // The Python row is sealed for node-1; stored under another node it
        // is the tip a new row links to, and fails only its own hash.
        sql_insert(&dsn, "fasten_chain_pg_extend", &python);
        let next = store.insert_stored(&row("evt-rust-2", "node-py")).unwrap();
        assert_eq!((next.monotonic_seq, next.prev_hash.as_deref()), (2, Some(python[0].hash.as_str())));
    }

    #[test]
    fn a_row_sealed_elsewhere_keeps_its_detail_text() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_chain_pg_exact");
        assert_exact_details(&store);
    }

    #[test]
    fn a_stored_id_is_returned_or_refused() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_chain_pg_held");
        let insert = |r: &Row| store.insert_stored(r);
        assert_stored_ids(&store, &insert);
    }

    #[test]
    fn a_foreign_origin_is_refused_and_takes_no_seq() {
        let Some(dsn) = dsn() else { return };
        let store = fresh(&dsn, "fasten_chain_pg_origin");
        assert_foreign_origin_refused(&store);
    }

    // A column of another type, or a negative seq, is an error that names
    // the row, not a panic.
    #[test]
    fn unreadable_rows_are_errors() {
        let Some(dsn) = dsn() else { return };
        let table = "fasten_chain_pg_unreadable";
        let store = fresh(&dsn, table);
        store.insert(&row("evt-1", "node-1")).unwrap();
        let mut c = connect_client(&dsn).unwrap();
        c.batch_execute(&format!("UPDATE {table} SET monotonic_seq = -5")).unwrap();
        for err in [
            store.chain_rows(&node("node-1")).unwrap_err(),
            store.query(&node("node-1")).unwrap_err(),
            store.chain_tips().unwrap_err(),
        ] {
            assert!(err.to_string().contains("monotonic_seq -5 is negative"), "{err}");
        }
        // The next seq would be negative too: nothing is sealed over it.
        let err = store.insert(&row("evt-2", "node-1")).unwrap_err();
        assert!(err.to_string().contains("is negative"), "{err}");

        c.batch_execute(&format!(
            "UPDATE {table} SET monotonic_seq = 1;
             ALTER TABLE {table} ALTER COLUMN timestamp TYPE TIMESTAMPTZ USING timestamp::timestamptz"
        ))
        .unwrap();
        let err = store.chain_rows(&node("node-1")).unwrap_err().to_string();
        assert!(err.contains("row evt-1: column timestamp"), "{err}");
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
        // Every connection is open before any thread inserts.
        let start = Arc::new(Barrier::new(4));
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let dsn = dsn.clone();
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    let store = PostgresStore::connect(&dsn, table).unwrap();
                    start.wait();
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
            // An edited row with its hash cleared is not read as unsealed.
            ("UPDATE {t} SET hash = '', prev_hash = '', actor = 'mallory' WHERE monotonic_seq = 4", 4, "no hash after"),
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
