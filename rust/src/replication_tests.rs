//! Replication on the bundled stores: ingest checks a batch against what the
//! store holds (spec §4), as the Python and Go stores do; shipping lists the
//! rows a node originated; purge keeps the chain verifiable.
//!
//! Every test runs on `SqliteStore` and, with `store-postgres` and
//! `FASTEN_TEST_POSTGRES_DSN`, on `PostgresStore`. With
//! `FASTEN_REQUIRE_POSTGRES=1` and no DSN they fail.

use std::sync::Arc;

use crate::checkpoints::{checkpoints_since, publish_checkpoints, CheckpointOptions, FileCheckpointSink};
use crate::{verify_chain, verify_chain_with_checkpoints, AuditStore, ChainRow, IngestResult, ReplicatedRow};

/// A store under test, and how to read all its rows back as stored.
struct Subject {
    name: &'static str,
    store: Arc<dyn AuditStore>,
    rows: Box<dyn Fn() -> Vec<ChainRow>>,
    _table: Option<pg::DropTable>,
}

impl Subject {
    fn ingest(&self, rows: &[ReplicatedRow]) -> IngestResult {
        self.store.ingest_replicated(rows, None).unwrap_or_else(|e| panic!("{}: {e}", self.name))
    }

    /// `(seq, id, target)` of every stored row, sorted.
    fn stored(&self) -> Vec<(u64, String, String)> {
        let mut out: Vec<_> =
            (self.rows)().into_iter().map(|r| (r.monotonic_seq, r.id, r.target)).collect();
        out.sort();
        out
    }

    fn seqs(&self) -> Vec<u64> {
        self.stored().into_iter().map(|(s, _, _)| s).collect()
    }
}

fn sqlite() -> Subject {
    let store = Arc::new(crate::SqliteStore::open(":memory:", "audit_log").unwrap());
    let reader = store.clone();
    Subject { name: "SqliteStore", store, rows: Box::new(move || reader.all_chain_rows().unwrap()), _table: None }
}

/// A fresh SqliteStore and, when a test database is configured, a fresh
/// PostgresStore.
fn subjects() -> Vec<Subject> {
    let mut out = vec![sqlite()];
    #[cfg(feature = "store-postgres")]
    if let Some(s) = pg::subject() {
        out.push(s);
    }
    out
}

#[cfg(feature = "store-postgres")]
pub(crate) mod pg {
    use std::sync::Arc;

    /// The DSN of the test database. Without one the Postgres tests return
    /// early, unless FASTEN_REQUIRE_POSTGRES=1 says they must run.
    pub(crate) fn dsn() -> Option<String> {
        let dsn = std::env::var("FASTEN_TEST_POSTGRES_DSN").ok().filter(|d| !d.is_empty());
        assert!(
            dsn.is_some() || std::env::var("FASTEN_REQUIRE_POSTGRES").as_deref() != Ok("1"),
            "FASTEN_REQUIRE_POSTGRES=1 but FASTEN_TEST_POSTGRES_DSN is not set"
        );
        dsn
    }

    pub(crate) fn client(dsn: &str) -> ::pg::Client {
        ::pg::Client::connect(dsn, ::pg::NoTls).expect("connect")
    }

    /// A table name no other test uses.
    pub(crate) fn table(prefix: &str) -> String {
        format!("{prefix}_{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
    }

    /// Drops its table when the test ends.
    pub(crate) struct DropTable(pub(crate) String, pub(crate) String);

    impl Drop for DropTable {
        fn drop(&mut self) {
            if let Ok(mut c) = ::pg::Client::connect(&self.0, ::pg::NoTls) {
                let _ = c.batch_execute(&format!("DROP TABLE IF EXISTS {}", self.1));
            }
        }
    }

    pub(super) fn subject() -> Option<super::Subject> {
        let dsn = dsn()?;
        let table = table("ingest");
        let store = Arc::new(crate::PostgresStore::new(&dsn, table.clone()).unwrap());
        let reader = store.clone();
        Some(super::Subject {
            name: "PostgresStore",
            store,
            rows: Box::new(move || reader.all_chain_rows().unwrap()),
            _table: Some(DropTable(dsn, table)),
        })
    }

    /// The detail column text of every row, by id.
    pub(crate) fn raw_details(dsn: &str, table: &str) -> std::collections::HashMap<String, String> {
        client(dsn)
            .query(&format!("SELECT id, detail FROM {table}") as &str, &[])
            .unwrap()
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect()
    }
}

#[cfg(not(feature = "store-postgres"))]
mod pg {
    pub(crate) struct DropTable;
}

/// An unsealed wire row at `seq`.
fn row(seq: u64, id: &str, node: &str, target: &str) -> ChainRow {
    let v = serde_json::json!({
        "wire_version": "1", "id": id, "origin_id": id, "monotonic_seq": seq,
        "timestamp": format!("2026-06-15T10:30:{:02}.000000Z", seq % 60),
        "code": "USER_CREATED", "action": "create", "severity": "info",
        "service_id": "svc", "source_node_id": node, "tenant_id": null,
        "actor": "a", "actor_kind": "user", "target": target, "category": "account",
        "domain": "user", "method": "sdk", "request_id": format!("req-{seq}"),
        "detail": {"k": "v", "n": 1.50},
    });
    ChainRow::from_json(&v.to_string()).unwrap()
}

fn seal(prev: &str, r: &ChainRow) -> ChainRow {
    fasten_core::chain::seal(prev, r).unwrap()
}

/// Rows at `seqs` on `node`, sealed into one chain after `prev`, with ids
/// from `id`.
fn chain_with(seqs: &[u64], prev: &str, node: &str, target: &str, id: impl Fn(u64) -> String) -> Vec<ReplicatedRow> {
    let mut prev = prev.to_string();
    seqs.iter()
        .map(|&seq| {
            let sealed = seal(&prev, &row(seq, &id(seq), node, target));
            prev.clone_from(&sealed.hash);
            ReplicatedRow::from(sealed)
        })
        .collect()
}

/// Rows `evt-<seq>` on node-1, sealed from genesis.
fn chain(seqs: &[u64]) -> Vec<ReplicatedRow> {
    chain_with(seqs, "genesis", "node-1", "u/1", |s| format!("evt-{s}"))
}

fn unsealed(seq: u64) -> ReplicatedRow {
    let mut r = row(seq, &format!("evt-{seq}"), "node-1", "u/1");
    r.prev_hash = String::new();
    ReplicatedRow::from(r)
}

fn result(inserted: usize, rejected_from_seq: Option<u64>) -> (usize, Option<u64>) {
    (inserted, rejected_from_seq)
}

fn got(r: &IngestResult) -> (usize, Option<u64>) {
    (r.inserted, r.rejected_from_seq)
}

#[test]
fn redelivering_a_stored_batch_is_a_no_op() {
    for s in subjects() {
        let rows = chain(&[1, 2, 3]);
        assert_eq!(got(&s.ingest(&rows)), result(3, None), "{}", s.name);
        let again = s.ingest(&rows);
        assert_eq!(got(&again), result(3, None), "{}", s.name);
        assert_eq!(s.seqs(), [1, 2, 3], "{}", s.name);
        assert!(verify_chain(&(s.rows)()).ok, "{}", s.name);
    }
}

#[test]
fn a_continuing_batch_is_stored() {
    for s in subjects() {
        let rows = chain(&[1, 2, 3, 4, 5]);
        s.ingest(&rows[..3]);
        assert_eq!(s.ingest(&rows[3..]).rejected_from_seq, None, "{}", s.name);
        assert_eq!(s.seqs(), [1, 2, 3, 4, 5], "{}", s.name);
    }
}

#[test]
fn a_row_that_differs_from_the_stored_row_with_its_id_is_rejected() {
    for s in subjects() {
        s.ingest(&chain_with(&[1, 2, 3], "genesis", "node-1", "u/other", |n| format!("evt-{n}")));
        let r = s.ingest(&chain(&[1, 2, 3]));
        assert_eq!(got(&r), result(0, Some(1)), "{}", s.name);
        assert!(r.reason.as_deref().unwrap().contains("stored row"), "{r:?}");
        assert!(s.stored().iter().all(|(_, _, t)| t == "u/other"), "{}", s.name);
    }
}

#[test]
fn a_new_row_at_a_stored_seq_is_rejected() {
    for s in subjects() {
        s.ingest(&chain(&[1, 2]));
        let other = chain_with(&[1], "genesis", "node-1", "u/1", |_| "evt-x1".into());
        let r = s.ingest(&other);
        assert_eq!(r.rejected_from_seq, Some(1), "{}", s.name);
        assert_eq!(r.reason.as_deref(), Some("row evt-x1: seq 1 on node 'node-1' is stored as row evt-1"));
        assert_eq!(s.seqs(), [1, 2], "{}", s.name);
    }
}

#[test]
fn a_new_row_must_link_to_the_stored_row_before_it() {
    for s in subjects() {
        s.ingest(&chain(&[1, 2]));
        let detached = chain_with(&[3, 4], &"0".repeat(64), "node-1", "u/1", |n| format!("evt-{n}"));
        let r = s.ingest(&detached);
        assert_eq!(r.rejected_from_seq, Some(3), "{}", s.name);
        assert_eq!(r.reason.as_deref(), Some("row evt-3: prev_hash does not match stored row evt-2"));
        assert_eq!(s.seqs(), [1, 2], "{}", s.name);
    }
}

#[test]
fn the_stored_row_after_a_new_one_must_link_to_it() {
    for s in subjects() {
        let rows = chain(&[1, 2, 3]);
        s.ingest(&rows[..1]);
        s.ingest(&rows[2..]); // seq 2 still missing
        let filler = vec![ReplicatedRow::from(seal(&rows[0].row.hash, &row(2, "evt-2", "node-1", "u/other")))];
        let r = s.ingest(&filler);
        assert_eq!(r.rejected_from_seq, Some(2), "{}", s.name);
        assert_eq!(r.reason.as_deref(), Some("row evt-2: stored row evt-3 does not link to it"));
        // The real row fits.
        assert_eq!(s.ingest(&rows[1..2]).rejected_from_seq, None, "{}", s.name);
        assert!(verify_chain(&(s.rows)()).ok, "{}", s.name);
    }
}

#[test]
fn a_kept_row_is_checked_against_the_stored_row_after_it() {
    // Stored 1-4 and 6; the batch's 6 conflicts, so only its 5 could be
    // kept, and that 5 must still link to the stored 6.
    for s in subjects() {
        let rows = chain(&[1, 2, 3, 4, 5, 6]);
        s.ingest(&rows[..4]);
        s.ingest(&rows[5..]);
        let mut other = chain_with(&[5], &rows[3].row.hash, "node-1", "u/other", |n| format!("evt-{n}"));
        other.push(ReplicatedRow::from(seal(&other[0].row.hash, &row(6, "evt-x6", "node-1", "u/other"))));
        let r = s.ingest(&other);
        assert_eq!(got(&r), result(0, Some(5)), "{}", s.name);
        assert_eq!(s.ingest(&rows[4..5]).rejected_from_seq, None, "{}", s.name);
    }
}

#[test]
fn one_id_on_two_nodes_in_a_batch_is_rejected() {
    for s in subjects() {
        let mut rows = chain(&[1]);
        rows.extend(chain_with(&[1], "genesis", "node-2", "u/1", |n| format!("evt-{n}")));
        let r = s.ingest(&rows);
        assert_eq!(got(&r), result(0, Some(1)), "{}", s.name);
        assert!(r.reason.as_deref().unwrap().contains("also in this batch"), "{r:?}");
        assert!(s.stored().is_empty(), "{}", s.name);
    }
}

#[test]
fn one_id_twice_on_one_node_in_a_batch_is_rejected() {
    for s in subjects() {
        let rows = chain_with(&[1, 2, 3], "genesis", "node-1", "u/1", |_| "evt-x".into());
        let r = s.ingest(&rows);
        assert_eq!(got(&r), result(0, Some(1)), "{}", s.name);
        assert!(s.stored().is_empty(), "{}", s.name);
    }
}

#[test]
fn a_row_sent_twice_in_a_batch_is_stored_once() {
    for s in subjects() {
        let rows = chain(&[1, 2, 3]);
        let batch = [rows[0].clone(), rows[1].clone(), rows[1].clone(), rows[2].clone()];
        assert_eq!(got(&s.ingest(&batch)), result(3, None), "{}", s.name);
        assert_eq!(s.seqs(), [1, 2, 3], "{}", s.name);
    }
}

/// An unsealed row at seq 1, then a sealed chain linked to genesis.
fn unsealed_head() -> Vec<ReplicatedRow> {
    let mut rows = vec![unsealed(1)];
    rows.extend(chain(&[2, 3]));
    rows
}

#[test]
fn an_unsealed_row_before_the_chain_is_not_inserted() {
    for s in subjects() {
        let rows = unsealed_head();
        let batch = [rows.clone(), vec![rows[2].clone()]].concat();
        assert_eq!(got(&s.ingest(&batch)), result(2, None), "{}", s.name);
        assert_eq!(s.seqs(), [2, 3], "{}", s.name);
    }
}

#[test]
fn an_unsealed_row_after_the_chain_starts_is_a_break() {
    for s in subjects() {
        let batch = [unsealed(1), chain(&[2])[0].clone(), unsealed(5)];
        let r = s.ingest(&batch);
        assert_eq!(got(&r), result(1, Some(5)), "{}", s.name);
        assert!(r.reason.as_deref().unwrap().contains("no hash after the node's chain started"), "{r:?}");
        assert_eq!(s.seqs(), [2], "{}", s.name);
    }
}

#[test]
fn an_unsealed_row_after_stored_rows_is_a_break() {
    for alone in [false, true] {
        for s in subjects() {
            s.ingest(&chain(&[1, 2, 3]));
            let mut batch = vec![unsealed(4)];
            if !alone {
                batch.extend(chain_with(&[5, 6], "genesis", "node-1", "u/1", |n| format!("evt-{n}")));
            }
            let r = s.ingest(&batch);
            assert_eq!(got(&r), result(0, Some(4)), "{}", s.name);
            assert_eq!(r.reason.as_deref(), Some("row evt-4: no hash after the node's chain started"));
            assert_eq!(s.seqs(), [1, 2, 3], "{}", s.name);
        }
    }
}

#[test]
fn a_row_after_a_stored_unsealed_row_links_to_genesis() {
    for s in subjects() {
        // An unsealed row at seq 1, stored as another writer stores it.
        let mut plain = crate::row_from_replicated(&unsealed(1)).unwrap();
        plain.hash = String::new();
        s.store.allocate_and_insert_originated(&plain).unwrap();
        let wrong = chain_with(&[2], "deadbeef", "node-1", "u/1", |n| format!("evt-{n}"));
        assert_eq!(s.ingest(&wrong).rejected_from_seq, Some(2), "{}", s.name);
        assert_eq!(got(&s.ingest(&chain(&[2]))), result(1, None), "{}", s.name);
    }
}

#[test]
fn a_form_1_row_without_a_form_id_is_stored_as_form_1() {
    let python = vector("python-sealed-forms.json")
        .into_iter()
        .find(|r| r.row.canonical_form_id == "1")
        .expect("a form-1 row");
    for form_id in ["", "1"] {
        for s in subjects() {
            let mut r = python.clone();
            r.row.canonical_form_id = form_id.to_string();
            assert_eq!(got(&s.ingest(&[r])), result(1, None), "{}", s.name);
            let back = (s.rows)();
            assert_eq!(back.iter().map(|r| r.canonical_form_id.as_str()).collect::<Vec<_>>(), ["1"]);
            assert!(verify_chain(&back).ok, "{}", s.name);
        }
    }
}

#[test]
fn rows_from_the_local_node_are_refused() {
    for s in subjects() {
        let r = s.store.ingest_replicated(&chain(&[1, 2]), Some("node-1")).unwrap();
        assert_eq!(got(&r), result(0, Some(1)), "{}", s.name);
        assert_eq!(r.reason.as_deref(), Some("row evt-1: source_node_id 'node-1' is this node"));

        // A mixed batch is cut at the lowest local seq; other nodes' rows from
        // there are left for the sender to resend.
        let mut batch = chain_with(&[1, 2, 3], "genesis", "node-2", "u/1", |n| format!("evt-{n}"));
        batch.push(ReplicatedRow::from(seal("genesis", &row(2, "evt-local", "node-1", "u/1"))));
        let r = s.store.ingest_replicated(&batch, Some("node-1")).unwrap();
        assert_eq!(got(&r), result(1, Some(2)), "{}", s.name);
        assert_eq!(r.reason.as_deref(), Some("row evt-local: source_node_id 'node-1' is this node"));
        assert_eq!(s.seqs(), [1], "{}", s.name);

        // An earlier break is still the one reported.
        let mut broken = chain_with(&[1, 2, 3], "genesis", "node-3", "u/1", |n| format!("n3-{n}"));
        broken[0].row.target = "tampered".into();
        broken.push(ReplicatedRow::from(seal("genesis", &row(3, "evt-local-3", "node-1", "u/1"))));
        let r = s.store.ingest_replicated(&broken, Some("node-1")).unwrap();
        assert_eq!(got(&r), result(0, Some(1)), "{}", s.name);
        assert!(r.reason.as_deref().unwrap().contains("hash mismatch"), "{r:?}");

        // An empty local node means no check.
        let own = chain_with(&[1], "genesis", "node-1", "u/1", |_| "own-1".into());
        assert_eq!(got(&s.store.ingest_replicated(&own, Some("")).unwrap()), result(1, None), "{}", s.name);
    }
}

// As in Python's ingest: the cut is at the lowest-seq local row, wherever
// the batch lists it, and a local row cuts the other nodes' rows at its seq.
#[test]
fn the_local_node_cut_is_at_its_lowest_seq_on_every_node() {
    for s in subjects() {
        let own = chain_with(&[1, 2, 3], "genesis", "agg", "u/1", |n| format!("agg-{n}"));
        let mut batch = chain_with(&[1, 2, 3], "genesis", "node-1", "u/1", |n| format!("n1-{n}"));
        batch.extend([own[2].clone(), own[1].clone()]);
        let r = s.store.ingest_replicated(&batch, Some("agg")).unwrap();
        assert_eq!(got(&r), result(1, Some(2)), "{}", s.name);
        assert!(r.reason.as_deref().unwrap().contains("agg-2"), "{r:?}");
        assert_eq!(s.stored().iter().map(|(_, id, _)| id.as_str()).collect::<Vec<_>>(), ["n1-1"], "{}", s.name);
    }
    for s in subjects() {
        let mut batch = chain_with(&[1, 2], "genesis", "node-1", "u/1", |n| format!("n1-{n}"));
        batch.extend(chain_with(&[1], "genesis", "agg", "u/1", |n| format!("agg-{n}")));
        let r = s.store.ingest_replicated(&batch, Some("agg")).unwrap();
        assert_eq!(got(&r), result(0, Some(1)), "{}", s.name);
        assert!(s.stored().is_empty(), "{}", s.name);
    }
}

#[test]
fn a_tampered_row_is_not_stored() {
    for s in subjects() {
        let mut rows = chain(&[1, 2, 3]);
        rows[1].row.detail = crate::Json::parse(r#"{"k":"changed","n":1.50}"#).unwrap();
        let r = s.ingest(&rows);
        assert_eq!(got(&r), result(1, Some(2)), "{}", s.name);
        assert_eq!(r.reason.as_deref(), Some("row evt-2: detail does not match its commitment"));
        assert_eq!(s.seqs(), [1], "{}", s.name);
    }
}

// A failed insert part-way leaves nothing of the batch stored: here the
// last row's seq is past what the column holds.
#[test]
fn an_insert_error_part_way_stores_nothing() {
    for s in subjects() {
        let mut batch = chain(&[1, 2]);
        batch.extend(chain_with(&[1u64 << 63], "genesis", "node-2", "u/1", |_| "evt-huge".into()));
        let err = s.store.ingest_replicated(&batch, None).unwrap_err();
        assert!(matches!(err, crate::Error::AuditStoreRejected(_)), "{}: {err:?}", s.name);
        assert!(s.stored().is_empty(), "{}", s.name);
        assert_eq!(got(&s.ingest(&batch[..2])), result(2, None), "{}", s.name);
    }
}

// The Python and Go stores cannot read a row whose timestamp does not
// canonicalise, so the whole batch is refused and nothing is stored.
#[test]
fn a_timestamp_the_other_stores_cannot_read_refuses_the_batch() {
    for bad in ["0000-06-15T10:30:01Z", "2026-06-15T10:30:01+24:00", "9999-12-31T23:59:59-00:01", "June"] {
        for s in subjects() {
            let mut batch = chain(&[1, 2]);
            let mut r = row(3, "evt-3", "node-1", "u/1");
            r.timestamp = bad.to_string();
            batch.push(ReplicatedRow::from(seal(&batch[1].row.hash, &r)));
            let err = s.store.ingest_replicated(&batch, None).unwrap_err();
            assert!(matches!(&err, crate::Error::AuditStoreRejected(m) if m.contains("rows[2]")), "{err:?}");
            assert!(!err.to_string().contains(bad), "{err}");
            assert!(s.stored().is_empty(), "{}", s.name);
        }
    }
}

// shipped_at is not hashed, but the other stores read it back too.
#[test]
fn a_shipped_at_the_other_stores_cannot_read_refuses_the_batch() {
    for s in subjects() {
        let mut batch = chain(&[1, 2]);
        batch[1].row.shipped_at = Some("0000-06-15T10:30:01Z".into());
        let err = s.store.ingest_replicated(&batch, None).unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, crate::Error::AuditStoreRejected(_)), "{}: {text}", s.name);
        assert!(text.contains("rows[1]") && text.contains("shipped_at"), "{text}");
        assert!(s.stored().is_empty(), "{}", s.name);
    }
}

#[test]
fn an_offset_shipped_at_is_stored_in_the_wire_form() {
    for s in subjects() {
        let mut batch = chain(&[1]);
        batch[0].row.shipped_at = Some("2026-06-15T16:00:01.5+05:30".into());
        assert_eq!(got(&s.ingest(&batch)), result(1, None), "{}", s.name);
        let back = (s.rows)();
        assert_eq!(back[0].shipped_at.as_deref(), Some("2026-06-15T10:30:01.500000Z"), "{}", s.name);
        assert!(verify_chain(&back).ok, "{}", s.name);
    }
}

// A timestamp with an offset is stored in the wire form, and still verifies.
#[test]
fn an_offset_timestamp_is_stored_in_the_wire_form() {
    for s in subjects() {
        let mut r = row(1, "evt-1", "node-1", "u/1");
        r.timestamp = "2026-06-15T16:00:01.5+05:30".into();
        let sealed = ReplicatedRow::from(seal("genesis", &r));
        assert_eq!(got(&s.ingest(&[sealed])), result(1, None), "{}", s.name);
        let back = (s.rows)();
        assert_eq!(back[0].timestamp, "2026-06-15T10:30:01.500000Z", "{}", s.name);
        assert!(verify_chain(&back).ok, "{}", s.name);
    }
}

/// Two threads ingest the same batches spanning nodes a and b, listing the
/// nodes in opposite orders, while two threads allocate rows on a local
/// node, each pair on its own store handle. Every call succeeds, nothing is
/// refused, and every chain verifies.
fn ingest_and_allocate_concurrently(name: &str, stores: [Arc<dyn AuditStore>; 2], rows: &dyn Fn() -> Vec<ChainRow>) {
    const SEQS: u64 = 24;
    const CHUNK: usize = 4;
    const LOCAL: usize = 15;
    let seqs: Vec<u64> = (1..=SEQS).collect();
    let a = chain_with(&seqs, "genesis", "node-a", "u/1", |n| format!("ca-{n}"));
    let b = chain_with(&seqs, "genesis", "node-b", "u/1", |n| format!("cb-{n}"));
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for (i, store) in stores.iter().enumerate() {
            let (a, b) = (&a, &b);
            handles.push(scope.spawn(move || {
                for (ca, cb) in a.chunks(CHUNK).zip(b.chunks(CHUNK)) {
                    let batch = if i == 0 { [ca, cb].concat() } else { [cb, ca].concat() };
                    let r = store.ingest_replicated(&batch, None).unwrap();
                    assert_eq!((r.inserted, r.rejected_from_seq), (batch.len(), None), "{:?}", r.reason);
                }
            }));
            handles.push(scope.spawn(move || {
                for n in 0..LOCAL {
                    let mut r = crate::row_from_replicated(&unsealed(1)).unwrap();
                    r.id = format!("local-{i}-{n}");
                    r.origin_id.clone_from(&r.id);
                    r.source_node_id = "local".into();
                    r.monotonic_seq = 0;
                    r.hash = String::new();
                    r.prev_hash = String::new();
                    let stored = store.allocate_and_insert_originated(&r).unwrap();
                    assert!(!stored.hash.is_empty());
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    });
    let back = rows();
    assert_eq!(back.len(), 2 * SEQS as usize + 2 * LOCAL, "{name}");
    let v = verify_chain(&back);
    assert!(v.ok, "{name}: {v:?}");
    for node in ["node-a", "node-b", "local"] {
        let seqs: Vec<u64> = back.iter().filter(|r| r.source_node_id == node).map(|r| r.monotonic_seq).collect();
        let want = if node == "local" { 2 * LOCAL as u64 } else { SEQS };
        assert_eq!(seqs, (1..=want).collect::<Vec<_>>(), "{name} {node}");
    }
}

#[test]
fn concurrent_ingests_and_allocations_on_one_sqlite_file() {
    let dir = std::env::temp_dir().join(format!("fasten-conc-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit.db");
    let path = path.to_str().unwrap();
    let one = Arc::new(crate::SqliteStore::open(path, "audit_log").unwrap());
    let two = Arc::new(crate::SqliteStore::open(path, "audit_log").unwrap());
    let reader = one.clone();
    ingest_and_allocate_concurrently("SqliteStore", [one, two], &|| reader.all_chain_rows().unwrap());
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(feature = "store-postgres")]
#[test]
fn concurrent_ingests_and_allocations_on_one_postgres_table() {
    let Some(dsn) = pg::dsn() else { return };
    let table = pg::table("conc");
    let _drop = pg::DropTable(dsn.clone(), table.clone());
    let one = Arc::new(crate::PostgresStore::new(&dsn, table.clone()).unwrap());
    let two = Arc::new(crate::PostgresStore::new(&dsn, table.clone()).unwrap());
    let reader = one.clone();
    ingest_and_allocate_concurrently("PostgresStore", [one, two], &|| reader.all_chain_rows().unwrap());
}

// list_unshipped reads rows as `Row`s: a detail that is not an object is an
// error, not an empty detail; a redacted (null) one reads as empty.
#[test]
fn list_unshipped_refuses_a_row_it_cannot_hold() {
    let store = crate::SqliteStore::open(":memory:", "audit_log").unwrap();
    let mut r = row(1, "evt-arr", "node-1", "u/1");
    r.detail = crate::Json::parse("[1,2]").unwrap();
    store.insert_replicated(&ReplicatedRow::from(seal("genesis", &r))).unwrap();
    let err = store.list_unshipped(0, None).unwrap_err();
    assert!(matches!(&err, crate::Error::AuditStoreRead(m) if m.contains("evt-arr") && m.contains("detail")), "{err:?}");

    let store = crate::SqliteStore::open(":memory:", "audit_log").unwrap();
    let mut r = row(1, "evt-null", "node-1", "u/1");
    r.detail = crate::Json::Null;
    store.insert_replicated(&ReplicatedRow::from(seal("genesis", &r))).unwrap();
    let rows = store.list_unshipped(0, None).unwrap();
    assert!(rows[0].detail.is_empty());
}

#[cfg(feature = "store-postgres")]
#[test]
fn postgres_list_unshipped_refuses_a_row_it_cannot_hold() {
    let Some(dsn) = pg::dsn() else { return };
    let table = pg::table("unshipped");
    let _drop = pg::DropTable(dsn.clone(), table.clone());
    let store = crate::PostgresStore::new(&dsn, table.clone()).unwrap();
    let mut r = row(1, "evt-arr", "node-1", "u/1");
    r.detail = crate::Json::parse("[1,2]").unwrap();
    let arr = seal("genesis", &r);
    let mut r = row(2, "evt-null", "node-1", "u/1");
    r.detail = crate::Json::Null;
    let null = seal(&arr.hash, &r);
    store.insert_replicated(&ReplicatedRow::from(arr)).unwrap();
    let err = store.list_unshipped(1, None).unwrap_err();
    assert!(matches!(&err, crate::Error::AuditStoreRead(m) if m.contains("evt-arr") && m.contains("detail")), "{err:?}");
    store.insert_replicated(&ReplicatedRow::from(null)).unwrap();
    store.mark_shipped(&["evt-arr".to_string()]).unwrap();
    let rows = store.list_unshipped(0, None).unwrap();
    assert!(rows[0].detail.is_empty());
}

/// The rows of a vector file in spec/.
pub(crate) fn vector(file: &str) -> Vec<ReplicatedRow> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec").join(file);
    let parsed = crate::Json::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
    let rows: Vec<crate::Json> = match parsed.get("cases") {
        Some(cases) => cases.as_array().unwrap().iter().map(|c| c.get("row").unwrap().clone()).collect(),
        None => parsed.as_array().unwrap().to_vec(),
    };
    rows.iter().map(|r| ReplicatedRow::from_value(r).unwrap()).collect()
}

// The sealed rows of each SDK's vector file are stored as they were sealed:
// they verify, keep their hashes, and the detail reads back with the
// sender's number tokens. Python's file holds one row per case, so each is
// a batch of its own.
#[test]
fn rows_every_sdk_sealed_are_ingested_as_they_were_sealed() {
    let mut batches: Vec<Vec<ReplicatedRow>> = vector("python-sealed-forms.json").into_iter().map(|r| vec![r]).collect();
    for file in ["go-sealed-form2.json", "js-sealed-form2.json", "rust-sealed-form2.json"] {
        batches.push(vector(file));
    }
    for batch in &batches {
        for s in subjects() {
            let r = s.ingest(batch);
            assert_eq!(got(&r), result(batch.len(), None), "{}: {:?}", s.name, r.reason);
            let back = (s.rows)();
            let v = verify_chain(&back);
            assert!(v.ok && v.sealed_rows == batch.len(), "{}: {v:?}", s.name);
            for sent in batch {
                let stored = back.iter().find(|b| b.id == sent.row.id).unwrap();
                assert_eq!(stored.hash, sent.row.hash);
                assert_eq!(stored.detail, sent.row.detail, "{}", sent.row.id);
                assert_eq!(stored.detail.to_string(), sent.row.detail.to_string());
            }
        }
    }
}

// On Postgres the detail column holds the sender's detail text.
#[cfg(feature = "store-postgres")]
#[test]
fn postgres_stores_the_detail_text_as_sent() {
    let Some(dsn) = pg::dsn() else { return };
    for file in ["go-sealed-form2.json", "js-sealed-form2.json", "rust-sealed-form2.json"] {
        let table = pg::table("vector");
        let _drop = pg::DropTable(dsn.clone(), table.clone());
        let store = crate::PostgresStore::new(&dsn, table.clone()).unwrap();
        let rows = vector(file);
        assert_eq!(store.ingest_replicated(&rows, None).unwrap().inserted, rows.len());
        let raw = pg::raw_details(&dsn, &table);
        for r in &rows {
            assert_eq!(raw[&r.row.id], r.row.detail.to_string(), "{file} {}", r.row.id);
        }
    }
}

// The replicated insert stores one row as it was sealed, flag included,
// and refuses an unsealed row or a different row under a stored id.
#[test]
fn insert_replicated_stores_a_row_as_it_was_sealed() {
    for s in subjects() {
        let mut rows = chain(&[1, 2]);
        rows[0].pii_in_detail = true;
        for r in &rows {
            s.store.insert_replicated(r).unwrap();
            s.store.insert_replicated(r).unwrap();
        }
        let listed = s.store.list_unshipped_sealed(0, None).unwrap();
        assert_eq!(listed, rows, "{}", s.name);
        assert!(s.store.insert_replicated(&unsealed(3)).is_err(), "{}", s.name);
        let mut other = rows[1].clone();
        other.row.hash = "ab".repeat(32);
        let err = s.store.insert_replicated(&other).unwrap_err();
        assert!(matches!(err, crate::Error::AuditStoreRejected(_)), "{}: {err:?}", s.name);
    }
}

fn register_code(code: &str) {
    let meta = crate::Meta { domain: "repl".into(), ..Default::default() };
    let _ = crate::register("repl".into(), [(code.to_string(), meta)]);
}

fn engine(service: &str, node: &str, store: Arc<dyn AuditStore>) -> crate::Engine {
    let e = crate::Engine::new();
    e.init_with_env(
        crate::Config {
            service_id: service.into(),
            node_id: node.into(),
            audit_store: Some(store),
            audit_store_failure_strategy: Some("raise".into()),
            ..Default::default()
        },
        &[],
    )
    .unwrap();
    e
}

// The engine ships only the rows it originated: not rows it ingested, nor
// rows another service or node wrote to the same table. What it ships is
// ingested by another node and verifies there; shipped rows are not listed
// again.
#[test]
fn the_engine_ships_what_it_originated_and_another_node_ingests_it() {
    register_code("REPL_SHIP");
    for s in subjects() {
        let e = engine("svc-a", "node-a", s.store.clone());
        for _ in 0..3 {
            crate::EmitBuilder::new("REPL_SHIP", "t").submit_to(&e).unwrap();
        }
        let other = engine("svc-b", "node-b", s.store.clone());
        crate::EmitBuilder::new("REPL_SHIP", "t").submit_to(&other).unwrap();
        // Rows from a third node, ingested here.
        let foreign = chain_with(&[1, 2], "genesis", "node-c", "u/1", |n| format!("c-{n}"));
        assert_eq!(e.ingest_replicated(&foreign).unwrap().inserted, 2);

        let ship = e.list_unshipped(0).unwrap();
        assert_eq!(ship.len(), 3, "{}", s.name);
        assert!(ship.iter().all(|r| r.row.source_node_id == "node-a" && r.row.origin_id == r.row.id));
        assert_eq!(e.list_unshipped(2).unwrap().len(), 2);

        // Over the wire, as JSON lines, to an aggregator.
        let lines: Vec<String> = ship.iter().map(ReplicatedRow::to_json).collect();
        let received: Vec<ReplicatedRow> = lines.iter().map(|l| ReplicatedRow::from_json(l).unwrap()).collect();
        let aggregator = sqlite();
        assert_eq!(got(&aggregator.ingest(&received)), result(3, None));
        let v = verify_chain(&(aggregator.rows)());
        assert!(v.ok && v.sealed_rows == 3, "{v:?}");

        let ids: Vec<String> = ship.iter().map(|r| r.row.id.clone()).collect();
        e.mark_shipped(&ids).unwrap();
        assert!(e.list_unshipped(0).unwrap().is_empty(), "{}", s.name);
        // The node's own rows are refused by its own ingest.
        let r = e.ingest_replicated(&received).unwrap();
        assert_eq!(r.rejected_from_seq, Some(1), "{}", s.name);
        // Unscoped, the store lists every unshipped row.
        assert_eq!(s.store.list_unshipped_sealed(0, None).unwrap().len(), 3, "{}", s.name);
    }
}

#[test]
fn replication_needs_an_audit_store() {
    let e = crate::Engine::new();
    assert!(matches!(e.list_unshipped(0), Err(crate::Error::NotInitialised)));
    e.init_with_env(crate::Config { service_id: "s".into(), node_id: "n".into(), ..Default::default() }, &[])
        .unwrap();
    assert!(matches!(e.ingest_replicated(&[]), Err(crate::Error::Unsupported(m)) if m.contains("FASTEN_AUDIT_DSN")));
    assert!(matches!(e.mark_shipped(&[]), Err(crate::Error::Unsupported(_))));
}

// Manual purge removes a seq prefix per node, so what is left verifies;
// checkpoints published after the purge verify it as a whole chain.
#[test]
fn a_purged_chain_still_verifies() {
    let dir = std::env::temp_dir().join(format!("fasten-purge-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    for (i, s) in subjects().into_iter().enumerate() {
        let at = |day: u32| -> crate::Row {
            let mut r = crate::row_from_replicated(&unsealed(1)).unwrap();
            r.id = format!("p{i}-{day}");
            r.origin_id.clone_from(&r.id);
            r.monotonic_seq = 0;
            r.hash = String::new();
            r.prev_hash = String::new();
            r.timestamp = format!("2020-01-{day:02}T00:00:00Z").parse().unwrap();
            r
        };
        for day in 1..=2 {
            s.store.allocate_and_insert_originated(&at(day)).unwrap();
        }
        let sink = FileCheckpointSink::new(dir.join(format!("cp-{i}.jsonl")));
        let tips = TipsOf(&s.rows);
        publish_checkpoints(&tips, &sink).unwrap();
        for day in 3..=5 {
            s.store.allocate_and_insert_originated(&at(day)).unwrap();
        }

        // Unshipped rows are kept with respect_unshipped.
        let before = "2020-01-03T00:00:00Z".parse().unwrap();
        assert_eq!(s.store.purge(before, true).unwrap(), 0, "{}", s.name);
        assert_eq!(s.store.purge(before, false).unwrap(), 2, "{}", s.name);
        let purged_at = chrono::Utc::now();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let left = (s.rows)();
        assert_eq!(left.iter().map(|r| r.monotonic_seq).collect::<Vec<_>>(), [3, 4, 5], "{}", s.name);
        assert!(verify_chain(&left).ok, "{}", s.name);

        // The checkpoint taken before the purge names a purged row.
        let whole = CheckpointOptions::whole();
        let all = crate::load_checkpoints(sink.path()).unwrap();
        assert!(!verify_chain_with_checkpoints(&left, &all, whole).ok, "{}", s.name);
        publish_checkpoints(&tips, &sink).unwrap();
        let all = crate::load_checkpoints(sink.path()).unwrap();
        let since = checkpoints_since(&all, purged_at).unwrap();
        assert_eq!(since.len(), 1, "{}", s.name);
        assert!(verify_chain_with_checkpoints(&left, &since, whole).ok, "{}", s.name);

        // A new row still extends the chain after the purge.
        s.store.allocate_and_insert_originated(&at(6)).unwrap();
        assert!(verify_chain(&(s.rows)()).ok, "{}", s.name);
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Chain tips from the rows a subject reads back, for the checkpoint sink.
struct TipsOf<'a>(&'a dyn Fn() -> Vec<ChainRow>);

impl crate::checkpoints::CheckpointStore for TipsOf<'_> {
    fn chain_tips(&self) -> Result<Vec<crate::ChainTip>, crate::Error> {
        let mut tips: Vec<crate::ChainTip> = Vec::new();
        for r in (self.0)().into_iter().filter(|r| !r.hash.is_empty()) {
            tips.retain(|t| t.source_node_id != r.source_node_id || t.monotonic_seq > r.monotonic_seq);
            if !tips.iter().any(|t| t.source_node_id == r.source_node_id) {
                tips.push(crate::ChainTip {
                    source_node_id: r.source_node_id.clone(),
                    monotonic_seq: r.monotonic_seq,
                    hash: r.hash.clone(),
                });
            }
        }
        tips.sort_by(|a, b| a.source_node_id.cmp(&b.source_node_id));
        Ok(tips)
    }
}

// The engine never purges audit rows (spec §7): the drainer's store adapter
// deletes nothing, and the PII purger only redacts.
#[test]
fn the_engine_never_purges_audit_rows() {
    use fasten_core::store::Store as _;
    struct Counting(std::sync::atomic::AtomicUsize);
    impl AuditStore for Counting {
        fn insert(&self, _: &crate::Row) -> Result<(), crate::Error> {
            Ok(())
        }
        fn purge(&self, _: chrono::DateTime<chrono::Utc>, _: bool) -> Result<u64, crate::Error> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(0)
        }
    }
    let store = Arc::new(Counting(std::sync::atomic::AtomicUsize::new(0)));
    let adapter = crate::engine::adapter_for_tests(store.clone());
    assert_eq!(adapter.purge("2999-01-01", false).unwrap(), 0);
    assert_eq!(store.0.load(std::sync::atomic::Ordering::SeqCst), 0);
}
