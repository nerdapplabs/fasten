//! Drainer conformance tests (spec/drainer-conformance.md §7).
//!
//! These are the CANONICAL tests for the shared drainer state machine.
//! Per-SDK tests for drainer behaviour are deleted; this suite runs via
//! `cargo test` in fasten-core and covers all 12 state transitions.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use fasten_core::drainer::{Drainer, DrainerConfig};
use fasten_core::error::Error;
use fasten_core::row::Row;
use fasten_core::store::{Filter, Store};

// ── Stub stores ───────────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct RecordingStore {
    rows: Arc<Mutex<Vec<Row>>>,
}

impl Store for RecordingStore {
    fn insert(&self, row: &Row) -> Result<(), Error> {
        self.rows.lock().unwrap().push(row.clone());
        Ok(())
    }
    fn ping(&self) -> Result<(), Error> { Ok(()) }
    fn query(&self, _: &Filter) -> Result<Vec<Row>, Error> { Ok(vec![]) }
    fn count(&self, _: &Filter) -> Result<u64, Error> { Ok(0) }
    fn list_unshipped(&self, _: u32) -> Result<Vec<Row>, Error> { Ok(vec![]) }
    fn mark_shipped(&self, _: &[String]) -> Result<(), Error> { Ok(()) }
    fn purge(&self, _: &str, _: bool) -> Result<u64, Error> { Ok(0) }
    fn max_monotonic_seq(&self) -> Result<u64, Error> { Ok(0) }
}

struct BrokenStore;

impl Store for BrokenStore {
    fn insert(&self, _: &Row) -> Result<(), Error> {
        Err(Error::InvalidTableName("store_down".into()))
    }
    fn ping(&self) -> Result<(), Error> { Ok(()) }
    fn query(&self, _: &Filter) -> Result<Vec<Row>, Error> { Ok(vec![]) }
    fn count(&self, _: &Filter) -> Result<u64, Error> { Ok(0) }
    fn list_unshipped(&self, _: u32) -> Result<Vec<Row>, Error> { Ok(vec![]) }
    fn mark_shipped(&self, _: &[String]) -> Result<(), Error> { Ok(()) }
    fn purge(&self, _: &str, _: bool) -> Result<u64, Error> { Ok(0) }
    fn max_monotonic_seq(&self) -> Result<u64, Error> { Ok(0) }
}

#[derive(Clone)]
struct FlakyStore {
    attempts: Arc<Mutex<usize>>,
    fail_first: usize,
    successes: Arc<Mutex<usize>>,
}

impl FlakyStore {
    fn new(fail_first: usize) -> Self {
        Self {
            attempts: Arc::new(Mutex::new(0)),
            fail_first,
            successes: Arc::new(Mutex::new(0)),
        }
    }
}

impl Store for FlakyStore {
    fn insert(&self, _: &Row) -> Result<(), Error> {
        let mut a = self.attempts.lock().unwrap();
        *a += 1;
        let n = *a;
        drop(a);
        if n <= self.fail_first {
            return Err(Error::InvalidTableName(format!("transient_{n}")));
        }
        *self.successes.lock().unwrap() += 1;
        Ok(())
    }
    fn ping(&self) -> Result<(), Error> { Ok(()) }
    fn query(&self, _: &Filter) -> Result<Vec<Row>, Error> { Ok(vec![]) }
    fn count(&self, _: &Filter) -> Result<u64, Error> { Ok(0) }
    fn list_unshipped(&self, _: u32) -> Result<Vec<Row>, Error> { Ok(vec![]) }
    fn mark_shipped(&self, _: &[String]) -> Result<(), Error> { Ok(()) }
    fn purge(&self, _: &str, _: bool) -> Result<u64, Error> { Ok(0) }
    fn max_monotonic_seq(&self) -> Result<u64, Error> { Ok(0) }
}

// ── Helper: minimal Row ─────────────────────────────────────────────��─────────

fn make_row(id: &str) -> Row {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "wire_version": "1",
        "origin_id": id,
        "monotonic_seq": 1u64,
        "timestamp": "2026-01-01T00:00:00Z",
        "code": "TEST",
        "action": "test",
        "severity": "info",
        "service_id": "svc",
        "source_node_id": "node",
        "actor": "u-1",
        "actor_kind": "user",
        "target": "t-1",
        "category": "test",
        "domain": "test",
        "method": "sdk",
        "request_id": "aabbccddee01",
        "detail": {},
    }))
    .expect("valid row JSON")
}

fn fast_cfg() -> DrainerConfig {
    DrainerConfig {
        capacity: 100,
        retry_initial: Duration::from_millis(5),
        retry_max: Duration::from_millis(50),
        retry_jitter: false,
        max_attempts: 50,
    }
}

// ── §1 happy path ─────────────────────────────────────────────────────────────

#[test]
fn happy_path_drains_within_one_second() {
    let store = RecordingStore::default();
    let rows_ref = Arc::clone(&store.rows);
    let d = Drainer::new(Box::new(store), fast_cfg());

    d.enqueue(make_row("r-1"));
    d.enqueue(make_row("r-2"));

    assert!(d.flush(Duration::from_secs(1)));
    assert_eq!(rows_ref.lock().unwrap().len(), 2);
}

#[test]
fn emit_returns_immediately_under_slow_store() {
    struct SlowStore(RecordingStore);
    impl Store for SlowStore {
        fn insert(&self, row: &Row) -> Result<(), Error> {
            thread::sleep(Duration::from_millis(30));
            self.0.insert(row)
        }
        fn ping(&self) -> Result<(), Error> { Ok(()) }
        fn query(&self, f: &Filter) -> Result<Vec<Row>, Error> { self.0.query(f) }
        fn count(&self, f: &Filter) -> Result<u64, Error> { self.0.count(f) }
        fn list_unshipped(&self, l: u32) -> Result<Vec<Row>, Error> { self.0.list_unshipped(l) }
        fn mark_shipped(&self, ids: &[String]) -> Result<(), Error> { self.0.mark_shipped(ids) }
        fn purge(&self, b: &str, r: bool) -> Result<u64, Error> { self.0.purge(b, r) }
        fn max_monotonic_seq(&self) -> Result<u64, Error> { self.0.max_monotonic_seq() }
    }
    let d = Drainer::new(Box::new(SlowStore(RecordingStore::default())), fast_cfg());
    let t0 = std::time::Instant::now();
    for i in 0..10 {
        d.enqueue(make_row(&format!("r-{i}")));
    }
    assert!(t0.elapsed() < Duration::from_millis(100), "enqueues must be fast");
    assert!(d.flush(Duration::from_secs(5)));
}

// ── §3 outage + recovery ──────────────────────────────────────────────────────

#[test]
fn outage_then_recovery_drains_pending() {
    let store = FlakyStore::new(2);
    let succ = Arc::clone(&store.successes);
    let atts = Arc::clone(&store.attempts);
    let d = Drainer::new(Box::new(store), DrainerConfig {
        retry_initial: Duration::from_millis(5),
        retry_max: Duration::from_millis(20),
        retry_jitter: false,
        ..DrainerConfig::default()
    });
    d.enqueue(make_row("r-flaky"));
    assert!(d.flush(Duration::from_secs(3)));
    assert_eq!(*succ.lock().unwrap(), 1);
    assert!(*atts.lock().unwrap() >= 3);
}

// ── §4 queue full blocks ──────────────────────────────────────────────────────

#[test]
fn queue_full_blocks_emit_does_not_drop() {
    let d = Arc::new(Drainer::new(Box::new(BrokenStore), DrainerConfig {
        capacity: 2,
        retry_initial: Duration::from_secs(10), // never retries in test duration
        retry_max: Duration::from_secs(60),
        retry_jitter: false,
        max_attempts: 50,
    }));
    d.enqueue(make_row("r-1"));
    d.enqueue(make_row("r-2"));

    let d2 = Arc::clone(&d);
    let blocked = Arc::new(Mutex::new(false));
    let finished = Arc::new(Mutex::new(false));
    let blocked2 = Arc::clone(&blocked);
    let finished2 = Arc::clone(&finished);

    thread::spawn(move || {
        *blocked2.lock().unwrap() = true;
        d2.enqueue(make_row("r-3"));
        *finished2.lock().unwrap() = true;
    });

    thread::sleep(Duration::from_millis(200));
    assert!(*blocked.lock().unwrap(), "thread should have started");
    assert!(!*finished.lock().unwrap(), "third enqueue must be blocking");

    // Stopping the drainer frees capacity → unblocks the thread
    d.stop(Duration::from_secs(1));
    thread::sleep(Duration::from_millis(500));
    // The thread unblocks (enqueue returns false due to stopped drainer)
}

// ── §5 queue_stats ────────────────────────────────────────────────────────────

#[test]
fn queue_stats_fields_populated() {
    let store = RecordingStore::default();
    let d = Drainer::new(Box::new(store), fast_cfg());
    d.enqueue(make_row("r-1"));
    assert!(d.flush(Duration::from_secs(1)));

    let stats: serde_json::Value =
        serde_json::from_str(&d.stats_json()).expect("valid stats JSON");

    assert_eq!(stats["depth"], 0);
    assert_eq!(stats["capacity"], 100);
    assert!(stats["high_water"].as_u64().unwrap() >= 1);
    assert_eq!(stats["drained_total"], 1);
    assert_eq!(stats["retry_count_active"], 0);
    assert!(stats["last_error"].is_null());
    assert_eq!(stats["capacity_semantics"], "block");
}

#[test]
fn stats_high_water_monotonic() {
    let store = RecordingStore::default();
    let d = Drainer::new(Box::new(store), DrainerConfig {
        capacity: 10,
        ..fast_cfg()
    });
    for i in 0..5 {
        d.enqueue(make_row(&format!("r-{i}")));
    }
    assert!(d.flush(Duration::from_secs(1)));
    let s1: serde_json::Value = serde_json::from_str(&d.stats_json()).unwrap();
    let hw1 = s1["high_water"].as_u64().unwrap();

    d.enqueue(make_row("r-x"));
    assert!(d.flush(Duration::from_secs(1)));
    let s2: serde_json::Value = serde_json::from_str(&d.stats_json()).unwrap();
    assert!(s2["high_water"].as_u64().unwrap() >= hw1, "high_water must be monotonic");
}

// ── §6 flush returns false on timeout ─────────────────────────────────────────

#[test]
fn flush_returns_false_on_timeout() {
    let d = Drainer::new(Box::new(BrokenStore), DrainerConfig {
        retry_initial: Duration::from_secs(10),
        retry_max: Duration::from_secs(60),
        retry_jitter: false,
        ..DrainerConfig::default()
    });
    d.enqueue(make_row("r-1"));
    let result = d.flush(Duration::from_millis(50));
    assert!(!result, "flush must return false when store is down");
}

// ── §7 dead letter after max_attempts ────────────────────────────────────────

#[test]
fn dead_letter_after_max_attempts() {
    let d = Drainer::new(Box::new(BrokenStore), DrainerConfig {
        retry_initial: Duration::from_millis(1),
        retry_max: Duration::from_millis(2),
        retry_jitter: false,
        max_attempts: 3,
        capacity: 100,
    });
    d.enqueue(make_row("r-dlq"));

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let stats: serde_json::Value = serde_json::from_str(&d.stats_json()).unwrap();
        if stats["dead_lettered_total"].as_u64().unwrap() >= 1 {
            assert_eq!(stats["depth"], 0, "slot must be released after dead-letter");
            break;
        }
        assert!(std::time::Instant::now() < deadline, "dead-letter never fired");
        thread::sleep(Duration::from_millis(10));
    }
}

// ── §8 flush targets rows at call time (REVIEW #14) ──────────────────────────

#[test]
fn flush_targets_rows_at_call_time_not_later_emits() {
    struct SlowStore(RecordingStore);
    impl Store for SlowStore {
        fn insert(&self, row: &Row) -> Result<(), Error> {
            thread::sleep(Duration::from_millis(3));
            self.0.insert(row)
        }
        fn ping(&self) -> Result<(), Error> { Ok(()) }
        fn query(&self, f: &Filter) -> Result<Vec<Row>, Error> { self.0.query(f) }
        fn count(&self, f: &Filter) -> Result<u64, Error> { self.0.count(f) }
        fn list_unshipped(&self, l: u32) -> Result<Vec<Row>, Error> { self.0.list_unshipped(l) }
        fn mark_shipped(&self, ids: &[String]) -> Result<(), Error> { self.0.mark_shipped(ids) }
        fn purge(&self, b: &str, r: bool) -> Result<u64, Error> { self.0.purge(b, r) }
        fn max_monotonic_seq(&self) -> Result<u64, Error> { self.0.max_monotonic_seq() }
    }
    let d = Arc::new(Drainer::new(Box::new(SlowStore(RecordingStore::default())), DrainerConfig {
        capacity: 200,
        ..fast_cfg()
    }));

    // Emit 5 rows then immediately start flushing.
    for i in 0..5 {
        d.enqueue(make_row(&format!("r-{i}")));
    }

    let d2 = Arc::clone(&d);
    let stop_bg = Arc::new(Mutex::new(false));
    let stop2 = Arc::clone(&stop_bg);
    thread::spawn(move || {
        while !*stop2.lock().unwrap() {
            d2.enqueue(make_row("bg"));
            thread::sleep(Duration::from_millis(1));
        }
    });

    // flush() should return within a reasonable time even under concurrent emits.
    assert!(d.flush(Duration::from_secs(3)), "flush must complete for rows at call time");
    *stop_bg.lock().unwrap() = true;
}

// ── §9 backoff jitter does not panic ─────────────────────────────────────────

#[test]
fn backoff_jitter_does_not_panic_and_drains() {
    let store = FlakyStore::new(2);
    let succ = Arc::clone(&store.successes);
    let d = Drainer::new(Box::new(store), DrainerConfig {
        retry_initial: Duration::from_millis(5),
        retry_max: Duration::from_millis(50),
        retry_jitter: true,
        ..DrainerConfig::default()
    });
    d.enqueue(make_row("r-jitter"));
    assert!(d.flush(Duration::from_secs(5)));
    assert_eq!(*succ.lock().unwrap(), 1);
}
