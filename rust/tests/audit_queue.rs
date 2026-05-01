//! P1-15 cross-language: same wire/API semantics as Python's
//! tests/test_audit_queue.py — happy path, slow store, outage+recovery,
//! queue full blocks, raise mode, sys self-report (via stdout capture
//! is hard in Rust — we assert stats instead), queue_stats, flush.
//!
//! Tests run serially (`#[serial]` via a process-level mutex) because
//! they share the `init` global config + drainer.

use fasten::{
    audit_queue, init, AuditStore, AuditStoreError, Config, EmitBuilder, Error, Meta,
    Row, Severity, RetentionClass, flush, queue_stats,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Process-level test mutex — serialise tests that touch globals.
static TEST_MU: Mutex<()> = Mutex::new(());

// ── Stub stores ────────────────────────────────────────────────────────────

struct RecordingStore {
    rows: Mutex<Vec<Row>>,
}
impl RecordingStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            rows: Mutex::new(Vec::new()),
        })
    }
    fn count(&self) -> usize {
        self.rows.lock().unwrap().len()
    }
}
impl AuditStore for RecordingStore {
    fn insert(&self, row: &Row) -> Result<(), Error> {
        self.rows.lock().unwrap().push(row.clone());
        Ok(())
    }
}

struct SlowStore {
    inner: RecordingStore,
    delay: Duration,
}
impl SlowStore {
    fn new(delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            inner: RecordingStore {
                rows: Mutex::new(Vec::new()),
            },
            delay,
        })
    }
    fn count(&self) -> usize {
        self.inner.count()
    }
}
impl AuditStore for SlowStore {
    fn insert(&self, row: &Row) -> Result<(), Error> {
        std::thread::sleep(self.delay);
        self.inner.insert(row)
    }
}

struct BrokenStore {
    attempts: AtomicUsize,
    msg: String,
}
impl BrokenStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            attempts: AtomicUsize::new(0),
            msg: "store down".into(),
        })
    }
}
impl AuditStore for BrokenStore {
    fn insert(&self, _row: &Row) -> Result<(), Error> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(Error::AuditStoreInsert(self.msg.clone()))
    }
}

struct FlakyStore {
    attempts: AtomicUsize,
    success: AtomicUsize,
    fail_first: usize,
}
impl FlakyStore {
    fn new(fail_first: usize) -> Arc<Self> {
        Arc::new(Self {
            attempts: AtomicUsize::new(0),
            success: AtomicUsize::new(0),
            fail_first,
        })
    }
}
impl AuditStore for FlakyStore {
    fn insert(&self, _row: &Row) -> Result<(), Error> {
        let n = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
        if n <= self.fail_first {
            Err(Error::AuditStoreInsert(format!("transient #{}", n)))
        } else {
            self.success.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn register_test_code() {
    // register may fail with DuplicateCode across tests sharing the registry.
    // We don't bother clearing — duplicates are no-ops for our purposes.
    let _ = fasten::register(
        "user".to_string(),
        vec![(
            "USER_CREATED".to_string(),
            Meta {
                id: "USER_CREATED".into(),
                domain: "user".into(),
                category: "account".into(),
                action: "create".into(),
                severity: Severity::Info,
                description: "test".into(),
                emitter: "test".into(),
                retention_class: RetentionClass::Long,
                high_volume: false,
                pii_in_detail: false,
                declared_unused: false,
                detail_passthrough_keys: vec![],
            },
        )],
    );
}

fn init_queue(store: Arc<dyn AuditStore>, mut tweak: impl FnMut(&mut Config)) {
    let mut cfg = Config {
        service_id: "svc".into(),
        node_id: "node".into(),
        audit_store: Some(store),
        audit_store_failure_strategy: Some("queue".into()),
        queue_capacity: Some(100),
        ..Default::default()
    };
    tweak(&mut cfg);
    init(cfg).expect("init");
}

fn init_raise(store: Arc<dyn AuditStore>) {
    init(Config {
        service_id: "svc".into(),
        node_id: "node".into(),
        audit_store: Some(store),
        audit_store_failure_strategy: Some("raise".into()),
        ..Default::default()
    })
    .expect("init");
}

fn emit_one() -> Result<Row, AuditStoreError> {
    EmitBuilder::new("USER_CREATED", "u-1").submit()
}

// ── #1 happy path ──────────────────────────────────────────────────────────

#[test]
fn queue_mode_drains_within_one_second() {
    let _g = TEST_MU.lock().unwrap();
    register_test_code();
    let store = RecordingStore::new();
    init_queue(store.clone() as Arc<dyn AuditStore>, |_| {});
    EmitBuilder::new("USER_CREATED", "u-1").submit().expect("emit");
    EmitBuilder::new("USER_CREATED", "u-2").submit().expect("emit");
    assert!(flush(Duration::from_secs(1)));
    assert_eq!(store.count(), 2);
    audit_queue::uninstall_drainer();
}

#[test]
fn queue_mode_emit_returns_immediately_under_slow_store() {
    let _g = TEST_MU.lock().unwrap();
    register_test_code();
    let store = SlowStore::new(Duration::from_millis(50));
    init_queue(store.clone() as Arc<dyn AuditStore>, |_| {});
    let t0 = std::time::Instant::now();
    for _ in 0..10 {
        EmitBuilder::new("USER_CREATED", "u").submit().expect("emit");
    }
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(150),
        "emit() should return immediately; took {:?}",
        elapsed
    );
    assert!(flush(Duration::from_secs(2)));
    assert_eq!(store.count(), 10);
    audit_queue::uninstall_drainer();
}

// ── #2 raise mode ──────────────────────────────────────────────────────────

#[test]
fn raise_mode_returns_audit_store_error() {
    let _g = TEST_MU.lock().unwrap();
    register_test_code();
    let store = BrokenStore::new();
    init_raise(store as Arc<dyn AuditStore>);
    let r = emit_one();
    let err = r.expect_err("expected error in raise mode");
    let msg = err.to_string();
    assert!(msg.contains("store down"), "msg = {}", msg);
    audit_queue::uninstall_drainer();
}

#[test]
fn raise_mode_does_not_install_drainer() {
    let _g = TEST_MU.lock().unwrap();
    register_test_code();
    let store = RecordingStore::new();
    init_raise(store as Arc<dyn AuditStore>);
    assert!(queue_stats().is_none());
    audit_queue::uninstall_drainer();
}

// ── #3 outage + recovery ───────────────────────────────────────────────────

#[test]
fn outage_then_recovery_drains_pending_rows() {
    let _g = TEST_MU.lock().unwrap();
    register_test_code();
    let store = FlakyStore::new(2);
    init_queue(store.clone() as Arc<dyn AuditStore>, |c| {
        c.queue_retry_initial = Some(Duration::from_millis(10));
        c.queue_retry_max = Some(Duration::from_millis(50));
        c.disable_queue_jitter = true;
    });
    EmitBuilder::new("USER_CREATED", "u-1").submit().expect("emit");
    assert!(flush(Duration::from_secs(2)));
    assert_eq!(store.success.load(Ordering::SeqCst), 1);
    assert!(store.attempts.load(Ordering::SeqCst) >= 3);
    audit_queue::uninstall_drainer();
}

// ── #6 queue_stats + flush ─────────────────────────────────────────────────

#[test]
fn queue_stats_fields() {
    let _g = TEST_MU.lock().unwrap();
    register_test_code();
    let store = RecordingStore::new();
    init_queue(store.clone() as Arc<dyn AuditStore>, |_| {});
    EmitBuilder::new("USER_CREATED", "u-1").submit().expect("emit");
    assert!(flush(Duration::from_secs(1)));
    let s = queue_stats().expect("expected stats in queue mode");
    assert_eq!(s.depth, 0);
    assert_eq!(s.capacity, 100);
    assert!(s.high_water >= 1);
    assert_eq!(s.drained_total, 1);
    assert_eq!(s.retry_count_active, 0);
    assert!(s.last_error.is_none());
    audit_queue::uninstall_drainer();
}

#[test]
fn public_flush_no_op_in_raise_mode() {
    let _g = TEST_MU.lock().unwrap();
    register_test_code();
    let store = RecordingStore::new();
    init_raise(store as Arc<dyn AuditStore>);
    // Even after a hypothetical emit, flush is no-op.
    assert!(flush(Duration::from_millis(100)));
    audit_queue::uninstall_drainer();
}

#[test]
fn queue_stats_high_water_monotonic() {
    let _g = TEST_MU.lock().unwrap();
    register_test_code();
    let store = RecordingStore::new();
    init_queue(store.clone() as Arc<dyn AuditStore>, |c| {
        c.queue_capacity = Some(10);
    });
    for _ in 0..5 {
        EmitBuilder::new("USER_CREATED", "u").submit().expect("emit");
    }
    assert!(flush(Duration::from_secs(1)));
    let high = queue_stats().unwrap().high_water;
    EmitBuilder::new("USER_CREATED", "u-x").submit().expect("emit");
    assert!(flush(Duration::from_secs(1)));
    assert!(queue_stats().unwrap().high_water >= high);
    audit_queue::uninstall_drainer();
}

