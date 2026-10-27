//! Drainer stop (spec/drainer-conformance.md §10).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use fasten_core::drainer::{Drainer, DrainerConfig};
use fasten_core::error::Error;
use fasten_core::row::Row;
use fasten_core::store::{Filter, Store};

struct TestStore {
    stored: Arc<Mutex<Vec<String>>>,
    attempts: Arc<AtomicUsize>,
    fail: bool,
    delay: Duration,
}

impl TestStore {
    fn new(fail: bool, delay: Duration) -> Self {
        Self { stored: Arc::default(), attempts: Arc::default(), fail, delay }
    }
}

impl Store for TestStore {
    fn insert(&self, row: &Row) -> Result<(), Error> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        thread::sleep(self.delay);
        if self.fail {
            return Err(Error::CallbackFailed(1));
        }
        self.stored.lock().unwrap().push(row.id.clone());
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

fn row(id: &str) -> Row {
    Row { id: id.into(), ..Row::default() }
}

fn cfg(capacity: usize, retry: Duration) -> DrainerConfig {
    DrainerConfig {
        capacity,
        retry_initial: retry,
        retry_max: retry,
        retry_jitter: false,
        max_attempts: 50,
    }
}

/// Run `f` on a thread and fail the test if it takes longer than `limit`.
fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || tx.send(f()).ok());
    rx.recv_timeout(limit).expect("timed out: possible hang")
}

#[test]
fn stop_returns_promptly_every_time() {
    for i in 0..300 {
        within(Duration::from_secs(5), move || {
            let d = Drainer::new(Box::new(TestStore::new(false, Duration::ZERO)),
                                 cfg(4, Duration::from_millis(5)));
            for n in 0..(i % 4) {
                d.enqueue(row(&format!("r-{n}")));
            }
            d.stop(Duration::from_secs(2));
        });
    }
}

#[test]
fn stop_releases_enqueue_blocked_on_a_full_queue() {
    let store = TestStore::new(false, Duration::from_millis(100));
    let stored = store.stored.clone();
    let d = Drainer::new(Box::new(store), cfg(1, Duration::from_millis(5)));
    let accepted = Arc::new(Mutex::new(Vec::new()));
    let threads: Vec<_> = (0..4)
        .map(|n| {
            let (d, accepted) = (d.clone(), accepted.clone());
            thread::spawn(move || {
                let id = format!("r-{n}");
                if d.enqueue(row(&id)) {
                    accepted.lock().unwrap().push(id);
                }
            })
        })
        .collect();
    thread::sleep(Duration::from_millis(50));
    within(Duration::from_secs(5), {
        let d = d.clone();
        move || d.stop(Duration::from_secs(2))
    });
    for t in threads {
        t.join().unwrap();
    }
    // Every row enqueue accepted was stored; the rest were refused.
    let mut accepted = accepted.lock().unwrap().clone();
    let mut stored = stored.lock().unwrap().clone();
    accepted.sort();
    stored.sort();
    assert_eq!(accepted, stored);
    assert!(accepted.len() < 4, "some enqueues must have been refused");
}

#[test]
fn no_retry_after_stop() {
    let store = TestStore::new(true, Duration::ZERO);
    let attempts = store.attempts.clone();
    let d = Drainer::new(Box::new(store), cfg(4, Duration::from_secs(10)));
    d.enqueue(row("r-1"));
    thread::sleep(Duration::from_millis(50)); // first attempt failed, now backing off
    within(Duration::from_secs(5), {
        let d = d.clone();
        move || d.stop(Duration::from_secs(2))
    });
    assert!(attempts.load(Ordering::SeqCst) <= 2, "retried after stop");
    assert_eq!(d.stats().dead_lettered_total, 1);
}

#[test]
fn every_accepted_row_is_stored_or_dead_lettered_when_stop_races_enqueue() {
    for round in 0..300 {
        let store = TestStore::new(false, Duration::ZERO);
        let stored = store.stored.clone();
        let d = Drainer::new(Box::new(store), cfg(64, Duration::from_millis(5)));
        let accepted = Arc::new(AtomicUsize::new(0));
        let workers: Vec<_> = (0..6)
            .map(|w| {
                let (d, accepted) = (d.clone(), accepted.clone());
                thread::spawn(move || {
                    for n in 0..20 {
                        if d.enqueue(row(&format!("r-{w}-{n}"))) {
                            accepted.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                })
            })
            .collect();
        d.stop(Duration::from_secs(2));
        for w in workers {
            w.join().unwrap();
        }
        let handled = stored.lock().unwrap().len() + d.stats().dead_lettered_total;
        assert_eq!(accepted.load(Ordering::SeqCst), handled, "round {round}");
    }
}
