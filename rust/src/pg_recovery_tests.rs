//! `PostgresStore` after the server drops its connection: between calls,
//! during a transaction, during a COMMIT, and while the drainer writes in
//! queue mode. No audit row is lost or stored twice, and the chain stays
//! unbroken. A statement timeout is not taken for a lost connection.
//!
//! The store's connection is found by its `application_name` and ended with
//! `pg_terminate_backend`, as a server restart or an operator would.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::replication_tests::pg::{client, dsn, table, DropTable};
use crate::{verify_chain, AuditStore, PostgresStore, ReplicatedRow};

/// `dsn` with one more connection parameter.
fn with_param(dsn: &str, param: &str) -> String {
    format!("{dsn}{}{param}", if dsn.contains('?') { '&' } else { '?' })
}

/// A store on a fresh table whose connection is named `app`.
fn store(dsn: &str, prefix: &str) -> (Arc<PostgresStore>, String, DropTable) {
    let table = table(prefix);
    let app = table.clone();
    let store = PostgresStore::new(&with_param(dsn, &format!("application_name={app}")), table.clone()).unwrap();
    (Arc::new(store), app, DropTable(dsn.to_string(), table))
}

/// End every connection named `app`; returns how many.
fn terminate(dsn: &str, app: &str) -> i64 {
    let n = client(dsn)
        .query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = $1",
            &[&app],
        )
        .unwrap()
        .len();
    i64::try_from(n).unwrap()
}

/// The backend pids of the connections named `app`.
fn pids(dsn: &str, app: &str) -> Vec<i32> {
    client(dsn)
        .query("SELECT pid FROM pg_stat_activity WHERE application_name = $1", &[&app])
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}

/// Wait until the connection named `app` waits on a lock.
fn wait_for_lock_wait(dsn: &str, app: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let waiting = client(dsn)
            .query(
                "SELECT 1 FROM pg_stat_activity WHERE application_name = $1 AND wait_event_type = 'Lock'",
                &[&app],
            )
            .unwrap();
        if !waiting.is_empty() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("{app} never waited on the lock");
}

/// A connection holding the node's advisory lock, as another writer
/// sealing a row on that node holds it.
fn hold_node_lock(dsn: &str, node: &str) -> ::pg::Client {
    let mut c = client(dsn);
    c.execute("SELECT pg_advisory_lock(hashtextextended($1, 0))", &[&node]).unwrap();
    c
}

fn row(id: &str, node: &str) -> crate::Row {
    crate::Row {
        wire_version: "1".into(),
        id: id.into(),
        origin_id: id.into(),
        timestamp: chrono::Utc::now(),
        code: "RECOVERY".into(),
        service_id: "svc".into(),
        source_node_id: node.into(),
        target: "t".into(),
        domain: "recovery".into(),
        method: "sdk".into(),
        detail: [("n".to_string(), serde_json::json!(1.5))].into_iter().collect(),
        ..Default::default()
    }
}

fn sealed_batch(node: &str, ids: &[&str]) -> Vec<ReplicatedRow> {
    let mut prev = crate::GENESIS.to_string();
    ids.iter()
        .enumerate()
        .map(|(i, id)| {
            let mut r = row(id, node);
            r.monotonic_seq = i as u64 + 1;
            let core = crate::engine::sdk_row_to_core(&r);
            let sealed = fasten_core::chain::seal(&prev, &crate::ChainRow::from(&core)).unwrap();
            prev.clone_from(&sealed.hash);
            ReplicatedRow::from(sealed)
        })
        .collect()
}

/// The node's rows verify as one chain at seqs 1..=n.
fn assert_chain(store: &PostgresStore, node: &str, n: u64) {
    let rows = store.chain_rows(node).unwrap();
    assert_eq!(rows.iter().map(|r| r.monotonic_seq).collect::<Vec<_>>(), (1..=n).collect::<Vec<_>>());
    let v = verify_chain(&rows);
    assert!(v.ok && v.sealed_rows as u64 == n, "{v:?}");
}

#[test]
fn every_call_reconnects_after_the_connection_is_lost_between_calls() {
    let Some(dsn) = dsn() else { return };
    let (store, app, _drop) = store(&dsn, "rec_between");
    store.allocate_and_insert_originated(&row("b-1", "node-1")).unwrap();

    assert_eq!(terminate(&dsn, &app), 1);
    store.allocate_and_insert_originated(&row("b-2", "node-1")).unwrap();
    assert_eq!(terminate(&dsn, &app), 1);
    assert_eq!(store.chain_rows("node-1").unwrap().len(), 2);
    assert_eq!(terminate(&dsn, &app), 1);
    let unshipped = store.list_unshipped_sealed(0, None).unwrap();
    assert_eq!(unshipped.len(), 2);
    assert_eq!(terminate(&dsn, &app), 1);
    store.mark_shipped(&["b-1".to_string()]).unwrap();
    assert_eq!(terminate(&dsn, &app), 1);
    let r = store.ingest_replicated(&sealed_batch("node-2", &["i-1", "i-2"]), None).unwrap();
    assert_eq!((r.inserted, r.rejected_from_seq), (2, None));
    assert_eq!(terminate(&dsn, &app), 1);
    assert_eq!(store.chain_tips().unwrap().len(), 2);
    assert_eq!(terminate(&dsn, &app), 1);
    let sealed = sealed_batch("node-3", &["s-1"]);
    store.insert_sealed(&sealed[0].row, false).unwrap();
    assert_eq!(terminate(&dsn, &app), 1);
    assert_eq!(store.purge("2000-01-01T00:00:00Z".parse().unwrap(), false).unwrap(), 0);

    assert_chain(&store, "node-1", 2);
    assert_chain(&store, "node-2", 2);
    assert_eq!(store.list_unshipped_sealed(0, None).unwrap().len(), 4);
}

// The connection ends while the insert waits for the node's lock: the
// transaction never committed, so it runs again on a new connection.
#[test]
fn a_transaction_cut_short_runs_again_on_a_new_connection() {
    let Some(dsn) = dsn() else { return };
    let (store, app, _drop) = store(&dsn, "rec_during");
    let mut holder = hold_node_lock(&dsn, "node-1");
    let writer = {
        let store = store.clone();
        std::thread::spawn(move || store.allocate_and_insert_originated(&row("d-1", "node-1")))
    };
    wait_for_lock_wait(&dsn, &app);
    let before = pids(&dsn, &app);
    assert_eq!(terminate(&dsn, &app), 1);
    holder.execute("SELECT pg_advisory_unlock(hashtextextended($1, 0))", &[&"node-1"]).unwrap();
    let stored = writer.join().unwrap().unwrap();
    assert_eq!((stored.monotonic_seq, stored.prev_hash.as_str()), (1, crate::GENESIS));
    assert_ne!(pids(&dsn, &app), before);
    assert_chain(&store, "node-1", 1);

    // The same for an ingest.
    holder.execute("SELECT pg_advisory_lock(hashtextextended($1, 0))", &[&"node-2"]).unwrap();
    let ingest = {
        let store = store.clone();
        std::thread::spawn(move || store.ingest_replicated(&sealed_batch("node-2", &["j-1", "j-2"]), None))
    };
    wait_for_lock_wait(&dsn, &app);
    assert_eq!(terminate(&dsn, &app), 1);
    holder.execute("SELECT pg_advisory_unlock(hashtextextended($1, 0))", &[&"node-2"]).unwrap();
    let r = ingest.join().unwrap().unwrap();
    assert_eq!((r.inserted, r.rejected_from_seq), (2, None));
    assert_chain(&store, "node-2", 2);
}

// A trigger that ends its own connection at COMMIT, for rows whose id
// starts with "kill-", and counts each time it runs in a sequence, which a
// rollback does not undo.
fn kill_at_commit(dsn: &str, table: &str) {
    client(dsn)
        .batch_execute(&format!(
            "CREATE SEQUENCE {table}_calls;
             CREATE FUNCTION {table}_kill() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
                 IF NEW.id LIKE 'kill-%' THEN
                     PERFORM nextval('{table}_calls');
                     PERFORM pg_terminate_backend(pg_backend_pid());
                 END IF;
                 RETURN NULL;
             END $$;
             CREATE CONSTRAINT TRIGGER {table}_kill AFTER INSERT ON {table}
                 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION {table}_kill();"
        ))
        .unwrap();
}

fn drop_kill(dsn: &str, table: &str) {
    let _ = client(dsn).batch_execute(&format!(
        "DROP TABLE IF EXISTS {table}; DROP FUNCTION IF EXISTS {table}_kill(); DROP SEQUENCE IF EXISTS {table}_calls;"
    ));
}

fn calls(dsn: &str, table: &str) -> i64 {
    let r = client(dsn)
        .query_one(&format!("SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM {table}_calls") as &str, &[])
        .unwrap();
    r.get(0)
}

// The connection ends during COMMIT. The COMMIT is not run again: the row
// is read back once, and since the server rolled it back, the call fails
// with an error the drainer retries. A later insert takes the seq.
#[test]
fn a_commit_cut_short_is_read_back_and_not_run_again() {
    let Some(dsn) = dsn() else { return };
    let (store, _app, drop) = store(&dsn, "rec_commit");
    let table = drop.1.clone();
    kill_at_commit(&dsn, &table);

    let err = store.allocate_and_insert_originated(&row("kill-1", "node-1")).unwrap_err();
    assert!(matches!(err, crate::Error::AuditStoreInsert(_)), "{err:?}");
    assert_eq!(calls(&dsn, &table), 1, "the COMMIT ran again");
    assert!(store.chain_rows("node-1").unwrap().is_empty());

    let sealed = sealed_batch("node-2", &["kill-s1"]);
    let err = store.insert_sealed(&sealed[0].row, false).unwrap_err();
    assert!(matches!(err, crate::Error::AuditStoreInsert(_)), "{err:?}");
    assert_eq!(calls(&dsn, &table), 2);

    let batch = sealed_batch("node-3", &["ok-1", "kill-2"]);
    let err = store.ingest_replicated(&batch, None).unwrap_err();
    assert!(matches!(err, crate::Error::AuditStoreInsert(_)), "{err:?}");
    assert_eq!(calls(&dsn, &table), 3);
    // Atomic: the row before the failed one is not stored either.
    assert!(store.chain_rows("node-3").unwrap().is_empty());

    let stored = store.allocate_and_insert_originated(&row("r-1", "node-1")).unwrap();
    assert_eq!(stored.monotonic_seq, 1);
    assert_chain(&store, "node-1", 1);
    drop_kill(&dsn, &table);
}

// SQLSTATE 57014 comes over a live connection: the error is returned, the
// connection kept, and nothing is run again.
#[test]
fn a_statement_timeout_is_not_a_lost_connection() {
    let Some(dsn) = dsn() else { return };
    let table = table("rec_timeout");
    let _drop = DropTable(dsn.clone(), table.clone());
    let app = table.clone();
    let timed = with_param(&dsn, &format!("application_name={app}&options=-c%20statement_timeout%3D300"));
    let store = PostgresStore::new(&timed, table).unwrap();
    store.allocate_and_insert_originated(&row("t-1", "node-1")).unwrap();
    let before = pids(&dsn, &app);
    assert_eq!(before.len(), 1);

    let mut holder = hold_node_lock(&dsn, "node-1");
    let err = store.allocate_and_insert_originated(&row("t-2", "node-1")).unwrap_err();
    assert!(matches!(&err, crate::Error::AuditStoreInsert(m) if m.contains("statement timeout")), "{err:?}");
    assert_eq!(pids(&dsn, &app), before, "the store connected again");
    holder.execute("SELECT pg_advisory_unlock(hashtextextended($1, 0))", &[&"node-1"]).unwrap();

    store.allocate_and_insert_originated(&row("t-2", "node-1")).unwrap();
    assert_chain(&store, "node-1", 2);
}

// Rows emitted in queue mode while the store's connection keeps being cut:
// every row is stored once, in one unbroken chain.
#[test]
fn queue_mode_loses_no_row_while_connections_drop() {
    let Some(dsn) = dsn() else { return };
    let (store, app, _drop) = store(&dsn, "rec_queue");
    let meta = crate::Meta { domain: "recovery".into(), ..Default::default() };
    let _ = crate::register("recovery".into(), [("RECOVERY_QUEUE".to_string(), meta)]);
    let engine = crate::Engine::new();
    engine
        .init_with_env(
            crate::Config {
                service_id: format!("svc-{app}"),
                node_id: "node-q".into(),
                audit_store: Some(store.clone()),
                audit_store_failure_strategy: Some("queue".into()),
                queue_capacity: Some(10_000),
                queue_retry_initial: Some(Duration::from_millis(5)),
                queue_retry_max: Some(Duration::from_millis(100)),
                ..Default::default()
            },
            &[],
        )
        .unwrap();

    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let killer = {
        let (dsn, app, done) = (dsn.clone(), app.clone(), done.clone());
        std::thread::spawn(move || {
            let mut kills = 0;
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                kills += terminate(&dsn, &app);
                std::thread::sleep(Duration::from_millis(15));
            }
            kills
        })
    };
    const N: u64 = 400;
    let mut ids = std::collections::HashSet::new();
    for _ in 0..N {
        let row = crate::EmitBuilder::new("RECOVERY_QUEUE", "t").submit_to(&engine).unwrap();
        ids.insert(row.id);
        std::thread::sleep(Duration::from_micros(500));
    }
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    let kills = killer.join().unwrap();
    assert!(engine.flush(Duration::from_secs(60)), "the queue did not drain");
    let stats = engine.queue_stats().unwrap();
    engine.reset_for_tests();

    assert!(kills >= 5, "only {kills} connections were cut");
    assert_eq!(stats.dead_lettered_total, 0, "{stats:?}");
    let rows = store.chain_rows("node-q").unwrap();
    assert_eq!(rows.len() as u64, N);
    assert_eq!(rows.iter().map(|r| r.id.clone()).collect::<std::collections::HashSet<_>>(), ids);
    assert_chain(&store, "node-q", N);
}
