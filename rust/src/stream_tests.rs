//! Stored sys and api logs: persist_streams, write-through, failures, the
//! pending cap, flush and close, retention, and the stream stores on every
//! backend. They follow the Python, Go and JS stream tests.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use crate::streams::{Stream, StreamFilter, StreamRow, StreamStore, MAX_PENDING};
use crate::test_support::{backends, leak, setup, uniq, Backend};
use crate::{Config, Engine, Error};

fn row(v: Value) -> StreamRow {
    serde_json::from_value(v).unwrap()
}

fn stderr_lines(label: &str) -> Vec<String> {
    crate::streams::STREAM_STDERR.lock().unwrap().iter().filter(|l| l.contains(label)).cloned().collect()
}

/// A store whose inserts fail, wait, or succeed as the test says.
#[derive(Default)]
struct Scripted {
    rows: Mutex<Vec<StreamRow>>,
    fail: Mutex<bool>,
    gate: Mutex<bool>,
    opened: Condvar,
    failures: AtomicUsize,
    purged_before: Mutex<Vec<DateTime<Utc>>>,
}

impl Scripted {
    fn hold(&self) {
        *self.gate.lock().unwrap() = true;
    }
    fn release(&self) {
        *self.gate.lock().unwrap() = false;
        self.opened.notify_all();
    }
}

impl StreamStore for Scripted {
    fn insert(&self, r: &StreamRow) -> Result<(), Error> {
        let mut held = self.gate.lock().unwrap();
        while *held {
            held = self.opened.wait(held).unwrap();
        }
        drop(held);
        if *self.fail.lock().unwrap() {
            return Err(Error::StreamStore(format!("value {:?} rejected", r.get("note"))));
        }
        self.rows.lock().unwrap().push(r.clone());
        Ok(())
    }
    fn query(&self, f: &StreamFilter, limit: u32) -> Result<Vec<StreamRow>, Error> {
        let rows = self.rows.lock().unwrap();
        Ok(rows.iter().rev().filter(|r| f.matches(r)).take(limit as usize).cloned().collect())
    }
    fn count_matching(&self, f: &StreamFilter) -> Result<u64, Error> {
        Ok(self.rows.lock().unwrap().iter().filter(|r| f.matches(r)).count() as u64)
    }
    fn search(&self, _: &str, _: &str, _: Option<&str>, _: u32) -> Result<Vec<StreamRow>, Error> {
        Ok(Vec::new())
    }
    fn purge(&self, before: DateTime<Utc>) -> Result<u64, Error> {
        self.purged_before.lock().unwrap().push(before);
        Ok(0)
    }
    fn note_write_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
    fn degraded(&self) -> bool {
        self.failures.load(Ordering::Relaxed) > 0
    }
}

fn engine_with(service: &str, api: Option<Arc<dyn StreamStore>>, sys: Option<Arc<dyn StreamStore>>) -> &'static Engine {
    let e = leak(Engine::new());
    e.init(Config { service_id: service.into(), node_id: "n".into(), api_store: api, syslog_store: sys, ..Default::default() })
        .unwrap();
    e
}

#[test]
fn persist_streams_must_match_the_stores() {
    let store = || -> Option<Arc<dyn StreamStore>> { Some(Arc::new(Scripted::default())) };
    let init = |ps: Option<Vec<&str>>, api, sys| {
        Engine::new().init(Config {
            service_id: "s".into(),
            node_id: "n".into(),
            api_store: api,
            syslog_store: sys,
            persist_streams: ps.map(|v| v.into_iter().map(String::from).collect()),
            ..Default::default()
        })
    };
    assert!(init(None, store(), None).is_ok());
    assert!(init(Some(vec!["api", "sys"]), store(), store()).is_ok());
    assert!(init(Some(vec![]), None, None).is_ok());
    let msg = |r: Result<(), Error>| r.unwrap_err().to_string();
    assert_eq!(
        msg(init(Some(vec!["api"]), None, None)),
        "fasten.init: persist_streams / stores mismatch: named in persist_streams but no store attached: ['api']"
    );
    assert_eq!(
        msg(init(Some(vec!["api"]), store(), store())),
        "fasten.init: persist_streams / stores mismatch: store attached but not in persist_streams: ['sys']"
    );
    assert_eq!(
        msg(init(Some(vec!["sys"]), store(), None)),
        "fasten.init: persist_streams / stores mismatch: named in persist_streams but no store attached: ['sys']; store attached but not in persist_streams: ['api']"
    );
    assert_eq!(
        msg(init(Some(vec!["audit", "sys"]), None, store())),
        "fasten.init: persist_streams=['audit', 'sys']: unknown stream(s) ['audit']. Only ['api', 'sys'] are valid (audit persistence is driven by audit_store, not persist_streams)."
    );
}

#[test]
fn a_failed_init_leaves_the_engine_as_it_was() {
    let e = engine_with("svc-keep", None, None);
    let err = e.init(Config {
        service_id: "svc-other".into(),
        node_id: "n".into(),
        persist_streams: Some(vec!["api".into()]),
        ..Default::default()
    });
    assert!(err.is_err());
    assert!(e.init(Config { service_id: "x".into(), node_id: "n".into(), retention_api: Some("7w".into()), ..Default::default() }).is_err());
    assert_eq!(e.current_config().unwrap().service_id, "svc-keep");
}

#[test]
fn sys_and_api_rows_are_stored_redacted_with_a_request_id() {
    let api = Arc::new(Scripted::default());
    let sys = Arc::new(Scripted::default());
    let service = uniq("svc");
    let e = engine_with(&service, Some(api.clone()), Some(sys.clone()));
    e.log_sys("info", "boot_step", json!({ "password": "p", "note": "a" }));
    crate::with_request_id("req-real".into(), || {
        e.log_sys("warn", "handled", json!({ "nested": { "token": "t" } }));
        e.log_api(json!({ "method": "POST", "path": "/login", "status": 201, "authorization": "Bearer x" }));
    });
    e.log_sys("info", "after", json!({}));
    assert!(e.flush(Duration::from_secs(5)));
    // Init's own sys events are stored too; these are the logged lines.
    let rows: Vec<StreamRow> =
        sys.rows.lock().unwrap().iter().filter(|r| r["event"] != "audit_chain_unavailable").cloned().collect();
    assert_eq!(rows.len(), 3);
    assert!(rows[0]["request_id"].as_str().unwrap().starts_with(&format!("boot-{service}-")));
    assert_eq!(rows[0]["password"], "***");
    assert!(rows[0].get("shape").is_none());
    assert_eq!(rows[0]["timestamp"].as_str().unwrap().len(), 27);
    assert_eq!(rows[1]["request_id"], "req-real");
    assert_eq!(rows[1]["nested"]["token"], "***");
    assert!(rows[2]["request_id"].as_str().unwrap().starts_with(&format!("orphan-{service}-")));
    let api_rows = api.rows.lock().unwrap().clone();
    assert_eq!(api_rows[0]["authorization"], "***");
    assert_eq!(api_rows[0]["request_id"], "req-real");
    assert_eq!(api_rows[0]["service_id"], service.as_str());
    let line = crate::engine::API_STDOUT.lock().unwrap().iter().find(|l| l["service_id"] == service.as_str()).cloned().unwrap();
    assert_eq!(line["shape"], "api");
    assert_eq!(line["authorization"], "***");
    // The stdout sys line carries the same stamped id.
    let sys_line = crate::engine::SYS_STDOUT.lock().unwrap().iter().find(|l| l["service_id"] == service.as_str()).cloned().unwrap();
    assert_eq!(sys_line["request_id"], rows[0]["request_id"]);
}

#[test]
fn a_failed_write_keeps_the_line_degrades_the_stream_and_reports_the_type() {
    let sys = Arc::new(Scripted::default());
    *sys.fail.lock().unwrap() = true;
    let service = uniq("svc");
    let before = stderr_lines("syslog persist failed").len();
    let e = engine_with(&service, None, Some(sys.clone()));
    for i in 0..3 {
        e.log_sys("info", "fails", json!({ "note": format!("secret-{i}") }));
    }
    e.flush(Duration::from_secs(5));
    let st = e.reader_state().streams.unwrap();
    assert_eq!(st.sys.source(), "store-degraded");
    assert_eq!(st.api.source(), "ring");
    assert!(sys.degraded());
    let lines = stderr_lines("syslog persist failed");
    // During an outage: the first failure (init's own sys event), then
    // nothing until a write succeeds or a minute passes.
    let new: Vec<&String> = lines[before..].iter().collect();
    assert!(new.iter().any(|l| l.as_str() == "fasten: syslog persist failed: StreamStore"), "{new:?}");
    assert!(!lines.iter().any(|l| l.contains("secret")));
    assert_eq!(crate::engine::SYS_STDOUT.lock().unwrap().iter().filter(|l| l["service_id"] == service.as_str()).count(), 3);
    *sys.fail.lock().unwrap() = false;
    e.log_sys("info", "works", json!({}));
    e.flush(Duration::from_secs(5));
    let lines = stderr_lines("then a write succeeded");
    assert!(lines.iter().any(|l| l == "fasten: syslog persist failed: 3 more, then a write succeeded"), "{lines:?}");
    // Degraded stays.
    assert_eq!(st.sys.source(), "store-degraded");
}

#[test]
fn the_pending_cap_drops_and_counts_and_flush_and_close_keep_their_timeout() {
    let store = Arc::new(Scripted::default());
    store.hold();
    let stream = Stream::new("api", Some(store.clone() as Arc<dyn StreamStore>));
    for i in 0..=MAX_PENDING {
        stream.push(row(json!({ "i": i })));
    }
    // The writer holds one row, the queue the rest; the last was dropped.
    let deadline = Instant::now() + Duration::from_secs(5);
    while stream.pending() < MAX_PENDING && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(stream.pending(), MAX_PENDING);
    assert_eq!(store.failures.load(Ordering::Relaxed), 1);
    assert_eq!(stream.source(), "store-degraded");
    let t = Instant::now();
    assert!(!stream.flush(Instant::now() + Duration::from_millis(100)));
    assert!(t.elapsed() < Duration::from_secs(2));
    store.release();
    assert!(stream.close(Instant::now() + Duration::from_secs(20)));
    assert_eq!(store.rows.lock().unwrap().len(), MAX_PENDING);
    // In push order.
    assert_eq!(store.rows.lock().unwrap()[MAX_PENDING - 1]["i"], MAX_PENDING - 1);
}

#[test]
fn engine_close_reports_writes_that_do_not_finish() {
    let store = Arc::new(Scripted::default());
    store.hold();
    let e = engine_with(&uniq("svc"), Some(store.clone()), None);
    e.log_api(json!({ "path": "/a" }));
    let t = Instant::now();
    assert!(!e.close(Duration::from_millis(200)));
    assert!(t.elapsed() < Duration::from_secs(3));
    assert!(e.reader_state().streams.is_none());
    store.release();
    // After close, log lines go to stdout only.
    e.log_api(json!({ "path": "/b" }));
    let e2 = engine_with(&uniq("svc"), Some(Arc::new(Scripted::default())), None);
    e2.log_api(json!({ "path": "/c" }));
    assert!(e2.close(Duration::from_secs(5)));
}

#[test]
fn retention_purges_the_stream_stores_on_init() {
    let api = Arc::new(Scripted::default());
    let sys = Arc::new(Scripted::default());
    let e = leak(Engine::new());
    e.init(Config {
        service_id: uniq("svc"),
        node_id: "n".into(),
        api_store: Some(api.clone()),
        syslog_store: Some(sys.clone()),
        retention_api: Some("1d".into()),
        retention_syslog: Some("2h".into()),
        ..Default::default()
    })
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while (api.purged_before.lock().unwrap().is_empty() || sys.purged_before.lock().unwrap().is_empty()) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let age = |s: &Scripted| Utc::now() - s.purged_before.lock().unwrap()[0];
    assert!((age(&api) - chrono::Duration::days(1)).num_seconds().abs() < 60);
    assert!((age(&sys) - chrono::Duration::hours(2)).num_seconds().abs() < 60);
    // Close stops the purgers.
    e.close(Duration::from_secs(5));
}

#[test]
fn the_ring_is_exact_and_newest_first() {
    let s = Stream::new("sys", None);
    for (i, level) in ["info", "INFO", "warn"].iter().enumerate() {
        s.push(row(json!({ "level": level, "i": i, "timestamp": format!("2026-01-0{}T00:00:00.000000Z", i + 1) })));
    }
    let q = |f: StreamFilter| s.query(&f, 10).unwrap().iter().map(|r| r["i"].as_u64().unwrap()).collect::<Vec<_>>();
    assert_eq!(q(StreamFilter::default()), [2, 1, 0]);
    assert_eq!(q(StreamFilter { level: Some("info".into()), ..Default::default() }), [0]);
    assert_eq!(q(StreamFilter { until: Some("2026-01-02T00:00:00.000000Z".into()), ..Default::default() }), [1, 0]);
    assert_eq!(s.count_matching(&StreamFilter::default()).unwrap(), 3);
    assert!(s.search("x", "2026", None, 10).is_none());
}

#[test]
fn stream_stores_on_every_backend() {
    for b in backends() {
        let table = uniq("syslog");
        let s = b.stream(&table);
        let rows = [
            json!({ "event": "a", "level": "info", "request_id": "r1", "service_id": "svc", "timestamp": "2026-01-01T00:00:00.000000Z", "note": "100% sure" }),
            json!({ "event": "b", "level": "warn", "request_id": "r1", "timestamp": "2026-01-02T00:00:00.000000Z", "note": "a_b", "n": 18446744073709551615u64 }),
            json!({ "event": "c", "level": "info", "request_id": "r2", "timestamp": "2026-01-03T00:00:00.000000Z", "note": r"c\d é" }),
            json!({ "method": "GET", "path": "/x", "status": "404", "note": "axb" }),
            json!({ "status": 9_999_999_999i64, "note": "cd" }),
        ];
        for r in &rows {
            s.insert(&row(r.clone())).unwrap();
        }
        let all = s.query(&StreamFilter::default(), 100).unwrap();
        assert_eq!(all.len(), 5, "{}", b.label());
        assert_eq!(all[4], row(rows[0].clone()));
        assert_eq!(all[3]["n"], 18446744073709551615u64);
        let count = |f: StreamFilter| s.count_matching(&f).unwrap();
        assert_eq!(count(StreamFilter { request_id: Some("r1".into()), ..Default::default() }), 2);
        assert_eq!(count(StreamFilter { level: Some("INFO".into()), ..Default::default() }), 0);
        assert_eq!(count(StreamFilter { status: Some(404), ..Default::default() }), 1);
        assert_eq!(count(StreamFilter { since: Some("2026-01-02T00:00:00.000000Z".into()), ..Default::default() }), 2);
        assert_eq!(count(StreamFilter { until: Some("2026-01-02T00:00:00.000000Z".into()), ..Default::default() }), 4);
        assert_eq!(s.query(&StreamFilter::default(), 2).unwrap()[0]["note"], "cd");
        let search = |q: &str| s.search(q, "", None, 50).unwrap().iter().map(|r| r["note"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(search("%"), ["100% sure"], "{}", b.label());
        assert_eq!(search("a_b"), ["a_b"]);
        assert_eq!(search("\\"), [r"c\d é"]);
        assert_eq!(search("É"), [r"c\d é"]);
        assert_eq!(s.search("sure", "2026-01-02", None, 50).unwrap().len(), 0);
        assert_eq!(s.search("a", "", Some("2026-01-01T12:00:00.000000Z"), 50).unwrap().len(), 3);
        // Rows without a timestamp are kept.
        let cutoff: DateTime<Utc> = "2026-01-02T00:00:00Z".parse().unwrap();
        assert_eq!(s.purge(cutoff).unwrap(), 1);
        assert_eq!(s.count().unwrap(), 4);
        // A second store on the same table reads the same rows.
        assert_eq!(b.stream(&table).count().unwrap(), 4);
    }
}

#[test]
fn the_engine_writes_both_streams_to_every_backend() {
    for b in backends() {
        let env = setup(&b, None);
        crate::with_request_id("rid-w".into(), || {
            for i in 0..50 {
                env.engine.log_sys("info", "tick", json!({ "i": i, "secret": "s" }));
            }
            env.engine.log_api(json!({ "method": "GET", "path": "/p", "status": 200 }));
        });
        env.flush();
        let rows = env.sys.query(&StreamFilter { event: Some("tick".into()), ..Default::default() }, 100).unwrap();
        assert_eq!(rows.len(), 50, "{}", b.label());
        assert_eq!(rows[0]["i"], 49);
        assert_eq!(rows[0]["secret"], "***");
        assert_eq!(env.api.count_matching(&StreamFilter { status: Some(200), ..Default::default() }).unwrap(), 1);
    }
}

#[test]
fn stream_dsns() {
    let dir = std::env::temp_dir().join(uniq("fasten_dsn"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("streams.db");
    let dsn = format!("sqlite:///{}?table=my_api&wal=false", path.display());
    let s = crate::stream_store_from_dsn(&dsn, "api_log").unwrap();
    s.insert(&row(json!({ "path": "/x" }))).unwrap();
    let again = crate::SqliteStreamStore::open(path.to_str().unwrap(), "my_api").unwrap();
    assert_eq!(again.count().unwrap(), 1);
    let bare = crate::stream_store_from_dsn(path.to_str().unwrap(), "syslog").unwrap();
    assert_eq!(bare.count().unwrap(), 0);
    let err = crate::stream_store_from_dsn(&format!("{}?table=bad-name", path.display()), "syslog");
    assert!(err.is_ok(), "a bare path takes no query");
    let err = crate::stream_store_from_dsn(&format!("sqlite:///{}?table=bad-name", path.display()), "syslog").err().unwrap();
    assert!(err.to_string().contains("not a valid SQL identifier"), "{err}");
    #[cfg(feature = "store-postgres")]
    if let Some(dsn) = crate::test_support::pg_dsn() {
        if let Some(url) = pg_url(&dsn) {
            let table = uniq("api_dsn");
            let sep = if url.contains('?') { '&' } else { '?' };
            let s = crate::stream_store_from_dsn(&format!("{url}{sep}table={table}"), "api_log").unwrap();
            s.insert(&row(json!({ "path": "/pg" }))).unwrap();
            assert_eq!(crate::PostgresStreamStore::new(&dsn, &table).unwrap().count().unwrap(), 1);
        }
        let err = crate::stream_store_from_dsn("postgres://u:hunter2@127.0.0.1:1/db", "api_log").err().unwrap().to_string();
        assert!(!err.contains("hunter2"), "{err}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// The test DSN as a URL, when it is in key=value form.
#[cfg(feature = "store-postgres")]
fn pg_url(dsn: &str) -> Option<String> {
    if dsn.starts_with("postgres") {
        return Some(dsn.to_string());
    }
    let kv: std::collections::HashMap<&str, &str> = dsn.split_whitespace().filter_map(|p| p.split_once('=')).collect();
    Some(format!(
        "postgres://{}:{}@{}:{}/{}?sslmode={}",
        kv.get("user")?,
        kv.get("password").unwrap_or(&""),
        kv.get("host")?,
        kv.get("port").unwrap_or(&"5432"),
        kv.get("dbname")?,
        kv.get("sslmode").unwrap_or(&"prefer")
    ))
}

#[cfg(feature = "store-postgres")]
#[test]
fn postgres_stream_tables_python_and_go_created() {
    let Some(dsn) = crate::test_support::pg_dsn() else { return };
    let mut c = pg::Client::connect(&dsn, pg::NoTls).unwrap();
    // Python's DDL (stream_postgres.py) and Go's (stream_store_postgres.go).
    let py = uniq("py_syslog");
    let go = uniq("go_api");
    c.batch_execute(&format!(
        "CREATE TABLE {py} (seq BIGSERIAL PRIMARY KEY, request_id TEXT, timestamp TEXT, level TEXT, service_id TEXT, event TEXT, method TEXT, path TEXT, status INTEGER, payload TEXT NOT NULL);
         CREATE INDEX idx_{py}_req ON {py}(request_id);
         INSERT INTO {py} (request_id, timestamp, level, service_id, event, payload) VALUES ('r-py', '2026-01-01T00:00:00.000000Z', 'info', 'pysvc', 'py_event', '{{\"request_id\": \"r-py\", \"event\": \"py_event\", \"level\": \"info\", \"n\": 1.0}}');
         CREATE TABLE {go} (seq BIGSERIAL PRIMARY KEY, request_id TEXT, timestamp TEXT, level TEXT, service_id TEXT, event TEXT, method TEXT, path TEXT, status INTEGER, payload TEXT NOT NULL);
         INSERT INTO {go} (request_id, method, path, status, payload) VALUES ('r-go', 'GET', '/go', 200, '{{\"method\":\"GET\",\"path\":\"/go\",\"request_id\":\"r-go\",\"status\":200}}');"
    ))
    .unwrap();
    for (table, filter) in [
        (&py, StreamFilter { event: Some("py_event".into()), ..Default::default() }),
        (&go, StreamFilter { status: Some(200), ..Default::default() }),
    ] {
        let s = crate::PostgresStreamStore::new(&dsn, table).unwrap();
        assert_eq!(s.query(&filter, 10).unwrap().len(), 1, "{table}");
        s.insert(&row(json!({ "request_id": "r-rust", "event": "py_event", "status": 200 }))).unwrap();
        assert_eq!(s.count_matching(&filter).unwrap(), 2, "{table}");
        assert_eq!(s.query(&filter, 10).unwrap()[0]["request_id"], "r-rust");
    }
}

#[cfg(feature = "store-postgres")]
#[test]
fn a_lost_connection_does_not_rerun_an_insert() {
    let Some(dsn) = crate::test_support::pg_dsn() else { return };
    let table = uniq("lost");
    let s = crate::PostgresStreamStore::new(&dsn, &table).unwrap();
    s.insert(&row(json!({ "request_id": "before" }))).unwrap();
    let mut admin = pg::Client::connect(&dsn, pg::NoTls).unwrap();
    // End the store's session: its last query named the table.
    admin
        .batch_execute(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND datname = current_database() AND query LIKE '%{table}%'"
        ))
        .unwrap();
    // The INSERT on the dead connection fails and is not run again.
    assert!(s.insert(&row(json!({ "request_id": "lost" }))).is_err());
    // A read opens a new connection.
    assert_eq!(s.count().unwrap(), 1);
    s.insert(&row(json!({ "request_id": "after" }))).unwrap();
    assert_eq!(s.count().unwrap(), 2, "each row once");
}

#[cfg(feature = "store-postgres")]
#[test]
fn backends_include_postgres_when_required() {
    let labels: Vec<&str> = backends().iter().map(Backend::label).collect();
    if std::env::var("FASTEN_REQUIRE_POSTGRES").as_deref() == Ok("1") {
        assert!(labels.contains(&"postgres"), "{labels:?}");
    }
    assert!(labels.contains(&"sqlite"));
}
