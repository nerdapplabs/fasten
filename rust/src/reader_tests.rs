//! Reader tests, run on every backend (SQLite, and Postgres when a DSN is
//! set). They follow the Python, Go and JS reader tests.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::reader::{require_bearer, Auth, Reader, Request};
use crate::streams::{StreamFilter, StreamRow, StreamStore};
use crate::test_support::{backends, emit, get, get_ok, leak, log_both, setup, uniq, Env};
use crate::{AuditQuery, AuditSearch, AuditStore, ChainRow, Engine, Error, Source};

const ROUTES: [&str; 7] = ["/audit", "/audit/doctor", "/correlate?request_id=r", "/search?q=x&since=2020-01-01T00:00:00Z", "/sys", "/api", "/topology"];

fn sys_events(event: &str) -> Vec<Value> {
    crate::engine::SYS_CAPTURE.lock().unwrap().iter().filter(|v| v["event"] == event).cloned().collect()
}

#[test]
fn auth_is_required() {
    let err = Reader::builder().build().err().unwrap().to_string();
    assert!(err.contains("auth is required"), "{err}");
    assert!(Reader::builder().auth(Auth::bearer("")).build().is_err());
    let r = Reader::builder().auth(Auth::None).engine(leak(Engine::new())).build().unwrap();
    assert_eq!(r.handle(&Request::new("GET", "/audit")).status, 200);
}

#[test]
fn require_bearer_reads_the_environment() {
    let name = uniq("FASTEN_TEST_READER_TOKEN");
    assert!(require_bearer(&name).is_err());
    std::env::set_var(&name, "from-env");
    assert!(matches!(require_bearer(&name), Ok(Auth::Bearer(t)) if t == "from-env"));
    std::env::remove_var(&name);
}

#[test]
fn enforce_tenant_isolation_needs_a_scope() {
    let err = Reader::builder().auth(Auth::None).enforce_tenant_isolation().build().err().unwrap().to_string();
    assert!(err.contains("tenant_scope"), "{err}");
    assert!(Reader::builder().auth(Auth::None).enforce_tenant_isolation().tenant_scope(|_| Some("t".into())).build().is_ok());
}

#[test]
fn every_route_needs_the_token() {
    let r = Reader::builder().auth(Auth::bearer("tok")).engine(leak(Engine::new())).build().unwrap();
    for path in ROUTES {
        for header in [None, Some("Bearer nope"), Some("bearer tok"), Some("Bearer tok "), Some("Basic tok"), Some("Bearer to")] {
            let mut req = Request::new("GET", path);
            if let Some(h) = header {
                req = req.with_header("Authorization", h);
            }
            let res = r.handle(&req);
            assert_eq!(res.status, 401, "{path} {header:?}");
            assert_eq!(res.json(), json!({ "detail": "unauthenticated" }));
        }
        assert_eq!(get(&r, path).status, 200, "{path}");
    }
}

#[test]
fn a_verify_function_decides() {
    let r = Reader::builder()
        .auth(Auth::verify(|req| req.header("x-key") == Some("k")))
        .engine(leak(Engine::new()))
        .build()
        .unwrap();
    assert_eq!(r.handle(&Request::new("GET", "/sys")).status, 401);
    assert_eq!(r.handle(&Request::new("GET", "/sys").with_header("X-Key", "k")).status, 200);
    let panics = Reader::builder().auth(Auth::verify(|_| panic!("secret"))).build().unwrap();
    let res = panics.handle(&Request::new("GET", "/sys"));
    assert_eq!(res.status, 401);
    assert!(!res.body.contains("secret"));
}

#[test]
fn unknown_paths_methods_and_prefix() {
    let r = Reader::builder().auth(Auth::None).engine(leak(Engine::new())).build().unwrap();
    assert!(r.try_handle(&Request::new("GET", "/nope")).is_none());
    assert_eq!(r.handle(&Request::new("GET", "/nope")).json(), json!({ "detail": "Not Found" }));
    for method in ["POST", "HEAD", "PUT", "DELETE", "get"] {
        let res = r.handle(&Request::new(method, "/audit"));
        assert_eq!(res.status, 405, "{method}");
        assert!(res.headers.contains(&("Allow".into(), "GET".into())));
    }
    let p = Reader::builder().auth(Auth::None).engine(leak(Engine::new())).prefix("/api/v1/logs/").build().unwrap();
    assert_eq!(p.handle(&Request::new("GET", "/api/v1/logs/audit")).status, 200);
    assert!(p.try_handle(&Request::new("GET", "/api/v1/logsx/audit")).is_none());
    assert!(p.try_handle(&Request::new("GET", "/audit")).is_none());
}

#[test]
fn paths_are_matched_as_sent() {
    let r = Reader::builder().auth(Auth::None).engine(leak(Engine::new())).prefix("/logs").build().unwrap();
    for path in [
        "/logs//audit", "/logs/./audit", "/logs/x/../audit", "/logs/audit/..", "/logs/audit/.", "/logs\\audit",
        "/logs/%61udit", "/logs%2Faudit", "/logs/%2e/audit", "/logs/audit%5c", "//logs/audit", "/logs/audit/",
    ] {
        assert!(r.try_handle(&Request::new("GET", path)).is_none(), "{path}");
    }
}

#[test]
fn auth_then_tenant_then_parameters() {
    let r = Reader::builder()
        .auth(Auth::bearer("tok"))
        .engine(leak(Engine::new()))
        .tenant_scope(|req| req.header("x-tenant").map(str::to_string))
        .build()
        .unwrap();
    let bad = "/audit?limit=0";
    assert_eq!(r.handle(&Request::new("GET", bad)).status, 401);
    let res = r.handle(&Request::new("GET", bad).with_header("Authorization", "Bearer tok"));
    assert_eq!((res.status, res.json()["detail"].clone()), (401, json!("unauthenticated: tenant scope unresolved")));
    let blank = r.handle(&Request::new("GET", bad).with_header("Authorization", "Bearer tok").with_header("X-Tenant", ""));
    assert_eq!(blank.status, 401);
    let res = r.handle(&Request::new("GET", bad).with_header("Authorization", "Bearer tok").with_header("X-Tenant", "t"));
    assert_eq!(res.status, 422);
}

#[test]
fn bad_parameters_are_422s() {
    let r = Reader::builder().auth(Auth::bearer("tok")).engine(leak(Engine::new())).build().unwrap();
    for (target, detail) in [
        ("/audit?limit=0", "limit must be between 1 and 1000"),
        ("/audit?limit=1001", "limit must be between 1 and 1000"),
        ("/audit?limit=abc", "limit must be an integer"),
        ("/audit?limit=1.5", "limit must be an integer"),
        ("/audit?offset=-1", "offset must be non-negative"),
        ("/audit?offset=9223372036854775808", "offset must be between -9223372036854775808 and 9223372036854775807"),
        ("/audit?after=0", "after must be >= 1 (monotonic_seq starts at 1; 0 is not a valid cursor)"),
        ("/audit?after=99999999999999999999", "after must be between -9223372036854775808 and 9223372036854775807"),
        ("/api?status=2147483648", "status must be between -2147483648 and 2147483647"),
        ("/api?status=-2147483649", "status must be between -2147483648 and 2147483647"),
        ("/api?status=ok", "status must be an integer"),
        ("/sys?event=a%00b", "event must not contain a NUL character"),
        ("/audit?unused=%00", "unused must not contain a NUL character"),
        ("/search?q=x&limit=201&since=2026-01-01T00:00:00Z", "limit must be between 1 and 200"),
        ("/search?since=2026-01-01T00:00:00Z", "q is required"),
        ("/search?q=x", "since is required"),
        ("/search?q=&since=x", "q must not be empty"),
        ("/correlate", "request_id is required"),
        ("/correlate?request_id=", "request_id is required"),
        ("/audit?since=yesterday", "since must be RFC3339 (e.g. 2026-08-21T10:00:00Z): Invalid isoformat string: 'yesterday'"),
        ("/topology?until=0000-01-01T00:00:00Z", "until must be RFC3339 (e.g. 2026-08-21T10:00:00Z): Invalid isoformat string: '0000-01-01T00:00:00Z'"),
    ] {
        let res = get(&r, target);
        assert_eq!(res.status, 422, "{target}: {}", res.body);
        assert_eq!(res.json()["detail"], detail, "{target}");
    }
    let long = "x".repeat(1025);
    assert_eq!(get(&r, &format!("/sys?q={long}")).json()["detail"], "q must be at most 1024 characters");
    for since in ["2026-08-21T10:00:00+24:00", "0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00", "2026-08-21"] {
        assert_eq!(get(&r, &format!("/audit?since={}", since.replace('+', "%2B"))).status, 422, "{since}");
    }
}

#[test]
fn without_init_the_routes_say_so() {
    let r = Reader::builder().auth(Auth::None).engine(leak(Engine::new())).build().unwrap();
    let get = |t: &str| r.handle(&Request::new("GET", t)).json();
    let audit = get("/audit");
    assert_eq!(audit["error"], "audit store not initialised — call fasten.init() first");
    assert_eq!((audit["total"].clone(), audit["next_after"].clone()), (json!(0), Value::Null));
    assert_eq!(audit["completeness"], json!({ "audit": "ring" }));
    assert_eq!(get("/sys")["error"], "transport not initialised — call fasten.init() first");
    assert_eq!(get("/api")["error"], "transport not initialised — call fasten.init() first");
    assert_eq!(get("/topology")["error"], "audit store not initialised — call fasten.init() first");
    let search = get("/search?q=x&since=2026-01-01T00:00:00Z");
    assert!(search["error"].as_str().unwrap().starts_with("search disabled"), "{search}");
    let corr = get("/correlate?request_id=r");
    assert_eq!(corr["totals"], json!({ "audit": null, "api": 0, "sys": 0 }));
    let doctor = get("/audit/doctor");
    assert_eq!(doctor["store"]["reachable"], false);
    assert_eq!(doctor["chain"]["verified"], Value::Null);
    assert_eq!(doctor["transport"]["stdout_active"], false);
}

#[test]
fn the_rings_serve_rows_without_a_store() {
    let engine = leak(Engine::new());
    engine.init(crate::Config { service_id: uniq("svc"), node_id: "n".into(), ..Default::default() }).unwrap();
    log_both(engine, "rid-ring", None, "hello");
    let r = Reader::builder().auth(Auth::None).engine(engine).build().unwrap();
    let sys = r.handle(&Request::new("GET", "/sys?event=order_viewed")).json();
    assert_eq!(sys["rows"].as_array().unwrap().len(), 1);
    assert_eq!(sys["completeness"], json!({ "sys": "ring" }));
    let api = r.handle(&Request::new("GET", "/api?status=200&request_id=rid-ring")).json();
    assert_eq!(api["rows"][0]["path"], "/orders");
    let search = r.handle(&Request::new("GET", "/search?q=x&since=2026-01-01T00:00:00Z")).json();
    assert!(search["error"].as_str().unwrap().starts_with("search disabled"));
    let r = Reader::builder().auth(Auth::None).engine(engine).search_enabled(true).build().unwrap();
    let search = r.handle(&Request::new("GET", "/search?q=hello&since=2026-01-01T00:00:00Z&streams=sys,api,audit")).json();
    assert_eq!(search["errors"], json!({
        "sys": "requires sys persistence: configure a syslog store",
        "api": "requires api persistence: configure an api store",
        "audit": "requires an audit store with a search method",
    }));
    assert_eq!(search["counts"], json!({ "sys": 0, "api": 0, "audit": 0 }));
}

#[test]
fn audit_rows_filters_and_paging() {
    for b in backends() {
        let env = setup(&b, Some("t1"));
        let mut rows = Vec::new();
        for i in 0..5 {
            rows.push(emit(env.engine, &format!("tgt-{i}"), &format!("rid-{i}"), json!({ "i": i, "who": "é<&>" })));
        }
        let r = env.reader();
        let all = get_ok(&r, "/audit");
        assert_eq!(all["total"], 5, "{}", b.label());
        assert_eq!(all["completeness"], json!({ "audit": "store" }));
        let first = &all["rows"][0];
        assert_eq!(first["target"], "tgt-4");
        assert_eq!(first["detail"], json!({ "i": 4, "who": "é<&>" }));
        assert_eq!(first["timestamp"].as_str().unwrap().len(), 27);
        assert_eq!(first["canonical_form_id"], "2");
        assert!(first["hash"].as_str().unwrap().len() == 64);
        assert_eq!(first["tenant_id"], "t1");
        // Two paging styles: a cursor and an offset.
        let page = get_ok(&r, "/audit?limit=2");
        assert_eq!(page["rows"].as_array().unwrap().len(), 2);
        let next = page["next_after"].as_u64().unwrap();
        let page2 = get_ok(&r, &format!("/audit?limit=2&after={next}"));
        assert_eq!(page2["rows"][0]["target"], "tgt-2");
        assert_eq!(page2["total"], 5);
        let off = get_ok(&r, "/audit?limit=2&offset=2");
        assert_eq!(off["rows"][0]["target"], "tgt-2");
        assert_eq!(off["offset"], 2);
        for (q, n) in [
            ("target=tgt-1", 1),
            ("request_id=rid-3", 1),
            ("actor=alice", 5),
            ("actor=bob", 0),
            ("code=READER_TEST_EVENT", 5),
            ("domain=readertest", 5),
            ("tenant_id=t1", 5),
            ("tenant_id=other", 0),
            ("tenant_id=", 0),
            (&format!("source_node_id={}", env.node), 5),
            ("since=2000-01-01T00:00:00%2B05:00", 5),
            ("until=2000-01-01T00:00:00Z", 0),
        ] {
            assert_eq!(get_ok(&r, &format!("/audit?{q}"))["total"], n, "{} {q}", b.label());
        }
        // A since in another offset is made canonical.
        let ts = rows[2].timestamp;
        let local = ts.with_timezone(&chrono::FixedOffset::east_opt(5 * 3600 + 1800).unwrap());
        let since = local.format("%Y-%m-%dT%H:%M:%S%.6f%:z").to_string().replace('+', "%2B");
        assert_eq!(get_ok(&r, &format!("/audit?since={since}"))["total"], 3, "{}", b.label());
    }
}

#[test]
fn exact_numbers_and_text_come_back() {
    for b in backends() {
        let env = setup(&b, None);
        let mut row = ChainRow::from(&crate::engine::sdk_row_to_core(&emit(env.engine, "seed", "rid-seed", json!({}))));
        // A row sealed elsewhere with a number serde_json cannot hold.
        row.id = "evt-exact".into();
        row.origin_id = "evt-exact".into();
        row.monotonic_seq += 1;
        row.detail = crate::Json::parse(r#"{"big": 123456789012345678901234567890, "f": 75.0, "s": "é"}"#).unwrap();
        row.detail_salt = Some("aa".repeat(16));
        row.detail_commitment = Some(fasten_core::chain::detail_commitment(row.detail_salt.as_deref().unwrap(), &row.detail));
        let prev = row.hash.clone();
        row.prev_hash = prev.clone();
        let sealed = fasten_core::chain::seal(&prev, &row).unwrap();
        match &b {
            crate::test_support::Backend::Sqlite(path) => {
                crate::SqliteStore::open(path.to_str().unwrap(), &env.tables.0).unwrap().insert_sealed(&sealed, false).unwrap();
            }
            #[cfg(feature = "store-postgres")]
            crate::test_support::Backend::Postgres(dsn) => {
                crate::PostgresStore::new(dsn, &env.tables.0).unwrap().insert_sealed(&sealed, false).unwrap();
            }
        }
        let res = get(&env.reader(), "/audit?limit=1");
        assert!(res.body.contains(r#""big":123456789012345678901234567890"#), "{}", res.body);
        assert!(res.body.contains(r#""f":75.0"#), "{}", res.body);
        let doctor = get_ok(&env.reader(), "/audit/doctor");
        assert_eq!(doctor["chain"]["verified"], true, "{} {doctor}", b.label());
        assert_eq!(doctor["chain"]["sealed_rows"], 2);
    }
}

#[test]
fn streams_correlate_topology() {
    for b in backends() {
        let env = setup(&b, None);
        emit(env.engine, "o-1", "rid-c", json!({}));
        emit(env.engine, "o-2", "rid-c", json!({}));
        log_both(env.engine, "rid-c", None, "first");
        log_both(env.engine, "rid-c", None, "second");
        log_both(env.engine, "rid-other", None, "third");
        env.flush();
        let r = env.reader();
        let sys = get_ok(&r, "/sys?event=order_viewed&request_id=rid-c");
        assert_eq!(sys["rows"].as_array().unwrap().len(), 2, "{}", b.label());
        assert_eq!(sys["rows"][0]["note"], "second");
        assert_eq!(sys["completeness"], json!({ "sys": "store" }));
        assert_eq!(sys["rows"][0]["timestamp"].as_str().unwrap().len(), 27);
        let api = get_ok(&r, "/api?method=GET&path=/orders&status=200");
        assert_eq!(api["rows"].as_array().unwrap().len(), 3);
        assert_eq!(get_ok(&r, "/api?status=404")["rows"], json!([]));
        assert_eq!(get_ok(&r, "/sys?level=INFO&event=order_viewed")["rows"], json!([]));

        let c = get_ok(&r, "/correlate?request_id=rid-c&limit=1");
        assert_eq!(c["counts"], json!({ "audit": 1, "api": 1, "sys": 1 }));
        assert_eq!(c["totals"], json!({ "audit": 2, "api": 2, "sys": 2 }));
        assert_eq!(c["truncated"], json!({ "audit": true, "api": true, "sys": true }));
        assert_eq!(c["completeness"], json!({ "audit": "store", "api": "store", "sys": "store" }));
        let c = get_ok(&r, "/correlate?request_id=rid-c");
        assert_eq!(c["truncated"], json!({ "audit": false, "api": false, "sys": false }));
        assert_eq!(c["audit"][0]["target"], "o-2");

        let topo = get_ok(&r, "/topology");
        assert_eq!(topo["nodes"], 1);
        assert_eq!(topo["services"], 1);
        assert_eq!(topo["tenants"], 0);
        assert_eq!(topo["sources"][0]["rows"], 2);
        assert_eq!(topo["sources"][0]["source_node_id"], env.node);
        assert_eq!(get_ok(&r, "/topology?until=2000-01-01T00:00:00Z")["sources"], json!([]));
    }
}

#[test]
fn search_and_q() {
    for b in backends() {
        let env = setup(&b, None);
        let notes = ["100% sure", "plain", "a_b", "axb", r"c\d", "cd", "MiXeD"];
        for n in notes {
            emit(env.engine, "t", "rid-s", json!({ "note": n }));
            env.engine.log_sys("info", "note", json!({ "note": n }));
            env.engine.log_api(json!({ "method": "GET", "path": format!("/n/{n}"), "status": 200 }));
        }
        env.flush();
        let r = env.reader();
        let since = "since=2000-01-01T00:00:00Z";
        // A broken escape would match more rows than these.
        for (q, want) in [("%25", "100% sure"), ("a_b", "a_b"), ("%5C", r"c\d"), ("mixed", "MiXeD")] {
            for stream in ["sys", "api", "audit"] {
                let res = get_ok(&r, &format!("/search?q={q}&{since}&streams={stream}"));
                let m = res["matches"].as_array().unwrap();
                assert_eq!(m.len(), 1, "{} {stream} {q}: {res}", b.label());
                let text = m[0]["row"].to_string();
                assert!(text.contains(&want.replace('\\', "\\\\")), "{text}");
            }
        }
        let res = get_ok(&r, &format!("/search?q=plain&{since}&streams=audit,api,%20sys,sys"));
        let order: Vec<&str> = res["matches"].as_array().unwrap().iter().map(|m| m["stream"].as_str().unwrap()).collect();
        assert_eq!(order, ["sys", "api", "audit"]);
        assert_eq!(res["counts"], json!({ "sys": 1, "api": 1, "audit": 1 }));
        assert_eq!(res["matches"][0]["summary"], "note");
        assert_eq!(res["matches"][1]["summary"], "GET /n/plain");
        assert_eq!(res["matches"][2]["summary"], "READER_TEST_EVENT");
        assert!(res.get("errors").is_none());
        let bad = get(&r, &format!("/search?q=x&{since}&streams=sys,bogus,it's"));
        assert_eq!(bad.status, 400);
        assert_eq!(bad.json()["detail"], r#"streams=['bogus', "it's", 'sys']: unknown stream(s) ['bogus', "it's"]. Valid: ['api', 'audit', 'sys']."#);
        assert_eq!(get_ok(&r, &format!("/search?q=plain&{since}&until=2000-01-02T00:00:00Z"))["matches"], json!([]));

        // q= on /sys.
        assert_eq!(get_ok(&r, &format!("/sys?q=plain&{since}"))["rows"].as_array().unwrap().len(), 1);
        assert_eq!(get_ok(&r, "/sys?q=plain")["error"], "q= search requires a 'since' bound (no unbounded scans)");
        let mixed = get(&r, &format!("/sys?q=plain&{since}&level=info&event=x"));
        assert_eq!(mixed.status, 400);
        assert!(mixed.json()["detail"].as_str().unwrap().contains("(level, event)"));
        let api_q = get(&r, "/api?q=plain");
        assert_eq!(api_q.status, 400);
        assert!(api_q.json()["detail"].as_str().unwrap().starts_with("free-text q= not accepted on /api"));
        let off = env.builder().search_enabled(false).build().unwrap();
        assert!(get_ok(&off, &format!("/sys?q=plain&{since}"))["error"].as_str().unwrap().starts_with("search disabled"));
    }
}

#[test]
fn tenant_scope_applies_to_every_row() {
    for b in backends() {
        let env = setup(&b, Some("t1"));
        let other = env.tenant_engine("t2");
        emit(env.engine, "mine", "rid-shared", json!({ "note": "needle" }));
        emit(other, "theirs", "rid-shared", json!({ "note": "needle" }));
        emit(other, "theirs-2", "rid-theirs", json!({ "note": "needle" }));
        log_both(env.engine, "rid-shared", Some("t1"), "needle");
        log_both(other, "rid-shared", Some("t2"), "needle");
        log_both(other, "rid-shared", None, "needle");
        env.flush();
        let r = env
            .builder()
            .tenant_scope(|req| req.header("x-tenant").map(str::to_string))
            .build()
            .unwrap();
        let get_t = |target: &str| {
            let res = r.handle(&Request::new("GET", target).with_header("Authorization", "Bearer tok").with_header("X-Tenant", "t1"));
            assert_eq!(res.status, 200, "{target}: {}", res.body);
            res.json()
        };
        for path in ROUTES {
            let res = r.handle(&Request::new("GET", path).with_header("Authorization", "Bearer tok"));
            assert_eq!(res.status, 401, "{path}");
        }
        let audit = get_t("/audit?tenant_id=t2");
        assert_eq!(audit["total"], 1, "{} {audit}", b.label());
        assert_eq!(audit["rows"][0]["target"], "mine");
        let c = get_t("/correlate?request_id=rid-shared");
        assert_eq!(c["counts"], json!({ "audit": 1, "api": 1, "sys": 1 }));
        assert_eq!(c["totals"], json!({ "audit": 1, "api": 1, "sys": 1 }));
        assert_eq!(c["truncated"], json!({ "audit": false, "api": false, "sys": false }));
        assert!(c.to_string().matches("t2").count() == 0, "{c}");
        assert_eq!(get_t("/correlate?request_id=rid-theirs")["audit"], json!([]));
        assert_eq!(get_t("/sys?request_id=rid-shared")["rows"].as_array().unwrap().len(), 1);
        assert_eq!(get_t("/api?request_id=rid-shared")["rows"].as_array().unwrap().len(), 1);
        let s = get_t("/search?q=needle&since=2000-01-01T00:00:00Z&streams=sys,api,audit");
        assert_eq!(s["counts"], json!({ "sys": 1, "api": 1, "audit": 1 }), "{} {s}", b.label());
        let topo = get_t("/topology");
        assert_eq!((topo["tenants"].clone(), topo["sources"][0]["rows"].clone()), (json!(1), json!(1)));
        let d = get_t("/audit/doctor");
        assert_eq!(d["store"]["rows"], 1);
        assert_eq!(d["store"]["kind"], Value::Null);
        assert_eq!((d["queue"].clone(), d["transport"].clone()), (Value::Null, Value::Null));
        for k in ["service_id", "node_id", "tenant_id", "worker_pid"] {
            assert_eq!(d["init"][k], Value::Null, "{k}");
        }
        assert_eq!(d["init"]["failure_strategy"], "raise");
        assert_eq!(d["chain"]["verified"], true);
        // Unscoped, the doctor reports the host.
        let d = get_ok(&env.reader(), "/audit/doctor");
        assert_eq!(d["store"]["rows"], 3);
        assert_eq!(d["init"]["tenant_id"], "t1");
        assert!(d["init"]["worker_pid"].is_u64());
        assert!(d["store"]["kind"].is_string());
    }
}

/// Returns every row whatever the filter, and can alter its chain sample.
struct Loose {
    rows: Vec<ChainRow>,
    tamper: bool,
    fail: Option<&'static str>,
}

impl AuditStore for Loose {
    fn insert(&self, _: &crate::Row) -> Result<(), Error> {
        Ok(())
    }
    fn seals(&self) -> bool {
        true
    }
    fn query(&self, _: &AuditQuery) -> Result<Vec<ChainRow>, Error> {
        match self.fail {
            Some(m) => Err(Error::AuditStoreRead(m.into())),
            None => Ok(self.rows.clone()),
        }
    }
    fn count(&self, _: &AuditQuery) -> Result<u64, Error> {
        match self.fail {
            Some(m) => Err(Error::AuditStoreRead(m.into())),
            None => Ok(self.rows.len() as u64),
        }
    }
    fn search(&self, _: &AuditSearch) -> Result<Vec<ChainRow>, Error> {
        Ok(self.rows.clone())
    }
    fn sources(&self, _: Option<&str>, _: Option<&str>) -> Result<Vec<Source>, Error> {
        Ok(Vec::new())
    }
    fn chain_tail(&self, _: &str, _: u32) -> Result<Vec<ChainRow>, Error> {
        if let Some(m) = self.fail {
            return Err(Error::AuditStoreRead(m.into()));
        }
        let mut rows = self.rows.clone();
        if self.tamper {
            rows[1].target = "changed".into();
        }
        Ok(rows)
    }
}

fn sealed_rows(env: &Env) -> Vec<ChainRow> {
    for i in 0..3 {
        emit(env.engine, &format!("x{i}"), "rid-l", json!({ "i": i }));
    }
    let other = env.tenant_engine("t2");
    emit(other, "theirs", "rid-l", json!({}));
    env.store.chain_tail(&env.node, 50).unwrap()
}

#[test]
fn rows_from_a_store_that_ignores_the_tenant_are_still_scoped() {
    let b = &backends()[0];
    let env = setup(b, Some("t1"));
    let rows = sealed_rows(&env);
    assert_eq!(rows.len(), 4);
    let store: Arc<dyn AuditStore> = Arc::new(Loose { rows, tamper: false, fail: None });
    let r = env.builder().audit_store(Some(store)).tenant_scope(|_| Some("t1".into())).build().unwrap();
    for target in ["/audit", "/correlate?request_id=rid-l", "/search?q=x&since=2000-01-01T00:00:00Z&streams=audit"] {
        let body = get(&r, target).body;
        assert!(!body.contains("theirs"), "{target}: {body}");
        assert!(body.contains("x2"), "{target}: {body}");
    }
}

#[test]
fn doctor_reports_a_break_and_hides_it_from_a_scoped_caller() {
    for b in backends() {
        let env = setup(&b, Some("t1"));
        let rows = sealed_rows(&env);
        let seq = rows[1].monotonic_seq;
        let store: Arc<dyn AuditStore> = Arc::new(Loose { rows, tamper: true, fail: None });
        let r = env.builder().audit_store(Some(Arc::clone(&store))).build().unwrap();
        let chain = get_ok(&r, "/audit/doctor")["chain"].clone();
        assert_eq!(chain["verified"], false);
        assert_eq!(chain["breaks"], 1);
        assert_eq!(chain["first_break_at"], seq);
        assert!(chain["reason"].as_str().unwrap().contains("hash mismatch"), "{chain}");
        let scoped = env.builder().audit_store(Some(store)).tenant_scope(|_| Some("t1".into())).build().unwrap();
        let chain = get_ok(&scoped, "/audit/doctor")["chain"].clone();
        assert_eq!(chain["first_break_at"], Value::Null);
        assert_eq!(chain["reason"], "chain break in this node's recent rows");
    }
}

#[test]
fn doctor_without_sealed_rows_and_with_failures() {
    let b = &backends()[0];
    let env = setup(b, None);
    // No rows: not checked, not clean.
    let d = get_ok(&env.reader(), "/audit/doctor");
    assert_eq!(d["chain"]["verified"], Value::Null);
    assert_eq!(d["chain"]["breaks"], Value::Null);
    assert_eq!(d["chain"]["sealed_rows"], 0);
    assert_eq!(d["chain"]["reason"], "no sealed rows in sample");
    assert_eq!(d["store"]["reachable"], true);
    assert_eq!(d["store"]["rows"], 0);
    // Unsealed rows only.
    let mut row = sealed_rows(&env).remove(0);
    row.hash.clear();
    let store: Arc<dyn AuditStore> = Arc::new(Loose { rows: vec![row], tamper: false, fail: None });
    let d = get_ok(&env.builder().audit_store(Some(store)).build().unwrap(), "/audit/doctor");
    assert_eq!((d["chain"]["verified"].clone(), d["chain"]["sealed_rows"].clone()), (Value::Null, json!(0)));
    // A failing store: fixed text, logged by type, never reachable.
    let failing: Arc<dyn AuditStore> = Arc::new(Loose { rows: vec![], tamper: false, fail: Some("host=db password=hunter2") });
    let r = env.builder().audit_store(Some(failing)).build().unwrap();
    let res = get(&r, "/audit/doctor");
    assert!(!res.body.contains("hunter2"), "{}", res.body);
    let d = res.json();
    assert_eq!(d["store"]["reachable"], false);
    assert_eq!(d["store"]["last_error"], "store check failed; see the service log");
    assert_eq!(d["chain"]["reason"], "chain check failed; see the service log");
    assert_eq!(d["chain"]["error"], "AuditStoreRead");
    assert_eq!(d["chain"]["verified"], Value::Null);
    let logged = sys_events("doctor_check_failed");
    assert!(logged.iter().any(|l| l["error_type"] == "AuditStoreRead" && l["service_id"] == env.service.as_str()));
    assert!(!logged.iter().any(|l| l.to_string().contains("hunter2")));
    // /audit: a 500 logged by type only.
    let res = get(&r, "/audit");
    assert_eq!((res.status, res.json()), (500, json!({ "detail": "internal error" })));
    let logged = sys_events("reader_query_failed");
    assert!(logged.iter().any(|l| l["path"] == "/audit" && l["error_type"] == "AuditStoreRead"));
    assert!(!logged.iter().any(|l| l.to_string().contains("hunter2")));
}

#[test]
fn a_store_that_does_not_seal_is_never_verified() {
    struct Plain;
    impl AuditStore for Plain {
        fn insert(&self, _: &crate::Row) -> Result<(), Error> {
            Ok(())
        }
    }
    let engine = leak(Engine::new());
    engine
        .init(crate::Config { service_id: uniq("svc"), node_id: "n".into(), audit_store: Some(Arc::new(Plain)), ..Default::default() })
        .unwrap();
    let r = Reader::builder().auth(Auth::None).engine(engine).build().unwrap();
    let d = r.handle(&Request::new("GET", "/audit/doctor")).json();
    assert_eq!(d["chain"]["verified"], false);
    assert_eq!(d["chain"]["chain_unavailable"], true);
    assert_eq!(d["chain"]["reason"], "the store has no chain_tail");
    // Nothing succeeded, so not reachable.
    assert_eq!(d["store"]["reachable"], false);
    assert_eq!(d["store"]["kind"], "AuditStore");
    let audit = r.handle(&Request::new("GET", "/audit"));
    assert_eq!(audit.status, 500);
    let topo = r.handle(&Request::new("GET", "/topology")).json();
    assert_eq!(topo["error"], "store does not support topology aggregation");
}

/// A stream store that answers reads from a fixed list and fails writes.
struct Fixed(Vec<StreamRow>);

impl StreamStore for Fixed {
    fn insert(&self, _: &StreamRow) -> Result<(), Error> {
        Err(Error::StreamStore("down".into()))
    }
    fn query(&self, _: &StreamFilter, _: u32) -> Result<Vec<StreamRow>, Error> {
        Ok(self.0.clone())
    }
    fn count_matching(&self, _: &StreamFilter) -> Result<u64, Error> {
        Ok(self.0.len() as u64)
    }
    fn search(&self, _: &str, _: &str, _: Option<&str>, _: u32) -> Result<Vec<StreamRow>, Error> {
        Ok(self.0.clone())
    }
    fn purge(&self, _: chrono::DateTime<chrono::Utc>) -> Result<u64, Error> {
        Ok(0)
    }
    fn degraded(&self) -> bool {
        true
    }
}

#[test]
fn reader_stream_options() {
    let row: StreamRow = serde_json::from_value(json!({ "event": "given", "request_id": "r" })).unwrap();
    let engine = leak(Engine::new());
    engine.init(crate::Config { service_id: uniq("svc"), node_id: "n".into(), ..Default::default() }).unwrap();
    engine.log_api(json!({ "path": "/own" }));
    let r = Reader::builder()
        .auth(Auth::None)
        .engine(engine)
        .syslog_store(Some(Arc::new(Fixed(vec![row]))))
        .audit_store(None)
        .build()
        .unwrap();
    let sys = r.handle(&Request::new("GET", "/sys")).json();
    assert_eq!(sys["rows"][0]["event"], "given");
    assert_eq!(sys["completeness"], json!({ "sys": "store-degraded" }));
    let api = r.handle(&Request::new("GET", "/api")).json();
    assert_eq!(api["rows"][0]["path"], "/own");
    assert_eq!(api["completeness"], json!({ "api": "ring" }));
    assert_eq!(r.handle(&Request::new("GET", "/audit")).json()["error"], "audit store not initialised — call fasten.init() first");
}

#[test]
fn a_repeated_parameter_takes_its_last_value() {
    let b = &backends()[0];
    let env = setup(b, Some("t1"));
    emit(env.engine, "a", "r1", json!({}));
    emit(env.engine, "b", "r2", json!({}));
    let r = env.reader();
    assert_eq!(get_ok(&r, "/audit?target=a&target=b")["rows"][0]["target"], "b");
    assert_eq!(get_ok(&r, "/audit?limit=abc&limit=1")["rows"].as_array().unwrap().len(), 1);
    assert_eq!(get_ok(&r, "/audit?target=a+b")["total"], 0);
}
