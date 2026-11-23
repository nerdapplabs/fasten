//! Helpers the reader and stream tests share: the stores they run on, an
//! engine per test, and rows to read.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Once};
use std::time::Duration;

use serde_json::Value;

use crate::reader::{Auth, Reader, ReaderBuilder, Request, Response};
use crate::streams::StreamStore;
use crate::{AuditStore, Config, EmitBuilder, Engine, Row};

pub(crate) const CODE: &str = "READER_TEST_EVENT";

pub(crate) fn ensure_code() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let meta = crate::Meta { domain: "readertest".into(), action: "test".into(), ..Default::default() };
        crate::register("readertest".into(), [(CODE.to_string(), meta)]).unwrap();
    });
}

pub(crate) fn uniq(prefix: &str) -> String {
    format!("{prefix}_{}", &uuid::Uuid::new_v4().simple().to_string()[..12])
}

/// The Postgres DSN for tests; a failure, not a skip, when it is required.
#[cfg(feature = "store-postgres")]
pub(crate) fn pg_dsn() -> Option<String> {
    let dsn = std::env::var("FASTEN_TEST_POSTGRES_DSN").ok();
    assert!(
        dsn.is_some() || std::env::var("FASTEN_REQUIRE_POSTGRES").as_deref() != Ok("1"),
        "FASTEN_REQUIRE_POSTGRES=1 but FASTEN_TEST_POSTGRES_DSN is not set"
    );
    dsn
}

/// A database the tests write to.
#[derive(Clone, Debug)]
pub(crate) enum Backend {
    Sqlite(PathBuf),
    #[cfg(feature = "store-postgres")]
    Postgres(String),
}

/// Every backend this build can run: SQLite, and Postgres when a DSN is set.
pub(crate) fn backends() -> Vec<Backend> {
    let mut out = Vec::new();
    out.push(Backend::Sqlite(std::env::temp_dir().join(format!("{}.db", uniq("fasten_reader")))));
    #[cfg(feature = "store-postgres")]
    if let Some(dsn) = pg_dsn() {
        out.push(Backend::Postgres(dsn));
    }
    out
}

impl Backend {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Backend::Sqlite(_) => "sqlite",
            #[cfg(feature = "store-postgres")]
            Backend::Postgres(_) => "postgres",
        }
    }

    pub(crate) fn audit(&self, table: &str) -> Arc<dyn AuditStore> {
        match self {
            Backend::Sqlite(path) => Arc::new(crate::SqliteStore::open(path.to_str().unwrap(), table).unwrap()),
            #[cfg(feature = "store-postgres")]
            Backend::Postgres(dsn) => Arc::new(crate::PostgresStore::new(dsn, table).unwrap()),
        }
    }

    pub(crate) fn stream(&self, table: &str) -> Arc<dyn StreamStore> {
        match self {
            Backend::Sqlite(path) => Arc::new(crate::SqliteStreamStore::open(path.to_str().unwrap(), table).unwrap()),
            #[cfg(feature = "store-postgres")]
            Backend::Postgres(dsn) => Arc::new(crate::PostgresStreamStore::new(dsn, table).unwrap()),
        }
    }
}

/// One test's engine, stores and names.
pub(crate) struct Env {
    pub(crate) engine: &'static Engine,
    pub(crate) store: Arc<dyn AuditStore>,
    pub(crate) api: Arc<dyn StreamStore>,
    pub(crate) sys: Arc<dyn StreamStore>,
    pub(crate) service: String,
    pub(crate) node: String,
    pub(crate) tables: (String, String, String),
}

pub(crate) fn leak(engine: Engine) -> &'static Engine {
    Box::leak(Box::new(engine))
}

/// An engine that stores audit rows synchronously and both streams, with
/// search on.
pub(crate) fn setup(backend: &Backend, tenant: Option<&str>) -> Env {
    ensure_code();
    let tables = (uniq("audit"), uniq("api"), uniq("sys"));
    let store = backend.audit(&tables.0);
    let api = backend.stream(&tables.1);
    let sys = backend.stream(&tables.2);
    let service = uniq("svc");
    let node = uniq("node");
    let engine = leak(Engine::new());
    engine.init(config(&service, &node, tenant, &store, &api, &sys)).unwrap();
    Env { engine, store, api, sys, service, node, tables }
}

pub(crate) fn config(
    service: &str,
    node: &str,
    tenant: Option<&str>,
    store: &Arc<dyn AuditStore>,
    api: &Arc<dyn StreamStore>,
    sys: &Arc<dyn StreamStore>,
) -> Config {
    Config {
        service_id: service.into(),
        node_id: node.into(),
        tenant_id: tenant.map(str::to_string),
        audit_store: Some(Arc::clone(store)),
        audit_store_failure_strategy: Some("raise".into()),
        api_store: Some(Arc::clone(api)),
        syslog_store: Some(Arc::clone(sys)),
        search_enabled: true,
        ..Default::default()
    }
}

impl Env {
    /// A second engine on the same stores, for another tenant.
    pub(crate) fn tenant_engine(&self, tenant: &str) -> &'static Engine {
        let engine = leak(Engine::new());
        engine.init(config(&self.service, &self.node, Some(tenant), &self.store, &self.api, &self.sys)).unwrap();
        engine
    }

    pub(crate) fn reader(&self) -> Reader {
        self.builder().build().unwrap()
    }

    pub(crate) fn builder(&self) -> ReaderBuilder {
        Reader::builder().auth(Auth::bearer("tok")).engine(self.engine)
    }

    pub(crate) fn flush(&self) {
        assert!(self.engine.flush(Duration::from_secs(10)));
    }
}

/// Emit one audit row through `engine` (stored at once: raise mode).
pub(crate) fn emit(engine: &Engine, target: &str, rid: &str, detail: Value) -> Row {
    let detail: HashMap<String, Value> = match detail {
        Value::Object(m) => m.into_iter().collect(),
        _ => HashMap::new(),
    };
    crate::with_request_id(rid.into(), || {
        EmitBuilder::new(CODE, target).actor("alice", "user").detail(detail).submit_to(engine).unwrap()
    })
}

/// A sys line and an api row with this request id and tenant.
pub(crate) fn log_both(engine: &Engine, rid: &str, tenant: Option<&str>, note: &str) {
    crate::with_request_id(rid.into(), || {
        let mut sys = serde_json::json!({ "note": note });
        let mut api = serde_json::json!({ "method": "GET", "path": "/orders", "status": 200, "note": note });
        if let Some(t) = tenant {
            sys["tenant_id"] = t.into();
            api["tenant_id"] = t.into();
        }
        engine.log_sys("info", "order_viewed", sys);
        engine.log_api(api);
    });
}

pub(crate) fn get(reader: &Reader, target: &str) -> Response {
    reader.handle(&Request::new("GET", target).with_header("Authorization", "Bearer tok"))
}

pub(crate) fn get_ok(reader: &Reader, target: &str) -> Value {
    let res = get(reader, target);
    assert_eq!(res.status, 200, "{target}: {}", res.body);
    res.json()
}
