//! The fasten HTTP reader behind tiny_http, with stored sys and api logs.
//!
//! Run:
//!
//!     cd rust
//!     FASTEN_READER_TOKEN=s3cret cargo run --example reader --features store-sqlite
//!     curl -H 'Authorization: Bearer s3cret' http://localhost:8081/logs/sys
//!     curl -H 'Authorization: Bearer s3cret' 'http://localhost:8081/logs/audit/doctor'

use std::sync::Arc;

use fasten::reader::{require_bearer, Reader, Request};
use fasten::Config;
use tiny_http::{Header, Response, Server};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    fasten::init(Config {
        service_id: "reader-demo".into(),
        node_id: "host-01".into(),
        search_enabled: true,
        audit_store: Some(Arc::new(fasten::SqliteStore::open("demo.db", "audit_log")?)),
        api_store: Some(Arc::new(fasten::SqliteStreamStore::open("demo.db", "api_log")?)),
        syslog_store: Some(Arc::new(fasten::SqliteStreamStore::open("demo.db", "syslog")?)),
        ..Default::default()
    })?;
    fasten::log::info("reader_demo_started", serde_json::json!({}));

    let reader = Reader::builder().auth(require_bearer("FASTEN_READER_TOKEN")?).prefix("/logs").build()?;
    let server = Server::http("127.0.0.1:8081")?;
    println!("listening on :8081");
    for req in server.incoming_requests() {
        let mut r = Request::new(&req.method().to_string(), req.url());
        for h in req.headers() {
            r = r.with_header(h.field.as_str().as_str(), h.value.as_str());
        }
        let res = reader.handle(&r);
        fasten::log::api(serde_json::json!({ "method": r.method, "path": r.path, "status": res.status }));
        let mut out = Response::from_string(res.body).with_status_code(res.status);
        for (k, v) in &res.headers {
            out.add_header(Header::from_bytes(k.as_bytes(), v.as_bytes()).map_err(|()| "header")?);
        }
        let _ = req.respond(out);
    }
    Ok(())
}
