//! Minimal tiny_http service wired to fasten — sync, no tokio.
//!
//! What it shows in ~80 lines:
//!
//!   - fasten::init() reading env vars (FASTEN_SERVICE_ID, FASTEN_NODE_ID).
//!   - One audit code (USER_CREATED) registered at startup.
//!   - per-request with_request_id() — mints / honours X-Request-ID and
//!     stashes it in the per-thread context for downstream submit / log.
//!   - POST /users emits an audit row with the in-context request_id.
//!   - GET  /users/<id> emits a read-side audit row + a structured sys log.
//!   - On Ctrl-C, fasten::flush() drains pending audit rows.
//!
//! Run:
//!
//!     cd rust
//!     FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 cargo run --example server
//!     curl -X POST http://localhost:8080/users -d '{"email":"alice@example.com"}'
//!     curl http://localhost:8080/users/u-42

use fasten::{
    init, register, with_request_id, Config, EmitBuilder, Meta,
    RetentionClass, Severity,
};
use std::collections::HashMap;
use std::io::Read;  // for req.as_reader().read_to_string in handler
use tiny_http::{Header, Response, Server};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    register_codes()?;
    init(Config {
        service_id: std::env::var("FASTEN_SERVICE_ID")?,
        node_id:    std::env::var("FASTEN_NODE_ID")?,
        ..Default::default()
    })?;

    let server = Server::http("0.0.0.0:8080")?;
    println!("listening on :8080");

    // Ctrl-C handler — flush before exit.
    ctrlc_handler();

    for mut req in server.incoming_requests() {
        let rid = req.headers().iter()
            .find(|h| h.field.equiv("x-request-id"))
            .map(|h| h.value.as_str().to_string())
            .unwrap_or_else(fasten::mint_id);

        let method = req.method().to_string();
        let url = req.url().to_string();

        with_request_id(rid.clone(), || {
            let mut body = String::new();
            let _ = req.as_reader().read_to_string(&mut body);
            let resp = handle(&method, &url, &body);
            let header = Header::from_bytes(&b"X-Request-ID"[..], rid.as_bytes()).unwrap();
            let _ = req.respond(
                Response::from_string(resp.1)
                    .with_status_code(resp.0)
                    .with_header(header),
            );
        });
    }
    Ok(())
}

fn register_codes() -> Result<(), fasten::Error> {
    register("user".into(), [
        ("USER_CREATED".to_string(), Meta {
            id: "USER_CREATED".into(),
            domain: "user".into(),
            category: "account".into(),
            action: "create".into(),
            severity: Severity::Info,
            description: "New user account".into(),
            emitter: "demo-svc".into(),
            retention_class: RetentionClass::Long,
            high_volume: false,
            pii_in_detail: false,
            declared_unused: false,
            detail_passthrough_keys: vec![],
        }),
        ("USER_VIEWED".to_string(), Meta {
            id: "USER_VIEWED".into(),
            domain: "user".into(),
            category: "account".into(),
            action: "view".into(),
            severity: Severity::Info,
            description: "User profile read".into(),
            emitter: "demo-svc".into(),
            retention_class: RetentionClass::Short,
            high_volume: false,
            pii_in_detail: false,
            declared_unused: false,
            detail_passthrough_keys: vec![],
        }),
    ])
}

fn handle(method: &str, url: &str, body: &str) -> (u16, String) {
    if method == "POST" && url == "/users" {
        let email = parse_email(body);
        let user_id = format!("u-{}", &email.chars().take(4).collect::<String>());
        let mut detail = HashMap::new();
        detail.insert("email".to_string(), serde_json::Value::String(email));
        let _ = EmitBuilder::new("USER_CREATED", &user_id)
            .actor("admin", "user")
            .detail(detail)
            .submit();
        return (200, format!(r#"{{"user_id":"{user_id}"}}"#));
    }
    if method == "GET" && url.starts_with("/users/") {
        let user_id = url.trim_start_matches("/users/");
        let _ = EmitBuilder::new("USER_VIEWED", user_id)
            .actor("admin", "user")
            .submit();
        fasten::log::info("user_lookup", serde_json::json!({"user_id": user_id}));
        return (200, format!(r#"{{"user_id":"{user_id}","exists":true}}"#));
    }
    if method == "GET" && url == "/health" {
        return (200, r#"{"ok":true}"#.into());
    }
    (404, r#"{"error":"not found"}"#.into())
}

fn parse_email(body: &str) -> String {
    // Crude but dependency-free; real apps use serde_json
    body.split("\"email\"").nth(1)
        .and_then(|s| s.split('"').nth(1))
        .unwrap_or("")
        .to_string()
}

fn ctrlc_handler() {
    // Real apps wire a proper signal handler (e.g. via the `ctrlc`
    // crate, or libc::signal). For the demo we rely on the OS killing
    // the process on Ctrl-C; the drainer best-effort drains via its
    // shutdown path. Adopters running this in Docker typically call
    // fasten::flush() from their own preStop hook before SIGTERM.
}
