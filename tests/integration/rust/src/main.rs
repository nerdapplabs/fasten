// Rust smoke: register, init, fasten::log::info (sys), EmitBuilder::emit (audit) with PII.
use std::collections::HashMap;

use fasten::{init, log, register, Config, EmitBuilder, Meta, RetentionClass, Severity};

fn main() {
    register(
        "user".to_string(),
        [(
            "USER_CREATED".to_string(),
            Meta {
                id: "USER_CREATED".into(),
                domain: "user".into(),
                category: "account".into(),
                action: "create".into(),
                severity: Severity::Info,
                description: "New user account created".into(),
                emitter: "auth-service".into(),
                retention_class: RetentionClass::Long,
                high_volume: false,
                pii_in_detail: false,
                declared_unused: false,
            },
        )],
    )
    .expect("register");

    init(Config {
        service_id: "itest-rust".into(),
        node_id: "host-itest".into(),
        tenant_id: None,
        extra_redact_keys: None,
    })
    .expect("init");

    // 1. sys row
    log::info("startup_ok", serde_json::json!({"lang": "rust"}));

    // 2. audit row with PII detail
    let mut detail: HashMap<String, serde_json::Value> = HashMap::new();
    detail.insert("email".into(), serde_json::json!("alice@acme.com"));
    detail.insert("api_key".into(), serde_json::json!("sk-secret-abc"));
    detail.insert(
        "nested".into(),
        serde_json::json!({"token": "xyz", "preserved": "ok"}),
    );

    EmitBuilder::new("USER_CREATED", "u-42")
        .actor("admin", "user")
        .detail(detail)
        .emit(None)
        .expect("emit");
}
