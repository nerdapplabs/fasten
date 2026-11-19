//! Hash chain tests (spec/chain-replication.md): the cross-SDK vectors in
//! spec/ and go/, and tamper detection.

use std::collections::BTreeMap;
use std::path::Path;

use fasten_core::chain::{
    canonical_json, detail_commitment, row_hash, seal, verify_chain, ChainRow, Json, JsonString,
    CURRENT_CANONICAL_FORM_ID,
};
use fasten_core::row::Row;

fn load(path: &str) -> Json {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(path);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Json::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn rows(v: &Json) -> Vec<ChainRow> {
    v.as_array().unwrap().iter().map(|r| ChainRow::from_value(r).unwrap()).collect()
}

/// (label, row) for a file of `{"label": ..., "row": ...}` cases.
fn cases(v: &Json) -> Vec<(String, ChainRow)> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let label = c.get("label").and_then(Json::as_str).unwrap().to_string();
            (label, ChainRow::from_value(c.get("row").unwrap()).unwrap())
        })
        .collect()
}

fn assert_verifies(label: &str, rows: &[ChainRow]) {
    let res = verify_chain(rows);
    assert!(res.ok, "{label}: {:?}", res.reason);
    assert_eq!(res.total_rows, rows.len());
    assert_eq!((res.first_break_at, res.first_break_node), (None, None));
}

// A vector row with no hash would verify as an unsealed row and prove nothing.
fn assert_sealed(label: &str, row: &ChainRow) {
    assert_eq!(row.hash.len(), 64, "{label}: no hash");
}

fn assert_commitment(label: &str, row: &ChainRow) {
    if row.canonical_form_id == "2" && row.detail != Json::Null {
        let salt = row.detail_salt.as_deref().unwrap();
        assert_eq!(
            Some(detail_commitment(salt, &row.detail)),
            row.detail_commitment,
            "{label}: commitment"
        );
    }
}

fn base_row(seq: u64) -> ChainRow {
    ChainRow::from_json(&format!(
        r#"{{"wire_version": "1", "id": "evt-{seq}", "origin_id": "evt-{seq}",
            "monotonic_seq": {seq}, "timestamp": "2026-06-15T10:30:4{seq}.000000Z",
            "code": "ORDER_PLACED", "action": "create", "severity": "info",
            "service_id": "gateway", "source_node_id": "node-1", "tenant_id": null,
            "actor": "alice", "actor_kind": "user", "target": "order/{seq}",
            "category": "order", "domain": "sales", "method": "http",
            "request_id": "req-{seq}", "detail": {{"qty": {seq}, "price": 75.0}}}}"#
    ))
    .unwrap()
}

/// A sealed chain of `n` rows on node-1, seq 1 to n.
fn chain(n: u64) -> Vec<ChainRow> {
    let mut out: Vec<ChainRow> = Vec::new();
    for seq in 1..=n {
        let prev = out.last().map_or("genesis", |r| r.hash.as_str()).to_string();
        out.push(seal(&prev, &base_row(seq)).unwrap());
    }
    out
}

fn assert_breaks_at(rows: &[ChainRow], seq: u64, reason: &str) {
    let res = verify_chain(rows);
    assert!(!res.ok, "verified, wanted a break at {seq}");
    assert_eq!(res.first_break_at, Some(seq), "{:?}", res.reason);
    let got = res.reason.unwrap();
    assert!(got.contains(reason), "reason {got:?} lacks {reason:?}");
}

// --- canonical JSON ---

#[test]
fn canonical_json_matches_cpython() {
    // Each expected value is json.dumps(json.loads(input), sort_keys=True,
    // separators=(',', ':')) in CPython.
    let cases = [
        (r#"{"b": 1, "a": {"d": [1, 2 ,3], "c": null}, "B": true}"#, r#"{"B":true,"a":{"c":null,"d":[1,2,3]},"b":1}"#),
        (r#"{"a":0.00005,"b":"0.00005","c":-0,"d":[1e-7,7,{"e":1.0E+2}],"f":"x\"0.1","g":-12.50,"h":12345678901234567890}"#,
         r#"{"a":5e-05,"b":"0.00005","c":0,"d":[1e-07,7,{"e":100.0}],"f":"x\"0.1","g":-12.5,"h":12345678901234567890}"#),
        (r#"{"a":1e400,"b":-1e400,"c":1e-400,"d":-1e-400}"#, r#"{"a":Infinity,"b":-Infinity,"c":0.0,"d":-0.0}"#),
        (r#"{"qty":3,"price":75.0,"rate":5e-05}"#, r#"{"price":75.0,"qty":3,"rate":5e-05}"#),
        (r#"{"n": 9007199254740993, "m": 123456789012345678901234567890}"#, r#"{"m":123456789012345678901234567890,"n":9007199254740993}"#),
        ("\"caf\u{e9} \u{2713} \u{1f600}\"", r#""caf\u00e9 \u2713 \ud83d\ude00""#),
        ("\"a\u{7f}b\"", r#""a\u007fb""#),
        (r#""\u0000\u001f\b\f\n\r\t\"\\\/<>&'""#, r#""\u0000\u001f\b\f\n\r\t\"\\/<>&'""#),
        (r#""\ud83d\ude00 \u00e9""#, r#""\ud83d\ude00 \u00e9""#),
        ("{\"\u{e9}\": 1, \"z\": 2, \"\u{1f600}\": 3, \"Z\": 4}", r#"{"Z":4,"z":2,"\u00e9":1,"\ud83d\ude00":3}"#),
        (r#"{"a": 1, "a": 2}"#, r#"{"a":2}"#),
        ("[]", "[]"),
        ("{}", "{}"),
    ];
    for (input, want) in cases {
        assert_eq!(canonical_json(&Json::parse(input).unwrap()), want, "input {input}");
    }
}

#[test]
fn floats_render_as_cpython_repr() {
    // (token, repr(float(token)))
    let cases = [
        ("5e-05", "5e-05"), ("0.00005", "5e-05"), ("1e-7", "1e-07"), ("1e-06", "1e-06"),
        ("0.00001", "1e-05"), ("0.0001", "0.0001"), ("0.001", "0.001"), ("0.1", "0.1"),
        ("0.5", "0.5"), ("1.5", "1.5"), ("12.5", "12.5"), ("75.0", "75.0"), ("100.0", "100.0"),
        ("1e2", "100.0"), ("123.456", "123.456"), ("1000000000000000.0", "1000000000000000.0"),
        ("1234567890123456.0", "1234567890123456.0"), ("9999999999999998.0", "9999999999999998.0"),
        ("1e16", "1e+16"), ("10000000000000000.0", "1e+16"),
        ("1.2345678901234566e+17", "1.2345678901234566e+17"), ("1e20", "1e+20"),
        ("1e+21", "1e+21"), ("1.5e300", "1.5e+300"), ("5e-324", "5e-324"),
        ("1.7976931348623157e308", "1.7976931348623157e+308"),
        ("0.30000000000000004", "0.30000000000000004"), ("2.5e-10", "2.5e-10"),
        ("-0.0", "-0.0"), ("-5e-05", "-5e-05"), ("-1e16", "-1e+16"), ("-12.5", "-12.5"),
        ("0.0", "0.0"), ("0e0", "0.0"), ("1.0000000000000001", "1.0"), ("1E5", "100000.0"),
    ];
    for (token, want) in cases {
        assert_eq!(canonical_json(&Json::Number(token.to_string())), want, "token {token}");
    }
}

#[test]
fn parse_rejects_what_is_not_json() {
    for bad in ["", "{", "[1,]", "{\"a\":}", "01", "1.", "-", "1e", "\"a", "\"\\x\"", "nul",
                "\"\u{1}\"", "{} x", "{a:1}", "\"\\u12\"", "+1", ".5"] {
        assert!(Json::parse(bad).is_err(), "parsed {bad:?}");
    }
    let deep = "[".repeat(200) + &"]".repeat(200);
    assert!(Json::parse(&deep).is_err());
}

// --- vectors sealed by Python and Go ---

#[test]
fn python_sealed_forms_verify() {
    let file = load("spec/python-sealed-forms.json");
    assert_eq!(file.get("current_form").and_then(Json::as_str), Some(CURRENT_CANONICAL_FORM_ID));
    let cases = cases(file.get("cases").unwrap());
    assert_eq!(cases.len(), 11);
    for (label, row) in &cases {
        assert_verifies(label, std::slice::from_ref(row));
        assert_commitment(label, row);
        // Form "1" rows sealed over the "Z" timestamp match only through the
        // verification fallback; the rest match the form's own hash.
        let fallback = label.contains("legacy_Z") || label == "form1_real_prefix_release";
        assert_eq!(row_hash(row).as_deref() == Some(row.hash.as_str()), !fallback, "{label}");
    }
}

#[test]
fn go_sealed_form2_chain_verifies() {
    let rows = rows(&load("spec/go-sealed-form2.json"));
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_sealed(&row.id, row);
        assert_eq!(row.canonical_form_id, "2");
        assert_commitment(&row.id, row);
        assert_eq!(row_hash(row).as_deref(), Some(row.hash.as_str()), "{}", row.id);
    }
    assert_verifies("go-sealed-form2", &rows);
    assert_eq!(verify_chain(&rows).sealed_rows, 2);
}

#[test]
fn go_sealed_numbers_verify() {
    let rows = rows(&load("spec/go-sealed-numbers.json"));
    assert_eq!(rows.len(), 1);
    assert_sealed("go-sealed-numbers", &rows[0]);
    assert_commitment("go-sealed-numbers", &rows[0]);
    assert_eq!(row_hash(&rows[0]).as_deref(), Some(rows[0].hash.as_str()));
    assert_verifies("go-sealed-numbers", &rows);
}

#[test]
fn python_sealed_form2_and_redacted_rows_verify() {
    let cases = cases(&load("go/xlang_form2.json"));
    assert_eq!(cases.len(), 4);
    for (label, row) in &cases {
        assert_sealed(label, row);
        assert_eq!(row.canonical_form_id, "2");
        assert_commitment(label, row);
        assert_eq!(row_hash(row).as_deref(), Some(row.hash.as_str()), "{label}");
        assert_verifies(label, std::slice::from_ref(row));
        if row.detail == Json::Null {
            continue;
        }
        let mut changed = row.clone();
        changed.detail = Json::parse(r#"{"qty": 999, "sku": "STOLEN"}"#).unwrap();
        assert_breaks_at(&[changed], 1, "detail does not match its commitment");
        let mut no_salt = row.clone();
        no_salt.detail_salt = None;
        assert_breaks_at(&[no_salt], 1, "detail_salt is missing");
    }
}

// The two rows go/verify_test.go pins: hashes Python computed for form "1".
const PY_VECTOR_HASH: &str = "cbf5a1ee4bb7baeb0b433bedfa60434bdea42627b9671183895970bbff02f9ac";
const PY_FLOAT_VECTOR_HASH: &str = "512021c690ddfd2077192cb6d75921ea36d35b3270a12fdf91888d5ffabcf54b";
const PY_FLOAT_VECTOR_JSON: &str = r#"{"id": "evt-float-vec", "origin_id": "evt-float-vec", "monotonic_seq": 1, "timestamp": "2026-06-15T10:30:45+00:00", "code": "SETPOINT_WRITE", "action": "write", "severity": "info", "service_id": "event-engine", "source_node_id": "node-1", "tenant_id": "acme", "actor": "event-engine", "actor_kind": "service", "target": "connector-opcua-01/ns=2;s=Valve", "category": "actuation", "domain": "control", "method": "sdk", "request_id": "req-float-1", "detail": {"setpoint": 75.0, "tolerance": 12.5, "retries": 7}, "wire_version": "1", "shipped_at": null, "canonical_form_id": "1", "prev_hash": "genesis", "hash": "512021c690ddfd2077192cb6d75921ea36d35b3270a12fdf91888d5ffabcf54b"}"#;

fn py_vector_row() -> ChainRow {
    let mut row = ChainRow::from_json(
        r#"{"wire_version": "1", "id": "evt-abc123", "origin_id": "evt-abc123",
            "monotonic_seq": 1, "timestamp": "2026-06-15T10:30:45.123456Z",
            "code": "ORDER_PLACED", "action": "create", "severity": "info",
            "service_id": "gateway", "source_node_id": "node-1", "tenant_id": "tenant-x",
            "actor": "alice", "actor_kind": "user", "target": "order/42",
            "category": "order", "domain": "sales", "method": "http",
            "request_id": "req-xyz", "detail": {"qty": 3, "sku": "WIDGET"},
            "prev_hash": "genesis"}"#,
    )
    .unwrap();
    row.hash = PY_VECTOR_HASH.to_string();
    row
}

#[test]
fn python_form1_vector_hash_matches() {
    let row = py_vector_row();
    assert_eq!(row_hash(&row).as_deref(), Some(PY_VECTOR_HASH));
    assert_verifies("pyVectorHash", &[row]);
}

#[test]
fn python_whole_number_float_vector_hash_matches() {
    let row = ChainRow::from_json(PY_FLOAT_VECTOR_JSON).unwrap();
    assert_eq!(row_hash(&row).as_deref(), Some(PY_FLOAT_VECTOR_HASH));
    assert_verifies("pyFloatVectorJSON", &[row]);
}

// --- sealing ---

#[test]
fn seal_stamps_the_current_form_and_verifies() {
    let rows = chain(3);
    assert_eq!(rows[0].prev_hash, "genesis");
    assert_eq!(rows[1].prev_hash, rows[0].hash);
    for row in &rows {
        assert_eq!(row.canonical_form_id, "2");
        assert_eq!(row.hash.len(), 64);
        assert_eq!(row.detail_salt.as_deref().unwrap().len(), 64);
        assert_commitment(&row.id, row);
    }
    assert_ne!(rows[0].detail_salt, rows[1].detail_salt);
    assert_verifies("sealed chain", &rows);
}

#[test]
fn seal_keeps_the_salt_a_row_already_has() {
    let mut row = base_row(1);
    row.detail_salt = Some("ab".repeat(32));
    let sealed = seal("genesis", &row).unwrap();
    assert_eq!(sealed.detail_salt, row.detail_salt);
    assert_eq!(seal("genesis", &row).unwrap().hash, sealed.hash);
}

#[test]
fn seal_ignores_shipped_at() {
    let mut row = base_row(1);
    row.detail_salt = Some("ab".repeat(32));
    let plain = seal("genesis", &row).unwrap();
    row.shipped_at = Some("2026-06-16T08:00:00.250000Z".to_string());
    let shipped = seal("genesis", &row).unwrap();
    assert_eq!(shipped.hash, plain.hash);
    assert_verifies("shipped", &[shipped]);
}

#[test]
fn timestamp_is_hashed_in_wire_form_whatever_its_spelling() {
    let mut row = base_row(1);
    row.detail_salt = Some("ab".repeat(32));
    let sealed = seal("genesis", &row).unwrap();
    for same_instant in ["2026-06-15T10:30:41Z", "2026-06-15T10:30:41.000+00:00", "2026-06-15T12:30:41+02:00"] {
        let mut other = sealed.clone();
        other.timestamp = same_instant.to_string();
        assert_verifies(same_instant, &[other]);
    }
}

// The hash Python's chain.seal gives this row with the same salt.
const PY_SEALED_HASH: &str = "83308165fea44c3454672df0845679fb19d6d7878ad3ba71867dd9b2dd6e65f0";

/// A row with the detail values SDKs have rendered differently.
fn cross_sdk_row() -> ChainRow {
    let mut row = base_row(1);
    row.tenant_id = Some("t\u{e9}nant".to_string());
    row.target = "order/\u{1f600}".to_string();
    row.detail = Json::parse(
        r#"{"whole": 75.0, "tiny": 5e-5, "big": 1e16, "bigint": 12345678901234567890,
            "neg": -0.0, "text": "café ✓ <&>", "del": "a\u007fb", "nested": {"l": [1, 2.5, null, true]}}"#,
    )
    .unwrap();
    row.detail_salt = Some("cd".repeat(32));
    row
}

#[test]
fn rust_sealed_row_has_the_hash_python_gives() {
    let sealed = seal("genesis", &cross_sdk_row()).unwrap();
    assert_eq!(sealed.hash, PY_SEALED_HASH);
    assert_verifies("cross-sdk row", &[sealed]);
}

fn wire_json(row: &ChainRow) -> Json {
    let s = |v: &str| Json::String(v.into());
    let o = |v: &Option<String>| v.as_deref().map_or(Json::Null, s);
    let fields: BTreeMap<JsonString, Json> = [
        ("wire_version", s(&row.wire_version)), ("id", s(&row.id)), ("origin_id", s(&row.origin_id)),
        ("monotonic_seq", Json::Number(row.monotonic_seq.to_string())),
        ("timestamp", s(&row.timestamp)), ("code", s(&row.code)), ("action", s(&row.action)),
        ("severity", s(&row.severity)), ("service_id", s(&row.service_id)),
        ("source_node_id", s(&row.source_node_id)), ("tenant_id", o(&row.tenant_id)),
        ("actor", s(&row.actor)), ("actor_kind", s(&row.actor_kind)), ("target", s(&row.target)),
        ("category", s(&row.category)), ("domain", s(&row.domain)), ("method", s(&row.method)),
        ("request_id", s(&row.request_id)), ("detail", row.detail.clone()),
        ("shipped_at", o(&row.shipped_at)), ("canonical_form_id", s(&row.canonical_form_id)),
        ("prev_hash", s(&row.prev_hash)), ("hash", s(&row.hash)),
        ("detail_salt", o(&row.detail_salt)), ("detail_commitment", o(&row.detail_commitment)),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v))
    .collect();
    Json::Object(fields)
}

/// With FASTEN_WRITE_RUST_SEALED set to a path, writes a Rust-sealed chain
/// there as a JSON array, for another SDK to verify.
#[test]
fn rust_sealed_chain_round_trips_through_json() {
    let first = seal("genesis", &cross_sdk_row()).unwrap();
    let mut second = base_row(2);
    second.detail = Json::Null;
    let second = seal(&first.hash, &second).unwrap();
    let third = seal(&second.hash, &base_row(3)).unwrap();
    let rows = vec![first, second, third];
    let text = canonical_json(&Json::Array(rows.iter().map(wire_json).collect()));
    if let Ok(path) = std::env::var("FASTEN_WRITE_RUST_SEALED") {
        std::fs::write(path, &text).unwrap();
    }
    let back = self::rows(&Json::parse(&text).unwrap());
    assert_verifies("round trip", &back);
    for (read, sealed) in back.iter().zip(&rows) {
        assert_eq!(row_hash(read).as_deref(), Some(sealed.hash.as_str()));
    }
}

#[test]
fn core_row_seals_and_takes_the_chain_fields() {
    let mut row = Row {
        wire_version: "1".into(), id: "evt-1".into(), origin_id: "evt-1".into(),
        monotonic_seq: 1, timestamp: "2026-06-15T10:30:45.123456Z".into(),
        code: "ORDER_PLACED".into(), action: "create".into(), severity: "info".into(),
        service_id: "gateway".into(), source_node_id: "node-1".into(),
        actor: "alice".into(), actor_kind: "user".into(), target: "order/42".into(),
        category: "order".into(), domain: "sales".into(), method: "http".into(),
        request_id: "req-xyz".into(),
        detail: serde_json::json!({"qty": 3, "price": 75.0, "rate": 5e-5, "big": 1e16}),
        ..Row::default()
    };
    let sealed = seal("genesis", &ChainRow::from(&row)).unwrap();
    sealed.stamp(&mut row);
    assert_eq!(row.hash.as_deref(), Some(sealed.hash.as_str()));
    assert_eq!(row.canonical_form_id.as_deref(), Some("2"));

    // The row as a store writes it and a reader parses it back.
    let wire = serde_json::to_string(&row).unwrap();
    let back = ChainRow::from_json(&wire).unwrap();
    assert_eq!(canonical_json(&back.detail), r#"{"big":1e+16,"price":75.0,"qty":3,"rate":5e-05}"#);
    assert_verifies("core row", &[back]);
    assert_verifies("core row", &[ChainRow::from(&row)]);
}

// --- tamper detection ---

#[test]
fn empty_chain_verifies() {
    let res = verify_chain(&[]);
    assert!(res.ok);
    assert_eq!(res.total_rows, 0);
}

#[test]
fn edited_target_breaks_at_that_row() {
    let mut rows = chain(3);
    rows[1].target = "order/9999".to_string();
    assert_breaks_at(&rows, 2, "row evt-2: hash mismatch");

    let mut row = py_vector_row();
    row.target = "order/9999".to_string();
    assert_breaks_at(&[row], 1, "hash mismatch");
}

#[test]
fn every_hashed_field_is_covered() {
    let edits: [fn(&mut ChainRow); 20] = [
        |r| r.wire_version = "9".into(), |r| r.id = "evt-x".into(), |r| r.origin_id = "evt-x".into(),
        |r| r.timestamp = "2026-06-15T10:30:42.000001Z".into(), |r| r.code = "X".into(),
        |r| r.action = "x".into(), |r| r.severity = "warn".into(), |r| r.service_id = "x".into(),
        |r| r.tenant_id = Some("x".into()), |r| r.actor = "mallory".into(),
        |r| r.actor_kind = "agent".into(), |r| r.target = "x".into(), |r| r.category = "x".into(),
        |r| r.domain = "x".into(), |r| r.method = "cli".into(), |r| r.request_id = "x".into(),
        |r| r.prev_hash = "x".into(), |r| r.detail_commitment = Some("x".into()),
        |r| r.canonical_form_id = "1".into(), |r| r.hash = "0".repeat(64),
    ];
    for (i, edit) in edits.iter().enumerate() {
        let mut rows = chain(2);
        edit(&mut rows[1]);
        let res = verify_chain(&rows);
        assert!(!res.ok, "edit {i} verified");
        assert_eq!(res.first_break_at, Some(2), "edit {i}");
    }
}

#[test]
fn edited_detail_breaks_at_that_row() {
    let mut rows = chain(3);
    rows[1].detail = Json::parse(r#"{"qty": 2, "price": 76.0}"#).unwrap();
    assert_breaks_at(&rows, 2, "row evt-2: detail does not match its commitment");

    // A number written another way is a different detail: 75.0 is not 75.
    let mut rows = chain(3);
    rows[1].detail = Json::parse(r#"{"qty": 2, "price": 75}"#).unwrap();
    assert_breaks_at(&rows, 2, "detail does not match its commitment");

    let mut form1 = py_vector_row();
    form1.detail = Json::parse(r#"{"qty": 4, "sku": "WIDGET"}"#).unwrap();
    assert_breaks_at(&[form1], 1, "hash mismatch");
}

#[test]
fn removed_row_breaks_at_the_next_one() {
    let mut rows = chain(4);
    rows.remove(1);
    assert_breaks_at(&rows, 3, "row evt-3: prev_hash does not match preceding row evt-1");
}

#[test]
fn inserted_row_breaks() {
    let mut rows = chain(2);
    let mut extra = base_row(3);
    extra.id = "evt-forged".to_string();
    extra.monotonic_seq = 2;
    rows.push(seal(&rows[0].hash, &extra).unwrap());
    assert_breaks_at(&rows, 2, "duplicate monotonic_seq 2 on node 'node-1'");
}

#[test]
fn reordered_rows_break() {
    // Order in the slice does not matter; the seq a row claims does.
    let mut shuffled = chain(4);
    shuffled.swap(0, 3);
    shuffled.swap(1, 2);
    assert_verifies("shuffled input", &shuffled);

    let mut rows = chain(4);
    rows[1].monotonic_seq = 3;
    rows[2].monotonic_seq = 2;
    let res = verify_chain(&rows);
    assert!(!res.ok);
    assert_eq!(res.first_break_at, Some(2));
}

#[test]
fn redacted_row_still_verifies() {
    let mut rows = chain(3);
    rows[1].detail = Json::Null;
    rows[1].detail_salt = None;
    assert_verifies("redacted", &rows);

    // Detail cleared but something else changed too.
    rows[1].target = "order/9999".to_string();
    assert_breaks_at(&rows, 2, "hash mismatch");
}

#[test]
fn unknown_form_is_rejected() {
    let mut rows = chain(2);
    rows[1].canonical_form_id = "3".to_string();
    assert_breaks_at(&rows, 2, "row evt-2: unknown canonical_form_id \"3\"");
    assert_eq!(row_hash(&rows[1]), None);
}

#[test]
fn chains_are_per_node() {
    let mut rows = chain(3);
    let mut prev = "genesis".to_string();
    for seq in 1..=3 {
        let mut row = base_row(seq);
        row.id = format!("evt-b-{seq}");
        row.source_node_id = "node-2".to_string();
        let sealed = seal(&prev, &row).unwrap();
        prev.clone_from(&sealed.hash);
        rows.insert(rows.len() / 2, sealed);
    }
    assert_verifies("two nodes", &rows);

    // The lowest breaking seq on any node is reported.
    let a3 = rows.iter().position(|r| r.id == "evt-3").unwrap();
    let b2 = rows.iter().position(|r| r.id == "evt-b-2").unwrap();
    rows[a3].target = "x".to_string();
    rows[b2].target = "x".to_string();
    assert_breaks_at(&rows, 2, "row evt-b-2: hash mismatch");
}

#[test]
fn unsealed_rows_are_skipped_only_before_the_chain_starts() {
    let mut early = base_row(1);
    early.id = "evt-early".to_string();
    let second = seal("genesis", &base_row(2)).unwrap();
    let third = seal(&second.hash, &base_row(3)).unwrap();
    assert_verifies("unsealed head", &[early.clone(), second.clone(), third.clone()]);

    // The first sealed row after an unsealed one at seq-1 links to genesis.
    let stray = seal("somewhere", &base_row(2)).unwrap();
    assert_breaks_at(&[early.clone(), stray], 2, "first sealed row does not link to genesis");

    // A purged head leaves a gap, so the first row may link to a row not here.
    let tail = chain(4).split_off(2);
    assert_verifies("purged head", &tail);

    let mut late = base_row(4);
    late.id = "evt-late".to_string();
    assert_breaks_at(&[second, third, late], 4, "row evt-late: no hash after the node's chain started");
}

#[test]
fn duplicate_ids_are_checked_once() {
    let rows = chain(3);

    let mut twice = rows.clone();
    twice.push(rows[1].clone());
    let res = verify_chain(&twice);
    assert!(res.ok, "{:?}", res.reason);
    assert_eq!(res.total_rows, 4);

    // A sealed copy wins over an unsealed one, whichever comes first.
    let mut unsealed = rows[1].clone();
    unsealed.hash = String::new();
    assert_verifies("unsealed first", &[rows[0].clone(), unsealed.clone(), rows[1].clone(), rows[2].clone()]);
    assert_verifies("unsealed last", &[rows[0].clone(), rows[1].clone(), rows[2].clone(), unsealed]);

    let mut other = rows[1].clone();
    other.hash = "0".repeat(64);
    let mut differing = rows.clone();
    differing.push(other);
    assert_breaks_at(&differing, 2, "row evt-2: two sealed copies with different hashes");

    // Two copies with the same hash, the second one edited.
    let mut edited = rows[1].clone();
    edited.target = "order/9999".to_string();
    let mut same_hash = rows.clone();
    same_hash.push(edited);
    assert_breaks_at(&same_hash, 2, "row evt-2: hash mismatch");
}

#[test]
fn row_without_a_form_id_is_form_1() {
    let mut row = py_vector_row();
    assert_eq!(row.canonical_form_id, "");
    assert_verifies("no form id", std::slice::from_ref(&row));
    row.canonical_form_id = "1".to_string();
    assert_verifies("form 1", &[row]);
}

#[test]
fn from_value_reports_bad_fields() {
    assert!(ChainRow::from_json("[]").is_err());
    assert!(ChainRow::from_json(r#"{"id": "a"}"#).is_err());
    assert!(ChainRow::from_json(r#"{"monotonic_seq": 1.5}"#).is_err());
    assert!(ChainRow::from_json(r#"{"monotonic_seq": -1}"#).is_err());
    assert!(ChainRow::from_json(r#"{"monotonic_seq": 1, "id": 7}"#).is_err());
    let row = ChainRow::from_json(r#"{"monotonic_seq": 18446744073709551615}"#).unwrap();
    assert_eq!(row.monotonic_seq, u64::MAX);
    assert_eq!((row.wire_version.as_str(), row.prev_hash.as_str()), ("1", "genesis"));
    assert_eq!(canonical_json(&row.detail), "{}");
}

// --- the Rust-sealed vector (spec/rust-sealed-form2.json) ---
//
// Written by the SDK's own sealing path (rust/src/sqlite_store.rs,
// `writes_the_rust_sealed_vector`); Python and Go verify the same file.

#[test]
fn rust_sealed_vector_is_stable() {
    let rows = rows(&load("spec/rust-sealed-form2.json"));
    assert_eq!(rows.len(), 4);
    let mut prev = "genesis".to_string();
    for (i, row) in rows.iter().enumerate() {
        assert_sealed(&row.id, row);
        assert_eq!((row.canonical_form_id.as_str(), row.monotonic_seq), ("2", i as u64 + 1));
        assert_eq!(row.prev_hash, prev, "{}", row.id);
        prev.clone_from(&row.hash);
        assert_eq!(row_hash(row).as_deref(), Some(row.hash.as_str()), "{}: hash drifted", row.id);
        if row.detail == Json::Null {
            // Redacted: the detail and the salt are gone, the commitment stays.
            assert_eq!(row.detail_salt, None);
            assert_eq!(row.detail_commitment.as_deref().map(str::len), Some(64));
            continue;
        }
        // Sealing again with the recorded salt gives the recorded row.
        let again = seal(&row.prev_hash, row).unwrap();
        assert_eq!(again.detail_commitment, row.detail_commitment, "{}: commitment drifted", row.id);
        assert_eq!(again.hash, row.hash, "{}: hash drifted", row.id);
    }
    assert_eq!(rows.iter().filter(|r| r.detail == Json::Null).count(), 1);
    assert_verifies("rust-sealed-form2", &rows);
    assert_eq!(verify_chain(&rows).sealed_rows, 4);

    // The details are the ones the vector is for.
    let details: String = rows.iter().map(|r| r.detail.to_string()).collect();
    for token in ["75.0", "1e-7", "18446744073709551615", "1.2345678901234568e+29", "\\u00e9", "\\u007f", "{\"list\":["] {
        assert!(details.contains(token), "{token} not in {details}");
    }

    let mut changed = rows.clone();
    changed[0].detail = Json::parse(r#"{"setpoint": 76.0}"#).unwrap();
    assert_breaks_at(&changed, 1, "detail does not match its commitment");
}

// --- strings and numbers Python stores that plain JSON parsers refuse ---

// Expected text and hashes are CPython 3.12's, from python/fasten/chain.py:
// json.loads of the detail text, sealed with the salt shown.
const PY_SURROGATE_DETAIL: &str = r#"{"name": "\udcff.txt", "\ud800": 1, "": 2, "\ue000": 3, "\ud83d\ude00": 4, "pair": "\ud83d\ude00", "tail": "a\udfffb"}"#;
const PY_SURROGATE_CANONICAL: &str = r#"{"":2,"name":"\udcff.txt","pair":"\ud83d\ude00","tail":"a\udfffb","\ud800":1,"\ue000":3,"\ud83d\ude00":4}"#;
const PY_SURROGATE_COMMITMENT: &str = "d65606d442d772bd4fdf71642e7854181587978af7c27cbf22dafe9aca1ff5ce";
const PY_SURROGATE_HASH: &str = "8a76f4a637269afe76df1686e0b533c1fe7b948b264a253e179ec2634cb07461";
const PY_NAN_DETAIL: &str = r#"{"nan": NaN, "inf": Infinity, "ninf": -Infinity, "list": [NaN, 1.5]}"#;
const PY_NAN_CANONICAL: &str = r#"{"inf":Infinity,"list":[NaN,1.5],"nan":NaN,"ninf":-Infinity}"#;
const PY_NAN_COMMITMENT: &str = "595df41153437098fa85880c9820a81c52bb6063b15d628ee0b6dd708e618c8b";
const PY_NAN_HASH: &str = "de157b8f434d3a7495bae23bdc9b1d8f7985f4e96e2d35a2654c5e138022389c";

fn py_row(seq: u64, detail: &str, salt: &str) -> ChainRow {
    let mut row = ChainRow::from_json(&format!(
        r#"{{"wire_version": "1", "id": "evt-py-{seq}", "origin_id": "evt-py-{seq}", "monotonic_seq": {seq},
            "timestamp": "2026-06-15T10:30:45.123456Z", "code": "SENSOR_READ", "action": "read",
            "severity": "info", "service_id": "gateway", "source_node_id": "node-py", "actor": "plc-7",
            "actor_kind": "device", "target": "sensor/42", "category": "telemetry", "domain": "plant",
            "method": "mqtt", "request_id": "req-1", "detail": {detail}}}"#
    ))
    .unwrap();
    row.detail_salt = Some(salt.to_string());
    row
}

#[test]
fn unpaired_surrogates_round_trip_as_cpython_writes_them() {
    for (text, canonical) in [
        (r#""\udcff""#, r#""\udcff""#),
        (r#""\ud83d\ude00""#, r#""\ud83d\ude00""#),
        (r#""\ude00\ud83d""#, r#""\ude00\ud83d""#),
        // Keys sort by code point: a lone surrogate after U+D7FF, before U+E000.
        (r#"{"\ud800":1,"":2,"\ue000":3,"\ud83d\ude00":4}"#, r#"{"":2,"\ud800":1,"\ue000":3,"\ud83d\ude00":4}"#),
        (PY_SURROGATE_DETAIL, PY_SURROGATE_CANONICAL),
    ] {
        let parsed = Json::parse(text).unwrap();
        assert_eq!(canonical_json(&parsed), canonical, "{text}");
        // The text a store writes reads back as the same value.
        assert_eq!(Json::parse(&parsed.to_string()).unwrap(), parsed, "{text}");
    }
    // A pair is one character; a lone surrogate is not text.
    assert_eq!(Json::parse(r#""\ud83d\ude00""#).unwrap().as_str(), Some("\u{1f600}"));
    let lone = Json::parse(r#""a\udcffb""#).unwrap();
    assert_eq!(lone.as_str(), None);
    let Json::String(lone) = lone else { panic!() };
    assert_eq!(lone.to_string_lossy(), "a\u{fffd}b");
    assert_eq!(lone.code_points().collect::<Vec<_>>(), [0x61, 0xdcff, 0x62]);
    assert_ne!(JsonString::from("a\u{fffd}b"), lone);
}

#[test]
fn python_sealed_row_with_unpaired_surrogates_verifies() {
    let salt = "a0".repeat(32);
    let sealed = seal("genesis", &py_row(1, PY_SURROGATE_DETAIL, &salt)).unwrap();
    assert_eq!(sealed.detail_commitment.as_deref(), Some(PY_SURROGATE_COMMITMENT));
    assert_eq!(sealed.hash, PY_SURROGATE_HASH);
    assert_verifies("surrogates", std::slice::from_ref(&sealed));

    let mut changed = sealed;
    changed.detail = Json::parse(&PY_SURROGATE_DETAIL.replace("udcff", "udcfe")).unwrap();
    assert_breaks_at(&[changed], 1, "detail does not match its commitment");
}

#[test]
fn nan_and_infinity_are_numbers_as_in_python() {
    let parsed = Json::parse("[NaN, Infinity, -Infinity]").unwrap();
    assert_eq!(canonical_json(&parsed), "[NaN,Infinity,-Infinity]");
    assert_eq!(parsed.to_string(), "[NaN,Infinity,-Infinity]");
    assert_eq!(canonical_json(&Json::parse(PY_NAN_DETAIL).unwrap()), PY_NAN_CANONICAL);
    for bad in ["-NaN", "nan", "Inf", "-Inf", "+Infinity", "Infinit", "NaNx", "infinity"] {
        assert!(Json::parse(bad).is_err(), "{bad}");
    }

    let first = seal("genesis", &py_row(1, PY_SURROGATE_DETAIL, &"a0".repeat(32))).unwrap();
    let second = seal(&first.hash, &py_row(2, PY_NAN_DETAIL, &"a1".repeat(32))).unwrap();
    assert_eq!(second.detail_commitment.as_deref(), Some(PY_NAN_COMMITMENT));
    assert_eq!(second.hash, PY_NAN_HASH);
    assert_verifies("nan", &[first, second]);
}

// --- what the result says ---

#[test]
fn an_all_unsealed_stream_verifies_with_no_sealed_rows() {
    let rows = vec![base_row(1), base_row(2)];
    let res = verify_chain(&rows);
    assert!(res.ok);
    assert_eq!((res.total_rows, res.sealed_rows), (2, 0));
    let res = verify_chain(&[]);
    assert!(res.ok);
    assert_eq!((res.total_rows, res.sealed_rows), (0, 0));

    // Copies of a row count once; unsealed rows not at all.
    let mut rows = chain(3);
    rows.push(rows[0].clone());
    rows.insert(0, { let mut r = base_row(9); r.source_node_id = "node-2".into(); r });
    let res = verify_chain(&rows);
    assert!(res.ok, "{res:?}");
    assert_eq!((res.total_rows, res.sealed_rows), (5, 3));
}

#[test]
fn a_break_names_its_node() {
    let mut a = chain(3);
    let mut b = chain(4);
    for row in &mut b {
        row.source_node_id = "node-b".into();
    }
    // Sealed for node-1, so every node-b row fails its hash; the edit on
    // node-1 is at a higher seq.
    a[2].target = "order/999".into();
    let res = verify_chain(&[a.clone(), b].concat());
    assert_eq!((res.first_break_at, res.first_break_node.as_deref()), (Some(1), Some("node-b")));
    let res = verify_chain(&a);
    assert_eq!((res.first_break_at, res.first_break_node.as_deref()), (Some(3), Some("node-1")));
}

#[test]
fn an_unsealed_row_tied_with_the_first_sealed_seq_breaks_in_any_order() {
    let sealed = chain(2);
    let mut tie = base_row(1);
    tie.id = "evt-tie".into();
    for rows in [[vec![tie.clone()], sealed.clone()].concat(), [sealed.clone(), vec![tie.clone()]].concat()] {
        assert_breaks_at(&rows, 1, "no hash after the node's chain started");
    }
}

#[test]
fn an_edit_below_a_duplicate_seq_is_the_first_break() {
    let mut rows = chain(4);
    let mut twin = rows[2].clone();
    twin.id = "evt-twin".into();
    rows.push(twin);
    assert_breaks_at(&rows, 3, "duplicate monotonic_seq 3");
    rows[1].target = "order/999".into();
    assert_breaks_at(&rows, 2, "hash mismatch");
}

#[test]
fn an_empty_salt_or_commitment_reads_as_none() {
    let text = r#"{"id": "evt-1", "monotonic_seq": 1, "detail_salt": "", "detail_commitment": ""}"#;
    let row = ChainRow::from_json(text).unwrap();
    assert_eq!((row.detail_salt.as_deref(), row.detail_commitment.as_deref()), (None, None));
    assert_eq!((row.wire_version.as_str(), row.prev_hash.as_str(), row.hash.as_str()), ("1", "genesis", ""));

    let mut core = Row::default();
    let odd = ChainRow { detail_salt: Some(String::new()), detail_commitment: Some(String::new()), ..row };
    odd.stamp(&mut core);
    assert_eq!((core.detail_salt, core.detail_commitment), (None, None));

    // A row field cannot hold an unpaired surrogate.
    let bad = ChainRow::from_json(r#"{"id": "evt-\udcff", "monotonic_seq": 1}"#);
    assert!(bad.is_err(), "{bad:?}");
}

#[test]
fn from_row_takes_the_detail_from_its_text() {
    let mut core = Row { id: "evt-1".into(), monotonic_seq: 1, ..Default::default() };
    core.detail = serde_json::json!({"n": 1.0e2});
    let text = r#"{"n": 1.0E+2, "big": 123456789012345678901234567890, "z": -0}"#;
    let row = ChainRow::from_row(&core, text).unwrap();
    assert_eq!(row.detail, Json::parse(text).unwrap());
    assert_eq!(row.detail.to_string(), r#"{"big":123456789012345678901234567890,"n":1.0E+2,"z":-0}"#);
    assert_ne!(row.detail, ChainRow::from(&core).detail);
    assert!(ChainRow::from_row(&core, "{").is_err());
}
