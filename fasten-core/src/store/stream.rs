//! What the api and sys stream stores share (spec persistent-streams.md):
//! the table layout, the lifted columns, the read filters and the search
//! pattern. The SQLite and Postgres stream stores of every SDK use the same
//! table, so one SDK can read and append to what another wrote.

use serde_json::{Map, Value};

use crate::error::Error;
use crate::validate::validate_table_name;

/// One api or sys row: a JSON object, stored whole as the `payload` text.
pub type StreamRow = Map<String, Value>;

/// The lifted columns of schema form "1" (spec §2.1), in table order.
pub const INDEXED_FIELDS: [&str; 8] =
    ["request_id", "timestamp", "level", "service_id", "event", "method", "path", "status"];

/// Filters for a stream read. Every field is an exact match and an empty
/// string is no filter; `since` and `until` bound the timestamp text,
/// inclusive (spec §4).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StreamFilter {
    pub level: Option<String>,
    pub request_id: Option<String>,
    pub service_id: Option<String>,
    pub event: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    /// The status column is a 32-bit INTEGER.
    pub status: Option<i32>,
    pub since: Option<String>,
    pub until: Option<String>,
}

/// A value bound to a stream query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamParam {
    Text(String),
    Int(i32),
}

impl StreamFilter {
    /// The text filters that apply, as (column, value).
    pub(crate) fn equalities(&self) -> Vec<(&'static str, &str)> {
        [
            ("level", &self.level),
            ("request_id", &self.request_id),
            ("service_id", &self.service_id),
            ("event", &self.event),
            ("method", &self.method),
            ("path", &self.path),
        ]
        .into_iter()
        .filter_map(|(col, v)| v.as_deref().filter(|s| !s.is_empty()).map(|s| (col, s)))
        .collect()
    }

    /// The WHERE clause (with a leading space, or empty) and its values.
    /// `placeholder(n)` renders the n-th parameter, counting from 1. The
    /// column names are fixed; every value is a parameter. For the stream
    /// stores of this crate and the SDK; not a stable API.
    #[doc(hidden)]
    pub fn where_clause(&self, placeholder: impl Fn(usize) -> String) -> (String, Vec<StreamParam>) {
        let mut conds = Vec::new();
        let mut params = Vec::new();
        for (col, v) in self.equalities() {
            params.push(StreamParam::Text(v.to_string()));
            conds.push(format!("{col} = {}", placeholder(params.len())));
        }
        if let Some(status) = self.status {
            params.push(StreamParam::Int(status));
            conds.push(format!("status = {}", placeholder(params.len())));
        }
        // A missing timestamp compares as "", as in the ring.
        for (bound, op) in [(&self.since, ">="), (&self.until, "<=")] {
            if let Some(ts) = bound.as_deref().filter(|s| !s.is_empty()) {
                params.push(StreamParam::Text(ts.to_string()));
                conds.push(format!("COALESCE(timestamp, '') {op} {}", placeholder(params.len())));
            }
        }
        let clause = if conds.is_empty() { String::new() } else { format!(" WHERE {}", conds.join(" AND ")) };
        (clause, params)
    }

    /// Whether `row` passes the filters, for a stream kept in memory.
    pub fn matches(&self, row: &StreamRow) -> bool {
        let eq = self.equalities().into_iter().all(|(col, v)| row.get(col).and_then(Value::as_str) == Some(v));
        let status = self.status.is_none_or(|want| lifted_status(row) == Some(want));
        let ts = row_timestamp(row);
        let since = self.since.as_deref().filter(|s| !s.is_empty()).is_none_or(|s| ts.as_str() >= s);
        let until = self.until.as_deref().filter(|s| !s.is_empty()).is_none_or(|s| ts.as_str() <= s);
        eq && status && since && until
    }
}

/// The row's timestamp text, or "" when it has none.
fn row_timestamp(row: &StreamRow) -> String {
    match row.get("timestamp") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// The value of a lifted text column: the field when it is a string, else
/// NULL.
pub fn lifted_text(row: &StreamRow, field: &str) -> Option<String> {
    row.get(field).and_then(Value::as_str).map(str::to_string)
}

/// The value of the status column: the field when it is an integer, or a
/// string of digits, that fits 32 bits; else NULL.
pub fn lifted_status(row: &StreamRow) -> Option<i32> {
    match row.get("status")? {
        Value::Number(n) => n.as_i64().and_then(|n| i32::try_from(n).ok()),
        Value::String(s) => {
            let t = s.trim();
            let digits = t.strip_prefix('-').unwrap_or(t);
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            t.parse().ok()
        }
        _ => None,
    }
}

/// The values of the lifted columns, in [`INDEXED_FIELDS`] order.
/// `None` is NULL.
pub fn lifted_values(row: &StreamRow) -> Vec<Option<StreamParam>> {
    INDEXED_FIELDS
        .iter()
        .map(|f| match *f {
            "status" => lifted_status(row).map(StreamParam::Int),
            f => lifted_text(row, f).map(StreamParam::Text),
        })
        .collect()
}

/// The row as payload text: compact JSON, non-ASCII left as it is, as the
/// Python and Go stores write it.
pub fn payload_text(row: &StreamRow) -> String {
    Value::Object(row.clone()).to_string()
}

/// A stored payload as a row. A payload that is not a JSON object comes
/// back under the key `payload`, so a read never fails on one odd row.
pub fn parse_payload(text: &str) -> Result<StreamRow, serde_json::Error> {
    match serde_json::from_str::<Value>(text)? {
        Value::Object(map) => Ok(map),
        other => Ok(Map::from_iter([("payload".to_string(), other)])),
    }
}

/// `%q%` for `LIKE` / `ILIKE` with a backslash escape: `%`, `_` and `\` in
/// `q` match literally.
pub fn like_pattern(q: &str) -> String {
    let mut out = String::with_capacity(q.len() + 2);
    out.push('%');
    for c in q.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

/// The CREATE statements for a stream table: the table, then its indexes.
/// `index_prefix` is the table name without a schema. `table` must be a
/// name or `schema.name` and `index_prefix` a name, each matching
/// `[A-Za-z_][A-Za-z0-9_]*`, as the stores require; anything else is
/// `InvalidTableName`. For the stream stores of this crate and the SDK; not
/// a stable API.
#[doc(hidden)]
pub fn ddl(table: &str, index_prefix: &str, postgres: bool) -> Result<Vec<String>, Error> {
    validate_table_name(table)?;
    if index_prefix.contains('.') {
        return Err(Error::InvalidTableName(index_prefix.to_owned()));
    }
    validate_table_name(index_prefix)?;
    let seq = if postgres { "BIGSERIAL PRIMARY KEY" } else { "INTEGER PRIMARY KEY AUTOINCREMENT" };
    let mut out = vec![format!(
        "CREATE TABLE IF NOT EXISTS {table} (
    seq          {seq},
    request_id   TEXT,
    timestamp    TEXT,
    level        TEXT,
    service_id   TEXT,
    event        TEXT,
    method       TEXT,
    path         TEXT,
    status       INTEGER,
    payload      TEXT NOT NULL
)"
    )];
    for (suffix, col) in [
        ("req", "request_id"),
        ("ts", "timestamp"),
        ("lvl", "level"),
        ("svc", "service_id"),
        ("evt", "event"),
        ("mth", "method"),
        ("pth", "path"),
        ("sts", "status"),
    ] {
        out.push(format!("CREATE INDEX IF NOT EXISTS idx_{index_prefix}_{suffix} ON {table}({col})"));
    }
    Ok(out)
}

/// The INSERT for a stream table, with `placeholder(n)` for the n-th value.
/// `table` is checked as in [`ddl`]. For the stream stores of this crate
/// and the SDK; not a stable API.
#[doc(hidden)]
pub fn insert_sql(table: &str, placeholder: impl Fn(usize) -> String) -> Result<String, Error> {
    validate_table_name(table)?;
    let values: Vec<String> = (1..=9).map(placeholder).collect();
    Ok(format!(
        "INSERT INTO {table} (request_id,timestamp,level,service_id,event,method,path,status,payload) VALUES ({})",
        values.join(",")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(v: Value) -> StreamRow {
        match v {
            Value::Object(m) => m,
            _ => unreachable!(),
        }
    }

    #[test]
    fn like_pattern_escapes_wildcards_and_backslash() {
        assert_eq!(like_pattern(r"50%_a\b"), r"%50\%\_a\\b%");
    }

    #[test]
    fn status_lifts_integers_and_digit_strings_only() {
        assert_eq!(lifted_status(&row(json!({"status": 200}))), Some(200));
        assert_eq!(lifted_status(&row(json!({"status": " 404 "}))), Some(404));
        assert_eq!(lifted_status(&row(json!({"status": "-1"}))), Some(-1));
        assert_eq!(lifted_status(&row(json!({"status": 2.5}))), None);
        assert_eq!(lifted_status(&row(json!({"status": "2xx"}))), None);
        assert_eq!(lifted_status(&row(json!({"status": 3_000_000_000_i64}))), None);
        assert_eq!(lifted_status(&row(json!({"status": true}))), None);
    }

    #[test]
    fn where_clause_skips_empty_filters() {
        let f = StreamFilter {
            level: Some(String::new()),
            request_id: Some("r1".into()),
            status: Some(500),
            since: Some("2026-01-01T00:00:00.000000Z".into()),
            ..Default::default()
        };
        let (sql, params) = f.where_clause(|n| format!("${n}"));
        assert_eq!(sql, " WHERE request_id = $1 AND status = $2 AND COALESCE(timestamp, '') >= $3");
        assert_eq!(params.len(), 3);
    }

    #[test]
    fn ring_match_treats_a_missing_timestamp_as_empty() {
        let f = StreamFilter { until: Some("2026".into()), ..Default::default() };
        assert!(f.matches(&row(json!({"event": "x"}))));
        let f = StreamFilter { since: Some("2026".into()), ..Default::default() };
        assert!(!f.matches(&row(json!({"event": "x"}))));
    }

    #[test]
    fn ddl_and_insert_refuse_a_table_name_the_stores_refuse() {
        assert!(ddl("logs.syslog", "syslog", true).is_ok());
        assert!(insert_sql("logs.syslog", |n| format!("${n}")).is_ok());
        for bad in ["x; DROP TABLE y", "a.b.c", "", "1x", "a-b"] {
            assert!(matches!(ddl(bad, "x", false), Err(Error::InvalidTableName(_))), "{bad}");
            assert!(matches!(insert_sql(bad, |n| format!("?{n}")), Err(Error::InvalidTableName(_))), "{bad}");
        }
        assert!(matches!(ddl("t", "a.b", false), Err(Error::InvalidTableName(_))));
        assert!(matches!(ddl("t", "x y", false), Err(Error::InvalidTableName(_))));
    }

    #[test]
    fn a_non_object_payload_reads_back() {
        assert_eq!(parse_payload("[1]").unwrap().get("payload"), Some(&json!([1])));
    }
}
