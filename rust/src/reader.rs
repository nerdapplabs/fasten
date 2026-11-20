//! HTTP reader for the audit, api and sys streams: the routes Python's
//! `fasten.reader.router()`, Go's `NewReader` and the JS `reader()` serve.
//!
//! The reader is not tied to a server. Hand it a [`Request`] (method, raw
//! path, raw query, headers) and send back the [`Response`] it returns:
//!
//! ```no_run
//! use fasten::reader::{Auth, Reader, Request};
//!
//! let reader = Reader::builder().auth(Auth::bearer("s3cret")).build().expect("reader");
//! let req = Request::new("GET", "/audit?limit=10").with_header("Authorization", "Bearer s3cret");
//! let res = reader.handle(&req);
//! assert_eq!(res.status, 200);
//! ```
//!
//! Routes, relative to the prefix:
//!
//! | Route | What |
//! |---|---|
//! | `GET /audit` | audit rows (filters, `limit`, `offset`, `after`) |
//! | `GET /audit/doctor` | audit pipeline health and a chain spot check |
//! | `GET /correlate` | audit, api and sys rows for one `request_id` |
//! | `GET /search` | free-text search over stored rows |
//! | `GET /sys` | sys rows (`q=` search when enabled) |
//! | `GET /api` | api rows |
//! | `GET /topology` | nodes, services and tenants writing audit rows |
//!
//! The reader returns raw audit rows, so it is built only with an explicit
//! auth choice.

use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::engine::{Engine, ReaderState};
use crate::streams::{Stream, StreamFilter, StreamRow, StreamStore};
use crate::{AuditQuery, AuditSearch, AuditStore, ChainRow, Error, Json, DEFAULT};

const NOT_INITIALISED: &str = "transport not initialised — call fasten.init() first";
const NO_AUDIT_STORE: &str = "audit store not initialised — call fasten.init() first";
const MAX_Q: usize = 1024;
const SEARCH_STREAMS: [&str; 3] = ["audit", "api", "sys"];

/// A request as the server received it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// The path as sent, without the query.
    pub path: String,
    /// The raw query string, without the `?`.
    pub query: String,
    pub headers: Vec<(String, String)>,
}

impl Request {
    /// A request for `target`, the path and query as sent (`/audit?limit=5`).
    pub fn new(method: &str, target: &str) -> Self {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        Self { method: method.to_string(), path: path.to_string(), query: query.to_string(), headers: Vec::new() }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// The first value of header `name`, matched without regard to case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// The reader's answer: a status, headers and a JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// JSON text.
    pub body: String,
}

impl Response {
    fn new(status: u16, body: String) -> Self {
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Content-Length".to_string(), body.len().to_string()),
        ];
        Self { status, headers, body }
    }

    fn detail(status: u16, detail: &str) -> Self {
        Self::new(status, json!({ "detail": detail }).to_string())
    }

    /// The body parsed. Numbers beyond what `serde_json` holds exactly are
    /// rounded; read `body` for the exact text.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

type VerifyFn = dyn Fn(&Request) -> bool + Send + Sync;
type TenantFn = dyn Fn(&Request) -> Option<String> + Send + Sync;

/// How the reader authenticates a request. There is no default.
#[derive(Clone)]
pub enum Auth {
    /// `Authorization: Bearer <token>`, compared in constant time.
    Bearer(String),
    /// A function that returns true when the request may read.
    Verify(Arc<VerifyFn>),
    /// No check: for routes authenticated in front of the reader (a
    /// gateway, the server's own middleware), or a trusted network only.
    None,
}

impl Auth {
    pub fn bearer(token: impl Into<String>) -> Self {
        Auth::Bearer(token.into())
    }

    pub fn verify(f: impl Fn(&Request) -> bool + Send + Sync + 'static) -> Self {
        Auth::Verify(Arc::new(f))
    }
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Auth::Bearer(_) => "Auth::Bearer(..)",
            Auth::Verify(_) => "Auth::Verify(..)",
            Auth::None => "Auth::None",
        })
    }
}

/// [`Auth::Bearer`] with the token in the environment variable `token_env`
/// (`FASTEN_READER_TOKEN` in the other SDKs). Fails when it is unset or
/// empty rather than allowing every request.
pub fn require_bearer(token_env: &str) -> Result<Auth, Error> {
    match std::env::var(token_env) {
        Ok(t) if !t.is_empty() => Ok(Auth::Bearer(t)),
        _ => Err(Error::InvalidConfig(format!(
            "fasten reader require_bearer: ${token_env} is unset or empty. Set it to the shared bearer token, or pass your own verify function."
        ))),
    }
}

// Compares every byte of the expected token, whatever was presented, so the
// time taken depends on the token's length only.
fn token_matches(presented: &[u8], expected: &[u8]) -> bool {
    let mut diff = u8::from(presented.len() != expected.len());
    for (i, e) in expected.iter().enumerate() {
        diff |= e ^ presented.get(i).copied().unwrap_or(!e);
    }
    std::hint::black_box(diff) == 0
}

/// Builds a [`Reader`]. [`ReaderBuilder::auth`] is required.
#[derive(Default)]
pub struct ReaderBuilder {
    auth: Option<Auth>,
    engine: Option<&'static Engine>,
    audit_store: Option<Option<Arc<dyn AuditStore>>>,
    api_store: Option<Option<Arc<dyn StreamStore>>>,
    syslog_store: Option<Option<Arc<dyn StreamStore>>>,
    tenant_scope: Option<Arc<TenantFn>>,
    enforce_tenant_isolation: bool,
    search_enabled: Option<bool>,
    node_id: Option<String>,
    prefix: String,
}

impl ReaderBuilder {
    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// The engine to read; default [`DEFAULT`].
    pub fn engine(mut self, engine: &'static Engine) -> Self {
        self.engine = Some(engine);
        self
    }

    /// The audit store to read instead of the engine's; `None` for none.
    pub fn audit_store(mut self, store: Option<Arc<dyn AuditStore>>) -> Self {
        self.audit_store = Some(store);
        self
    }

    /// The api stream store to read instead of the engine's api stream.
    pub fn api_store(mut self, store: Option<Arc<dyn StreamStore>>) -> Self {
        self.api_store = Some(store);
        self
    }

    /// The sys stream store to read instead of the engine's sys stream.
    pub fn syslog_store(mut self, store: Option<Arc<dyn StreamStore>>) -> Self {
        self.syslog_store = Some(store);
        self
    }

    /// Resolve the caller's tenant from the (already authenticated)
    /// request. Every route is then limited to that tenant, any
    /// `?tenant_id=` is ignored, and a request it returns `None` or an empty
    /// tenant for gets a 401.
    pub fn tenant_scope(mut self, f: impl Fn(&Request) -> Option<String> + Send + Sync + 'static) -> Self {
        self.tenant_scope = Some(Arc::new(f));
        self
    }

    /// Refuse to build without a tenant scope. Set it on any shared-store
    /// multi-tenant deployment.
    pub fn enforce_tenant_isolation(mut self) -> Self {
        self.enforce_tenant_isolation = true;
        self
    }

    /// Whether free-text search is on; default the engine's setting.
    pub fn search_enabled(mut self, on: bool) -> Self {
        self.search_enabled = Some(on);
        self
    }

    /// The node whose chain the doctor checks; default the engine's.
    pub fn node_id(mut self, node_id: impl Into<String>) -> Self {
        self.node_id = Some(node_id.into());
        self
    }

    /// A path prefix the routes sit under, such as `/api/v1/logs`.
    pub fn prefix(mut self, prefix: &str) -> Self {
        self.prefix = prefix.trim_end_matches('/').to_string();
        self
    }

    pub fn build(self) -> Result<Reader, Error> {
        let auth = match self.auth {
            None => {
                return Err(Error::InvalidConfig(
                    "fasten reader: auth is required. Pass Auth::bearer(token) (or require_bearer()), Auth::verify(fn), or Auth::None when the routes are authenticated outside the reader. There is no default, so a reader cannot be deployed without auth by mistake.".into(),
                ))
            }
            Some(Auth::Bearer(t)) if t.is_empty() => {
                return Err(Error::InvalidConfig("fasten reader: the bearer token must not be empty.".into()))
            }
            Some(a) => a,
        };
        if self.enforce_tenant_isolation && self.tenant_scope.is_none() {
            return Err(Error::InvalidConfig(
                "fasten reader: enforce_tenant_isolation requires a tenant_scope function. Wire (request) -> tenant from your auth layer, or drop enforce_tenant_isolation for a single-tenant deployment.".into(),
            ));
        }
        Ok(Reader {
            auth,
            engine: self.engine.unwrap_or(&DEFAULT),
            audit_store: self.audit_store,
            api_store: self.api_store,
            syslog_store: self.syslog_store,
            tenant_scope: self.tenant_scope,
            search_enabled: self.search_enabled,
            node_id: self.node_id,
            prefix: self.prefix,
        })
    }
}

/// The HTTP reader. Build it with [`Reader::builder`].
pub struct Reader {
    auth: Auth,
    engine: &'static Engine,
    audit_store: Option<Option<Arc<dyn AuditStore>>>,
    api_store: Option<Option<Arc<dyn StreamStore>>>,
    syslog_store: Option<Option<Arc<dyn StreamStore>>>,
    tenant_scope: Option<Arc<TenantFn>>,
    search_enabled: Option<bool>,
    node_id: Option<String>,
    prefix: String,
}

#[derive(Debug)]
struct HttpError {
    status: u16,
    detail: String,
    /// The error type to log, for a 500.
    error_type: Option<&'static str>,
}

fn unprocessable(detail: impl Into<String>) -> HttpError {
    HttpError { status: 422, detail: detail.into(), error_type: None }
}

fn bad_request(detail: impl Into<String>) -> HttpError {
    HttpError { status: 400, detail: detail.into(), error_type: None }
}

impl From<Error> for HttpError {
    fn from(e: Error) -> Self {
        HttpError { status: 500, detail: "internal error".into(), error_type: Some(crate::retention::error_type(&e)) }
    }
}

type Result2<T> = std::result::Result<T, HttpError>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    Sys,
    Api,
    Audit,
    Doctor,
    Correlate,
    Search,
    Topology,
}

/// The path as sent, or `None` for a path the reader does not serve: one
/// with an empty, `.` or `..` segment, a backslash, or `%2e`, `%2f` or
/// `%5c`. A router in front could read such a path as another one.
fn raw_path(path: &str) -> Option<&str> {
    let lower = path.to_ascii_lowercase();
    let refused = path.contains("//")
        || path.contains('\\')
        || path.contains("/./")
        || path.contains("/../")
        || path.ends_with("/.")
        || path.ends_with("/..")
        || ["%2e", "%2f", "%5c"].iter().any(|e| lower.contains(e));
    (!refused).then_some(path)
}

/// Query parameters: the last value of a repeated one, as FastAPI reads it.
struct Params(Vec<(String, String)>);

impl Params {
    fn parse(query: &str) -> Self {
        Params(crate::streams::query_pairs(query))
    }

    /// A value with a NUL is a 422: a Postgres text value cannot hold one.
    fn get(&self, name: &str) -> Result2<Option<&str>> {
        let v = self.0.iter().rev().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
        if v.is_some_and(|v| v.contains('\0')) {
            return Err(unprocessable(format!("{name} must not contain a NUL character")));
        }
        Ok(v)
    }

    fn has(&self, name: &str) -> bool {
        self.0.iter().any(|(k, _)| k == name)
    }

    /// Every value is checked for a NUL, used or not.
    fn check_nul(&self) -> Result2<()> {
        for (k, _) in &self.0 {
            self.get(k)?;
        }
        Ok(())
    }

    fn text(&self, name: &str) -> Result2<Option<String>> {
        Ok(self.get(name)?.map(str::to_string))
    }
}

fn int(name: &str, s: &str) -> Result2<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(unprocessable(format!("{name} must be an integer")));
    }
    s.parse().map_err(|_| unprocessable(format!("{name} must be between {} and {}", i64::MIN, i64::MAX)))
}

fn limit(p: &Params, default: u32, max: u32) -> Result2<u32> {
    match p.get("limit")? {
        None | Some("") => Ok(default),
        Some(s) => {
            let n = int("limit", s)?;
            u32::try_from(n)
                .ok()
                .filter(|n| (1..=max).contains(n))
                .ok_or_else(|| unprocessable(format!("limit must be between 1 and {max}")))
        }
    }
}

fn q_param(p: &Params, required: bool) -> Result2<Option<String>> {
    match p.get("q")? {
        None if required => Err(unprocessable("q is required")),
        None => Ok(None),
        Some("") => Err(unprocessable("q must not be empty")),
        Some(s) if s.chars().count() > MAX_Q => Err(unprocessable(format!("q must be at most {MAX_Q} characters"))),
        Some(s) => Ok(Some(s.to_string())),
    }
}

/// Python's repr of a string.
fn py_repr(s: &str) -> String {
    if s.contains('\'') && !s.contains('"') {
        format!("\"{}\"", s.replace('\\', "\\\\"))
    } else {
        format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
    }
}

fn py_list<S: AsRef<str>>(items: &[S]) -> String {
    format!("[{}]", items.iter().map(|s| py_repr(s.as_ref())).collect::<Vec<_>>().join(", "))
}

/// `?since=` or `?until=` in the canonical form (spec §4.3), since stored
/// timestamps are compared as text. Empty gives `None`; a timestamp without
/// an offset is UTC. Refuses what Python's `datetime.fromisoformat` refuses
/// (year 0, an offset of a day or more) and any instant outside years 1 to
/// 9999 in UTC, which the stores cannot hold.
fn window_ts(name: &str, s: Option<&str>) -> Result2<Option<String>> {
    let Some(s) = s.filter(|s| !s.is_empty()) else { return Ok(None) };
    parse_window_ts(s).map(Some).ok_or_else(|| {
        unprocessable(format!(
            "{name} must be RFC3339 (e.g. 2026-08-21T10:00:00Z): Invalid isoformat string: {}",
            py_repr(s)
        ))
    })
}

fn parse_window_ts(s: &str) -> Option<String> {
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime, TimeDelta};
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<u32> {
        let part = b.get(from..from + len)?;
        part.iter().all(u8::is_ascii_digit).then(|| part.iter().fold(0, |n, d| n * 10 + u32::from(d - b'0')))
    };
    let year = num(0, 4)?;
    if b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') || !matches!(b.get(10), Some(b'T' | b't' | b' ')) {
        return None;
    }
    if b.get(13) != Some(&b':') || b.get(16) != Some(&b':') {
        return None;
    }
    let (month, day, hour, minute, second) = (num(5, 2)?, num(8, 2)?, num(11, 2)?, num(14, 2)?, num(17, 2)?);
    let mut i = 19;
    let mut micros = 0u32;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        let mut end = start;
        while b.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end == start {
            return None;
        }
        let digits = &s[start..end];
        let six: String = digits.chars().chain(std::iter::repeat('0')).take(6).collect();
        micros = six.parse().ok()?;
        i = end;
    }
    let offset_secs: i64 = match &s[i..] {
        "" | "Z" | "z" => 0,
        off => {
            let ob = off.as_bytes();
            if ob.len() != 6 || ob[3] != b':' || !matches!(ob[0], b'+' | b'-') {
                return None;
            }
            let oh = num(i + 1, 2)?;
            let om = num(i + 4, 2)?;
            if oh > 23 || om > 59 {
                return None;
            }
            let secs = i64::from(oh * 3600 + om * 60);
            if ob[0] == b'-' { -secs } else { secs }
        }
    };
    if year == 0 {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, month, day)?;
    let time = NaiveTime::from_hms_micro_opt(hour, minute, second, micros)?;
    let utc = NaiveDateTime::new(date, time).checked_sub_signed(TimeDelta::seconds(offset_secs))?;
    let y = chrono::Datelike::year(&utc);
    if !(1..=9999).contains(&y) {
        return None;
    }
    Some(utc.and_utc().to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
}

/// Raw JSON spliced into a response, so audit `detail` goes out as stored,
/// every number token exact.
struct Out {
    nonce: String,
    raws: Vec<String>,
}

impl Out {
    fn new() -> Self {
        Self { nonce: uuid::Uuid::new_v4().simple().to_string(), raws: Vec::new() }
    }

    fn raw(&mut self, text: String) -> Value {
        self.raws.push(text);
        Value::String(format!("\u{1}fasten-raw-{}-{}", self.nonce, self.raws.len() - 1))
    }

    fn render(&self, v: &Value) -> String {
        let mut body = v.to_string();
        for (i, raw) in self.raws.iter().enumerate() {
            let marker = Value::String(format!("\u{1}fasten-raw-{}-{i}", self.nonce)).to_string();
            body = body.replacen(&marker, raw, 1);
        }
        body
    }
}

/// `detail` as JSON text. A Python `NaN` or `Infinity` token, which is not
/// JSON, goes out as null.
fn detail_text(j: &Json) -> String {
    fn plain(j: &Json) -> bool {
        match j {
            Json::Number(t) => t.starts_with(|c: char| c == '-' || c.is_ascii_digit()) && !t.ends_with("Infinity"),
            Json::Array(items) => items.iter().all(plain),
            Json::Object(map) => map.values().all(plain),
            _ => true,
        }
    }
    fn lossy(j: &Json) -> Value {
        match j {
            Json::Null => Value::Null,
            Json::Bool(b) => Value::Bool(*b),
            Json::Number(t) => t.parse::<serde_json::Number>().map_or(Value::Null, Value::Number),
            Json::String(s) => Value::String(s.to_string_lossy()),
            Json::Array(items) => Value::Array(items.iter().map(lossy).collect()),
            Json::Object(map) => Value::Object(map.iter().map(|(k, v)| (k.to_string_lossy(), lossy(v))).collect()),
        }
    }
    if plain(j) {
        j.to_string()
    } else {
        lossy(j).to_string()
    }
}

fn audit_json(r: &ChainRow, out: &mut Out) -> Value {
    let form = if r.canonical_form_id.is_empty() { "1" } else { r.canonical_form_id.as_str() };
    json!({
        "id": r.id,
        "origin_id": r.origin_id,
        "monotonic_seq": r.monotonic_seq,
        "timestamp": r.timestamp,
        "code": r.code,
        "action": r.action,
        "severity": r.severity,
        "service_id": r.service_id,
        "source_node_id": r.source_node_id,
        "tenant_id": r.tenant_id,
        "actor": r.actor,
        "actor_kind": r.actor_kind,
        "target": r.target,
        "category": r.category,
        "domain": r.domain,
        "method": r.method,
        "request_id": r.request_id,
        "detail": out.raw(detail_text(&r.detail)),
        "wire_version": r.wire_version,
        "shipped_at": r.shipped_at,
        "canonical_form_id": form,
        "prev_hash": r.prev_hash,
        "hash": r.hash,
        "detail_salt": r.detail_salt,
        "detail_commitment": r.detail_commitment,
    })
}

/// sys and api rows carry `tenant_id` in the payload, not a column, so they
/// are filtered here. A row without one is left out of a scoped read.
fn scope_rows(rows: Vec<StreamRow>, tenant: Option<&str>) -> Vec<StreamRow> {
    match tenant {
        None => rows,
        Some(t) => rows.into_iter().filter(|r| r.get("tenant_id").and_then(Value::as_str) == Some(t)).collect(),
    }
}

fn scope_audit(rows: Vec<ChainRow>, tenant: Option<&str>) -> Vec<ChainRow> {
    match tenant {
        None => rows,
        Some(t) => rows.into_iter().filter(|r| r.tenant_id.as_deref() == Some(t)).collect(),
    }
}

fn rows_json(rows: Vec<StreamRow>) -> Value {
    Value::Array(rows.into_iter().map(Value::Object).collect())
}

/// One stream as a request reads it: the engine's, or a store given to the
/// reader.
enum StreamRef<'a> {
    Engine(&'a Stream),
    Store(Option<&'a Arc<dyn StreamStore>>),
}

impl StreamRef<'_> {
    fn source(&self) -> &'static str {
        match self {
            StreamRef::Engine(s) => s.source(),
            StreamRef::Store(None) => "ring",
            StreamRef::Store(Some(s)) if s.degraded() => "store-degraded",
            StreamRef::Store(Some(_)) => "store",
        }
    }

    fn query(&self, f: &StreamFilter, limit: u32) -> Result<Vec<StreamRow>, Error> {
        match self {
            StreamRef::Engine(s) => s.query(f, limit),
            StreamRef::Store(None) => Ok(Vec::new()),
            StreamRef::Store(Some(s)) => s.query(f, limit),
        }
    }

    fn count_matching(&self, f: &StreamFilter) -> Result<u64, Error> {
        match self {
            StreamRef::Engine(s) => s.count_matching(f),
            StreamRef::Store(None) => Ok(0),
            StreamRef::Store(Some(s)) => s.count_matching(f),
        }
    }

    fn search(&self, q: &str, since: &str, until: Option<&str>, limit: u32) -> Option<Result<Vec<StreamRow>, Error>> {
        match self {
            StreamRef::Engine(s) => s.search(q, since, until, limit),
            StreamRef::Store(None) => None,
            StreamRef::Store(Some(s)) => Some(s.search(q, since, until, limit)),
        }
    }
}

/// What one request reads.
struct Ctx<'a> {
    reader: &'a Reader,
    state: ReaderState,
    store: Option<Arc<dyn AuditStore>>,
    search_on: bool,
    node_id: Option<String>,
}

impl Ctx<'_> {
    /// The api or sys stream, or `None` when there is neither an engine
    /// stream nor a store given to the reader.
    fn stream(&self, name: &str) -> Option<StreamRef<'_>> {
        let given = if name == "api" { &self.reader.api_store } else { &self.reader.syslog_store };
        let given_any = self.reader.api_store.is_some() || self.reader.syslog_store.is_some();
        match (given, &self.state.streams) {
            (Some(store), _) => Some(StreamRef::Store(store.as_ref())),
            (None, Some(s)) => Some(StreamRef::Engine(s.get(name))),
            (None, None) if given_any => Some(StreamRef::Store(None)),
            (None, None) => None,
        }
    }

    fn source(&self, name: &str) -> &'static str {
        if name == "audit" {
            let Some(store) = &self.store else { return "ring" };
            let own = self.state.cfg.as_ref().and_then(|c| c.audit_store.as_ref());
            let is_own = own.is_some_and(|o| std::ptr::addr_eq(Arc::as_ptr(o), Arc::as_ptr(store)));
            return if is_own && self.reader.engine.audit_degraded() { "store-degraded" } else { "store" };
        }
        self.stream(name).map_or("ring", |s| s.source())
    }

    fn search_guard(&self, since: Option<&str>) -> Option<&'static str> {
        if !self.search_on {
            return Some("search disabled — set search.enabled (FASTEN_SEARCH_ENABLED=true) to enable free-text q=");
        }
        if since.is_none_or(str::is_empty) {
            return Some("q= search requires a 'since' bound (no unbounded scans)");
        }
        None
    }
}

impl Reader {
    pub fn builder() -> ReaderBuilder {
        ReaderBuilder::default()
    }

    /// Answer `req`; a path the reader does not serve gets a 404.
    pub fn handle(&self, req: &Request) -> Response {
        self.try_handle(req).unwrap_or_else(|| Response::detail(404, "Not Found"))
    }

    /// Answer `req`, or `None` when its path is not one the reader serves,
    /// so the server can pass it on.
    pub fn try_handle(&self, req: &Request) -> Option<Response> {
        let mut path = raw_path(&req.path)?;
        if !self.prefix.is_empty() {
            let rest = path.strip_prefix(self.prefix.as_str())?;
            if !rest.is_empty() && !rest.starts_with('/') {
                return None;
            }
            path = if rest.is_empty() { "/" } else { rest };
        }
        let route = match path {
            "/sys" => Route::Sys,
            "/api" => Route::Api,
            "/audit" => Route::Audit,
            "/audit/doctor" => Route::Doctor,
            "/correlate" => Route::Correlate,
            "/search" => Route::Search,
            "/topology" => Route::Topology,
            _ => return None,
        };
        if req.method != "GET" {
            let mut res = Response::detail(405, "Method Not Allowed");
            res.headers.push(("Allow".into(), "GET".into()));
            return Some(res);
        }
        Some(self.answer(route, path, req))
    }

    fn authorised(&self, req: &Request) -> bool {
        match &self.auth {
            Auth::None => true,
            Auth::Verify(f) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(req))).unwrap_or(false),
            Auth::Bearer(token) => req
                .header("authorization")
                .and_then(|h| h.strip_prefix("Bearer "))
                .is_some_and(|presented| token_matches(presented.as_bytes(), token.as_bytes())),
        }
    }

    fn answer(&self, route: Route, path: &str, req: &Request) -> Response {
        if !self.authorised(req) {
            return Response::detail(401, "unauthenticated");
        }
        // The tenant before the parameters: a caller without one learns
        // nothing from a 422.
        let tenant = match &self.tenant_scope {
            None => None,
            Some(f) => match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(req))) {
                // An empty tenant would read as no filter.
                Ok(Some(t)) if !t.is_empty() => Some(t),
                _ => return Response::detail(401, "unauthenticated: tenant scope unresolved"),
            },
        };
        let params = Params::parse(&req.query);
        let mut out = Out::new();
        let result = params.check_nul().and_then(|()| {
            let ctx = self.context();
            let t = tenant.as_deref();
            match route {
                Route::Sys => route_sys(&ctx, &params, t),
                Route::Api => route_api(&ctx, &params, t),
                Route::Audit => route_audit(&ctx, &params, t, &mut out),
                Route::Doctor => Ok(route_doctor(&ctx, t)),
                Route::Correlate => route_correlate(&ctx, &params, t, &mut out),
                Route::Search => route_search(&ctx, &params, t, &mut out),
                Route::Topology => route_topology(&ctx, &params, t),
            }
        });
        match result {
            Ok(body) => Response::new(200, out.render(&body)),
            Err(e) => {
                if let Some(error_type) = e.error_type {
                    // Type only: driver errors can quote SQL, row values and the host.
                    self.log("reader_query_failed", json!({ "path": path, "error_type": error_type }));
                }
                Response::detail(e.status, &e.detail)
            }
        }
    }

    fn context(&self) -> Ctx<'_> {
        let state = self.engine.reader_state();
        let store = match &self.audit_store {
            Some(s) => s.clone(),
            None => state.cfg.as_ref().and_then(|c| c.audit_store.clone()),
        };
        let search_on = self.search_enabled.unwrap_or_else(|| state.cfg.as_ref().is_some_and(|c| c.search_enabled));
        let node_id = self
            .node_id
            .clone()
            .or_else(|| state.cfg.as_ref().map(|c| c.node_id.clone()))
            .filter(|n| !n.is_empty());
        Ctx { reader: self, state, store, search_on, node_id }
    }

    fn log(&self, event: &str, mut fields: Value) {
        if let (Value::Object(m), Some(rid)) = (&mut fields, crate::current_request_id()) {
            m.insert("request_id".into(), rid.into());
        }
        self.engine.sys_event("error", event, fields);
    }

    /// The store's count, or `None` when it cannot count: the rows are
    /// still worth returning.
    fn count_or_null(&self, store: &dyn AuditStore, q: &AuditQuery) -> Option<u64> {
        match store.count(q) {
            Ok(n) => Some(n),
            Err(Error::Unsupported(_)) => None,
            Err(e) => {
                self.log("reader_count_failed", json!({ "error_type": crate::retention::error_type(&e) }));
                None
            }
        }
    }

    /// Log a failed doctor check by type and return the fixed text the
    /// response carries.
    fn check_failed(&self, check: &str, e: &Error) -> String {
        self.log("doctor_check_failed", json!({ "check": check, "error_type": crate::retention::error_type(e) }));
        format!("{check} check failed; see the service log")
    }
}

fn route_sys(ctx: &Ctx<'_>, p: &Params, tenant: Option<&str>) -> Result2<Value> {
    let limit = limit(p, 100, 1000)?;
    let text = q_param(p, false)?;
    let completeness = json!({ "sys": ctx.source("sys") });
    let Some(sys) = ctx.stream("sys") else {
        return Ok(json!({ "rows": [], "completeness": completeness, "error": NOT_INITIALISED }));
    };
    let since = window_ts("since", p.get("since")?)?;
    let until = window_ts("until", p.get("until")?)?;
    if let Some(q) = text {
        if let Some(err) = ctx.search_guard(since.as_deref()) {
            return Ok(json!({ "rows": [], "completeness": completeness, "error": err }));
        }
        // q= cannot be combined with filters; reject rather than ignore them.
        let dropped: Vec<&str> = ["level", "request_id", "service_id", "event"].into_iter().filter(|n| p.has(n)).collect();
        if !dropped.is_empty() {
            return Err(bad_request(format!(
                "q= is a free-text search and cannot be combined with structured filters ({}). Use one or the other — structured filters run over the store index; q= runs over the raw payload.",
                dropped.join(", ")
            )));
        }
        let Some(rows) = sys.search(&q, since.as_deref().unwrap_or(""), until.as_deref(), limit.min(200)) else {
            return Ok(json!({
                "rows": [], "completeness": completeness,
                "error": "search requires sys persistence: configure a syslog store",
            }));
        };
        return Ok(json!({ "rows": rows_json(scope_rows(rows?, tenant)), "completeness": completeness }));
    }
    let f = StreamFilter {
        level: p.text("level")?,
        request_id: p.text("request_id")?,
        service_id: p.text("service_id")?,
        event: p.text("event")?,
        since,
        until,
        ..Default::default()
    };
    let rows = sys.query(&f, limit)?;
    Ok(json!({ "rows": rows_json(scope_rows(rows, tenant)), "completeness": completeness }))
}

fn route_api(ctx: &Ctx<'_>, p: &Params, tenant: Option<&str>) -> Result2<Value> {
    let limit = limit(p, 100, 1000)?;
    let status = match p.get("status")? {
        None | Some("") => None,
        Some(s) => {
            let n = int("status", s)?;
            // The status column is a 32-bit INTEGER.
            Some(i32::try_from(n).map_err(|_| unprocessable("status must be between -2147483648 and 2147483647"))?)
        }
    };
    if let Some(q) = p.get("q")? {
        if q.chars().count() > MAX_Q {
            return Err(unprocessable(format!("q must be at most {MAX_Q} characters")));
        }
        return Err(bad_request(
            "free-text q= not accepted on /api — use /search?streams=api (or /logs/sys?q= for syslog only)",
        ));
    }
    let completeness = json!({ "api": ctx.source("api") });
    let Some(api) = ctx.stream("api") else {
        return Ok(json!({ "rows": [], "completeness": completeness, "error": NOT_INITIALISED }));
    };
    let f = StreamFilter {
        method: p.text("method")?,
        path: p.text("path")?,
        request_id: p.text("request_id")?,
        status,
        since: window_ts("since", p.get("since")?)?,
        until: window_ts("until", p.get("until")?)?,
        ..Default::default()
    };
    let rows = api.query(&f, limit)?;
    Ok(json!({ "rows": rows_json(scope_rows(rows, tenant)), "completeness": completeness }))
}

fn route_audit(ctx: &Ctx<'_>, p: &Params, tenant: Option<&str>, out: &mut Out) -> Result2<Value> {
    let limit = limit(p, 100, 1000)?;
    let offset = match p.get("offset")? {
        None | Some("") => 0,
        Some(s) => int("offset", s)?,
    };
    if offset < 0 {
        return Err(unprocessable("offset must be non-negative"));
    }
    let after = match p.get("after")? {
        None | Some("") => None,
        Some(s) => {
            let n = int("after", s)?;
            if n < 1 {
                return Err(unprocessable("after must be >= 1 (monotonic_seq starts at 1; 0 is not a valid cursor)"));
            }
            Some(n)
        }
    };
    let since = window_ts("since", p.get("since")?)?;
    let until = window_ts("until", p.get("until")?)?;
    let completeness = json!({ "audit": ctx.source("audit") });
    let Some(store) = &ctx.store else {
        return Ok(json!({
            "rows": [], "total": 0, "limit": limit, "offset": offset, "next_after": null,
            "completeness": completeness, "error": NO_AUDIT_STORE,
        }));
    };
    // A scoped caller's tenant replaces any ?tenant_id=.
    let q = AuditQuery {
        request_id: p.text("request_id")?,
        code: p.text("code")?,
        domain: p.text("domain")?,
        source_node_id: p.text("source_node_id")?,
        tenant_id: match tenant {
            Some(t) => Some(t.to_string()),
            None => p.text("tenant_id")?,
        },
        actor: p.text("actor")?,
        target: p.text("target")?,
        since,
        until,
        limit,
        offset: offset.unsigned_abs(),
        after_seq: after.map_or(0, i64::unsigned_abs),
    };
    let rows = scope_audit(store.query(&q)?, tenant);
    let total = ctx.reader.count_or_null(store.as_ref(), &q);
    // Rows are newest first, so next_after is the smallest seq.
    let next_after = rows.last().map(|r| r.monotonic_seq);
    let rows: Vec<Value> = rows.iter().map(|r| audit_json(r, out)).collect();
    Ok(json!({
        "rows": rows, "total": total, "limit": limit, "offset": offset,
        "next_after": next_after, "completeness": completeness,
    }))
}

fn route_correlate(ctx: &Ctx<'_>, p: &Params, tenant: Option<&str>, out: &mut Out) -> Result2<Value> {
    let rid = match p.get("request_id")? {
        Some(r) if !r.is_empty() => r.to_string(),
        _ => return Err(unprocessable("request_id is required")),
    };
    let limit = limit(p, 100, 1000)?;
    let mut counts = Map::new();
    let mut totals = Map::new();
    let mut truncated = Map::new();
    // Every stream is scoped, so a known request_id cannot reach another
    // tenant's rows.
    let (audit, audit_total) = match &ctx.store {
        Some(s) => {
            let q = AuditQuery {
                request_id: Some(rid.clone()),
                tenant_id: tenant.map(str::to_string),
                limit,
                ..Default::default()
            };
            (scope_audit(s.query(&q)?, tenant), ctx.reader.count_or_null(s.as_ref(), &q))
        }
        None => (Vec::new(), None),
    };
    counts.insert("audit".into(), json!(audit.len()));
    totals.insert("audit".into(), json!(audit_total));
    truncated.insert("audit".into(), json!(audit_total.map(|t| (audit.len() as u64) < t)));
    let mut out_rows = Map::new();
    for name in ["api", "sys"] {
        let Some(stream) = ctx.stream(name) else {
            out_rows.insert(name.into(), json!([]));
            counts.insert(name.into(), json!(0));
            totals.insert(name.into(), json!(0));
            truncated.insert(name.into(), json!(false));
            continue;
        };
        let f = StreamFilter { request_id: Some(rid.clone()), ..Default::default() };
        let rows = scope_rows(stream.query(&f, limit)?, tenant);
        let n = rows.len() as u64;
        counts.insert(name.into(), json!(n));
        if tenant.is_none() {
            let total = stream.count_matching(&f)?;
            totals.insert(name.into(), json!(total));
            truncated.insert(name.into(), json!(n < total));
        } else {
            // Stream counts cannot take a tenant, so a scoped caller's
            // totals count its own rows, as Python and Go do.
            totals.insert(name.into(), json!(n));
            truncated.insert(name.into(), json!(false));
        }
        out_rows.insert(name.into(), rows_json(rows));
    }
    let audit: Vec<Value> = audit.iter().map(|r| audit_json(r, out)).collect();
    Ok(json!({
        "request_id": rid,
        "audit": audit,
        "api": out_rows.remove("api"),
        "sys": out_rows.remove("sys"),
        "counts": counts,
        "totals": totals,
        "truncated": truncated,
        "completeness": {
            "audit": ctx.source("audit"),
            "api": ctx.source("api"),
            "sys": ctx.source("sys"),
        },
    }))
}

fn route_search(ctx: &Ctx<'_>, p: &Params, tenant: Option<&str>, out: &mut Out) -> Result2<Value> {
    let Some(text) = q_param(p, true)? else { return Err(unprocessable("q is required")) };
    if p.get("since")?.is_none() {
        return Err(unprocessable("since is required"));
    }
    let limit = limit(p, 50, 200)?;
    let raw = p.get("streams")?.filter(|s| !s.is_empty()).unwrap_or("sys");
    let mut parsed: Vec<String> = raw.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect();
    parsed.sort();
    parsed.dedup();
    let unknown: Vec<&String> = parsed.iter().filter(|s| !SEARCH_STREAMS.contains(&s.as_str())).collect();
    if !unknown.is_empty() {
        return Err(bad_request(format!(
            "streams={}: unknown stream(s) {}. Valid: {}.",
            py_list(&parsed),
            py_list(&unknown),
            py_list(&["api", "audit", "sys"])
        )));
    }
    if parsed.is_empty() {
        parsed.push("sys".into());
    }
    let mut completeness = Map::new();
    let mut empty_counts = Map::new();
    for s in &parsed {
        completeness.insert(s.clone(), json!(ctx.source(s)));
        empty_counts.insert(s.clone(), json!(0));
    }
    let since = window_ts("since", p.get("since")?)?.unwrap_or_default();
    let until = window_ts("until", p.get("until")?)?;
    let fail = |error: &str| json!({ "matches": [], "counts": empty_counts, "completeness": completeness, "error": error });
    if let Some(err) = ctx.search_guard(Some(&since)) {
        return Ok(fail(err));
    }
    if ctx.stream("sys").is_none() {
        return Ok(fail(NOT_INITIALISED));
    }
    let mut matches = Vec::new();
    let mut counts = Map::new();
    let mut errors = Map::new();
    // Fixed order: sys, api, audit.
    for stream in ["sys", "api", "audit"] {
        if !parsed.iter().any(|s| s == stream) {
            continue;
        }
        if stream == "audit" {
            let found = match &ctx.store {
                None => None,
                Some(s) => {
                    let search = AuditSearch {
                        q: text.clone(),
                        since: since.clone(),
                        until: until.clone(),
                        limit,
                        tenant_id: tenant.map(str::to_string),
                    };
                    match s.search(&search) {
                        Err(Error::Unsupported(_)) => None,
                        other => Some(other?),
                    }
                }
            };
            let Some(rows) = found else {
                errors.insert("audit".into(), json!("requires an audit store with a search method"));
                counts.insert("audit".into(), json!(0));
                continue;
            };
            let rows = scope_audit(rows, tenant);
            counts.insert("audit".into(), json!(rows.len()));
            for r in &rows {
                matches.push(json!({
                    "stream": "audit",
                    "request_id": r.request_id,
                    "ts": if r.timestamp.is_empty() { Value::Null } else { json!(r.timestamp) },
                    "summary": r.code,
                    "row": audit_json(r, out),
                }));
            }
            continue;
        }
        let found = ctx.stream(stream).and_then(|s| s.search(&text, &since, until.as_deref(), limit));
        let Some(rows) = found else {
            let msg = if stream == "sys" {
                "requires sys persistence: configure a syslog store"
            } else {
                "requires api persistence: configure an api store"
            };
            errors.insert(stream.into(), json!(msg));
            counts.insert(stream.into(), json!(0));
            continue;
        };
        let rows = scope_rows(rows?, tenant);
        counts.insert(stream.into(), json!(rows.len()));
        for row in rows {
            let summary = if stream == "sys" {
                row.get("event").cloned().unwrap_or(Value::Null)
            } else {
                let part = |k: &str| match row.get(k) {
                    None | Some(Value::Null) => String::new(),
                    Some(Value::String(s)) => s.clone(),
                    Some(v) => v.to_string(),
                };
                json!(format!("{} {}", part("method"), part("path")).trim())
            };
            matches.push(json!({
                "stream": stream,
                "request_id": row.get("request_id").cloned().unwrap_or(Value::Null),
                "ts": row.get("timestamp").cloned().unwrap_or(Value::Null),
                "summary": summary,
                "row": Value::Object(row),
            }));
        }
    }
    let mut resp = json!({ "matches": matches, "counts": counts, "completeness": completeness });
    if !errors.is_empty() {
        resp["errors"] = Value::Object(errors);
    }
    Ok(resp)
}

fn route_topology(ctx: &Ctx<'_>, p: &Params, tenant: Option<&str>) -> Result2<Value> {
    let since = window_ts("since", p.get("since")?)?;
    let until = window_ts("until", p.get("until")?)?;
    let empty = |error: &str| json!({ "sources": [], "nodes": 0, "services": 0, "tenants": 0, "error": error });
    let Some(store) = &ctx.store else { return Ok(empty(NO_AUDIT_STORE)) };
    let mut sources = match store.sources(since.as_deref(), until.as_deref()) {
        Err(Error::Unsupported(_)) => return Ok(empty("store does not support topology aggregation")),
        other => other?,
    };
    if let Some(t) = tenant {
        sources.retain(|s| s.tenant_id.as_deref() == Some(t));
    }
    let distinct = |f: &dyn Fn(&crate::Source) -> Option<&str>| {
        let mut v: Vec<&str> = sources.iter().filter_map(f).collect();
        v.sort_unstable();
        v.dedup();
        v.len()
    };
    let nodes = distinct(&|s| Some(s.source_node_id.as_str()));
    let services = distinct(&|s| Some(s.service_id.as_str()));
    let tenants = distinct(&|s| s.tenant_id.as_deref().filter(|t| !t.is_empty()));
    Ok(json!({ "sources": sources, "nodes": nodes, "services": services, "tenants": tenants }))
}

fn route_doctor(ctx: &Ctx<'_>, tenant: Option<&str>) -> Value {
    // A scoped caller gets its own rows' data, not the host's.
    let scoped = tenant.is_some();
    let store = ctx.store.as_ref();
    let mut reachable = false;
    let mut rows: Option<u64> = None;
    let mut last_error: Option<String> = None;
    if let Some(s) = store {
        let q = AuditQuery { tenant_id: tenant.map(str::to_string), ..Default::default() };
        match s.count(&q) {
            Ok(n) => {
                rows = Some(n);
                reachable = true;
            }
            Err(Error::Unsupported(_)) => {}
            Err(e) => last_error = Some(ctx.reader.check_failed("store", &e)),
        }
    }

    let (queue, transport) = if scoped {
        (Value::Null, Value::Null)
    } else {
        let queue = ctx.reader.engine.queue_stats().map_or(Value::Null, |q| {
            let mut v = serde_json::to_value(&q).unwrap_or(Value::Null);
            // The type of the drainer's last error, without its message.
            if let Some(Value::String(e)) = v.get("last_error") {
                let t = e.split(':').next().unwrap_or("").to_string();
                v["last_error"] = json!(t);
            }
            v
        });
        let own = ctx.state.streams.as_ref();
        let transport = json!({
            "stdout_active": own.is_some(),
            "syslog_ring_depth": own.map_or(0, |s| s.sys.ring_len()),
            "api_ring_depth": own.map_or(0, |s| s.api.ring_len()),
        });
        (queue, transport)
    };

    let chain_unavailable = store.is_some_and(|s| !s.seals());
    let mut chain = json!({
        "verified": null,
        "breaks": null,
        "sealed_rows": null,
        "last_verified_at": null,
        "chain_unavailable": chain_unavailable,
    });
    if let Some(s) = store {
        let tail = match &ctx.node_id {
            None => Err("no node id to check"),
            // By seq: a timestamp-ordered sample skips seqs after a clock
            // step back and reads as a break.
            Some(node) => match s.chain_tail(node, 50) {
                Err(Error::Unsupported(_)) => Err("the store has no chain_tail"),
                other => Ok(other),
            },
        };
        match tail {
            Err(reason) => {
                // A store that does not seal can never be verified.
                if chain_unavailable {
                    chain["verified"] = json!(false);
                }
                chain["reason"] = json!(reason);
            }
            Ok(Err(e)) => {
                chain = json!({
                    "verified": null,
                    "breaks": null,
                    "sealed_rows": null,
                    "error": crate::retention::error_type(&e),
                    "reason": ctx.reader.check_failed("chain", &e),
                    "last_verified_at": null,
                    "chain_unavailable": chain_unavailable,
                });
            }
            Ok(Ok(recent)) => {
                reachable = true;
                let result = crate::verify_chain(&recent);
                let sealed = result.sealed_rows;
                let verified = if chain_unavailable { json!(false) } else if sealed > 0 { json!(result.ok) } else { Value::Null };
                let breaks = if chain_unavailable || sealed == 0 { Value::Null } else { json!(u8::from(!result.ok)) };
                chain = json!({
                    "verified": verified,
                    "breaks": breaks,
                    "sealed_rows": sealed,
                    "first_break_at": result.first_break_at,
                    "reason": if sealed > 0 { json!(result.reason) } else { json!("no sealed rows in sample") },
                    "last_verified_at": if sealed > 0 { json!(crate::canonical_ts(&chrono::Utc::now())) } else { Value::Null },
                    "chain_unavailable": chain_unavailable,
                });
                // The sample is this node's chain, which can hold other
                // tenants' rows: a scoped caller gets the verdict only.
                if scoped && !result.ok {
                    chain["first_break_at"] = Value::Null;
                    chain["reason"] = json!("chain break in this node's recent rows");
                }
            }
        }
    }

    let cfg = ctx.state.cfg.as_ref();
    let host = |v: Option<String>| if scoped { Value::Null } else { json!(v) };
    json!({
        "store": {
            "kind": if scoped { Value::Null } else { json!(store.map(|s| s.kind().to_string())) },
            "reachable": reachable,
            "rows": rows,
            "last_insert_at": null,
            "last_error": last_error,
        },
        "queue": queue,
        "transport": transport,
        "redactor": { "active": cfg.is_some() },
        "init": {
            "service_id": host(cfg.map(|c| c.service_id.clone()).filter(|s| !s.is_empty())),
            "node_id": host(cfg.map(|c| c.node_id.clone()).filter(|s| !s.is_empty())),
            // The host's own tenant is not a scoped caller's to read.
            "tenant_id": host(cfg.and_then(|c| c.tenant_id.clone())),
            "failure_strategy": cfg.and_then(|c| c.audit_store_failure_strategy.clone()),
            "worker_pid": if scoped { Value::Null } else { json!(std::process::id()) },
        },
        "chain": chain,
    })
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn window_timestamps() {
        let ok = |s: &str| parse_window_ts(s).unwrap_or_else(|| panic!("{s} refused"));
        assert_eq!(ok("2026-08-21T10:00:00Z"), "2026-08-21T10:00:00.000000Z");
        assert_eq!(ok("2026-08-21 10:00:00.5"), "2026-08-21T10:00:00.500000Z");
        assert_eq!(ok("2026-08-21t10:00:00.1234567+02:00"), "2026-08-21T08:00:00.123456Z");
        assert_eq!(ok("2026-08-21T10:00:00-23:59"), "2026-08-22T09:59:00.000000Z");
        for bad in [
            "2026-08-21", "2026-08-21T10:00", "0000-01-01T00:00:00Z", "2026-02-30T00:00:00Z",
            "2026-08-21T24:00:00Z", "2026-08-21T10:00:60Z", "2026-08-21T10:00:00+24:00",
            "2026-08-21T10:00:00+23:60", "0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00",
            "2026-08-21T10:00:00.Z", "2026-08-21T10:00:00+0200", " 2026-08-21T10:00:00Z",
            "２０２６-08-21T10:00:00Z",
        ] {
            assert!(parse_window_ts(bad).is_none(), "{bad} accepted");
        }
    }

    #[test]
    fn raw_paths() {
        for bad in ["//audit", "/a/./b", "/a/../audit", "/a/..", "/a/.", "/a\\b", "/%2e%2e/audit", "/a%2Fb", "/a%5c"] {
            assert!(raw_path(bad).is_none(), "{bad}");
        }
        assert_eq!(raw_path("/audit"), Some("/audit"));
    }

    #[test]
    fn token_comparison() {
        assert!(token_matches(b"abc", b"abc"));
        assert!(!token_matches(b"abd", b"abc"));
        assert!(!token_matches(b"ab", b"abc"));
        assert!(!token_matches(b"abcd", b"abc"));
        assert!(!token_matches(b"", b"abc"));
    }

    #[test]
    fn python_repr() {
        assert_eq!(py_list(&["a", "it's", "b\\"]), r#"['a', "it's", 'b\\']"#);
    }

    #[test]
    fn non_json_tokens_go_out_as_null() {
        let j = Json::parse(r#"{"a": NaN, "b": 1}"#).unwrap();
        assert_eq!(detail_text(&j), r#"{"a":null,"b":1}"#);
        let j = Json::parse(r#"{"big": 123456789012345678901234567890, "f": 75.0}"#).unwrap();
        assert_eq!(detail_text(&j), r#"{"big":123456789012345678901234567890,"f":75.0}"#);
    }
}
