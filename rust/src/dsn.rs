//! Store DSNs, as `FASTEN_AUDIT_DSN`, `FASTEN_API_DSN` and
//! `FASTEN_SYSLOG_DSN` hold them. The forms are the Python SDK's:
//!
//! - `postgres://...` or `postgresql://...` (the scheme in any case);
//! - `sqlite:///rel.db` (relative), `sqlite:////abs.db` (absolute), or a
//!   bare path;
//! - `?table=name` names the table, and `?wal=false` turns SQLite's WAL
//!   journal off.
//!
//! Any other scheme, and libpq's keyword form (`host=db dbname=app`), is an
//! error. An error names the scheme at most, never the DSN, which can hold
//! a password, and names it only when `//` follows it: in
//! `user:password@host/db` or `host:5432/db` the text before the colon is
//! not a scheme.

use std::fmt;

/// A parsed store DSN.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Dsn {
    /// A Postgres server. `url` is the DSN with its scheme in lowercase and
    /// without its `table` parameter, both as the driver needs.
    #[non_exhaustive]
    Postgres { url: String, table: String },
    /// A SQLite file.
    #[non_exhaustive]
    Sqlite { path: String, table: String, wal: bool },
}

impl Dsn {
    /// `postgres` or `sqlite`, as errors name the scheme.
    pub fn scheme(&self) -> &'static str {
        match self {
            Dsn::Postgres { .. } => "postgres",
            Dsn::Sqlite { .. } => "sqlite",
        }
    }
}

/// Leaves out the Postgres URL, which can hold a password.
impl fmt::Debug for Dsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dsn::Postgres { table, .. } => {
                f.debug_struct("Postgres").field("table", table).finish_non_exhaustive()
            }
            Dsn::Sqlite { path, table, wal } => {
                f.debug_struct("Sqlite").field("path", path).field("table", table).field("wal", wal).finish()
            }
        }
    }
}

/// Why a DSN was refused. Its text names the scheme at most.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DsnError {
    /// libpq's keyword form, which the driver does not read.
    KeywordForm,
    /// A scheme other than `sqlite`, `postgres` and `postgresql`.
    Scheme(String),
    /// Text before a colon that is none of those schemes and has no `//`
    /// after it, such as `host:5432/db`.
    Form,
    /// A SQLite DSN with no path.
    NoPath,
}

impl fmt::Display for DsnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DsnError::KeywordForm => f.write_str(
                "DSN in libpq keyword form not supported; use postgres://user@host/db, \
                 sqlite:///./fasten.db or a bare filesystem path",
            ),
            DsnError::Scheme(scheme) => write!(
                f,
                "DSN scheme '{scheme}' not supported; use sqlite:///./fasten.db, postgres://... \
                 or a bare filesystem path"
            ),
            DsnError::Form => f.write_str(
                "DSN form not recognised; use postgres://..., sqlite:///./fasten.db \
                 or a bare filesystem path",
            ),
            DsnError::NoPath => f.write_str("the SQLite DSN has no path; use sqlite:///./fasten.db or similar"),
        }
    }
}

impl std::error::Error for DsnError {}

/// The scheme, lowercased (empty for a bare path), and the text after it.
fn split_scheme(dsn: &str) -> (String, &str) {
    let Some((scheme, rest)) = dsn.split_once(':') else {
        return (String::new(), dsn);
    };
    let mut chars = scheme.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if valid {
        (scheme.to_ascii_lowercase(), rest)
    } else {
        (String::new(), dsn)
    }
}

/// `%XX` escapes and `+` decoded, as a query string is read.
fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes.get(i + 1..i + 3).filter(|h| bytes[i] == b'%' && h.iter().all(u8::is_ascii_hexdigit));
        match (bytes[i], hex) {
            (b'%', Some(h)) => {
                // Two ASCII hex digits always parse.
                out.push(u8::from_str_radix(std::str::from_utf8(h).unwrap_or("00"), 16).unwrap_or(0));
                i += 3;
                continue;
            }
            (b'+', _) => out.push(b' '),
            (b, _) => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The query parameters, decoded (`+` is a space), in order. A key
/// without `=` has an empty value.
pub(crate) fn params(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

/// The value of the last `name` parameter, unless it is empty.
fn param<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params.iter().rev().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
}

/// Parse a store DSN; `default_table` is the table when the DSN names none
/// (`audit_log` for the audit store, `api_log` or `syslog` for the stream
/// stores). Opens nothing and creates no file.
pub fn parse_dsn(dsn: &str, default_table: &str) -> Result<Dsn, DsnError> {
    let keyword = dsn.trim_start();
    let key_len = keyword.find(|c: char| !(c.is_ascii_alphabetic() || c == '_')).unwrap_or(keyword.len());
    if key_len > 0 && keyword[key_len..].trim_start().starts_with('=') {
        return Err(DsnError::KeywordForm);
    }
    let (scheme, rest) = split_scheme(dsn);
    let rest = rest.split('#').next().unwrap_or("");
    let (before_query, query) = rest.split_once('?').unwrap_or((rest, ""));
    let query = params(query);
    let table = param(&query, "table").unwrap_or(default_table).to_string();
    match scheme.as_str() {
        "postgres" | "postgresql" => {
            // The driver reads the scheme in lowercase only.
            let dsn = format!("{scheme}:{}", split_scheme(dsn).1);
            let url = match dsn.split_once('?') {
                None => dsn.clone(),
                Some((base, tail)) => {
                    let (q, fragment) = match tail.split_once('#') {
                        Some((q, f)) => (q, format!("#{f}")),
                        None => (tail, String::new()),
                    };
                    let kept: Vec<&str> = q
                        .split('&')
                        .filter(|p| !p.is_empty() && decode(p.split_once('=').map_or(p, |(k, _)| k)) != "table")
                        .collect();
                    if kept.is_empty() {
                        format!("{base}{fragment}")
                    } else {
                        format!("{base}?{}{fragment}", kept.join("&"))
                    }
                }
            };
            Ok(Dsn::Postgres { url, table })
        }
        "sqlite" | "" => {
            let mut path = before_query;
            if !scheme.is_empty() {
                // After "//" comes a host, which a file DSN leaves empty.
                if let Some(after) = path.strip_prefix("//") {
                    path = after.find('/').map_or("", |i| &after[i..]);
                }
                // Only the separator slash: sqlite:///rel.db is relative.
                path = path.strip_prefix('/').unwrap_or(path);
            }
            if path.is_empty() {
                return Err(DsnError::NoPath);
            }
            let wal = param(&query, "wal") != Some("false");
            Ok(Dsn::Sqlite { path: path.to_string(), table, wal })
        }
        _ if rest.starts_with("//") => Err(DsnError::Scheme(scheme)),
        _ => Err(DsnError::Form),
    }
}

/// The audit store for `dsn` (see [`parse_dsn`]): a [`crate::PostgresStore`]
/// or a [`crate::SqliteStore`], with the table `audit_log` unless the DSN
/// names one. Every error is [`crate::Error::InvalidConfig`] and names
/// `FASTEN_AUDIT_DSN` and the scheme only: a DSN that does not parse, a
/// scheme whose store feature (`store-postgres`, `store-sqlite`) is not
/// built in, or a store that cannot be opened.
pub fn audit_store_from_dsn(dsn: &str) -> Result<std::sync::Arc<dyn crate::AuditStore>, crate::Error> {
    open_audit_store("FASTEN_AUDIT_DSN", dsn)
}

/// [`audit_store_from_dsn`], with errors starting with `label`.
pub(crate) fn open_audit_store(label: &str, dsn: &str) -> Result<std::sync::Arc<dyn crate::AuditStore>, crate::Error> {
    let parsed = parse_dsn(dsn, "audit_log").map_err(|e| crate::Error::InvalidConfig(format!("{label}: {e}")))?;
    check_openable(label, &parsed)?;
    #[cfg(any(feature = "store-postgres", feature = "store-sqlite"))]
    let failed = |e: crate::Error| open_failed(label, &parsed, &e);
    match &parsed {
        #[cfg(feature = "store-postgres")]
        Dsn::Postgres { url, table } => {
            Ok(std::sync::Arc::new(crate::PostgresStore::new(url, table.as_str()).map_err(failed)?))
        }
        #[cfg(feature = "store-sqlite")]
        Dsn::Sqlite { path, table, wal } => {
            Ok(std::sync::Arc::new(crate::SqliteStore::open_with_wal(path, table, *wal).map_err(failed)?))
        }
        #[allow(unreachable_patterns)]
        other => Err(feature_missing(label, other)),
    }
}

/// The error for a DSN whose store feature is not built in.
pub(crate) fn feature_missing(label: &str, dsn: &Dsn) -> crate::Error {
    let scheme = dsn.scheme();
    crate::Error::InvalidConfig(format!("{label}: a {scheme} DSN needs the store-{scheme} feature"))
}

#[cfg(any(feature = "store-sqlite", feature = "store-postgres"))]
/// The error for a store from `dsn` that could not be opened. The driver's
/// text is left out: it can quote the user, host, path or database name. A
/// configuration error of the store's own, such as a bad table name, is
/// kept.
pub(crate) fn open_failed(label: &str, dsn: &Dsn, e: &crate::Error) -> crate::Error {
    if let crate::Error::InvalidConfig(msg) = e {
        return crate::Error::InvalidConfig(format!("{label}: {msg}"));
    }
    crate::Error::InvalidConfig(format!(
        "{label}: cannot open the {} store ({})",
        dsn.scheme(),
        crate::retention::error_type(e)
    ))
}

/// Refuse, before any store is opened, a DSN whose table name no store
/// takes, or a SQLite DSN whose file cannot be created because its
/// directory does not exist, so a failed `init` creates no file for the
/// other DSNs.
pub(crate) fn check_openable(label: &str, dsn: &Dsn) -> Result<(), crate::Error> {
    let table = match dsn {
        Dsn::Postgres { table, .. } | Dsn::Sqlite { table, .. } => table,
    };
    fasten_core::validate::validate_table_name(table)
        .map_err(|e| crate::Error::InvalidConfig(format!("{label}: {e}")))?;
    let Dsn::Sqlite { path, .. } = dsn else { return Ok(()) };
    if path == ":memory:" || path.starts_with("file:") {
        return Ok(());
    }
    let dir = std::path::Path::new(path).parent().filter(|d| !d.as_os_str().is_empty());
    match dir {
        Some(d) if !d.is_dir() => {
            Err(crate::Error::InvalidConfig(format!("{label}: cannot open the sqlite store (NotFound)")))
        }
        _ => Ok(()),
    }
}

/// The DSN variables `init` reads. FASTEN_AUDIT_DSN opens the audit store;
/// the stream stores read FASTEN_API_DSN and FASTEN_SYSLOG_DSN.
pub(crate) const DSN_ENV: [&str; 3] = ["FASTEN_AUDIT_DSN", "FASTEN_API_DSN", "FASTEN_SYSLOG_DSN"];

/// Whether `name` looks like a DSN variable of this SDK that `init` does
/// not read, such as a misspelt one.
pub(crate) fn unread_dsn_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("FASTEN_") else { return false };
    let named_like_dsn = ["DSN", "DNS", "URL"].iter().any(|s| rest.ends_with(s));
    named_like_dsn
        && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !DSN_ENV.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sqlite(path: &str, table: &str, wal: bool) -> Dsn {
        Dsn::Sqlite { path: path.into(), table: table.into(), wal }
    }

    #[test]
    fn the_python_forms() {
        assert_eq!(parse_dsn("sqlite:///rel.db", "audit_log"), Ok(sqlite("rel.db", "audit_log", true)));
        assert_eq!(parse_dsn("sqlite:////abs/a.db", "audit_log"), Ok(sqlite("/abs/a.db", "audit_log", true)));
        assert_eq!(parse_dsn("SQLite:///rel.db?wal=false", "x"), Ok(sqlite("rel.db", "x", false)));
        assert_eq!(parse_dsn("/var/a.db?table=t1", "audit_log"), Ok(sqlite("/var/a.db", "t1", true)));
        assert_eq!(parse_dsn("./a.db", "api_log"), Ok(sqlite("./a.db", "api_log", true)));
        assert_eq!(parse_dsn("sqlite:///a.db?table=&wal=true", "syslog"), Ok(sqlite("a.db", "syslog", true)));
        assert_eq!(
            parse_dsn("postgres://u:p@db/app?table=audit.rows&sslmode=disable", "audit_log"),
            Ok(Dsn::Postgres { url: "postgres://u:p@db/app?sslmode=disable".into(), table: "audit.rows".into() })
        );
        assert_eq!(
            parse_dsn("PostgreSQL://db/app?table=t", "audit_log"),
            Ok(Dsn::Postgres { url: "postgresql://db/app".into(), table: "t".into() })
        );
        assert_eq!(
            parse_dsn("postgres://db/app", "syslog"),
            Ok(Dsn::Postgres { url: "postgres://db/app".into(), table: "syslog".into() })
        );
    }

    #[test]
    fn errors_name_the_scheme_only() {
        let secret = "s3cret";
        for (dsn, want) in [
            (format!("mysql://u:{secret}@db/app"), DsnError::Scheme("mysql".into())),
            (format!("postgresql+psycopg://u:{secret}@db/app"), DsnError::Scheme("postgresql+psycopg".into())),
            (format!("host=db password={secret}"), DsnError::KeywordForm),
            (format!(" dbname = app password={secret}"), DsnError::KeywordForm),
            ("sqlite://".to_string(), DsnError::NoPath),
            ("sqlite:///".to_string(), DsnError::NoPath),
        ] {
            let err = parse_dsn(&dsn, "audit_log").unwrap_err();
            assert_eq!(err, want, "{dsn}");
            assert!(!err.to_string().contains(secret), "{err}");
        }
        let debug = format!("{:?}", parse_dsn("postgres://u:s3cret@db/app", "t").unwrap());
        assert!(!debug.contains("s3cret"), "{debug}");
    }

    #[test]
    fn dsn_errors_name_a_scheme_only_when_the_dsn_has_one() {
        let words = ["admin", "s3cret", "db.internal", "user", "pw", "host", "hunter2"];
        for (dsn, want) in [
            ("admin:s3cret@db.internal:5432/app", DsnError::Form),
            ("db.internal:5432/app", DsnError::Form),
            ("user:pw@host/db", DsnError::Form),
            ("mysql://u:hunter2@db/app", DsnError::Scheme("mysql".into())),
        ] {
            let err = parse_dsn(dsn, "audit_log").unwrap_err();
            assert_eq!(err, want, "{dsn}");
            let text = err.to_string();
            assert!(!words.iter().any(|w| text.contains(w)), "{text}");
        }
        // The sqlite forms without "//" still parse.
        assert_eq!(parse_dsn("sqlite:rel.db", "audit_log"), Ok(sqlite("rel.db", "audit_log", true)));
        assert_eq!(parse_dsn("sqlite:/abs.db", "audit_log"), Ok(sqlite("abs.db", "audit_log", true)));
    }

    #[test]
    fn query_decoding() {
        assert_eq!(decode("a%20b%zz%4"), "a b%zz%4");
        assert_eq!(decode("%e2%82%ac"), "€");
        assert_eq!(params("a=1&b&c=x+y&a=2&d=%2B"), vec![
            ("a".into(), "1".into()),
            ("b".into(), String::new()),
            ("c".into(), "x y".into()),
            ("a".into(), "2".into()),
            ("d".into(), "+".into()),
        ]);
    }

    #[test]
    fn unread_names() {
        assert!(unread_dsn_name("FASTEN_AUDIT_DNS"));
        assert!(unread_dsn_name("FASTEN_AUDITDSN"));
        assert!(unread_dsn_name("FASTEN_READER_URL"));
        assert!(!unread_dsn_name("FASTEN_AUDIT_DSN"));
        assert!(!unread_dsn_name("FASTEN_SYSLOG_DSN"));
        assert!(!unread_dsn_name("FASTEN_SERVICE_ID"));
        assert!(!unread_dsn_name("OTHER_DSN"));
    }
}

#[cfg(all(test, feature = "store-sqlite"))]
mod init_tests {
    use std::sync::Arc;

    use crate::{AuditStore, Config, Engine};

    fn config(service: &str) -> Config {
        Config {
            service_id: service.into(),
            node_id: "node-1".into(),
            audit_store_failure_strategy: Some("raise".into()),
            ..Default::default()
        }
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn store_of(e: &Engine) -> Option<Arc<dyn AuditStore>> {
        e.current_config().unwrap().audit_store
    }

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("fasten-dsn-{}", uuid::Uuid::new_v4().simple()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn init_opens_the_audit_store_from_the_dsn_and_keeps_it_for_the_same_dsn() {
        let dir = TempDir::new();
        let file = dir.0.join("a.db");
        let dsn = format!("sqlite:///{}?table=env_audit", file.display());
        let e = Engine::new();
        e.init_with_env(config("dsn-a"), &env(&[("FASTEN_AUDIT_DSN", &dsn)])).unwrap();
        let first = store_of(&e).expect("a store from the DSN");
        assert!(file.exists());
        assert!(first.seals());
        let stored = first.allocate_and_insert_originated(&crate::row_from_replicated(&crate::ReplicatedRow::from(
            crate::ChainRow::from_json(
                r#"{"id":"e1","origin_id":"e1","monotonic_seq":0,"timestamp":"2026-06-15T10:30:00Z","source_node_id":"node-1"}"#,
            )
            .unwrap(),
        ))
        .unwrap());
        assert_eq!(stored.unwrap().monotonic_seq, 1);

        // The same DSN: the same store.
        e.init_with_env(config("dsn-a"), &env(&[("FASTEN_AUDIT_DSN", &dsn)])).unwrap();
        assert!(Arc::ptr_eq(&first, &store_of(&e).unwrap()));

        // Another DSN: a new store, and the old one let go of.
        let other = format!("{}", dir.0.join("b.db").display());
        e.init_with_env(config("dsn-a"), &env(&[("FASTEN_AUDIT_DSN", &other)])).unwrap();
        let second = store_of(&e).unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(Arc::strong_count(&first), 1, "the old store is still held");
        assert!(dir.0.join("b.db").exists());

        // A store in the config wins over the DSN.
        let mine: Arc<dyn AuditStore> = Arc::new(crate::SqliteStore::open(":memory:", "mine").unwrap());
        let cfg = Config { audit_store: Some(mine.clone()), ..config("dsn-a") };
        e.init_with_env(cfg, &env(&[("FASTEN_AUDIT_DSN", &other)])).unwrap();
        assert!(Arc::ptr_eq(&mine, &store_of(&e).unwrap()));
        assert_eq!(Arc::strong_count(&second), 1);

        // No DSN, or an empty one: no store.
        e.init_with_env(config("dsn-a"), &env(&[("FASTEN_AUDIT_DSN", "")])).unwrap();
        assert!(store_of(&e).is_none());
    }

    #[test]
    fn a_dsn_init_cannot_use_is_an_error_naming_the_scheme_only_and_creates_no_file() {
        let dir = TempDir::new();
        let e = Engine::new();
        for (dsn, want) in [
            (format!("mysql://u:s3cret@host/{}", dir.0.join("m.db").display()), "'mysql'"),
            (format!("ftp:///{}", dir.0.join("f.db").display()), "'ftp'"),
            ("host=db password=s3cret".to_string(), "keyword form"),
        ] {
            let err = e.init_with_env(config("dsn-b"), &env(&[("FASTEN_AUDIT_DSN", &dsn)])).unwrap_err();
            assert!(matches!(err, crate::Error::InvalidConfig(_)), "{err:?}");
            let text = err.to_string();
            assert!(text.contains(want) && text.contains("FASTEN_AUDIT_DSN"), "{text}");
            assert!(!text.contains("s3cret") && !text.contains(&dir.0.display().to_string()), "{text}");
        }
        assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
        assert!(e.current_config().is_err(), "a failed init left a config");
    }

    #[test]
    fn dsn_errors_from_init_name_a_scheme_only_when_the_dsn_has_one() {
        let words = ["admin", "s3cret", "db.internal", "user", "pw", "host", "hunter2"];
        let e = Engine::new();
        for name in crate::dsn::DSN_ENV {
            for dsn in ["admin:s3cret@db.internal:5432/app", "db.internal:5432/app", "user:pw@host/db"] {
                let text = e.init_with_env(config("dsn-f"), &env(&[(name, dsn)])).unwrap_err().to_string();
                assert_eq!(
                    text,
                    format!("{name}: DSN form not recognised; use postgres://..., sqlite:///./fasten.db or a bare filesystem path")
                );
            }
            let text = e.init_with_env(config("dsn-f"), &env(&[(name, "mysql://u:hunter2@db/app")])).unwrap_err().to_string();
            assert!(text.contains("'mysql'"), "{text}");
            assert!(!words.iter().any(|w| text.contains(w)), "{text}");
        }
        for dsn in ["admin:s3cret@db.internal:5432/app", "db.internal:5432/app", "user:pw@host/db"] {
            assert!(crate::audit_store_from_dsn(dsn).is_err());
            assert!(crate::stream_store_from_dsn(dsn, "syslog").is_err());
        }
        for path in ["admin:s3cret@db.internal:5432", "s3cret@db.internal:5432", "db.internal:5432", "5432", "user:pw@host", "pw@host", "app"] {
            assert!(!std::path::Path::new(path).exists(), "{path}");
        }
    }

    #[test]
    fn init_opens_the_stream_stores_from_their_dsns_by_the_same_rules() {
        let dir = TempDir::new();
        let api = format!("sqlite:///{}?table=env_api", dir.0.join("s.db").display());
        let sys = format!("{}", dir.0.join("s.db").display());
        let audit = format!("{}", dir.0.join("a.db").display());
        let vars = env(&[("FASTEN_AUDIT_DSN", &audit), ("FASTEN_API_DSN", &api), ("FASTEN_SYSLOG_DSN", &sys)]);
        let e = Engine::new();
        e.init_with_env(config("dsn-s"), &vars).unwrap();
        let cfg = e.current_config().unwrap();
        let (first_api, first_sys) = (cfg.api_store.unwrap(), cfg.syslog_store.unwrap());
        let first_audit = cfg.audit_store.unwrap();
        e.log_api(serde_json::json!({ "path": "/x" }));
        assert!(e.flush(std::time::Duration::from_secs(5)));
        let again = crate::SqliteStreamStore::open(dir.0.join("s.db").to_str().unwrap(), "env_api").unwrap();
        assert_eq!(crate::StreamStore::count(&again).unwrap(), 1);

        // The same DSNs: the same stores.
        e.init_with_env(config("dsn-s"), &vars).unwrap();
        let cfg = e.current_config().unwrap();
        assert!(Arc::ptr_eq(&first_api, cfg.api_store.as_ref().unwrap()));
        assert!(Arc::ptr_eq(&first_sys, cfg.syslog_store.as_ref().unwrap()));
        drop(cfg);

        // A bad syslog DSN fails init, naming the variable and the scheme
        // only, and leaves every store as it was.
        let bad = env(&[
            ("FASTEN_AUDIT_DSN", &format!("{}", dir.0.join("other.db").display())),
            ("FASTEN_API_DSN", &api),
            ("FASTEN_SYSLOG_DSN", "mysql://u:s3cret@db/app"),
        ]);
        let text = e.init_with_env(config("dsn-s"), &bad).unwrap_err().to_string();
        assert!(text.contains("FASTEN_SYSLOG_DSN") && text.contains("'mysql'"), "{text}");
        assert!(!text.contains("s3cret"), "{text}");
        assert!(!dir.0.join("other.db").exists(), "a failed init left a store open");
        e.init_with_env(config("dsn-s"), &vars).unwrap();
        let cfg = e.current_config().unwrap();
        assert!(Arc::ptr_eq(&first_audit, cfg.audit_store.as_ref().unwrap()));
        assert!(Arc::ptr_eq(&first_api, cfg.api_store.as_ref().unwrap()));
        drop(cfg);

        // Another DSN: a new store, and the old one let go of.
        let other = format!("sqlite:///{}", dir.0.join("t.db").display());
        let moved = env(&[("FASTEN_AUDIT_DSN", &audit), ("FASTEN_API_DSN", &api), ("FASTEN_SYSLOG_DSN", &other)]);
        e.init_with_env(config("dsn-s"), &moved).unwrap();
        let cfg = e.current_config().unwrap();
        assert!(!Arc::ptr_eq(&first_sys, cfg.syslog_store.as_ref().unwrap()));
        assert!(Arc::ptr_eq(&first_api, cfg.api_store.as_ref().unwrap()));
        assert_eq!(Arc::strong_count(&first_sys), 1, "the old stream store is still held");
        drop(cfg);

        // A store in the config wins; no DSN opens none.
        let mine: Arc<dyn crate::StreamStore> = Arc::new(crate::SqliteStreamStore::open(":memory:", "syslog").unwrap());
        let cfg = Config { syslog_store: Some(mine.clone()), ..config("dsn-s") };
        e.init_with_env(cfg, &env(&[("FASTEN_SYSLOG_DSN", &other)])).unwrap();
        let cfg = e.current_config().unwrap();
        assert!(Arc::ptr_eq(&mine, cfg.syslog_store.as_ref().unwrap()));
        assert!(cfg.api_store.is_none());
        assert_eq!(Arc::strong_count(&first_api), 1);
        drop(cfg);
        e.close(std::time::Duration::from_secs(5));
    }

    // A DSN that parses but whose store cannot be opened fails init, naming
    // the variable and scheme only. The directory is checked before any
    // store opens, so the audit DSN's new file is not created, and the
    // stores of the last init stay.
    #[test]
    fn a_dsn_whose_store_cannot_be_opened_fails_init_and_creates_no_file() {
        let dir = TempDir::new();
        let audit = format!("{}", dir.0.join("a.db").display());
        let e = Engine::new();
        e.init_with_env(config("dsn-o"), &env(&[("FASTEN_AUDIT_DSN", &audit)])).unwrap();
        let before = store_of(&e).unwrap();

        let missing = dir.0.join("no-such-dir").join("s.db");
        let new_audit = dir.0.join("new.db");
        let vars = env(&[
            ("FASTEN_AUDIT_DSN", &format!("{}", new_audit.display())),
            ("FASTEN_SYSLOG_DSN", &format!("sqlite:///{}", missing.display())),
        ]);
        let err = e.init_with_env(config("dsn-o"), &vars).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidConfig(_)), "{err:?}");
        let text = err.to_string();
        assert_eq!(text, "FASTEN_SYSLOG_DSN: cannot open the sqlite store (NotFound)");
        assert!(Arc::ptr_eq(&before, &store_of(&e).unwrap()));
        assert!(!new_audit.exists(), "a failed init created the audit file");

        // A store that fails to open names the variable and scheme, not the
        // path or the driver's text.
        let file = dir.0.join("plain-file");
        std::fs::write(&file, b"not a database").unwrap();
        let err = e
            .init_with_env(config("dsn-o"), &env(&[("FASTEN_API_DSN", &format!("{}", file.display()))]))
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("FASTEN_API_DSN: cannot open the sqlite store ("), "{err}");
        assert!(!err.contains("plain-file") && !err.contains(&dir.0.display().to_string()), "{err}");
    }

    // close releases the stores opened from DSNs, as JS's close does; a store
    // passed in the config stays in use.
    #[test]
    fn close_releases_the_stores_opened_from_dsns() {
        let dir = TempDir::new();
        let e = Engine::new();
        let vars = env(&[
            ("FASTEN_AUDIT_DSN", &format!("{}", dir.0.join("a.db").display())),
            ("FASTEN_SYSLOG_DSN", &format!("{}", dir.0.join("s.db").display())),
        ]);
        e.init_with_env(config("dsn-close"), &vars).unwrap();
        let (audit, sys) = {
            let cfg = e.current_config().unwrap();
            (cfg.audit_store.unwrap(), cfg.syslog_store.unwrap())
        };
        assert!(e.close(std::time::Duration::from_secs(5)));
        let cfg = e.current_config().unwrap();
        assert!(cfg.audit_store.is_none() && cfg.syslog_store.is_none());
        assert_eq!(Arc::strong_count(&audit), 1, "the audit store is still held");
        assert_eq!(Arc::strong_count(&sys), 1, "the sys store is still held");
        drop(cfg);

        // The next init opens them again.
        e.init_with_env(config("dsn-close"), &vars).unwrap();
        assert!(!Arc::ptr_eq(&audit, &store_of(&e).unwrap()));

        let mine: Arc<dyn AuditStore> = Arc::new(crate::SqliteStore::open(":memory:", "mine").unwrap());
        e.init_with_env(Config { audit_store: Some(mine.clone()), ..config("dsn-close") }, &[]).unwrap();
        e.close(std::time::Duration::from_secs(5));
        assert!(Arc::ptr_eq(&mine, &store_of(&e).unwrap()));
    }

    #[cfg(feature = "store-postgres")]
    #[test]
    fn a_postgres_dsn_that_cannot_connect_names_the_variable_only() {
        let e = Engine::new();
        let err = e
            .init_with_env(config("dsn-p"), &env(&[("FASTEN_AUDIT_DSN", "postgres://u:hunter2@127.0.0.1:1/db")]))
            .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidConfig(_)), "{err:?}");
        let text = err.to_string();
        assert!(text.starts_with("FASTEN_AUDIT_DSN: cannot open the postgres store ("), "{text}");
        assert!(!text.contains("hunter2") && !text.contains("127.0.0.1"), "{text}");
    }

    #[test]
    fn set_stream_dsns_are_read_not_reported() {
        let dir = TempDir::new();
        let path = format!("{}", dir.0.join("s.db").display());
        let e = Engine::new();
        let vars = env(&[("FASTEN_API_DSN", &path), ("FASTEN_SYSLOG_DSN", &path)]);
        e.init_with_env(config("dsn-r"), &vars).unwrap();
        let cfg = e.current_config().unwrap();
        assert!(cfg.api_store.is_some() && cfg.syslog_store.is_some());
        let reported = crate::engine::SYS_CAPTURE
            .lock()
            .unwrap()
            .iter()
            .any(|v| v["event"] == "env_dsn_not_read" && v["variable"].as_str().is_some_and(|n| n.ends_with("_API_DSN") || n.ends_with("_SYSLOG_DSN")));
        assert!(!reported);
        drop(cfg);
        e.close(std::time::Duration::from_secs(5));
    }

    #[cfg(feature = "store-postgres")]
    #[test]
    fn a_postgres_dsn_opens_a_postgres_store_on_its_table() {
        let Some(dsn) = crate::replication_tests::pg::dsn() else { return };
        let table = crate::replication_tests::pg::table("envdsn");
        let _drop = crate::replication_tests::pg::DropTable(dsn.clone(), table.clone());
        // The scheme in another case, and the table parameter among others.
        let url = dsn.replacen("postgres://", "PostgreSQL://", 1);
        let url = format!("{url}{}table={table}", if url.contains('?') { '&' } else { '?' });
        let e = Engine::new();
        e.init_with_env(config("dsn-c"), &env(&[("FASTEN_AUDIT_DSN", &url)])).unwrap();
        assert!(store_of(&e).unwrap().seals());
        let n = crate::replication_tests::pg::client(&dsn)
            .query("SELECT 1 FROM information_schema.tables WHERE table_name = $1", &[&table])
            .unwrap()
            .len();
        assert_eq!(n, 1);
    }

    #[test]
    fn a_dsn_variable_init_does_not_read_is_reported_once_without_its_value() {
        let name = format!("FASTEN_AUDIT_{}_DNS", uuid::Uuid::new_v4().simple().to_string()[..8].to_uppercase());
        let e = Engine::new();
        let vars = env(&[(&name, "postgres://u:s3cret@db/app"), ("FASTEN_AUDIT_DSN", "")]);
        e.init_with_env(config("dsn-d"), &vars).unwrap();
        e.init_with_env(config("dsn-d"), &vars).unwrap();
        let reports: Vec<serde_json::Value> = crate::engine::SYS_CAPTURE
            .lock()
            .unwrap()
            .iter()
            .filter(|v| v["event"] == "env_dsn_not_read" && v["variable"] == name.as_str())
            .cloned()
            .collect();
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert!(!reports[0].to_string().contains("s3cret"));
        assert_eq!(reports[0]["level"], "warn");
    }
}
