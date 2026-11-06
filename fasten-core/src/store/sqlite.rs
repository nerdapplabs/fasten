use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, TransactionBehavior};

use crate::{
    error::Error,
    row::Row,
    store::Filter,
    validate::{split_table, validate_table_name},
};

use super::{non_empty, purge_sql, unsealed, RedactGate, RedactionCandidates, Store, CHAIN_COLUMNS, SELECT_COLUMNS};

pub struct SqliteStore {
    conn: Mutex<Connection>,
    table: String,
    insert_sql: String,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStore").field("table", &self.table).finish_non_exhaustive()
    }
}

/// Create a missing database file with mode 0600, so SQLite does not create
/// it with the umask. An existing file keeps its mode. If the file cannot be
/// created, `Connection::open` reports the error.
#[cfg(unix)]
fn create_owner_only(path: &str) {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    let bytes = match path.strip_prefix("file:") {
        Some(uri) => match uri_file_path(uri) {
            Some(p) => p,
            None => return,
        },
        None => path.as_bytes().to_vec(),
    };
    if bytes.is_empty() || bytes == b":memory:" {
        return;
    }
    let path = std::ffi::OsStr::from_bytes(&bytes);
    // Not create_new: like SQLite, follow a symlink to a missing file. The
    // mode applies only when the file is created.
    let _ = std::fs::OpenOptions::new().write(true).create(true).mode(0o600).open(path);
}

/// File path of a SQLite `file:` URI (after the scheme), or `None` when the
/// URI names no file to create (in-memory, read-only, another VFS, or
/// another host). Escapes decode as in SQLite: a `%` without two hex digits
/// stays as it is.
#[cfg(unix)]
fn uri_file_path(uri: &str) -> Option<Vec<u8>> {
    let rest = uri.split('#').next().unwrap_or("");
    let (mut rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let no_create = |p: &str| {
        let (key, value) = p.split_once('=').unwrap_or((p, ""));
        matches!(p, "mode=memory" | "mode=ro" | "mode=rw")
            || key == "vfs"
            || (key == "immutable" && uri_true(value))
    };
    if query.split('&').any(no_create) {
        return None;
    }
    if let Some(after) = rest.strip_prefix("//") {
        let slash = after.find('/').unwrap_or(after.len());
        if !matches!(&after[..slash], "" | "localhost") {
            return None;
        }
        rest = &after[slash..];
    }
    let raw = rest.as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let hex = raw.get(i + 1..i + 3).filter(|h| raw[i] == b'%' && h.iter().all(u8::is_ascii_hexdigit));
        match hex.and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()) {
            // SQLite ends the path at a %00.
            Some(0) => break,
            Some(v) => {
                out.push(v);
                i += 3;
            }
            None => {
                out.push(raw[i]);
                i += 1;
            }
        }
    }
    Some(out)
}

/// A URI boolean as `sqlite3_uri_boolean` reads it.
#[cfg(unix)]
fn uri_true(value: &str) -> bool {
    if value.starts_with(|c: char| c.is_ascii_digit()) {
        return value.chars().take_while(char::is_ascii_digit).any(|c| c != '0');
    }
    ["yes", "on", "true", "full", "extra", "normal"].iter().any(|w| value.eq_ignore_ascii_case(w))
}

#[cfg(not(unix))]
fn create_owner_only(_path: &str) {}

impl SqliteStore {
    /// Open (or create) the SQLite database at `path` and bootstrap the
    /// audit table + indexes.
    ///
    /// `path` may be a filesystem path or `":memory:"`.
    /// `table` must match `[A-Za-z_][A-Za-z0-9_]*`; a schema prefix is not
    /// supported here.
    /// `wal`  enables WAL journal mode (ignored for `:memory:` databases).
    ///
    /// A new database file is created owner-only (0600) on Unix.
    pub fn open(path: &str, table: &str, wal: bool) -> Result<Self, Error> {
        validate_table_name(table)?;

        create_owner_only(path);
        let conn = Connection::open(path)?;
        // Another handle on the same file may hold the write lock while it
        // allocates a seq; wait for it instead of failing with SQLITE_BUSY.
        // rusqlite's default is also 5 s; set here so we don't rely on it.
        conn.busy_timeout(Duration::from_secs(5))?;

        if wal && path != ":memory:" {
            conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        }

        let insert_sql = build_insert_sql(table);

        let store = Self {
            insert_sql,
            table: table.to_owned(),
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), Error> {
        let t = &self.table;
        let chain: String = CHAIN_COLUMNS
            .iter()
            .map(|(name, def)| format!("{name} {def},\n                "))
            .collect();
        let ddl = format!(
            "CREATE TABLE IF NOT EXISTS {t} (
                id              TEXT    PRIMARY KEY,
                wire_version    TEXT    NOT NULL DEFAULT '1',
                origin_id       TEXT    NOT NULL,
                monotonic_seq   INTEGER NOT NULL DEFAULT 0,
                timestamp       TEXT    NOT NULL,
                code            TEXT    NOT NULL,
                action          TEXT    NOT NULL DEFAULT '',
                severity        TEXT    NOT NULL DEFAULT 'info',
                service_id      TEXT    NOT NULL DEFAULT '',
                source_node_id  TEXT    NOT NULL DEFAULT '',
                tenant_id       TEXT,
                actor           TEXT    NOT NULL DEFAULT '',
                actor_kind      TEXT    NOT NULL DEFAULT '',
                target          TEXT    NOT NULL DEFAULT '',
                category        TEXT    NOT NULL DEFAULT '',
                domain          TEXT    NOT NULL DEFAULT '',
                method          TEXT    NOT NULL DEFAULT '',
                request_id      TEXT    NOT NULL DEFAULT '',
                detail          TEXT    NOT NULL DEFAULT '{{}}',
                pii_in_detail   INTEGER NOT NULL DEFAULT 0,
                shipped_at      TEXT,
                {chain}UNIQUE (source_node_id, monotonic_seq)
            );
            CREATE INDEX IF NOT EXISTS idx_{t}_req  ON {t}(request_id);
            CREATE INDEX IF NOT EXISTS idx_{t}_code ON {t}(code);
            CREATE INDEX IF NOT EXISTS idx_{t}_ts   ON {t}(timestamp);
            CREATE INDEX IF NOT EXISTS idx_{t}_svc  ON {t}(service_id);"
        );

        // Probe first, so opening an up-to-date table takes no write lock.
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if Self::schema_missing(&guard, t)?.is_nothing() {
            return Ok(());
        }
        // One write transaction, so a second process opening the same old
        // table waits here, then sees what this one added.
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(&ddl)?;
        let missing = Self::schema_missing(&tx, t)?;
        for (name, def) in missing.columns {
            tx.execute_batch(&format!("ALTER TABLE {t} ADD COLUMN {name} {def}"))?;
        }
        // A table created before the UNIQUE constraint has no index here and
        // may already repeat seqs on a node, so this one is not unique.
        if missing.node_seq_index {
            tx.execute_batch(&format!(
                "CREATE INDEX IF NOT EXISTS idx_{t}_node_seq ON {t}(source_node_id, monotonic_seq)"
            ))?;
        }
        tx.commit()?;
        Ok(())
    }

    /// What `migrate` still has to create on `table`.
    fn schema_missing(conn: &Connection, table: &str) -> Result<Missing, Error> {
        let (schema, bare) = split_table(table);
        let schema = schema.unwrap_or("main");
        let mut stmt = conn.prepare(
            "SELECT l.name,
                    (SELECT name FROM pragma_index_info(l.name, ?2) WHERE seqno = 0),
                    (SELECT name FROM pragma_index_info(l.name, ?2) WHERE seqno = 1)
             FROM pragma_index_list(?1, ?2) l",
        )?;
        let mut names = Vec::new();
        let mut node_seq = false;
        let mut rows = stmt.query([bare, schema])?;
        while let Some(r) = rows.next()? {
            names.push(r.get::<_, String>(0)?);
            let first: Option<String> = r.get(1)?;
            let second: Option<String> = r.get(2)?;
            node_seq |= first.as_deref() == Some("source_node_id")
                && second.as_deref() == Some("monotonic_seq");
        }
        let indexes = ["req", "code", "ts", "svc"]
            .iter()
            .all(|s| names.iter().any(|n| n.eq_ignore_ascii_case(&format!("idx_{bare}_{s}"))));

        let mut stmt = conn.prepare("SELECT name FROM pragma_table_info(?1, ?2)")?;
        let have: Vec<String> = stmt
            .query_map([bare, schema], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let columns = CHAIN_COLUMNS
            .into_iter()
            .filter(|(name, _)| !have.iter().any(|h| h.eq_ignore_ascii_case(name)))
            .collect();
        Ok(Missing { table_or_indexes: have.is_empty() || !indexes, node_seq_index: !node_seq, columns })
    }

    fn redact_gate(conn: &Connection, table: &str) -> Result<RedactGate, Error> {
        let (schema, bare) = split_table(table);
        let mut stmt = conn.prepare("SELECT name FROM pragma_table_info(?1, ?2)")?;
        let cols = stmt
            .query_map(rusqlite::params![bare, schema.unwrap_or("main")], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RedactGate::from_columns(&cols))
    }
}

struct Missing {
    table_or_indexes: bool,
    node_seq_index: bool,
    columns: Vec<(&'static str, &'static str)>,
}

impl Missing {
    fn is_nothing(&self) -> bool {
        !self.table_or_indexes && !self.node_seq_index && self.columns.is_empty()
    }
}

/// Ids or codes bound per statement. SQLite caps bound variables per
/// statement (999 before 3.32, 32766 since).
const BIND_CHUNK: usize = 500;

fn placeholders(from: usize, n: usize) -> String {
    (from..from + n).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ")
}

impl Store for SqliteStore {
    fn insert(&self, row: &Row) -> Result<(), Error> {
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if row.monotonic_seq != 0 {
            return insert_row(&guard, &self.insert_sql, row, row.monotonic_seq as i64);
        }
        let row = &unsealed(row);

        // BEGIN IMMEDIATE takes the write lock before the MAX read, so two
        // handles on one file cannot both read the same tip (spec §2.1).
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {} WHERE id = ?1)", self.table),
            rusqlite::params![row.id],
            |r| r.get(0),
        )?;
        if !exists {
            let seq: i64 = tx.query_row(
                &format!(
                    "SELECT COALESCE(MAX(monotonic_seq), 0) + 1 FROM {} \
                     WHERE source_node_id = ?1",
                    self.table
                ),
                rusqlite::params![row.source_node_id],
                |r| r.get(0),
            )?;
            insert_row(&tx, &self.insert_sql, row, seq)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn ping(&self) -> Result<(), Error> {
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        guard.execute_batch("SELECT 1")?;
        Ok(())
    }

    fn query(&self, filter: &Filter) -> Result<Vec<Row>, Error> {
        let (where_clause, params_owned) = build_filter_where(filter);
        // LIMIT and OFFSET are integers, so interpolating them is safe.
        let mut sql = format!(
            "SELECT {SELECT_COLUMNS} FROM {} {} ORDER BY monotonic_seq ASC",
            self.table, where_clause
        );
        if filter.limit > 0 {
            sql.push_str(&format!(" LIMIT {}", filter.limit));
            if filter.offset > 0 {
                sql.push_str(&format!(" OFFSET {}", filter.offset));
            }
        }

        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_owned.iter().map(|p| p.as_ref()).collect();

        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare(&sql)?;
        let rows: Vec<Row> = stmt
            .query_map(params_refs.as_slice(), row_from_sqlite)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn count(&self, filter: &Filter) -> Result<u64, Error> {
        let (where_clause, params_owned) = build_filter_where(filter);
        let sql = format!("SELECT COUNT(*) FROM {} {}", self.table, where_clause);
        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_owned.iter().map(|p| p.as_ref()).collect();

        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare(&sql)?;
        let n: i64 = stmt.query_row(params_refs.as_slice(), |r| r.get(0))?;
        Ok(n.unsigned_abs())
    }

    fn list_unshipped(&self, limit: u32) -> Result<Vec<Row>, Error> {
        // limit 0 means all rows; i64::MAX keeps the statement cacheable.
        let effective: i64 = if limit == 0 {
            i64::MAX
        } else {
            i64::from(limit)
        };
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM {} \
             WHERE shipped_at IS NULL ORDER BY monotonic_seq ASC LIMIT ?1",
            self.table
        );
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare_cached(&sql)?;
        let rows: Vec<Row> = stmt
            .query_map(rusqlite::params![effective], row_from_sqlite)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn mark_shipped(&self, ids: &[String]) -> Result<(), Error> {
        if ids.is_empty() {
            return Ok(());
        }
        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        // ?1 = shipped_at timestamp; ?2 .. ?N = IDs.
        let placeholders: String = (2..=ids.len() + 1)
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "UPDATE {} SET shipped_at = ?1 WHERE id IN ({})",
            self.table, placeholders
        );

        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::with_capacity(ids.len() + 1);
        params.push(Box::new(now));
        for id in ids {
            params.push(Box::new(id.clone()));
        }
        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();

        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        guard.execute(&sql, params_refs.as_slice())?;
        Ok(())
    }

    fn purge(&self, before: &str, respect_unshipped: bool) -> Result<u64, Error> {
        let sql = purge_sql(&self.table, "?1", respect_unshipped, false);
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let n = guard.execute(&sql, rusqlite::params![before])?;
        Ok(n as u64)
    }

    fn max_monotonic_seq(&self) -> Result<u64, Error> {
        let sql = format!(
            "SELECT COALESCE(MAX(monotonic_seq), 0) FROM {}",
            self.table
        );
        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare_cached(&sql)?;
        let seq: i64 = stmt.query_row([], |r| r.get(0))?;
        Ok(seq.unsigned_abs())
    }

    fn list_redaction_candidates(
        &self,
        before: &str,
        codes: &[String],
    ) -> Result<RedactionCandidates, Error> {
        let mut codes: Vec<&String> = codes.iter().collect();
        codes.sort();
        codes.dedup();
        let mut out = RedactionCandidates::default();
        if codes.is_empty() {
            return Ok(out);
        }
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        // One read transaction so every chunk sees the same rows.
        let tx = guard.transaction()?;
        let gate = Self::redact_gate(&tx, &self.table)?;
        for chunk in codes.chunks(BIND_CHUNK) {
            let base = format!(
                "FROM {} WHERE timestamp < ?1 AND code IN ({}) AND detail <> 'null'",
                self.table,
                placeholders(2, chunk.len())
            );
            let mut params: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(chunk.len() + 1);
            params.push(&before);
            for c in chunk {
                params.push(*c);
            }
            let allowed = gate.allowed();
            let mut stmt = tx.prepare(&format!("SELECT id, monotonic_seq {base}{allowed}"))?;
            let rows = stmt.query_map(params.as_slice(), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?.unsigned_abs()))
            })?;
            for r in rows {
                out.rows.push(r?);
            }
            if let Some(refused) = gate.refused() {
                let n: i64 = tx.query_row(
                    &format!("SELECT COUNT(*) {base}{refused}"),
                    params.as_slice(),
                    |r| r.get(0),
                )?;
                out.skipped += n.unsigned_abs();
            }
        }
        tx.commit()?;
        out.rows.sort_by_key(|(_, seq)| *seq);
        Ok(out)
    }

    fn redact_rows(&self, ids: &[String]) -> Result<Vec<String>, Error> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let tx = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let gate = Self::redact_gate(&tx, &self.table)?;
        for chunk in ids.chunks(BIND_CHUNK) {
            let sql = format!(
                "UPDATE {} SET {} WHERE id IN ({}){}",
                self.table,
                gate.set(),
                placeholders(1, chunk.len()),
                gate.allowed()
            );
            let params: Vec<&dyn rusqlite::ToSql> =
                chunk.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
            tx.execute(&sql, params.as_slice())?;
        }
        tx.commit()?;
        Ok(ids.to_vec())
    }
}

fn insert_row(conn: &Connection, insert_sql: &str, row: &Row, seq: i64) -> Result<(), Error> {
    let detail_str = serde_json::to_string(&row.detail)?;
    let pii: i64 = row.pii_in_detail as i64;
    let mut stmt = conn.prepare_cached(insert_sql)?;
    stmt.execute(rusqlite::params![
        row.id,
        row.wire_version,
        row.origin_id,
        seq,
        row.timestamp,
        row.code,
        row.action,
        row.severity,
        row.service_id,
        row.source_node_id,
        row.tenant_id,      // None is stored as NULL
        row.actor,
        row.actor_kind,
        row.target,
        row.category,
        row.domain,
        row.method,
        row.request_id,
        detail_str,
        pii,
        row.shipped_at,     // None is stored as NULL
        row.prev_hash.as_deref().unwrap_or(""),
        row.hash.as_deref().unwrap_or(""),
        row.canonical_form_id.as_deref().unwrap_or("1"),
        row.detail_salt.as_deref().unwrap_or(""),
        row.detail_commitment.as_deref().unwrap_or(""),
    ])
    .map_err(seq_clash)?;

    Ok(())
}

/// A UNIQUE failure on insert is the (source_node_id, monotonic_seq) index:
/// a repeated id is `ON CONFLICT (id) DO NOTHING`.
fn seq_clash(e: rusqlite::Error) -> Error {
    match &e {
        rusqlite::Error::SqliteFailure(f, Some(msg))
            if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                && msg.contains("source_node_id") =>
        {
            Error::SeqClash(msg.clone())
        }
        _ => e.into(),
    }
}

// ON CONFLICT (id), not INSERT OR IGNORE: a repeated id is a no-op, but a
// clash on (source_node_id, monotonic_seq) must fail, not drop the row.
fn build_insert_sql(table: &str) -> String {
    format!(
        "INSERT INTO {table} \
         (id, wire_version, origin_id, monotonic_seq, timestamp, \
          code, action, severity, service_id, source_node_id, tenant_id, \
          actor, actor_kind, target, category, domain, method, \
          request_id, detail, pii_in_detail, shipped_at, \
          prev_hash, hash, canonical_form_id, detail_salt, detail_commitment) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,\
                 ?22,?23,?24,?25,?26) \
         ON CONFLICT (id) DO NOTHING"
    )
}

/// Build `" WHERE col = ? AND ..."` and the matching positional params.
/// Unnamed `?` binds are added in the same order as the conditions.
fn build_filter_where(f: &Filter) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
    let mut parts: Vec<&str> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(ref v) = f.request_id {
        parts.push("request_id = ?");
        params.push(Box::new(v.clone()));
    }
    if let Some(ref v) = f.code {
        parts.push("code = ?");
        params.push(Box::new(v.clone()));
    }
    if let Some(ref v) = f.domain {
        parts.push("domain = ?");
        params.push(Box::new(v.clone()));
    }
    if let Some(ref v) = f.source_node_id {
        parts.push("source_node_id = ?");
        params.push(Box::new(v.clone()));
    }
    if let Some(ref v) = f.since {
        parts.push("timestamp >= ?");
        params.push(Box::new(v.clone()));
    }
    if let Some(ref v) = f.until {
        parts.push("timestamp <= ?");
        params.push(Box::new(v.clone()));
    }

    let clause = if parts.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", parts.join(" AND "))
    };
    (clause, params)
}

/// Map a rusqlite `Row` (column order from our SELECT) to a `Row` struct.
fn row_from_sqlite(r: &rusqlite::Row) -> rusqlite::Result<Row> {
    let detail_str: String = r.get(18)?;
    let detail = serde_json::from_str(&detail_str).unwrap_or(serde_json::Value::Null);
    let pii: i64 = r.get(19)?;
    let seq: i64 = r.get(3)?;
    Ok(Row {
        id:             r.get(0)?,
        wire_version:   r.get(1)?,
        origin_id:      r.get(2)?,
        monotonic_seq:  seq.unsigned_abs(),
        timestamp:      r.get(4)?,
        code:           r.get(5)?,
        action:         r.get(6)?,
        severity:       r.get(7)?,
        service_id:     r.get(8)?,
        source_node_id: r.get(9)?,
        tenant_id:      r.get(10)?,
        actor:          r.get(11)?,
        actor_kind:     r.get(12)?,
        target:         r.get(13)?,
        category:       r.get(14)?,
        domain:         r.get(15)?,
        method:         r.get(16)?,
        request_id:     r.get(17)?,
        detail,
        pii_in_detail:  pii != 0,
        shipped_at:     r.get(20)?,
        prev_hash:         r.get(21)?,
        hash:              r.get(22)?,
        canonical_form_id: r.get(23)?,
        detail_salt:       non_empty(r.get(24)?),
        detail_commitment: non_empty(r.get(25)?),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::row::Row;

    fn make_row(id: &str, code: &str) -> Row {
        Row {
            wire_version: "1".into(),
            id: id.into(),
            origin_id: id.into(),
            monotonic_seq: 0,
            timestamp: "2026-05-07T00:00:00.000Z".into(),
            code: code.into(),
            action: "test".into(),
            severity: "info".into(),
            service_id: "svc".into(),
            source_node_id: "node-1".into(),
            tenant_id: None,
            actor: "tester".into(),
            actor_kind: "user".into(),
            target: "res-1".into(),
            category: "test".into(),
            domain: "test".into(),
            method: "sdk".into(),
            request_id: "req-001".into(),
            detail: serde_json::json!({"key": "value"}),
            pii_in_detail: false,
            shipped_at: None,
            ..Default::default()
        }
    }

    #[test]
    fn open_memory_and_insert() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        let row = make_row("evt-001", "TEST");
        store.insert(&row).unwrap();
    }

    #[test]
    fn insert_is_idempotent() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        let row = make_row("evt-idem-001", "TEST");
        store.insert(&row).unwrap();
        store.insert(&row).unwrap(); // ON CONFLICT (id) DO NOTHING, no error
    }

    #[test]
    fn ping_succeeds() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        store.ping().unwrap();
    }

    #[test]
    fn nullable_columns_accepted() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        let mut row = make_row("evt-null-001", "TEST");
        row.tenant_id = Some("tenant-abc".into());
        row.shipped_at = Some("2026-05-07T01:00:00.000Z".into());
        store.insert(&row).unwrap();
    }

    #[test]
    fn pii_flag_stored() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        let mut row = make_row("evt-pii-001", "TEST");
        row.pii_in_detail = true;
        store.insert(&row).unwrap();
    }

    #[test]
    fn invalid_table_name_rejected_before_open() {
        let err = SqliteStore::open(":memory:", "bad-name!", false).unwrap_err();
        assert!(matches!(err, Error::InvalidTableName(_)));
    }

    #[test]
    fn custom_table_name() {
        let store = SqliteStore::open(":memory:", "fasten_audit", false).unwrap();
        store.insert(&make_row("evt-custom-001", "TEST")).unwrap();
    }

    #[test]
    fn query_with_code_filter() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        store.insert(&make_row("evt-q-001", "MATCH")).unwrap();
        store.insert(&make_row("evt-q-002", "OTHER")).unwrap();
        let rows = store
            .query(&Filter { code: Some("MATCH".into()), ..Default::default() })
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].code, "MATCH");
    }

    #[test]
    fn count_all_rows() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        store.insert(&make_row("evt-c-001", "TEST")).unwrap();
        store.insert(&make_row("evt-c-002", "TEST")).unwrap();
        assert_eq!(store.count(&Filter::default()).unwrap(), 2);
    }

    #[test]
    fn list_unshipped_and_mark_shipped() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        store.insert(&make_row("evt-ship-001", "TEST")).unwrap();
        store.insert(&make_row("evt-ship-002", "TEST")).unwrap();

        let unshipped = store.list_unshipped(0).unwrap();
        assert_eq!(unshipped.len(), 2);

        store.mark_shipped(&["evt-ship-001".into()]).unwrap();

        let after = store.list_unshipped(0).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].id, "evt-ship-002");
    }

    #[test]
    fn purge_removes_old_rows() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        let mut old = make_row("evt-purge-001", "TEST");
        old.timestamp = "2020-01-01T00:00:00.000Z".into();
        store.insert(&old).unwrap();
        store.insert(&make_row("evt-purge-002", "TEST")).unwrap(); // 2026 timestamp
        let deleted = store.purge("2021-01-01T00:00:00.000Z", false).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(store.count(&Filter::default()).unwrap(), 1);
    }

    #[test]
    fn max_monotonic_seq_empty_and_after_insert() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        assert_eq!(store.max_monotonic_seq().unwrap(), 0);
        store.insert(&make_row("evt-seq-001", "TEST")).unwrap(); // allocated seq 1
        assert_eq!(store.max_monotonic_seq().unwrap(), 1);
    }

    fn row_on(id: &str, node: &str) -> Row {
        let mut r = make_row(id, "TEST");
        r.source_node_id = node.into();
        r
    }

    fn seqs(store: &SqliteStore, node: &str) -> Vec<u64> {
        let f = Filter { source_node_id: Some(node.into()), ..Default::default() };
        store.query(&f).unwrap().iter().map(|r| r.monotonic_seq).collect()
    }

    #[test]
    fn purge_deletes_only_a_seq_prefix() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        // Seq 2 is newer than the cutoff and seq 3 older: a timestamp-only
        // delete takes 3 and keeps 2 and 4, and the chain breaks at 4.
        for (id, node, ts) in [
            ("evt-a1", "node-a", "2020-01-01"),
            ("evt-a2", "node-a", "2020-01-03"),
            ("evt-a3", "node-a", "2020-01-02"),
            ("evt-a4", "node-a", "2020-01-04"),
            ("evt-b1", "node-b", "2020-01-01"),
            ("evt-b2", "node-b", "2020-01-02"),
        ] {
            let mut r = row_on(id, node);
            r.timestamp = format!("{ts}T00:00:00.000Z");
            store.insert(&r).unwrap();
        }
        assert_eq!(store.purge("2020-01-02T12:00:00.000Z", false).unwrap(), 3);
        assert_eq!(seqs(&store, "node-a"), vec![2, 3, 4]);
        assert!(seqs(&store, "node-b").is_empty());
    }

    #[test]
    fn purge_keeps_rows_above_an_unshipped_row() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        for (id, ts) in [("evt-u1", "2020-01-01"), ("evt-u2", "2020-01-02"), ("evt-u3", "2020-01-03")] {
            let mut r = row_on(id, "node-a");
            r.timestamp = format!("{ts}T00:00:00.000Z");
            store.insert(&r).unwrap();
        }
        store.mark_shipped(&["evt-u1".to_string(), "evt-u3".to_string()]).unwrap();
        assert_eq!(store.purge("2021-01-01T00:00:00.000Z", true).unwrap(), 1);
        assert_eq!(seqs(&store, "node-a"), vec![2, 3]);
    }

    /// A temp file path, removed (with its WAL files) on drop.
    struct TempDb(String);

    impl TempDb {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "fasten_core_{name}_{}_{}.db",
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            TempDb(p.to_string_lossy().into_owned())
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for ext in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{ext}", self.0));
            }
        }
    }

    #[test]
    fn seq_zero_is_allocated_per_node() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        store.insert(&row_on("evt-a1", "node-a")).unwrap();
        store.insert(&row_on("evt-a2", "node-a")).unwrap();
        store.insert(&row_on("evt-b1", "node-b")).unwrap();
        assert_eq!(seqs(&store, "node-a"), vec![1, 2]);
        assert_eq!(seqs(&store, "node-b"), vec![1]);
    }

    #[test]
    fn explicit_seq_is_kept() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        let mut r = row_on("evt-rep-1", "node-a");
        r.monotonic_seq = 7;
        store.insert(&r).unwrap();
        store.insert(&row_on("evt-own-1", "node-a")).unwrap();
        assert_eq!(seqs(&store, "node-a"), vec![7, 8]);
    }

    #[test]
    fn duplicate_node_seq_is_rejected() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        let mut a = row_on("evt-dup-1", "node-a");
        a.monotonic_seq = 3;
        let mut b = row_on("evt-dup-2", "node-a");
        b.monotonic_seq = 3;
        store.insert(&a).unwrap();
        assert!(matches!(store.insert(&b), Err(Error::SeqClash(_))));
        assert_eq!(store.count(&Filter::default()).unwrap(), 1);
    }

    /// A replayed row keeps its id and seq, so storing it again is a no-op;
    /// another row on that node and seq is a clash.
    #[test]
    fn replayed_explicit_seq_row_is_stored_once() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        let mut r = row_on("evt-replay-1", "node-a");
        r.monotonic_seq = 7;
        store.insert(&r).unwrap();
        store.insert(&r).unwrap();
        assert_eq!(store.count(&Filter::default()).unwrap(), 1);
        let mut other = row_on("evt-replay-2", "node-a");
        other.monotonic_seq = 7;
        assert!(matches!(store.insert(&other), Err(Error::SeqClash(_))));
        assert_eq!(store.count(&Filter::default()).unwrap(), 1);
        assert_eq!(seqs(&store, "node-a"), vec![7]);
    }

    /// A table from before the UNIQUE constraint already repeats seqs, so
    /// it gets a plain index.
    #[test]
    fn old_table_gets_a_non_unique_node_seq_index() {
        let db = TempDb::new("old_table");
        {
            let conn = Connection::open(&db.0).unwrap();
            conn.execute_batch(
                "CREATE TABLE audit_log (
                    id TEXT PRIMARY KEY, wire_version TEXT NOT NULL DEFAULT '1',
                    origin_id TEXT NOT NULL, monotonic_seq INTEGER NOT NULL DEFAULT 0,
                    timestamp TEXT NOT NULL, code TEXT NOT NULL,
                    action TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT 'info',
                    service_id TEXT NOT NULL DEFAULT '', source_node_id TEXT NOT NULL DEFAULT '',
                    tenant_id TEXT, actor TEXT NOT NULL DEFAULT '',
                    actor_kind TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '',
                    method TEXT NOT NULL DEFAULT '', request_id TEXT NOT NULL DEFAULT '',
                    detail TEXT NOT NULL DEFAULT '{}', pii_in_detail INTEGER NOT NULL DEFAULT 0,
                    shipped_at TEXT);
                 INSERT INTO audit_log (id, origin_id, monotonic_seq, timestamp, code, source_node_id)
                 VALUES ('a', 'a', 1, 't', 'C', 'node-a'), ('b', 'b', 1, 't', 'C', 'node-a');",
            )
            .unwrap();
        }
        let store = SqliteStore::open(&db.0, "audit_log", false).unwrap();
        let conn = store.conn.lock().unwrap();
        let unique: i64 = conn
            .query_row(
                "SELECT \"unique\" FROM pragma_index_list('audit_log') WHERE name = 'idx_audit_log_node_seq'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(unique, 0);
        assert!(SqliteStore::schema_missing(&conn, "audit_log").unwrap().is_nothing());
    }

    /// Opening an up-to-date table takes no write lock, so it does not wait
    /// for another connection's write transaction.
    #[test]
    fn opening_an_up_to_date_table_takes_no_write_lock() {
        let db = TempDb::new("no_write_lock");
        drop(SqliteStore::open(&db.0, "audit_log", true).unwrap());
        let other = Connection::open(&db.0).unwrap();
        other.execute_batch("BEGIN IMMEDIATE").unwrap();
        let started = std::time::Instant::now();
        drop(SqliteStore::open(&db.0, "audit_log", true).unwrap());
        assert!(started.elapsed() < Duration::from_secs(2));
        other.execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn retried_id_does_not_take_a_seq() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        let r = row_on("evt-retry-1", "node-a");
        store.insert(&r).unwrap();
        store.insert(&r).unwrap();
        store.insert(&row_on("evt-retry-2", "node-a")).unwrap();
        assert_eq!(seqs(&store, "node-a"), vec![1, 2]);
    }

    /// #92: two stores on one file, one node. Each used to mint its own seq.
    #[test]
    fn two_handles_on_one_file_get_unique_seqs() {
        let db = TempDb::new("two_handles");
        let a = SqliteStore::open(&db.0, "audit_log", true).unwrap();
        let b = SqliteStore::open(&db.0, "audit_log", true).unwrap();
        for i in 0..10 {
            a.insert(&row_on(&format!("evt-a-{i}"), "node-1")).unwrap();
            b.insert(&row_on(&format!("evt-b-{i}"), "node-1")).unwrap();
        }
        assert_eq!(seqs(&a, "node-1"), (1..=20).collect::<Vec<u64>>());
    }

    #[test]
    fn concurrent_handles_allocate_contiguous_seqs() {
        let db = TempDb::new("concurrent");
        // Create the table before the threads race to open it.
        drop(SqliteStore::open(&db.0, "audit_log", true).unwrap());
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let path = db.0.clone();
                std::thread::spawn(move || {
                    let store = SqliteStore::open(&path, "audit_log", true).unwrap();
                    for i in 0..25 {
                        store.insert(&row_on(&format!("evt-{t}-{i}"), "node-1")).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let store = SqliteStore::open(&db.0, "audit_log", true).unwrap();
        assert_eq!(seqs(&store, "node-1"), (1..=100).collect::<Vec<u64>>());
    }

    fn days_ago(days: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::days(days))
            .format("%Y-%m-%dT%H:%M:%S%.6fZ")
            .to_string()
    }

    fn detail_of(store: &SqliteStore, id: &str) -> serde_json::Value {
        let rows = store.query(&Filter::default()).unwrap();
        rows.into_iter().find(|r| r.id == id).unwrap().detail
    }

    #[test]
    fn redaction_blanks_only_expired_pii_rows() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        let mut pii = make_row("evt-pii-old", "USER_LOGIN");
        pii.timestamp = days_ago(40);
        let mut ops = make_row("evt-ops-old", "JOB_RAN");
        ops.timestamp = days_ago(40);
        store.insert(&pii).unwrap();
        store.insert(&ops).unwrap();

        let codes = vec!["USER_LOGIN".to_string()];
        let cutoff = days_ago(30);
        let found = store.list_redaction_candidates(&cutoff, &codes).unwrap();
        assert_eq!(found.rows, vec![("evt-pii-old".to_string(), 1)]);
        assert_eq!(found.skipped, 0);
        let ids: Vec<String> = found.rows.into_iter().map(|(id, _)| id).collect();
        assert_eq!(store.redact_rows(&ids).unwrap(), ids);

        assert_eq!(detail_of(&store, "evt-pii-old"), serde_json::Value::Null);
        assert_eq!(detail_of(&store, "evt-ops-old"), serde_json::json!({"key": "value"}));
        assert_eq!(store.count(&Filter::default()).unwrap(), 2);

        // Idempotent: nothing left to list, and a repeat redact is harmless.
        assert_eq!(
            store.list_redaction_candidates(&cutoff, &codes).unwrap(),
            RedactionCandidates::default()
        );
        assert_eq!(store.redact_rows(&ids).unwrap(), ids);
        assert_eq!(detail_of(&store, "evt-pii-old"), serde_json::Value::Null);
        assert_eq!(store.count(&Filter::default()).unwrap(), 2);
    }

    /// On a table that also carries chain columns (Go adds them), a sealed
    /// row's detail is inside its hash and must not be touched.
    #[test]
    fn redaction_skips_sealed_rows() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        for id in ["evt-sealed", "evt-unsealed"] {
            let mut r = make_row(id, "USER_LOGIN");
            r.timestamp = days_ago(40);
            if id == "evt-sealed" {
                r.monotonic_seq = 1;
                r.hash = Some("abc".into());
            }
            store.insert(&r).unwrap();
        }

        let codes = vec!["USER_LOGIN".to_string()];
        let found = store.list_redaction_candidates(&days_ago(30), &codes).unwrap();
        assert_eq!(found.rows, vec![("evt-unsealed".to_string(), 2)]);
        assert_eq!(found.skipped, 1);
        let all = vec!["evt-sealed".to_string(), "evt-unsealed".to_string()];
        store.redact_rows(&all).unwrap();
        assert_eq!(detail_of(&store, "evt-sealed"), serde_json::json!({"key": "value"}));
        assert_eq!(detail_of(&store, "evt-unsealed"), serde_json::Value::Null);
    }

    /// A sealed form-"2" row hashes without its detail, so it is redacted
    /// like an unsealed one; only sealed form-"1" rows are refused.
    #[test]
    fn redaction_covers_sealed_form_2_rows() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        for id in ["evt-form1", "evt-form2", "evt-unsealed"] {
            let mut r = make_row(id, "USER_LOGIN");
            r.timestamp = days_ago(40);
            store.insert(&r).unwrap();
        }
        store
            .conn
            .lock()
            .unwrap()
            .execute_batch(
                "UPDATE audit_log SET hash = 'abc' WHERE id = 'evt-form1';
                 UPDATE audit_log SET hash = 'def', canonical_form_id = '2', detail_salt = 'salt'
                 WHERE id = 'evt-form2';",
            )
            .unwrap();

        let codes = vec!["USER_LOGIN".to_string()];
        let found = store.list_redaction_candidates(&days_ago(30), &codes).unwrap();
        assert_eq!(
            found.rows,
            vec![("evt-form2".to_string(), 2), ("evt-unsealed".to_string(), 3)]
        );
        assert_eq!(found.skipped, 1);
        let all = vec!["evt-form1".to_string(), "evt-form2".to_string(), "evt-unsealed".to_string()];
        store.redact_rows(&all).unwrap();
        assert_eq!(detail_of(&store, "evt-form1"), serde_json::json!({"key": "value"}));
        assert_eq!(detail_of(&store, "evt-form2"), serde_json::Value::Null);
        assert_eq!(detail_of(&store, "evt-unsealed"), serde_json::Value::Null);
        let salt: String = store
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT detail_salt FROM audit_log WHERE id = 'evt-form2'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(salt, "");
    }

    /// More ids and codes than SQLite binds in one statement.
    #[test]
    fn redaction_handles_more_ids_than_one_statement_binds() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        let n = 1200;
        for i in 0..n {
            let mut r = make_row(&format!("evt-{i}"), "USER_LOGIN");
            r.timestamp = days_ago(40);
            store.insert(&r).unwrap();
        }
        // 40_000 is above SQLite's default per-statement variable limit.
        let mut codes: Vec<String> = (0..40_000).map(|i| format!("UNUSED_{i}")).collect();
        codes.push("USER_LOGIN".into());
        let found = store.list_redaction_candidates(&days_ago(30), &codes).unwrap();
        assert_eq!(found.rows.len(), n);
        assert_eq!(
            found.rows.iter().map(|(_, seq)| *seq).collect::<Vec<_>>(),
            (1..=n as u64).collect::<Vec<_>>()
        );

        let mut ids: Vec<String> = found.rows.into_iter().map(|(id, _)| id).collect();
        ids.extend((0..40_000).map(|i| format!("missing-{i}")));
        assert_eq!(store.redact_rows(&ids).unwrap(), ids);
        let rows = store.query(&Filter::default()).unwrap();
        assert_eq!(rows.len(), n);
        assert!(rows.iter().all(|r| r.detail.is_null()));
        assert_eq!(store.redact_rows(&ids).unwrap(), ids);
    }

    fn sealed(id: &str) -> Row {
        let mut r = make_row(id, "TEST");
        r.monotonic_seq = 1;
        r.prev_hash = Some("genesis".into());
        r.hash = Some("h1".into());
        r.canonical_form_id = Some("2".into());
        r.detail_salt = Some("salt".into());
        r.detail_commitment = Some("commit".into());
        r
    }

    fn chain_of(r: &Row) -> [Option<&str>; 5] {
        [
            r.prev_hash.as_deref(),
            r.hash.as_deref(),
            r.canonical_form_id.as_deref(),
            r.detail_salt.as_deref(),
            r.detail_commitment.as_deref(),
        ]
    }

    /// #139: a sealed row came back without its hash.
    #[test]
    fn chain_fields_round_trip() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        let row = sealed("evt-sealed");
        store.insert(&row).unwrap();
        let got = store.query(&Filter::default()).unwrap();
        assert_eq!(chain_of(&got[0]), chain_of(&row));
        assert_eq!(chain_of(&store.list_unshipped(0).unwrap()[0]), chain_of(&row));
    }

    /// The store picks the seq, so a hash sealed over another one is dropped.
    #[test]
    fn allocating_insert_drops_chain_fields() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        let mut row = sealed("evt-alloc");
        row.monotonic_seq = 0;
        store.insert(&row).unwrap();
        let got = &store.query(&Filter::default()).unwrap()[0];
        assert_eq!(got.monotonic_seq, 1);
        assert_eq!(chain_of(got), [Some(""), Some(""), Some("1"), None, None]);
    }

    #[test]
    fn unsealed_row_reads_back_with_empty_hash_and_no_salt() {
        let store = SqliteStore::open(":memory:", "audit_log", false).unwrap();
        store.insert(&make_row("evt-plain", "TEST")).unwrap();
        let got = &store.query(&Filter::default()).unwrap()[0];
        assert_eq!(chain_of(got), [Some(""), Some(""), Some("1"), None, None]);
    }

    /// A table an older fasten-core created gets the chain columns on open.
    #[test]
    fn open_adds_chain_columns_to_an_old_table() {
        let dir = std::env::temp_dir().join(format!("fasten-old-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.db");
        let _ = std::fs::remove_file(&path);
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE audit_log (
                    id TEXT PRIMARY KEY, wire_version TEXT NOT NULL DEFAULT '1',
                    origin_id TEXT NOT NULL, monotonic_seq INTEGER NOT NULL DEFAULT 0,
                    timestamp TEXT NOT NULL, code TEXT NOT NULL,
                    action TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT 'info',
                    service_id TEXT NOT NULL DEFAULT '', source_node_id TEXT NOT NULL DEFAULT '',
                    tenant_id TEXT, actor TEXT NOT NULL DEFAULT '',
                    actor_kind TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '',
                    method TEXT NOT NULL DEFAULT '', request_id TEXT NOT NULL DEFAULT '',
                    detail TEXT NOT NULL DEFAULT '{}', pii_in_detail INTEGER NOT NULL DEFAULT 0,
                    shipped_at TEXT, UNIQUE (source_node_id, monotonic_seq));
                 INSERT INTO audit_log (id, origin_id, timestamp, code, monotonic_seq)
                 VALUES ('evt-old', 'evt-old', '2026-05-07T00:00:00.000000Z', 'TEST', 1);",
            )
            .unwrap();
        let store = SqliteStore::open(path.to_str().unwrap(), "audit_log", false).unwrap();
        let mut row = sealed("evt-new");
        row.monotonic_seq = 2;
        store.insert(&row).unwrap();
        let got = store.query(&Filter::default()).unwrap();
        assert_eq!(chain_of(&got[0]), [Some(""), Some(""), Some("1"), None, None]);
        assert_eq!(chain_of(&got[1]), chain_of(&row));
        // Opening again finds the columns there.
        drop(store);
        SqliteStore::open(path.to_str().unwrap(), "audit_log", false).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A table that already has some chain columns, as the Go store creates
    /// them (salt and commitment NOT NULL), gets the rest.
    #[test]
    fn open_adds_only_the_missing_chain_columns() {
        let dir = std::env::temp_dir().join(format!("fasten-partial-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.db");
        let _ = std::fs::remove_file(&path);
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE audit_log (
                    id TEXT PRIMARY KEY, wire_version TEXT NOT NULL DEFAULT '1',
                    origin_id TEXT NOT NULL, monotonic_seq INTEGER NOT NULL DEFAULT 0,
                    timestamp TEXT NOT NULL, code TEXT NOT NULL,
                    action TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT 'info',
                    service_id TEXT NOT NULL DEFAULT '', source_node_id TEXT NOT NULL DEFAULT '',
                    tenant_id TEXT, actor TEXT NOT NULL DEFAULT '',
                    actor_kind TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL DEFAULT '', domain TEXT NOT NULL DEFAULT '',
                    method TEXT NOT NULL DEFAULT '', request_id TEXT NOT NULL DEFAULT '',
                    detail TEXT NOT NULL DEFAULT '{}', pii_in_detail INTEGER NOT NULL DEFAULT 0,
                    shipped_at TEXT, hash TEXT NOT NULL DEFAULT '',
                    detail_salt TEXT NOT NULL DEFAULT '',
                    detail_commitment TEXT NOT NULL DEFAULT '',
                    UNIQUE (source_node_id, monotonic_seq));",
            )
            .unwrap();
        let store = SqliteStore::open(path.to_str().unwrap(), "audit_log", false).unwrap();
        store.insert(&make_row("evt-plain", "TEST")).unwrap();
        let mut row = sealed("evt-sealed");
        row.monotonic_seq = 2;
        store.insert(&row).unwrap();
        let got = store.query(&Filter::default()).unwrap();
        assert_eq!(chain_of(&got[0]), [Some(""), Some(""), Some("1"), None, None]);
        assert_eq!(chain_of(&got[1]), chain_of(&row));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn file_mode(path: &str) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Under the usual 022 umask SQLite alone would create these 0644. The
    /// test relies on that default: the umask is process-wide and tests run
    /// in threads, so it does not set one.
    #[cfg(unix)]
    #[test]
    fn new_file_and_wal_are_0600() {
        let db = TempDb::new("mode_new");
        let store = SqliteStore::open(&db.0, "audit_log", true).unwrap();
        store.insert(&make_row("evt-mode", "TEST")).unwrap();
        assert_eq!(file_mode(&db.0), 0o600);
        assert_eq!(file_mode(&format!("{}-wal", db.0)), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn existing_file_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let db = TempDb::new("mode_existing");
        std::fs::File::create(&db.0).unwrap();
        std::fs::set_permissions(&db.0, std::fs::Permissions::from_mode(0o644)).unwrap();
        SqliteStore::open(&db.0, "audit_log", true).unwrap();
        assert_eq!(file_mode(&db.0), 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_target_is_0600() {
        let target = TempDb::new("mode_target");
        let link = TempDb::new("mode_link");
        std::os::unix::fs::symlink(&target.0, &link.0).unwrap();
        let store = SqliteStore::open(&link.0, "audit_log", true).unwrap();
        store.insert(&make_row("evt-link", "TEST")).unwrap();
        assert_eq!(file_mode(&target.0), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn file_uri_is_0600() {
        let db = TempDb::new("mode uri");
        let uri = format!("file://{}?cache=private", db.0.replace(' ', "%20"));
        SqliteStore::open(&uri, "audit_log", true).unwrap();
        assert_eq!(file_mode(&db.0), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn read_only_file_uri_creates_nothing() {
        let db = TempDb::new("mode_ro");
        assert!(SqliteStore::open(&format!("file:{}?mode=ro", db.0), "audit_log", true).is_err());
        assert!(!std::path::Path::new(&db.0).exists());
    }

    #[cfg(unix)]
    #[test]
    fn file_uri_without_a_file_to_create_creates_nothing() {
        for param in ["immutable=1", "vfs=memdb"] {
            let db = TempDb::new("mode_nocreate");
            let _ = SqliteStore::open(&format!("file:{}?{param}", db.0), "audit_log", false);
            // Some SQLite versions create an empty file for immutable=1
            // themselves, with the umask; fasten must not create one 0600 first.
            let exists = std::path::Path::new(&db.0).exists();
            assert!(!exists || (param == "immutable=1" && file_mode(&db.0) == 0o644), "{param}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn file_uri_keeps_an_invalid_escape() {
        let db = TempDb::new("mode%zz%+f");
        SqliteStore::open(&format!("file:{}", db.0), "audit_log", true).unwrap();
        assert_eq!(file_mode(&db.0), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn file_uri_path_ends_at_nul() {
        let db = TempDb::new("mode_nul");
        SqliteStore::open(&format!("file:{}%00x.db", db.0), "audit_log", true).unwrap();
        assert_eq!(file_mode(&db.0), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn file_uri_immutable_forms() {
        for (value, creates) in [("TRUE", false), ("7", false), ("0", true), ("off", true)] {
            let got = uri_file_path(&format!("/d/a.db?immutable={value}"));
            assert_eq!(got.as_deref() == Some(&b"/d/a.db"[..]), creates, "immutable={value}");
        }
    }
}
