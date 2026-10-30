use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, TransactionBehavior};

use crate::{
    error::Error,
    row::Row,
    store::Filter,
    validate::{split_table, validate_table_name},
};

use super::{RedactionCandidates, Store};

// ── SqliteStore ───────────────────────────────────────────────────────────────

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

impl SqliteStore {
    /// Open (or create) the SQLite database at `path` and bootstrap the
    /// audit table + indexes.
    ///
    /// `path` may be a filesystem path or `":memory:"`.
    /// `table` must match `[A-Za-z_][A-Za-z0-9_]*` — no schema prefix.
    /// `wal`  enables WAL journal mode (ignored for `:memory:` databases).
    pub fn open(path: &str, table: &str, wal: bool) -> Result<Self, Error> {
        validate_table_name(table)?;

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
                UNIQUE (source_node_id, monotonic_seq)
            );
            CREATE INDEX IF NOT EXISTS idx_{t}_req  ON {t}(request_id);
            CREATE INDEX IF NOT EXISTS idx_{t}_code ON {t}(code);
            CREATE INDEX IF NOT EXISTS idx_{t}_ts   ON {t}(timestamp);
            CREATE INDEX IF NOT EXISTS idx_{t}_svc  ON {t}(service_id);"
        );

        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        guard.execute_batch(&ddl)?;
        Ok(())
    }

    /// Whether the table has a `hash` column.
    ///
    /// Tables created here have no chain columns, so every row is unsealed.
    /// A table shared with an SDK that seals (Go adds `hash` on open) may hold
    /// sealed rows, which redaction leaves alone.
    fn has_hash_column(conn: &Connection, table: &str) -> Result<bool, Error> {
        let (schema, bare) = split_table(table);
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info(?1, ?2) WHERE name = 'hash'",
            rusqlite::params![bare, schema.unwrap_or("main")],
            |r| r.get(0),
        )?;
        Ok(n > 0)
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
        // LIMIT / OFFSET are integers, interpolated directly — no injection risk.
        let mut sql = format!(
            "SELECT id,wire_version,origin_id,monotonic_seq,timestamp,\
             code,action,severity,service_id,source_node_id,tenant_id,\
             actor,actor_kind,target,category,domain,method,\
             request_id,detail,pii_in_detail,shipped_at \
             FROM {} {} ORDER BY monotonic_seq ASC",
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
        // Always emit LIMIT; use i64::MAX when the caller passes 0.
        let effective: i64 = if limit == 0 {
            i64::MAX
        } else {
            i64::from(limit)
        };
        let sql = format!(
            "SELECT id,wire_version,origin_id,monotonic_seq,timestamp,\
             code,action,severity,service_id,source_node_id,tenant_id,\
             actor,actor_kind,target,category,domain,method,\
             request_id,detail,pii_in_detail,shipped_at \
             FROM {} WHERE shipped_at IS NULL ORDER BY monotonic_seq ASC LIMIT ?1",
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
        let sql = if respect_unshipped {
            format!(
                "DELETE FROM {} WHERE timestamp < ?1 AND shipped_at IS NOT NULL",
                self.table
            )
        } else {
            format!("DELETE FROM {} WHERE timestamp < ?1", self.table)
        };
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
        let has_hash = Self::has_hash_column(&tx, &self.table)?;
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
            let gate = if has_hash { " AND hash = ''" } else { "" };
            let mut stmt = tx.prepare(&format!("SELECT id, monotonic_seq {base}{gate}"))?;
            let rows = stmt.query_map(params.as_slice(), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?.unsigned_abs()))
            })?;
            for r in rows {
                out.rows.push(r?);
            }
            if has_hash {
                let n: i64 = tx.query_row(
                    &format!("SELECT COUNT(*) {base} AND hash <> ''"),
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
        let gate = if Self::has_hash_column(&tx, &self.table)? { " AND hash = ''" } else { "" };
        for chunk in ids.chunks(BIND_CHUNK) {
            // 'null' is the JSON literal: detail is NOT NULL, and it reads
            // back as a null detail.
            let sql = format!(
                "UPDATE {} SET detail = 'null' WHERE id IN ({}){gate}",
                self.table,
                placeholders(1, chunk.len())
            );
            let params: Vec<&dyn rusqlite::ToSql> =
                chunk.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
            tx.execute(&sql, params.as_slice())?;
        }
        tx.commit()?;
        Ok(ids.to_vec())
    }
}

// ── SQL helpers ───────────────────────────────────────────────────────────────

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
        row.tenant_id,      // Option<String> → NULL when None
        row.actor,
        row.actor_kind,
        row.target,
        row.category,
        row.domain,
        row.method,
        row.request_id,
        detail_str,
        pii,
        row.shipped_at,     // Option<String> → NULL when None
    ])?;

    Ok(())
}

// ON CONFLICT (id), not INSERT OR IGNORE: a repeated id is a no-op, but a
// clash on (source_node_id, monotonic_seq) must fail, not drop the row.
fn build_insert_sql(table: &str) -> String {
    format!(
        "INSERT INTO {table} \
         (id, wire_version, origin_id, monotonic_seq, timestamp, \
          code, action, severity, service_id, source_node_id, tenant_id, \
          actor, actor_kind, target, category, domain, method, \
          request_id, detail, pii_in_detail, shipped_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21) \
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

// ── Row mapper ────────────────────────────────────────────────────────────────

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
        ..Default::default()
    })
}

// ── tests ─────────────────────────────────────────────────────────────────────

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
        store.insert(&row).unwrap(); // ON CONFLICT (id) DO NOTHING — no error
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
        assert!(store.insert(&b).is_err());
        assert_eq!(store.count(&Filter::default()).unwrap(), 1);
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
        {
            let c = store.conn.lock().unwrap();
            c.execute_batch(
                "ALTER TABLE audit_log ADD COLUMN hash TEXT NOT NULL DEFAULT '';
                 ALTER TABLE audit_log ADD COLUMN canonical_form_id TEXT NOT NULL DEFAULT '1';",
            )
            .unwrap();
        }
        for id in ["evt-sealed", "evt-unsealed"] {
            let mut r = make_row(id, "USER_LOGIN");
            r.timestamp = days_ago(40);
            store.insert(&r).unwrap();
        }
        store
            .conn
            .lock()
            .unwrap()
            .execute("UPDATE audit_log SET hash = 'abc' WHERE id = 'evt-sealed'", [])
            .unwrap();

        let codes = vec!["USER_LOGIN".to_string()];
        let found = store.list_redaction_candidates(&days_ago(30), &codes).unwrap();
        assert_eq!(found.rows, vec![("evt-unsealed".to_string(), 2)]);
        assert_eq!(found.skipped, 1);
        let all = vec!["evt-sealed".to_string(), "evt-unsealed".to_string()];
        store.redact_rows(&all).unwrap();
        assert_eq!(detail_of(&store, "evt-sealed"), serde_json::json!({"key": "value"}));
        assert_eq!(detail_of(&store, "evt-unsealed"), serde_json::Value::Null);
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
}
