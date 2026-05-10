use std::sync::Mutex;

use rusqlite::Connection;

use crate::{
    error::Error,
    row::Row,
    store::Filter,
    validate::validate_table_name,
};

use super::Store;

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
                shipped_at      TEXT
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
}

impl Store for SqliteStore {
    fn insert(&self, row: &Row) -> Result<(), Error> {
        let detail_str = serde_json::to_string(&row.detail)?;
        let pii: i64 = row.pii_in_detail as i64;
        let seq: i64 = row.monotonic_seq as i64;

        let guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = guard.prepare_cached(&self.insert_sql)?;

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
}

// ── SQL helpers ───────────────────────────────────────────────────────────────

fn build_insert_sql(table: &str) -> String {
    format!(
        "INSERT OR IGNORE INTO {table} \
         (id, wire_version, origin_id, monotonic_seq, timestamp, \
          code, action, severity, service_id, source_node_id, tenant_id, \
          actor, actor_kind, target, category, domain, method, \
          request_id, detail, pii_in_detail, shipped_at) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)"
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
            monotonic_seq: 1,
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
        store.insert(&row).unwrap(); // INSERT OR IGNORE — no error
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
        store.insert(&make_row("evt-seq-001", "TEST")).unwrap(); // monotonic_seq = 1
        assert_eq!(store.max_monotonic_seq().unwrap(), 1);
    }
}
