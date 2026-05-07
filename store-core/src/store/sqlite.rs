use std::sync::Mutex;

use rusqlite::Connection;

use crate::{
    error::Error,
    row::Row,
    validate::{split_table, validate_table_name},
};

use super::Store;

// ── SqliteStore ───────────────────────────────────────────────────────────────

pub struct SqliteStore {
    conn: Mutex<Connection>,
    table: String,
    insert_sql: String,
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
}

// ── helpers ───────────────────────────────────────────────────────────────────

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

// SQLite schema doesn't support `schema.table`, so `split_table` is exposed
// only for the callers who need the bare name for index naming. The store
// itself validates that `table` is a plain identifier (no dot).
#[allow(dead_code)]
pub(crate) use crate::validate::split_table as _split;

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
}
