import Foundation
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite3
#endif

/// SQLite-backed AuditStore.  Uses the system SQLite3 library (always available on
/// Apple platforms; install libsqlite3-dev on Linux).
///
/// Usage:
///   let store = try SQLiteStore(path: "./fasten-audit.db")
///   // or in-memory for tests:
///   let store = try SQLiteStore(path: ":memory:")
public final class SQLiteStore: AuditStore, @unchecked Sendable {

    private var db: OpaquePointer?
    private let lock = Lock()
    private let table: String

    private static let safeName = try! NSRegularExpression(
        pattern: #"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$"#
    )

    public init(path: String, table: String = "audit_log") throws {
        guard Self.safeName.firstMatch(
            in: table, range: NSRange(table.startIndex..., in: table)) != nil
        else {
            throw FastenError("invalid table name: \(table)")
        }
        self.table = table
        if sqlite3_open(path, &db) != SQLITE_OK {
            throw FastenError("cannot open SQLite at \(path)")
        }
        try bootstrap()
    }

    deinit { sqlite3_close(db) }

    // ── Schema ─────────────────────────────────────────────────────────────

    private func bootstrap() throws {
        let ddl = """
        CREATE TABLE IF NOT EXISTS \(table) (
            id               TEXT PRIMARY KEY,
            origin_id        TEXT NOT NULL,
            monotonic_seq    INTEGER NOT NULL,
            timestamp        TEXT NOT NULL,
            code             TEXT NOT NULL,
            action           TEXT NOT NULL,
            severity         TEXT NOT NULL,
            service_id       TEXT NOT NULL,
            source_node_id   TEXT NOT NULL,
            tenant_id        TEXT,
            actor            TEXT NOT NULL,
            actor_kind       TEXT NOT NULL,
            target           TEXT NOT NULL,
            category         TEXT NOT NULL,
            domain           TEXT NOT NULL,
            method           TEXT NOT NULL,
            request_id       TEXT NOT NULL,
            detail           TEXT NOT NULL,
            shipped_at       TEXT,
            prev_hash        TEXT NOT NULL DEFAULT 'genesis',
            hash             TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_\(table)_req  ON \(table)(request_id);
        CREATE INDEX IF NOT EXISTS idx_\(table)_code ON \(table)(code);
        CREATE INDEX IF NOT EXISTS idx_\(table)_ts   ON \(table)(timestamp);
        """
        try exec(ddl)
        // Hash-chain migration for pre-existing tables.
        let migrations = [
            "ALTER TABLE \(table) ADD COLUMN prev_hash TEXT NOT NULL DEFAULT 'genesis'",
            "ALTER TABLE \(table) ADD COLUMN hash      TEXT NOT NULL DEFAULT ''",
        ]
        for m in migrations {
            try? exec(m)   // ignore if column already exists
        }
    }

    // ── AuditStore protocol ─────────────────────────────────────────────────

    public func insert(_ row: AuditRow) throws {
        let detail = (try? JSONEncoder().encode(row.detail)).flatMap {
            String(data: $0, encoding: .utf8)
        } ?? "{}"

        let sql = """
        INSERT OR IGNORE INTO \(table)
        (id,origin_id,monotonic_seq,timestamp,code,action,severity,
         service_id,source_node_id,tenant_id,actor,actor_kind,
         target,category,domain,method,request_id,detail,shipped_at,
         prev_hash,hash)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """
        lock.withLock {
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return }
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_text(stmt,  1, row.id,            -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt,  2, row.originID,      -1, SQLITE_TRANSIENT)
            sqlite3_bind_int64(stmt, 3, Int64(row.monotonicSeq))
            sqlite3_bind_text(stmt,  4, row.timestamp,     -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt,  5, row.code,          -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt,  6, row.action,        -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt,  7, row.severity,      -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt,  8, row.serviceID,     -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt,  9, row.sourceNodeID,  -1, SQLITE_TRANSIENT)
            if let tid = row.tenantID {
                sqlite3_bind_text(stmt, 10, tid,           -1, SQLITE_TRANSIENT)
            } else {
                sqlite3_bind_null(stmt, 10)
            }
            sqlite3_bind_text(stmt, 11, row.actor,         -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 12, row.actorKind,     -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 13, row.target,        -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 14, row.category,      -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 15, row.domain,        -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 16, row.method,        -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 17, row.requestID,     -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 18, detail,            -1, SQLITE_TRANSIENT)
            if let sa = row.shippedAt {
                sqlite3_bind_text(stmt, 19, sa,            -1, SQLITE_TRANSIENT)
            } else {
                sqlite3_bind_null(stmt, 19)
            }
            sqlite3_bind_text(stmt, 20, row.prevHash,      -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 21, row.hash,          -1, SQLITE_TRANSIENT)
            sqlite3_step(stmt)
        }
    }

    public func ping() throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT 1", -1, &stmt, nil) == SQLITE_OK else {
            throw FastenError("SQLite ping failed")
        }
        sqlite3_finalize(stmt)
    }

    public func maxMonotonicSeq() -> Int {
        var stmt: OpaquePointer?
        let sql = "SELECT COALESCE(MAX(monotonic_seq),0) FROM \(table)"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return 0 }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private func exec(_ sql: String) throws {
        var err: UnsafeMutablePointer<CChar>? = nil
        guard sqlite3_exec(db, sql, nil, nil, &err) == SQLITE_OK else {
            let msg = err.map { String(cString: $0) } ?? "sqlite3_exec error"
            sqlite3_free(err)
            throw FastenError(msg)
        }
    }
}

let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
