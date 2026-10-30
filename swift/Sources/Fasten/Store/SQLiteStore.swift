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

    /// `busyTimeoutMs` is how long a write waits for another connection's
    /// lock before failing with SQLITE_BUSY.
    public init(path: String, table: String = "audit_log", busyTimeoutMs: Int32 = 5000) throws {
        guard Self.safeName.firstMatch(
            in: table, range: NSRange(table.startIndex..., in: table)) != nil
        else {
            throw FastenError("invalid table name: \(table)")
        }
        self.table = table
        if sqlite3_open(path, &db) != SQLITE_OK {
            throw FastenError("cannot open SQLite at \(path)")
        }
        sqlite3_busy_timeout(db, busyTimeoutMs)
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
            pii_in_detail    INTEGER NOT NULL DEFAULT 0,
            shipped_at       TEXT,
            canonical_form_id TEXT NOT NULL DEFAULT '1',
            detail_salt      TEXT DEFAULT '',
            detail_commitment TEXT DEFAULT '',
            prev_hash        TEXT NOT NULL DEFAULT 'genesis',
            hash             TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_\(table)_req  ON \(table)(request_id);
        CREATE INDEX IF NOT EXISTS idx_\(table)_code ON \(table)(code);
        CREATE INDEX IF NOT EXISTS idx_\(table)_ts   ON \(table)(timestamp);
        """
        try exec(ddl)
        // Columns added after the first release; same names and defaults as
        // the Python and Go stores so all three can share a table.
        let migrations = [
            "ALTER TABLE \(table) ADD COLUMN prev_hash TEXT NOT NULL DEFAULT 'genesis'",
            "ALTER TABLE \(table) ADD COLUMN hash      TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE \(table) ADD COLUMN pii_in_detail INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE \(table) ADD COLUMN canonical_form_id TEXT NOT NULL DEFAULT '1'",
            "ALTER TABLE \(table) ADD COLUMN detail_salt TEXT DEFAULT ''",
            "ALTER TABLE \(table) ADD COLUMN detail_commitment TEXT DEFAULT ''",
        ]
        for m in migrations {
            try? exec(m)   // ignore if column already exists
        }
    }

    // ── AuditStore protocol ─────────────────────────────────────────────────

    /// A row with `monotonicSeq == 0` gets the next seq for its
    /// `source_node_id`, allocated under `BEGIN IMMEDIATE` so two connections
    /// on one file cannot pick the same value (spec 2.1).
    public func insert(_ row: AuditRow) throws {
        try lock.withLock {
            if row.monotonicSeq != 0 {
                try insertRow(row, seq: row.monotonicSeq)
                return
            }
            try execInsert("BEGIN IMMEDIATE")
            do {
                try insertRow(row, seq: try nextSeq(node: row.sourceNodeID))
                try execInsert("COMMIT")
            } catch {
                // Also after a failed COMMIT, which leaves the transaction open.
                sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
                throw error
            }
        }
    }

    private func nextSeq(node: String) throws -> Int {
        var stmt: OpaquePointer?
        let sql = "SELECT COALESCE(MAX(monotonic_seq),0)+1 FROM \(table) WHERE source_node_id = ?"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw FastenError("SQLite insert failed: \(lastError())")
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, node, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw FastenError("SQLite insert failed: \(lastError())")
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    private func insertRow(_ row: AuditRow, seq: Int) throws {
        let detail = (try? JSONEncoder().encode(row.detail)).flatMap {
            String(data: $0, encoding: .utf8)
        } ?? "{}"

        let sql = """
        INSERT OR IGNORE INTO \(table)
        (id,origin_id,monotonic_seq,timestamp,code,action,severity,
         service_id,source_node_id,tenant_id,actor,actor_kind,
         target,category,domain,method,request_id,detail,shipped_at,
         prev_hash,hash,detail_salt,detail_commitment)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'','')
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw FastenError("SQLite insert failed: \(lastError())")
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt,  1, row.id,            -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt,  2, row.originID,      -1, SQLITE_TRANSIENT)
        sqlite3_bind_int64(stmt, 3, Int64(seq))
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
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw FastenError("SQLite insert failed: \(lastError())")
        }
    }

    // ── Redaction (spec 7.1) ───────────────────────────────────────────────

    // Only rows whose detail is outside any hash: unsealed rows, or form "2"
    // rows where the hash covers detail_commitment. A sealed form "1" row is
    // never touched; redacting it would break its chain.
    private static let redactable = "(hash = '' OR canonical_form_id = '2')"

    public func listRedactionCandidates(before: Date, codes: [Code]) throws -> [RedactionCandidate] {
        guard !codes.isEmpty else { return [] }
        let ph = Array(repeating: "?", count: codes.count).joined(separator: ",")
        let sql = """
        SELECT id, monotonic_seq FROM \(table)
        WHERE timestamp < ? AND code IN (\(ph)) AND \(Self.redactable) AND detail <> 'null'
        ORDER BY monotonic_seq
        """
        return try lock.withLock {
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw FastenError("SQLite query failed: \(lastError())")
            }
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_text(stmt, 1, canonicalTS(before), -1, SQLITE_TRANSIENT)
            for (i, c) in codes.enumerated() {
                sqlite3_bind_text(stmt, Int32(i + 2), c, -1, SQLITE_TRANSIENT)
            }
            var out: [RedactionCandidate] = []
            while true {
                let rc = sqlite3_step(stmt)
                if rc == SQLITE_DONE { break }
                guard rc == SQLITE_ROW else {
                    throw FastenError("SQLite query failed: \(lastError())")
                }
                let id = String(cString: sqlite3_column_text(stmt, 0))
                out.append(RedactionCandidate(id: id, monotonicSeq: Int(sqlite3_column_int64(stmt, 1))))
            }
            return out
        }
    }

    public func countRefusedLegacyRows(before: Date, codes: [Code]) throws -> Int {
        guard !codes.isEmpty else { return 0 }
        let ph = Array(repeating: "?", count: codes.count).joined(separator: ",")
        let sql = """
        SELECT COUNT(*) FROM \(table)
        WHERE timestamp < ? AND code IN (\(ph)) AND hash <> '' AND canonical_form_id <> '2'
          AND detail <> 'null'
        """
        return try lock.withLock {
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw FastenError("SQLite query failed: \(lastError())")
            }
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_text(stmt, 1, canonicalTS(before), -1, SQLITE_TRANSIENT)
            for (i, c) in codes.enumerated() {
                sqlite3_bind_text(stmt, Int32(i + 2), c, -1, SQLITE_TRANSIENT)
            }
            guard sqlite3_step(stmt) == SQLITE_ROW else {
                throw FastenError("SQLite query failed: \(lastError())")
            }
            return Int(sqlite3_column_int64(stmt, 0))
        }
    }

    /// Sets `detail` to the JSON literal 'null' (the column is NOT NULL).
    public func redactRows(ids: [String]) throws -> [String] {
        guard !ids.isEmpty else { return [] }
        let ph = Array(repeating: "?", count: ids.count).joined(separator: ",")
        let sql = """
        UPDATE \(table) SET detail = 'null', detail_salt = ''
        WHERE id IN (\(ph)) AND \(Self.redactable)
        """
        try lock.withLock {
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw FastenError("SQLite redact failed: \(lastError())")
            }
            defer { sqlite3_finalize(stmt) }
            for (i, id) in ids.enumerated() {
                sqlite3_bind_text(stmt, Int32(i + 1), id, -1, SQLITE_TRANSIENT)
            }
            guard sqlite3_step(stmt) == SQLITE_DONE else {
                throw FastenError("SQLite redact failed: \(lastError())")
            }
        }
        return ids
    }

    // Every use of `db` takes `lock`: SQLite does not serialize one
    // connection across threads, and the drainer inserts from its own thread.
    public func ping() throws {
        try lock.withLock {
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, "SELECT 1", -1, &stmt, nil) == SQLITE_OK else {
                throw FastenError("SQLite ping failed")
            }
            sqlite3_finalize(stmt)
        }
    }

    public func maxMonotonicSeq() -> Int {
        lock.withLock {
            var stmt: OpaquePointer?
            let sql = "SELECT COALESCE(MAX(monotonic_seq),0) FROM \(table)"
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return 0 }
            defer { sqlite3_finalize(stmt) }
            guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
            return Int(sqlite3_column_int64(stmt, 0))
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private func lastError() -> String {
        sqlite3_errmsg(db).map { String(cString: $0) } ?? "unknown error"
    }

    private func execInsert(_ sql: String) throws {
        do { try exec(sql) } catch let e as FastenError {
            throw FastenError("SQLite insert failed: \(e.message)")
        }
    }

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
