import Foundation
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite3
#endif

/// AuditStore backed by the system SQLite3 library (install libsqlite3-dev on
/// Linux). Pass ":memory:" as the path for an in-memory database. A new
/// database file is created owner-only (0600).
public final class SQLiteStore: AuditStore, @unchecked Sendable {

    private(set) var db: OpaquePointer?   // internal for tests
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
        // NOMUTEX: `lock` is the only thing serializing this connection, on
        // every platform, whatever threading mode the system SQLite was built with.
        Self.createOwnerOnly(path)
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_URI
        if sqlite3_open_v2(path, &db, flags, nil) != SQLITE_OK {
            throw FastenError("cannot open SQLite at \(path)")
        }
        sqlite3_busy_timeout(db, busyTimeoutMs)
        try bootstrap()
    }

    deinit { sqlite3_close(db) }

    /// Creates a missing database file with mode 0600, so SQLite does not
    /// create it with the umask. An existing file keeps its mode. If the file
    /// cannot be created, sqlite3_open_v2 reports the error.
    static func createOwnerOnly(_ path: String) {
        // file: is a URI; init opens with SQLITE_OPEN_URI.
        let file = path.hasPrefix("file:") ? uriFilePath(path) : Array(path.utf8)
        guard let file, !file.isEmpty, file != Array(":memory:".utf8) else { return }
        // From the raw bytes, so a name that is not UTF-8 matches what SQLite opens.
        let fd = (file + [0]).withUnsafeBufferPointer {
            // No O_EXCL: like SQLite, follow a symlink to a missing file.
            // The mode applies only when the file is created.
            $0.withMemoryRebound(to: CChar.self) { open($0.baseAddress!, O_CREAT | O_WRONLY, 0o600) }
        }
        if fd >= 0 { close(fd) }
    }

    /// File path bytes of a SQLite file: URI, or nil when the URI names no
    /// file to create (in-memory, read-only, another VFS, or another host).
    /// Escapes decode as in SQLite: a `%` without two hex digits stays as it
    /// is, and the path ends at a %00.
    static func uriFilePath(_ uri: String) -> [UInt8]? {
        var rest = Substring(uri.dropFirst(5).prefix { $0 != "#" })
        var query = Substring("")
        if let q = rest.firstIndex(of: "?") {
            query = rest[rest.index(after: q)...]
            rest = rest[..<q]
        }
        let noCreate: Set<Substring> = ["mode=memory", "mode=ro", "mode=rw"]
        for p in query.split(separator: "&") {
            let kv = p.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let value = kv.count > 1 ? kv[1] : ""
            if noCreate.contains(p) || kv[0] == "vfs" || (kv[0] == "immutable" && uriTrue(value)) {
                return nil
            }
        }
        if rest.hasPrefix("//") {
            let after = rest.dropFirst(2)
            let slash = after.firstIndex(of: "/") ?? after.endIndex
            guard ["", "localhost"].contains(after[..<slash]) else { return nil }
            rest = after[slash...]
        }
        let raw = Array(rest.utf8)
        var out: [UInt8] = []
        var i = 0
        while i < raw.count {
            if raw[i] == UInt8(ascii: "%"), i + 2 < raw.count,
               let hi = hexValue(raw[i + 1]), let lo = hexValue(raw[i + 2]) {
                if hi == 0 && lo == 0 { break }
                out.append(hi << 4 | lo)
                i += 3
            } else {
                out.append(raw[i])
                i += 1
            }
        }
        return out
    }

    /// A URI boolean as sqlite3_uri_boolean reads it.
    static func uriTrue(_ value: Substring) -> Bool {
        if let first = value.first, first.isASCII, first.isNumber {
            return value.prefix { $0.isASCII && $0.isNumber }.contains { $0 != "0" }
        }
        return ["yes", "on", "true", "full", "extra", "normal"].contains(value.lowercased())
    }

    private static func hexValue(_ c: UInt8) -> UInt8? {
        switch c {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
        default: return nil
        }
    }

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
        CREATE INDEX IF NOT EXISTS idx_\(table)_node_seq ON \(table)(source_node_id, monotonic_seq);
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
            do {
                try exec(m)
            } catch let e as FastenError where e.message.hasPrefix("duplicate column name") {}
        }
    }

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
                // Some errors roll back on their own, so ROLLBACK failing only
                // matters while a transaction is still open.
                if sqlite3_exec(db, "ROLLBACK", nil, nil, nil) != SQLITE_OK,
                   sqlite3_get_autocommit(db) == 0 {
                    throw FastenError("\(error.localizedDescription); ROLLBACK failed, "
                        + "the connection is still in a transaction: \(lastError())")
                }
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
         prev_hash,hash,pii_in_detail,detail_salt,detail_commitment)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'','')
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
        sqlite3_bind_int(stmt,  22, CodeRegistry.shared.lookup(row.code)?.piiInDetail == true ? 1 : 0)
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

    /// Clears `hash` and `prev_hash` on sealed form "1" rows so
    /// `redactExpired` can reach them. The Swift release before store-assigned
    /// seqs sealed rows with a hash that never covered `detail`, and those
    /// rows are form "1" too. Only safe on a table Swift alone wrote: a Go or
    /// Python form "1" hash does cover `detail` and cannot be told apart.
    /// Returns the number of rows cleared.
    @discardableResult
    public func clearLegacySwiftHashes() throws -> Int {
        try lock.withLock {
            try exec("UPDATE \(table) SET hash = '', prev_hash = '' "
                + "WHERE canonical_form_id = '1' AND hash <> ''")
            return Int(sqlite3_changes(db))
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

    public func maxMonotonicSeq(sourceNodeID: String?) -> Int {
        lock.withLock {
            var stmt: OpaquePointer?
            var sql = "SELECT COALESCE(MAX(monotonic_seq),0) FROM \(table)"
            if sourceNodeID != nil { sql += " WHERE source_node_id = ?" }
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return 0 }
            defer { sqlite3_finalize(stmt) }
            if let node = sourceNodeID {
                sqlite3_bind_text(stmt, 1, node, -1, SQLITE_TRANSIENT)
            }
            guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
            return Int(sqlite3_column_int64(stmt, 0))
        }
    }

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
