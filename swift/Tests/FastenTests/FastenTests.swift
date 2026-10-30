import XCTest
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite3
#endif
@testable import Fasten

// MARK: - Codes + Registry

final class CodesTests: XCTestCase {
    override func setUp() { Fasten._resetForTests() }

    func testRegisterAndEmitKnownCode() throws {
        Fasten.register("user", codes: [
            "USER_CREATED": Meta(id: "USER_CREATED", domain: "user",
                                 category: "account", action: "create",
                                 severity: .info, description: "Test code",
                                 emitter: "test", retentionClass: .short_),
        ])
        let store = MemoryStore()
        try Fasten.configure(serviceID: "svc", nodeID: "node",
                              store: store, strategy: .raise)
        XCTAssertNoThrow(
            try Fasten.emit("USER_CREATED", target: "res-1", actor: "admin")
        )
        XCTAssertEqual(store.all().count, 1)
    }

    func testUnknownCodeThrows() throws {
        let store = MemoryStore()
        try Fasten.configure(serviceID: "svc", nodeID: "node",
                              store: store, strategy: .raise)
        XCTAssertThrowsError(
            try Fasten.emit("UNKNOWN_CODE", target: "res", actor: "admin")
        )
    }
}

// MARK: - Redactor

final class RedactorTests: XCTestCase {

    func testApiKeyRedacted() {
        let r = Redactor()
        let out = r.redact(["api_key": "sk-secret"])
        XCTAssertEqual(out["api_key"] as? String, "***")
    }

    func testPasswordRedacted() {
        let r = Redactor()
        let out = r.redact(["password": "hunter2"])
        XCTAssertEqual(out["password"] as? String, "***")
    }

    func testSafeKeyPreserved() {
        let r = Redactor()
        let out = r.redact(["user_id": "u-42"])
        XCTAssertEqual(out["user_id"] as? String, "u-42")
    }

    func testRedactEnvConfig() {
        setenv("FASTEN_REDACT_KEYS", "badge_no, employee_ref", 1)
        setenv("FASTEN_REDACT_REPLACEMENT", "[X]", 1)
        defer {
            unsetenv("FASTEN_REDACT_KEYS")
            unsetenv("FASTEN_REDACT_REPLACEMENT")
        }
        XCTAssertEqual(Fasten.envRedactKeys(), ["badge_no", "employee_ref"])
        XCTAssertEqual(Fasten.envRedactReplacement(), "[X]")
        // configure() defaults to the env values; a Redactor built from them
        // redacts the env extra key AND the built-ins with the custom token.
        let r = Redactor(extraKeys: Fasten.envRedactKeys(),
                         replacement: Fasten.envRedactReplacement())
        let out = r.redact(["badge_no": "b", "password": "p", "ok": "v"])
        XCTAssertEqual(out["badge_no"] as? String, "[X]")
        XCTAssertEqual(out["password"] as? String, "[X]")
        XCTAssertEqual(out["ok"] as? String, "v")
    }

    func testRedactEnvDefaultsWhenUnset() {
        unsetenv("FASTEN_REDACT_KEYS")
        unsetenv("FASTEN_REDACT_REPLACEMENT")
        XCTAssertEqual(Fasten.envRedactKeys(), [])
        XCTAssertEqual(Fasten.envRedactReplacement(), "***")
    }

    func testNestedRedaction() {
        let r = Redactor()
        let out = r.redact(["meta": ["token": "xyz", "ok": "visible"] as [String: Any]])
        let inner = out["meta"] as? [String: Any]
        XCTAssertEqual(inner?["token"] as? String, "***")
        XCTAssertEqual(inner?["ok"] as? String, "visible")
    }

    func testCaseInsensitive() {
        let r = Redactor()
        XCTAssertEqual(r.redact(["API_KEY": "x"])["API_KEY"] as? String, "***")
        XCTAssertEqual(r.redact(["Password": "x"])["Password"] as? String, "***")
    }

    func testJwtValueRedacted() {
        let r = Redactor()
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTQyIn0.abc123def456ghi789"
        let out = r.redact(["notes": jwt])
        XCTAssertEqual(out["notes"] as? String, "***JWT***")
    }

    func testAwsKeyRedacted() {
        let r = Redactor()
        let out = r.redact(["meta": "AKIAIOSFODNN7EXAMPLE"])
        XCTAssertEqual(out["meta"] as? String, "***AWS_KEY***")
    }

    func testStripeKeyRedacted() {
        let r = Redactor()
        let out = r.redact(["ref": "sk_live_" + String(repeating: "A", count: 24)])
        XCTAssertEqual(out["ref"] as? String, "***STRIPE_KEY***")
    }

    func testGhTokenRedacted() {
        let r = Redactor()
        let tok = "ghp_" + String(repeating: "A", count: 36)
        let out = r.redact(["raw": tok])
        XCTAssertEqual(out["raw"] as? String, "***GH_TOKEN***")
    }

    func testCcLuhnValidRedacted() {
        let r = Redactor()
        // Visa test card — passes Luhn
        let out = r.redact(["notes": "4111111111111111"])
        XCTAssertEqual(out["notes"] as? String, "***CC***")
    }

    func testCcLuhnInvalidNotRedacted() {
        let r = Redactor()
        let out = r.redact(["notes": "4111111111111112"])
        XCTAssertEqual(out["notes"] as? String, "4111111111111112")
    }

    func testUserPasswordSubstringMatch() {
        let r = Redactor()
        XCTAssertEqual(r.redact(["user_password": "secret"])["user_password"] as? String, "***")
    }
}

// MARK: - SQLite store

final class SQLiteStoreTests: XCTestCase {
    override func setUp() { Fasten._resetForTests() }

    func testOpenMemoryAndPing() throws {
        let store = try SQLiteStore(path: ":memory:")
        XCTAssertNoThrow(try store.ping())
    }

    func testInsertAndCount() throws {
        Fasten.register("user", codes: [
            "USER_CREATED": Meta(id: "USER_CREATED", domain: "user",
                                 category: "account", action: "create",
                                 description: "Test", emitter: "test"),
        ])
        let store = try SQLiteStore(path: ":memory:")
        try Fasten.configure(serviceID: "svc", nodeID: "node",
                              store: store, strategy: .raise)
        try Fasten.emit("USER_CREATED", target: "res-1", actor: "admin")
        XCTAssertEqual(store.maxMonotonicSeq(), 1)
    }

    func testInsertIdempotent() throws {
        let store = try SQLiteStore(path: ":memory:")
        let row = AuditRow(wireVersion: "1", id: "evt-idem-001",
                           originID: "evt-idem-001", monotonicSeq: 1,
                           timestamp: isoNow(), code: "TEST",
                           action: "test", severity: "info",
                           serviceID: "svc", sourceNodeID: "node",
                           tenantID: nil, actor: "svc", actorKind: "service",
                           target: "res", category: "test", domain: "test",
                           method: "sdk", requestID: "req-001", detail: [:],
                           shippedAt: nil, prevHash: "genesis", hash: "")
        try store.insert(row)
        XCTAssertNoThrow(try store.insert(row))  // INSERT OR IGNORE
    }

    func testInvalidTableNameThrows() {
        XCTAssertThrowsError(try SQLiteStore(path: ":memory:", table: "bad-name!"))
    }

    private func row(_ id: String) -> AuditRow {
        AuditRow(wireVersion: "1", id: id, originID: id, monotonicSeq: 1,
                 timestamp: isoNow(), code: "TEST", action: "test", severity: "info",
                 serviceID: "svc", sourceNodeID: "node", tenantID: nil, actor: "svc",
                 actorKind: "service", target: "res", category: "test", domain: "test",
                 method: "sdk", requestID: "req-001", detail: [:], shippedAt: nil,
                 prevHash: "genesis", hash: "")
    }

    private func tempPath() -> String {
        let path = NSTemporaryDirectory() + "fasten-\(UUID().uuidString).db"
        addTeardownBlock { try? FileManager.default.removeItem(atPath: path) }
        return path
    }

    private func otherConnection(_ path: String, _ sql: String) -> OpaquePointer? {
        var db: OpaquePointer?
        sqlite3_open(path, &db)
        sqlite3_exec(db, sql, nil, nil, nil)
        return db
    }

    func testInsertThrowsWhenTableIsGone() throws {
        let path = tempPath()
        let store = try SQLiteStore(path: path)
        sqlite3_close(otherConnection(path, "DROP TABLE audit_log"))
        XCTAssertThrowsError(try store.insert(row("evt-gone")))
    }

    func testInsertThrowsWhenDatabaseIsLocked() throws {
        let path = tempPath()
        let store = try SQLiteStore(path: path, busyTimeoutMs: 0)
        let other = otherConnection(path, "BEGIN EXCLUSIVE")
        defer { sqlite3_close(other) }
        XCTAssertThrowsError(try store.insert(row("evt-locked")))
    }

    func testRaiseModeEmitThrowsWhenInsertFails() throws {
        Fasten.register("user", codes: [
            "USER_CREATED": Meta(id: "USER_CREATED", domain: "user",
                                 category: "account", action: "create",
                                 description: "Test", emitter: "test"),
        ])
        let path = tempPath()
        let store = try SQLiteStore(path: path)
        try Fasten.configure(serviceID: "svc", nodeID: "node", store: store, strategy: .raise)
        sqlite3_close(otherConnection(path, "DROP TABLE audit_log"))
        XCTAssertThrowsError(try Fasten.emit("USER_CREATED", target: "res-1", actor: "admin"))
    }

    func testQueueModeRetriesWhileTheDatabaseIsLocked() throws {
        Fasten.register("user", codes: [
            "USER_CREATED": Meta(id: "USER_CREATED", domain: "user",
                                 category: "account", action: "create",
                                 description: "Test", emitter: "test"),
        ])
        let path = tempPath()
        let store = try SQLiteStore(path: path, busyTimeoutMs: 0)
        try Fasten.configure(serviceID: "svc", nodeID: "node", store: store, strategy: .queue)
        let other = otherConnection(path, "BEGIN EXCLUSIVE")
        try Fasten.emit("USER_CREATED", target: "res-1", actor: "admin")
        XCTAssertFalse(Fasten.flush(timeout: 0.3))
        XCTAssertEqual(store.maxMonotonicSeq(), 0)
        sqlite3_exec(other, "COMMIT", nil, nil, nil)
        sqlite3_close(other)
        XCTAssertTrue(Fasten.flush(timeout: 5))
        XCTAssertEqual(store.maxMonotonicSeq(), 1)
    }

    func testDrainerKeepsTheStoreErrorMessage() throws {
        let path = tempPath()
        let store = try SQLiteStore(path: path, busyTimeoutMs: 0)
        let other = otherConnection(path, "BEGIN EXCLUSIVE")
        defer { sqlite3_close(other) }
        let drainer = QueueDrainer(store: store, retryInitialMs: 20, retryMaxMs: 20, retryJitter: false)
        defer { drainer.close() }
        drainer.enqueue(row("evt-locked"))
        XCTAssertFalse(drainer.flush(timeout: 0.2))
        XCTAssertTrue(drainer.statsJSON.contains("SQLite insert failed"), drainer.statsJSON)
    }
}

// MARK: - Context propagation

final class ContextTests: XCTestCase {
    override func setUp() { Fasten._resetForTests() }

    func testMintIDFormat() {
        let id = Fasten.mintID()
        XCTAssertTrue(id.hasPrefix("evt-"))
    }

    func testRequestScopeSetsCurrent() {
        XCTAssertNil(Fasten.currentRequestID)
        let scope = RequestScope(id: "req-xyz")
        XCTAssertEqual(_currentRequestID(), "req-xyz")
        scope.end()
        XCTAssertNil(Fasten.currentRequestID)
    }

    func testWithRequestIDBlock() {
        Fasten.withRequestID("req-abc") {
            XCTAssertEqual(Fasten.currentRequestID, "req-abc")
        }
        XCTAssertNil(Fasten.currentRequestID)
    }
}

// MARK: - Store-assigned seq (spec 2.1, #92)

private func tempDBPath(_ test: XCTestCase) -> String {
    let path = NSTemporaryDirectory() + "fasten-\(UUID().uuidString).db"
    test.addTeardownBlock { try? FileManager.default.removeItem(atPath: path) }
    return path
}

private func testRow(_ id: String, seq: Int = 0, code: String = "TEST",
                     timestamp: String = isoNow(), detail: [String: AnyCodable] = [:],
                     hash: String = "") -> AuditRow {
    AuditRow(wireVersion: "1", id: id, originID: id, monotonicSeq: seq,
             timestamp: timestamp, code: code, action: "test", severity: "info",
             serviceID: "svc", sourceNodeID: "node", tenantID: nil, actor: "svc",
             actorKind: "service", target: "res", category: "test", domain: "test",
             method: "sdk", requestID: "req-001", detail: detail, shippedAt: nil,
             prevHash: hash.isEmpty ? "" : "genesis", hash: hash)
}

/// Runs a query on a separate connection; one row per result, columns as text.
private func query(_ path: String, _ sql: String) -> [[String]] {
    var db: OpaquePointer?
    sqlite3_open(path, &db)
    defer { sqlite3_close(db) }
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
    defer { sqlite3_finalize(stmt) }
    var out: [[String]] = []
    while sqlite3_step(stmt) == SQLITE_ROW {
        out.append((0..<sqlite3_column_count(stmt)).map {
            sqlite3_column_text(stmt, $0).map { String(cString: $0) } ?? ""
        })
    }
    return out
}

private final class CapturingStore: AuditStore, @unchecked Sendable {
    private let lock = Lock()
    private var captured: [AuditRow] = []
    func insert(_ row: AuditRow) throws { lock.withLock { captured.append(row) } }
    func ping() throws {}
    func maxMonotonicSeq() -> Int { 0 }
    var rows: [AuditRow] { lock.withLock { captured } }
}

private let userCreated: [Code: Meta] = [
    "USER_CREATED": Meta(id: "USER_CREATED", domain: "user", category: "account",
                         action: "create", description: "Test", emitter: "test"),
]

final class ChainTests: XCTestCase {
    override func setUp() { Fasten._resetForTests() }

    func testEmitHandsTheStoreAnUnsealedRowWithSeqZero() throws {
        Fasten.register("user", codes: userCreated)
        let store = CapturingStore()
        try Fasten.configure(serviceID: "svc", nodeID: "node", store: store, strategy: .raise)
        try Fasten.emit("USER_CREATED", target: "r1", actor: "a")
        try Fasten.emit("USER_CREATED", target: "r2", actor: "a")
        XCTAssertEqual(store.rows.map(\.monotonicSeq), [0, 0])
        XCTAssertEqual(store.rows.map(\.hash), ["", ""])
        XCTAssertEqual(store.rows.map(\.prevHash), ["", ""])
    }

    func testMemoryStoreAssignsSeqPerNode() throws {
        let store = MemoryStore()
        try store.insert(testRow("a"))
        try store.insert(testRow("b"))
        try store.insert(testRow("c", seq: 7))
        XCTAssertEqual(store.all().map(\.monotonicSeq), [1, 2, 7])
    }

    func testSQLiteStoreAssignsSeqAndKeepsAGivenOne() throws {
        let path = tempDBPath(self)
        let store = try SQLiteStore(path: path)
        try store.insert(testRow("a"))
        try store.insert(testRow("b", seq: 9))
        try store.insert(testRow("c"))
        XCTAssertEqual(query(path, "SELECT id, monotonic_seq FROM audit_log ORDER BY id"),
                       [["a", "1"], ["b", "9"], ["c", "10"]])
    }

    // #92: two engines, each with its own connection to one file, same node.
    func testTwoEnginesOnOneFileGetSeqsOneToN() throws {
        Fasten.register("user", codes: userCreated)
        let path = tempDBPath(self)
        let engines = try (0..<2).map { _ -> Engine in
            let e = Engine()
            e.configure(serviceID: "svc", nodeID: "node",
                        store: try SQLiteStore(path: path), strategy: .raise)
            return e
        }
        let perEngine = 25
        let errors = Lock()
        var failures: [Error] = []
        DispatchQueue.concurrentPerform(iterations: 2 * perEngine) { i in
            do {
                try engines[i % 2].emit(code: "USER_CREATED", target: "r\(i)", actor: "a")
            } catch {
                errors.withLock { failures.append(error) }
            }
        }
        XCTAssertTrue(failures.isEmpty, "\(failures)")
        let seqs = query(path, "SELECT monotonic_seq FROM audit_log ORDER BY monotonic_seq")
            .map { Int($0[0])! }
        XCTAssertEqual(seqs, Array(1...(2 * perEngine)))
    }

    func testFailedCommitRollsBack() throws {
        let path = tempDBPath(self)
        let store = try SQLiteStore(path: path, busyTimeoutMs: 0)
        // A reader holding a SHARED lock makes our COMMIT fail with SQLITE_BUSY.
        var reader: OpaquePointer?
        sqlite3_open(path, &reader)
        sqlite3_exec(reader, "BEGIN; SELECT COUNT(*) FROM audit_log;", nil, nil, nil)
        XCTAssertThrowsError(try store.insert(testRow("lost")))
        sqlite3_exec(reader, "COMMIT", nil, nil, nil)
        sqlite3_close(reader)
        // Left in a transaction, this insert would fail on BEGIN IMMEDIATE.
        try store.insert(testRow("kept"))
        XCTAssertEqual(query(path, "SELECT id, monotonic_seq FROM audit_log"), [["kept", "1"]])
    }
}

// MARK: - PII redaction (spec 7)

final class RedactionTests: XCTestCase {
    override func setUp() { Fasten._resetForTests() }

    private let day: TimeInterval = 86_400

    private func registerCodes() {
        Fasten.register("user", codes: [
            "USER_EMAIL_SEEN": Meta(id: "USER_EMAIL_SEEN", domain: "user", category: "account",
                                    action: "read", description: "PII", emitter: "test",
                                    piiInDetail: true),
            "USER_LOGIN": Meta(id: "USER_LOGIN", domain: "user", category: "account",
                               action: "login", description: "not PII", emitter: "test"),
        ])
    }

    func testPiiCodesFromRegistry() {
        registerCodes()
        Fasten.register("ops", codes: [
            "OPS_SHORT": Meta(id: "OPS_SHORT", domain: "ops", category: "x", action: "y",
                              description: "", emitter: "test", retentionClass: .short_),
        ])
        XCTAssertEqual(Fasten.piiCodes(), ["OPS_SHORT", "USER_EMAIL_SEEN"])
    }

    func testRedactExpiredOnSQLite() throws {
        registerCodes()
        let path = tempDBPath(self)
        let store = try SQLiteStore(path: path)
        try Fasten.configure(serviceID: "svc", nodeID: "node", store: store, strategy: .raise)
        let old = isoString40DaysAgo()
        let email: [String: AnyCodable] = ["email": AnyCodable("a@example.com")]
        try store.insert(testRow("pii", code: "USER_EMAIL_SEEN", timestamp: old, detail: email))
        try store.insert(testRow("ops", code: "USER_LOGIN", timestamp: old, detail: email))
        try store.insert(testRow("sealed", seq: 50, code: "USER_EMAIL_SEEN", timestamp: old,
                                 detail: email, hash: "abc"))
        try store.insert(testRow("fresh", code: "USER_EMAIL_SEEN", detail: email))

        let cutoff = Date().addingTimeInterval(-30 * day)
        XCTAssertEqual(try Fasten.redactExpired(before: cutoff), ["pii"])

        let detail = Dictionary(uniqueKeysWithValues: query(
            path, "SELECT id, detail FROM audit_log WHERE code <> 'AUDIT_ROW_REDACTED'")
            .map { ($0[0], $0[1]) })
        XCTAssertEqual(detail["pii"], "null")
        XCTAssertEqual(detail["ops"], #"{"email":"a@example.com"}"#)
        XCTAssertEqual(detail["sealed"], #"{"email":"a@example.com"}"#)
        XCTAssertEqual(detail["fresh"], #"{"email":"a@example.com"}"#)

        let records = query(path, "SELECT target, detail FROM audit_log WHERE code = 'AUDIT_ROW_REDACTED'")
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records.first?[0], "pii")
        XCTAssertTrue(records.first?[1].contains(#""redacted_seq":1"#) ?? false, "\(records)")

        XCTAssertEqual(try Fasten.redactExpired(before: cutoff), [])
        XCTAssertEqual(query(path, "SELECT COUNT(*) FROM audit_log"), [["5"]])
    }

    func testRedactExpiredOnMemoryStore() throws {
        registerCodes()
        let store = MemoryStore()
        try Fasten.configure(serviceID: "svc", nodeID: "node", store: store, strategy: .raise)
        let old = isoString40DaysAgo()
        try store.insert(testRow("pii", code: "USER_EMAIL_SEEN", timestamp: old,
                                 detail: ["email": AnyCodable("a@example.com")]))
        try store.insert(testRow("ops", code: "USER_LOGIN", timestamp: old))
        let cutoff = Date().addingTimeInterval(-30 * day)
        XCTAssertEqual(try Fasten.redactExpired(before: cutoff), ["pii"])
        XCTAssertTrue(store.isRedacted("pii"))
        XCTAssertFalse(store.isRedacted("ops"))
        XCTAssertTrue(store.all().first { $0.id == "pii" }!.detail.isEmpty)
        XCTAssertEqual(store.all().filter { $0.code == "AUDIT_ROW_REDACTED" }.map(\.target), ["pii"])
        XCTAssertEqual(try Fasten.redactExpired(before: cutoff), [])
    }

    func testStoreWithoutRedactionSupportThrows() throws {
        registerCodes()
        try Fasten.configure(serviceID: "svc", nodeID: "node", store: CapturingStore(),
                             strategy: .raise)
        XCTAssertThrowsError(try Fasten.redactExpired(before: Date()))
    }

    private func isoString40DaysAgo() -> String {
        ISO8601DateFormatter().string(from: Date().addingTimeInterval(-40 * day))
    }
}

// MARK: - Queue drainer

final class QueueTests: XCTestCase {
    override func setUp() { Fasten._resetForTests() }

    func testQueueModeFlushesRows() throws {
        Fasten.register("user", codes: [
            "USER_CREATED": Meta(id: "USER_CREATED", domain: "user",
                                 category: "account", action: "create",
                                 description: "Test", emitter: "test"),
        ])
        let store = MemoryStore()
        try Fasten.configure(serviceID: "svc", nodeID: "node",
                              store: store, strategy: .queue, queueCapacity: 100)
        try Fasten.emit("USER_CREATED", target: "res", actor: "admin")
        let drained = Fasten.flush(timeout: 5.0)
        XCTAssertTrue(drained)
        XCTAssertEqual(store.all().count, 1)
    }
}
