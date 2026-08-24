import XCTest
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

// MARK: - Hash chain

final class HashChainTests: XCTestCase {
    override func setUp() { Fasten._resetForTests() }

    func testHashPresentOnEmit() throws {
        Fasten.register("user", codes: [
            "USER_CREATED": Meta(id: "USER_CREATED", domain: "user",
                                 category: "account", action: "create",
                                 description: "Test", emitter: "test"),
        ])
        let store = MemoryStore()
        try Fasten.configure(serviceID: "svc", nodeID: "node",
                              store: store, strategy: .raise)
        try Fasten.emit("USER_CREATED", target: "res", actor: "admin")
        let rows = store.all()
        XCTAssertEqual(rows.count, 1)
        XCTAssertFalse(rows[0].hash.isEmpty)
        XCTAssertEqual(rows[0].prevHash, "genesis")
    }

    func testChainLinksRows() throws {
        Fasten.register("user", codes: [
            "USER_CREATED": Meta(id: "USER_CREATED", domain: "user",
                                 category: "account", action: "create",
                                 description: "Test", emitter: "test"),
        ])
        let store = MemoryStore()
        try Fasten.configure(serviceID: "svc", nodeID: "node",
                              store: store, strategy: .raise)
        try Fasten.emit("USER_CREATED", target: "r1", actor: "a")
        try Fasten.emit("USER_CREATED", target: "r2", actor: "a")
        let rows = store.all().sorted { $0.monotonicSeq < $1.monotonicSeq }
        XCTAssertEqual(rows[1].prevHash, rows[0].hash)
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
