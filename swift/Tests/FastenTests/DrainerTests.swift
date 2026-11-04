import XCTest
@testable import Fasten

// spec/drainer-conformance.md

private let codes: [Code: Meta] = [
    "USER_CREATED": Meta(id: "USER_CREATED", domain: "user", category: "account",
                         action: "create", description: "Test", emitter: "test"),
]

private final class SysLog: @unchecked Sendable {
    private let lock = Lock()
    private var lines: [[String: Any]] = []

    func add(_ level: String, _ event: String, _ fields: [String: Any]) {
        var obj = fields
        obj["level"] = level
        obj["event"] = event
        lock.withLock { lines.append(obj) }
    }

    func capture(_ engine: Engine) {
        engine.transport.write = { [self] line in
            if let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] {
                lock.withLock { lines.append(obj) }
            }
        }
    }

    var all: [[String: Any]] { lock.withLock { lines } }
    var events: [String] { all.compactMap { $0["event"] as? String } }
    func named(_ event: String) -> [[String: Any]] {
        all.filter { $0["event"] as? String == event }
    }
}

/// Fails the first `failures` inserts, then stores rows. Inserts wait while
/// the gate is closed.
private final class TestStore: AuditStore, @unchecked Sendable {
    private let lock = Lock()
    private var rows: [AuditRow] = []
    private var failuresLeft: Int
    private var gateOpen: Bool
    private var calls = 0

    init(failures: Int = 0, gateOpen: Bool = true) {
        self.failuresLeft = failures
        self.gateOpen = gateOpen
    }

    func insert(_ row: AuditRow) throws {
        lock.withLock { calls += 1 }
        while !lock.withLock({ gateOpen }) { Thread.sleep(forTimeInterval: 0.005) }
        try lock.withLock {
            if failuresLeft > 0 {
                failuresLeft -= 1
                throw FastenError("insert failed")
            }
            rows.append(row)
        }
    }
    func ping() throws {}
    func maxMonotonicSeq(sourceNodeID: String?) -> Int { 0 }

    func setGate(_ open: Bool) { lock.withLock { gateOpen = open } }
    var stored: [String] { lock.withLock { rows.map(\.id) } }
    var insertCalls: Int { lock.withLock { calls } }
}

private func waitUntil(_ timeout: TimeInterval = 5, _ cond: () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if cond() { return true }
        Thread.sleep(forTimeInterval: 0.01)
    }
    return cond()
}

private func row(_ id: String) -> AuditRow {
    AuditRow(wireVersion: "1", id: id, originID: id, monotonicSeq: 0,
             timestamp: isoNow(), code: "USER_CREATED", action: "create", severity: "info",
             serviceID: "svc", sourceNodeID: "node", tenantID: nil, actor: "a",
             actorKind: "user", target: "t", category: "account", domain: "user",
             method: "sdk", requestID: "req", detail: [:], shippedAt: nil,
             prevHash: "", hash: "")
}

final class DrainerConformanceTests: XCTestCase {
    override func setUp() {
        Fasten._resetForTests()
        Fasten.register("user", codes: codes)
    }

    // §10: a row waiting for a slot when a re-init stops the old drainer is
    // stored inline, not dropped.
    func testReinitStoresARowTheOldDrainerRefused() throws {
        let store = TestStore(gateOpen: false)
        let engine = Engine()
        engine.installFlushTimeout = 0.1
        engine.stopTimeout = 0.1
        engine.configure(serviceID: "svc", nodeID: "node", store: store, queueCapacity: 1)
        let log = SysLog()
        log.capture(engine)
        try engine.emit(code: "USER_CREATED", target: "a", actor: "x")
        XCTAssertTrue(waitUntil { store.insertCalls == 1 })

        let waiting = expectation(description: "second emit returns")
        DispatchQueue.global().async {
            try? engine.emit(code: "USER_CREATED", target: "b", actor: "x")
            waiting.fulfill()
        }
        // The row line is written once the emit holds the old drainer.
        XCTAssertTrue(waitUntil { log.all.contains { $0["target"] as? String == "b" } })
        engine.configure(serviceID: "svc", nodeID: "node", store: MemoryStore(), queueCapacity: 1)
        store.setGate(true)
        wait(for: [waiting], timeout: 5)

        XCTAssertTrue(waitUntil { store.stored.count == 2 }, "\(store.stored)")
        let events = log.events
        let abandoned = events.firstIndex(of: "audit_drain_abandoned")
        let inline = events.firstIndex(of: "audit_drain_stored_inline")
        XCTAssertNotNil(abandoned, "\(events)")
        XCTAssertNotNil(inline, "\(events)")
        if let a = abandoned, let i = inline { XCTAssertLessThan(a, i) }
        XCTAssertEqual(log.named("audit_drain_install_incomplete").first?["flushed"] as? Bool, false)

        // "a" was still being inserted at the stop deadline: reported lost,
        // then recovered once its insert stored it.
        let a = log.all.first { $0["target"] as? String == "a" }?["id"] as? String
        XCTAssertEqual(log.named("audit_drain_lost_at_stop").compactMap { $0["row_id"] as? String }, [a])
        XCTAssertTrue(waitUntil { !log.named("audit_drain_recovered_at_stop").isEmpty })
        XCTAssertEqual(log.named("audit_drain_recovered_at_stop").first?["row_ids"] as? [String], a.map { [$0] })
    }

    // A re-init after an earlier dead letter, with every pending row stored,
    // is complete.
    func testReinitIgnoresEarlierDeadLetters() throws {
        let store = TestStore(failures: 2)
        let engine = Engine()
        engine.retryInitialMs = 1
        engine.maxAttempts = 2
        engine.configure(serviceID: "svc", nodeID: "node", store: store)
        let log = SysLog()
        log.capture(engine)
        try engine.emit(code: "USER_CREATED", target: "a", actor: "x")
        XCTAssertTrue(engine.flush(timeout: 2))
        XCTAssertEqual(log.named("audit_drain_dead_letter").count, 1)
        try engine.emit(code: "USER_CREATED", target: "b", actor: "x")
        engine.configure(serviceID: "svc", nodeID: "node", store: MemoryStore())
        XCTAssertEqual(store.stored.count, 1)
        XCTAssertEqual(log.named("audit_drain_install_incomplete").count, 0, "\(log.events)")
        XCTAssertTrue(engine.close(timeout: 1))
    }

    // A row pending at the swap that dead-letters before retire() starts
    // still makes the re-init incomplete.
    func testReinitCountsADeadLetterRightAfterTheSwap() throws {
        let store = TestStore(failures: 1, gateOpen: false)
        let engine = Engine()
        engine.maxAttempts = 1
        engine.configure(serviceID: "svc", nodeID: "node", store: store)
        let log = SysLog()
        log.capture(engine)
        let flags = Lock()
        var held = false, swapping = false
        let write = engine.transport.write
        engine.transport.write = { [unowned engine] line in
            // Hold the dead-letter line until the re-init has swapped
            // drainers, then let the row settle before the re-init's own log
            // line is written.
            if line.contains("audit_drain_dead_letter") {
                flags.withLock { held = true }
                _ = waitUntil { flags.withLock { swapping } }
                Thread.sleep(forTimeInterval: 0.2)
            }
            if line.contains("audit_chain_unavailable") {
                _ = engine.flush(timeout: 2)
            }
            write(line)
        }
        try engine.emit(code: "USER_CREATED", target: "a", actor: "x")
        XCTAssertTrue(waitUntil { store.insertCalls == 1 })
        store.setGate(true)
        XCTAssertTrue(waitUntil { flags.withLock { held } })
        flags.withLock { swapping = true }
        engine.configure(serviceID: "svc", nodeID: "node", store: MemoryStore())

        let incomplete = log.named("audit_drain_install_incomplete")
        XCTAssertEqual(incomplete.count, 1, "\(log.events)")
        XCTAssertEqual(incomplete.first?["unstored"] as? Int, 1)
        XCTAssertEqual(incomplete.first?["flushed"] as? Bool, true)
        XCTAssertTrue(engine.close(timeout: 1))
    }

    // §10: close() covers a drainer a re-init is still retiring, and every
    // drainer shares the one deadline.
    func testEngineCloseCoversRetiringDrainers() throws {
        let first = TestStore(gateOpen: false)
        let second = TestStore(gateOpen: false)
        let engine = Engine()
        engine.installFlushTimeout = 10
        engine.stopTimeout = 10
        engine.configure(serviceID: "svc", nodeID: "node", store: first)
        let log = SysLog()
        log.capture(engine)
        try engine.emit(code: "USER_CREATED", target: "a", actor: "x")
        XCTAssertTrue(waitUntil { first.insertCalls == 1 })

        let reinit = expectation(description: "re-init returns")
        DispatchQueue.global().async {
            engine.configure(serviceID: "svc", nodeID: "node", store: second)
            reinit.fulfill()
        }
        // Logged after the swap, before the old drainer is retired.
        XCTAssertTrue(waitUntil { !log.named("audit_chain_unavailable").isEmpty })
        try engine.emit(code: "USER_CREATED", target: "b", actor: "x")
        XCTAssertTrue(waitUntil { second.insertCalls == 1 })

        let start = Date()
        XCTAssertFalse(engine.close(timeout: 1))
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.6)
        first.setGate(true)
        second.setGate(true)
        wait(for: [reinit], timeout: 15)
    }

    // §6: flush() returns only after the event that settled the row.
    func testFlushWaitsForTheSettlingEvent() {
        for (failures, event) in [(1, "audit_drain_recovered"), (1_000, "audit_drain_dead_letter")] {
            let log = SysLog()
            let drainer = QueueDrainer(
                store: TestStore(failures: failures), retryInitialMs: 1, retryMaxMs: 1,
                retryJitter: false, maxAttempts: 2,
                sysLog: { level, name, fields in
                    if name == event { Thread.sleep(forTimeInterval: 0.2) }
                    log.add(level, name, fields)
                })
            drainer.enqueue(row("r1"))
            XCTAssertTrue(drainer.flush(timeout: 2))
            XCTAssertEqual(log.named(event).count, 1, event)
            XCTAssertTrue(drainer.statsJSON.contains("\"depth\":0"), drainer.statsJSON)
            drainer.close()
        }
    }

    // §10: a row whose one shutdown attempt fails is reported.
    func testRowFailingItsStopAttemptIsReportedLost() throws {
        let store = TestStore(failures: 1_000)
        let engine = Engine()
        engine.configure(serviceID: "svc", nodeID: "node", store: store)
        let log = SysLog()
        log.capture(engine)
        try engine.emit(code: "USER_CREATED", target: "a", actor: "x")
        XCTAssertTrue(waitUntil { store.insertCalls >= 1 })
        engine.reset()

        let lost = log.named("audit_drain_lost_at_stop")
        XCTAssertEqual(lost.count, 1, "\(log.events)")
        XCTAssertEqual(lost.first?["error_type"] as? String, "FastenError")
        XCTAssertNotNil(lost.first?["row_id"] as? String)
    }

    // §6: a dead-lettered row counts toward flush().
    func testFlushReturnsOnceAPendingRowIsDeadLettered() {
        let drainer = QueueDrainer(store: TestStore(failures: 1_000), retryInitialMs: 1,
                                   retryMaxMs: 5, retryJitter: false, maxAttempts: 3)
        defer { drainer.close() }
        drainer.enqueue(row("r1"))
        XCTAssertTrue(drainer.flush(timeout: 2))
        XCTAssertTrue(drainer.statsJSON.contains("\"dead_lettered_total\":1"), drainer.statsJSON)
        XCTAssertTrue(drainer.statsJSON.contains("\"depth\":0"), drainer.statsJSON)
    }

    // §4 capacity thresholds: once per crossing, re-armed below 50 %.
    func testCapacityThresholdEvents() throws {
        let store = TestStore(gateOpen: false)
        let engine = Engine()
        engine.configure(serviceID: "svc", nodeID: "node", store: store, queueCapacity: 4)
        let log = SysLog()
        log.capture(engine)
        for i in 0..<4 { try engine.emit(code: "USER_CREATED", target: "t\(i)", actor: "x") }

        let high = log.named("audit_queue_high_water")
        let full = log.named("audit_queue_near_full")
        XCTAssertEqual(high.count, 1)
        XCTAssertEqual(high.first?["level"] as? String, "warn")
        XCTAssertEqual(high.first?["depth"] as? Int, 2)
        XCTAssertEqual(high.first?["capacity"] as? Int, 4)
        XCTAssertEqual(full.count, 1)
        XCTAssertEqual(full.first?["level"] as? String, "error")
        XCTAssertEqual(full.first?["depth"] as? Int, 4)

        store.setGate(true)
        XCTAssertTrue(engine.flush(timeout: 5))
        store.setGate(false)
        for i in 4..<6 { try engine.emit(code: "USER_CREATED", target: "t\(i)", actor: "x") }
        XCTAssertEqual(log.named("audit_queue_high_water").count, 2)
        XCTAssertEqual(log.named("audit_queue_near_full").count, 1)
        store.setGate(true)
        XCTAssertTrue(engine.flush(timeout: 5))
    }

    // V-11 on the engine's default backoff (about 3 s).
    func testDrainStateEventsFireInOrder() throws {
        let store = TestStore(failures: 5)
        let engine = Engine()
        engine.configure(serviceID: "svc", nodeID: "node", store: store)
        let log = SysLog()
        log.capture(engine)
        try engine.emit(code: "USER_CREATED", target: "a", actor: "x")
        XCTAssertTrue(engine.flush(timeout: 10))

        let drain = log.events.filter { $0.hasPrefix("audit_drain_") }
        XCTAssertEqual(drain, ["audit_drain_failed", "audit_drain_degraded", "audit_drain_recovered"])
        XCTAssertEqual(log.named("audit_drain_failed").first?["error"] as? String,
                       "FastenError: insert failed")
        let degraded = log.named("audit_drain_degraded").first
        XCTAssertEqual(degraded?["retry_count"] as? Int, 5)
        XCTAssertEqual(degraded?["last_error"] as? String, "FastenError: insert failed")
        XCTAssertNotNil(degraded?["in_backoff_seconds"] as? Double)
        let after = log.named("audit_drain_recovered").first?["recovery_after_seconds"] as? Double
        XCTAssertGreaterThan(after ?? 0, 0)
    }
}

final class DrainerStopTests: XCTestCase {
    override func setUp() {
        Fasten._resetForTests()
        Fasten.register("user", codes: codes)
    }

    // V-10
    func testDeadLetterEvent() {
        let log = SysLog()
        let drainer = QueueDrainer(store: TestStore(failures: 1_000), retryInitialMs: 1,
                                   retryMaxMs: 5, retryJitter: false, maxAttempts: 3,
                                   sysLog: log.add)
        defer { drainer.close() }
        drainer.enqueue(row("r1"))
        XCTAssertTrue(drainer.flush(timeout: 2))
        let dead = log.named("audit_drain_dead_letter")
        XCTAssertEqual(dead.count, 1)
        XCTAssertEqual(dead.first?["row_id"] as? String, "r1")
        XCTAssertEqual(dead.first?["attempt_count"] as? Int, 3)
        XCTAssertEqual(dead.first?["last_error"] as? String, "FastenError: insert failed")
    }

    func testEnqueueAfterCloseIsRefusedAndReported() {
        let log = SysLog()
        let drainer = QueueDrainer(store: MemoryStore(), sysLog: log.add)
        XCTAssertTrue(drainer.close())
        XCTAssertFalse(drainer.enqueue(row("late")))
        let abandoned = log.named("audit_drain_abandoned")
        XCTAssertEqual(abandoned.first?["reason"] as? String, "drainer_stopped")
        XCTAssertEqual(abandoned.first?["row_id"] as? String, "late")
    }

    func testCloseReturnsFalseWhenARowIsLost() {
        let log = SysLog()
        let drainer = QueueDrainer(store: TestStore(failures: 1_000), sysLog: log.add)
        drainer.enqueue(row("r1"))
        XCTAssertTrue(waitUntil { log.events.contains("audit_drain_failed") })
        XCTAssertFalse(drainer.close(timeout: 2))
        XCTAssertEqual(log.named("audit_drain_lost_at_stop").first?["row_id"] as? String, "r1")
    }

    // close() waits for an insert in progress.
    func testCloseWaitsForAnInsertInProgress() {
        let store = TestStore(gateOpen: false)
        let drainer = QueueDrainer(store: store)
        drainer.enqueue(row("r1"))
        XCTAssertTrue(waitUntil { store.insertCalls == 1 })
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { store.setGate(true) }
        XCTAssertTrue(drainer.close(timeout: 2))
        XCTAssertEqual(store.stored, ["r1"])
    }

    func testCloseTimeoutReportsTheRowsStillHeld() {
        let log = SysLog()
        let store = TestStore(gateOpen: false)
        let drainer = QueueDrainer(store: store, sysLog: log.add)
        drainer.enqueue(row("r1"))
        drainer.enqueue(row("r2"))
        XCTAssertTrue(waitUntil { store.insertCalls == 1 })
        XCTAssertFalse(drainer.close(timeout: 0.1))
        XCTAssertEqual(log.named("audit_drain_lost_at_stop").compactMap { $0["row_id"] as? String },
                       ["r1", "r2"])
        store.setGate(true)
    }

    // An insert left running at the close deadline keeps the drainer alive,
    // and releasing the drainer does not wait for it.
    func testDrainerOutlivesACloseTimeout() {
        let log = SysLog()
        let store = TestStore(gateOpen: false)
        var drainer: QueueDrainer? = QueueDrainer(store: store, sysLog: log.add)
        drainer?.enqueue(row("r1"))
        XCTAssertTrue(waitUntil { store.insertCalls == 1 })

        let start = Date()
        let closed = drainer!.close(timeout: 0.2)
        drainer = nil
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertFalse(closed)
        XCTAssertLessThan(elapsed, 1.0)

        // The insert returns after the drainer was released.
        store.setGate(true)
        XCTAssertTrue(waitUntil { !log.named("audit_drain_recovered_at_stop").isEmpty })
        XCTAssertEqual(store.stored, ["r1"])
        XCTAssertEqual(log.named("audit_drain_lost_at_stop").compactMap { $0["row_id"] as? String }, ["r1"])
        XCTAssertEqual(log.named("audit_drain_recovered_at_stop").first?["row_ids"] as? [String], ["r1"])
    }

    func testEngineCloseReportsLossAndLaterEmitsStoreInline() throws {
        let failing = TestStore(failures: 1_000)
        try Fasten.configure(serviceID: "svc", nodeID: "node", store: failing)
        try Fasten.emit("USER_CREATED", target: "a", actor: "x")
        XCTAssertTrue(waitUntil { failing.insertCalls >= 1 })
        XCTAssertFalse(Fasten.close(timeout: 2))

        let store = MemoryStore()
        try Fasten.configure(serviceID: "svc", nodeID: "node", store: store)
        XCTAssertTrue(Fasten.close())
        try Fasten.emit("USER_CREATED", target: "b", actor: "x")
        XCTAssertEqual(store.all().map(\.target), ["b"])
    }
}
