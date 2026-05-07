import Foundation

/// Bounded in-memory queue + background drainer with exponential backoff.
/// Mirrors drainer-conformance.md — same state machine as Python/Go/JS/Rust/C++.
public enum FailureStrategy { case queue, raise }

final class AuditQueue: @unchecked Sendable {

    typealias Strategy = FailureStrategy

    private let store:       AuditStore
    private let transport:   StdoutTransport
    private let capacity:    Int
    private let strategy:    Strategy

    private var rows:        [AuditRow] = []
    private var draining     = false
    private let lock         = Lock()
    private let workSignal   = DispatchSemaphore(value: 0)
    private var stopped      = false

    // Drainer state
    private var backoffMs:   Int = 100
    private static let maxBackoffMs = 60_000
    private var retryCount   = 0
    private var totalDrained = 0
    private var highWater    = 0

    init(store: AuditStore, transport: StdoutTransport,
         capacity: Int = 500, strategy: Strategy = .queue) {
        self.store     = store
        self.transport = transport
        self.capacity  = capacity
        self.strategy  = strategy

        let t = Thread { [self] in self._drainLoop() }
        t.name = "fasten.drainer"
        t.start()
    }

    func enqueue(_ row: AuditRow) throws {
        switch strategy {
        case .raise:
            try store.insert(row)
            transport.emit(row)
        case .queue:
            lock.withLock {
                if rows.count >= capacity {
                    // Near-full sys warning (logged inline to avoid recursion).
                    transport.log(level: "warn", event: "audit_queue_near_full",
                                  serviceID: nil, nodeID: nil, requestID: nil, fields: [:])
                } else {
                    rows.append(row)
                    if rows.count > highWater { highWater = rows.count }
                }
            }
            workSignal.signal()
        }
    }

    func flush(timeout: TimeInterval) -> Bool {
        guard strategy == .queue else { return true }
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let empty = lock.withLock { rows.isEmpty && !draining }
            if empty { return true }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return lock.withLock { rows.isEmpty && !draining }
    }

    func stop() {
        lock.withLock { stopped = true }
        workSignal.signal()
    }

    private func _drainLoop() {
        while true {
            workSignal.wait()
            if lock.withLock({ stopped }) { return }
            _drainBatch()
        }
    }

    private func _drainBatch() {
        while true {
            let row: AuditRow? = lock.withLock {
                draining = !rows.isEmpty
                return rows.first
            }
            guard let row else {
                lock.withLock { draining = false }
                backoffMs = 100
                retryCount = 0
                return
            }
            do {
                try store.insert(row)
                transport.emit(row)
                lock.withLock {
                    if !rows.isEmpty { rows.removeFirst() }
                    totalDrained += 1
                }
                if retryCount > 0 {
                    transport.log(level: "info", event: "audit_drain_recovered",
                                  serviceID: nil, nodeID: nil, requestID: nil,
                                  fields: ["retry_count": retryCount])
                }
                backoffMs = 100
                retryCount = 0
            } catch {
                retryCount += 1
                transport.log(level: "warn", event: "audit_drain_failed",
                              serviceID: nil, nodeID: nil, requestID: nil,
                              fields: ["error": "\(error)", "retry": retryCount])
                let jitter = Int.random(in: -backoffMs/5 ... backoffMs/5)
                Thread.sleep(forTimeInterval: Double(backoffMs + jitter) / 1000)
                backoffMs = min(backoffMs * 2, Self.maxBackoffMs)
                return
            }
        }
    }
}
