import Foundation

private let DEGRADED_AFTER = 5

/// Pure Swift bounded-queue drainer — spec-conformant (drainer-conformance.md v1.1).
///
/// `enqueue()` blocks the caller when depth ≥ capacity (capacity > 0), matching
/// the `"block"` capacity_semantics used by Python / Go / C++.
final class QueueDrainer: @unchecked Sendable {

    private let store:          any AuditStore
    private let capacity:       Int
    private let retryInitialMs: Double
    private let retryMaxMs:     Double
    private let retryJitter:    Bool
    private let maxAttempts:    Int

    private var q:                    [AuditRow] = []
    private var inFlight:             Int    = 0
    private var drainedTotal:         Int    = 0
    private var retryCount:           Int    = 0
    private var highWater:            Int    = 0
    private var deadLetteredTotal:    Int    = 0
    private var dlq:                  [AuditRow] = []   // ring max 10
    private var stopped:              Bool   = false
    private var lastError:            String? = nil
    private var failureBurstStart:    Date?  = nil
    private var inBackoffUntil:       Date   = .distantPast
    private var degradedFired:        Bool   = false

    private let cond = NSCondition()
    private var drainThread: Thread?

    init(
        store:          any AuditStore,
        capacity:       Int    = 500,
        retryInitialMs: Double = 100,
        retryMaxMs:     Double = 60_000,
        retryJitter:    Bool   = true,
        maxAttempts:    Int    = 50
    ) {
        self.store          = store
        self.capacity       = capacity
        self.retryInitialMs = retryInitialMs
        self.retryMaxMs     = retryMaxMs
        self.retryJitter    = retryJitter
        self.maxAttempts    = maxAttempts
        let t = Thread { [unowned self] in self._run() }
        drainThread = t
        t.start()
    }

    func enqueue(_ row: AuditRow) {
        cond.lock()
        // Block until space is available (capacity > 0 semantics = "block")
        while capacity > 0 && (q.count + inFlight) >= capacity && !stopped {
            cond.wait(until: Date().addingTimeInterval(0.05))
        }
        if stopped { cond.unlock(); return }
        q.append(row)
        let used = q.count + inFlight
        if used > highWater { highWater = used }
        cond.signal()
        cond.unlock()
    }

    @discardableResult
    func flush(timeout: TimeInterval) -> Bool {
        // Snapshot semantics §6: target locked at call time
        cond.lock()
        let target = drainedTotal + q.count + inFlight
        let alreadyDone = drainedTotal >= target
        cond.unlock()
        if alreadyDone { return true }

        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
            cond.lock()
            let done = drainedTotal >= target
            cond.unlock()
            if done { return true }
        }
        cond.lock()
        let done = drainedTotal >= target
        cond.unlock()
        return done
    }

    func close() {
        cond.lock()
        stopped = true
        cond.broadcast()
        cond.unlock()
    }

    var statsJSON: String {
        cond.lock()
        let depth  = q.count + inFlight
        let hw     = highWater
        let dt     = drainedTotal
        let rc     = retryCount
        let dl     = deadLetteredTotal
        let dld    = dlq.count
        let remMs  = inBackoffUntil.timeIntervalSinceNow
        let backS  = remMs > 0 ? remMs : 0.0
        let le     = lastError
        cond.unlock()

        var s  = "{"
        s += "\"depth\":\(depth),"
        s += "\"capacity\":\(capacity),"
        s += "\"high_water\":\(hw),"
        s += "\"drained_total\":\(dt),"
        s += "\"retry_count_active\":\(rc),"
        s += "\"in_backoff_seconds\":\(String(format: "%.3f", backS)),"
        if let err = le {
            let esc = err.replacingOccurrences(of: "\\", with: "\\\\")
                        .replacingOccurrences(of: "\"", with: "\\\"")
            s += "\"last_error\":\"\(esc)\","
        } else {
            s += "\"last_error\":null,"
        }
        s += "\"dead_lettered_total\":\(dl),"
        s += "\"dead_letter_depth\":\(dld),"
        s += "\"capacity_semantics\":\"block\""
        s += "}"
        return s
    }

    deinit { close() }

    private func _run() {
        while true {
            cond.lock()
            while q.isEmpty && !stopped {
                cond.wait(until: Date().addingTimeInterval(0.05))
            }
            if stopped && q.isEmpty { cond.unlock(); break }
            if q.isEmpty            { cond.unlock(); continue }
            let row = q.removeFirst()
            inFlight += 1
            cond.broadcast()    // signal enqueue() that space freed
            cond.unlock()

            _drainOne(row)

            cond.lock()
            inFlight -= 1
            cond.broadcast()
            cond.unlock()
        }
    }

    private func _drainOne(_ row: AuditRow) {
        for attempt in 1...maxAttempts {
            do {
                try store.insert(row)
                _onSuccess()
                return
            } catch {
                let msg = error.localizedDescription
                cond.lock()
                let isStopped = stopped
                cond.unlock()
                if isStopped { return }
                _onFailure(msg, attempt: attempt)
                if attempt == maxAttempts {
                    _onDeadLetter(row, attempt: attempt, error: msg)
                    return
                }
                _waitBackoff(attempt: attempt)
                cond.lock()
                let stillStopped = stopped
                cond.unlock()
                if stillStopped { return }
            }
        }
    }

    private func _onSuccess() {
        cond.lock()
        let wasRetrying = retryCount > 0
        let burstStart  = failureBurstStart
        retryCount      = 0
        inBackoffUntil  = .distantPast
        failureBurstStart = nil
        lastError       = nil
        degradedFired   = false
        drainedTotal   += 1
        cond.broadcast()
        cond.unlock()
        if wasRetrying, let s = burstStart {
            let _ = Date().timeIntervalSince(s)
        }
    }

    private func _onFailure(_ msg: String, attempt: Int) {
        cond.lock()
        let isFirst = retryCount == 0
        if isFirst { failureBurstStart = Date() }
        retryCount += 1
        lastError   = msg
        let crossedDegraded = retryCount >= DEGRADED_AFTER && !degradedFired
        if crossedDegraded { degradedFired = true }
        cond.unlock()
    }

    private func _onDeadLetter(_ row: AuditRow, attempt: Int, error: String) {
        cond.lock()
        deadLetteredTotal += 1
        retryCount         = 0
        lastError          = error
        if dlq.count >= 10 { dlq.removeFirst() }
        dlq.append(row)
        cond.unlock()
    }

    private func _waitBackoff(attempt: Int) {
        var delay = retryInitialMs * pow(2.0, Double(max(0, attempt - 1)))
        if delay > retryMaxMs { delay = retryMaxMs }
        if retryJitter {
            let j = delay * 0.2
            delay += Double.random(in: -j...j)
            if delay < 0 { delay = 0 }
        }
        let until = Date().addingTimeInterval(delay / 1000.0)
        cond.lock()
        inBackoffUntil = until
        cond.unlock()

        let stepMs = min(delay, 50.0)
        var now = Date()
        while now < until {
            cond.lock()
            let s = stopped
            cond.unlock()
            if s { return }
            Thread.sleep(forTimeInterval: stepMs / 1000.0)
            now = Date()
        }
    }
}
