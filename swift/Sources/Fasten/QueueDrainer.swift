import Foundation

/// How emit() writes to the store: `.queue` hands rows to a background
/// QueueDrainer, `.raise` inserts inline and rethrows store errors.
public enum FailureStrategy { case queue, raise }

private let DEGRADED_AFTER = 5

/// "<Type>: <message>", the error format of the drainer's sys events.
func describeError(_ error: Error) -> String {
    "\(type(of: error)): \(error.localizedDescription)"
}

private func round3(_ x: Double) -> Double { (x * 1000).rounded() / 1000 }

/// Bounded queue plus a background thread that writes rows to the store,
/// retrying with exponential backoff (spec/drainer-conformance.md).
///
/// When capacity > 0, `enqueue()` blocks while the queue is full, like the
/// Python, Go and C++ drainers ("block" capacity_semantics). Sys events go
/// to `sysLog(level, event, fields)`.
final class QueueDrainer: @unchecked Sendable {

    let store:                  any AuditStore
    private let capacity:       Int
    private let retryInitialMs: Double
    private let retryMaxMs:     Double
    private let retryJitter:    Bool
    private let maxAttempts:    Int
    private let sysLog:         (String, String, [String: Any]) -> Void

    private var q:                    [AuditRow] = []
    private var inFlight:             Int    = 0
    private var current:              AuditRow? = nil
    private var drainedTotal:         Int    = 0
    private var retryCount:           Int    = 0
    private var highWater:            Int    = 0
    private var deadLetteredTotal:    Int    = 0
    private var lostTotal:            Int    = 0
    private var dlq:                  [AuditRow] = []   // ring max 10
    private var stopped:              Bool   = false
    private var finished:             Bool   = false
    private var lastError:            String? = nil
    private var failureBurstStart:    Date?  = nil
    private var inBackoffUntil:       Date   = .distantPast
    private var degradedFired:        Bool   = false
    private var highWaterFired:       Bool   = false
    private var nearFullFired:        Bool   = false

    private let cond = NSCondition()
    private var drainThread: Thread?

    init(
        store:          any AuditStore,
        capacity:       Int    = 500,
        retryInitialMs: Double = 100,
        retryMaxMs:     Double = 60_000,
        retryJitter:    Bool   = true,
        maxAttempts:    Int    = 50,
        sysLog: @escaping (String, String, [String: Any]) -> Void = { _, _, _ in }
    ) {
        self.store          = store
        self.capacity       = capacity
        self.retryInitialMs = retryInitialMs
        self.retryMaxMs     = retryMaxMs
        self.retryJitter    = retryJitter
        self.maxAttempts    = maxAttempts
        self.sysLog         = sysLog
        let t = Thread { [unowned self] in self._run() }
        drainThread = t
        t.start()
    }

    /// Queues the row. Returns false, after logging audit_drain_abandoned,
    /// when the drainer has stopped; the caller then stores the row itself.
    @discardableResult
    func enqueue(_ row: AuditRow) -> Bool {
        cond.lock()
        while capacity > 0 && (q.count + inFlight) >= capacity && !stopped {
            cond.wait(until: Date().addingTimeInterval(0.05))
        }
        if stopped {
            cond.unlock()
            sysLog("error", "audit_drain_abandoned", ["reason": "drainer_stopped", "row_id": row.id])
            return false
        }
        q.append(row)
        let used = q.count + inFlight
        if used > highWater { highWater = used }
        _rearmLocked()
        var crossed: [(String, String)] = []
        if capacity > 0 {
            let ratio = Double(used) / Double(capacity)
            if ratio >= 0.5 && !highWaterFired {
                highWaterFired = true
                crossed.append(("warn", "audit_queue_high_water"))
            }
            if ratio >= 0.8 && !nearFullFired {
                nearFullFired = true
                crossed.append(("error", "audit_queue_near_full"))
            }
        }
        cond.signal()
        cond.unlock()
        for (level, event) in crossed {
            sysLog(level, event, ["depth": used, "capacity": capacity])
        }
        return true
    }

    /// Waits for the rows pending at call time to be stored, dead-lettered
    /// or lost at stop (spec §6), so new rows can't keep it waiting forever.
    @discardableResult
    func flush(timeout: TimeInterval) -> Bool {
        cond.lock()
        let target = _settledLocked + q.count + inFlight
        cond.unlock()

        let deadline = Date().addingTimeInterval(timeout)
        while true {
            cond.lock()
            let done = _settledLocked >= target
            cond.unlock()
            if done { return true }
            if Date() >= deadline { return false }
            Thread.sleep(forTimeInterval: 0.01)
        }
    }

    /// Stops the drainer (spec §10): queued rows get one insert attempt each,
    /// and an insert in progress is waited for, up to `timeout`. Rows not
    /// stored are reported with audit_drain_lost_at_stop and close returns
    /// false.
    @discardableResult
    func close(timeout: TimeInterval = 5.0) -> Bool {
        cond.lock()
        let lostBefore = lostTotal
        stopped = true
        cond.broadcast()
        let deadline = Date().addingTimeInterval(timeout)
        while !finished && Date() < deadline {
            cond.wait(until: min(deadline, Date().addingTimeInterval(0.05)))
        }
        var lost: [AuditRow] = []
        if !finished {
            if let c = current { lost.append(c) }
            current = nil
            lost += q
            q.removeAll()
            lostTotal += lost.count
            _rearmLocked()
        }
        let ok = lostTotal == lostBefore
        cond.unlock()
        for row in lost {
            sysLog("error", "audit_drain_lost_at_stop", ["error_type": "TimeoutError", "row_id": row.id])
        }
        return ok
    }

    /// Rows dead-lettered or lost at stop.
    var unstoredTotal: Int {
        cond.lock()
        defer { cond.unlock() }
        return deadLetteredTotal + lostTotal
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

    private var _settledLocked: Int { drainedTotal + deadLetteredTotal + lostTotal }

    // Both threshold flags re-arm once depth is below 50 %.
    private func _rearmLocked() {
        if capacity > 0 && Double(q.count + inFlight) / Double(capacity) < 0.5 {
            highWaterFired = false
            nearFullFired  = false
        }
    }

    private func _run() {
        while true {
            cond.lock()
            while q.isEmpty && !stopped {
                cond.wait(until: Date().addingTimeInterval(0.05))
            }
            if stopped && q.isEmpty {
                finished = true
                cond.broadcast()
                cond.unlock()
                break
            }
            if q.isEmpty            { cond.unlock(); continue }
            let row = q.removeFirst()
            inFlight += 1
            current = row
            cond.broadcast()    // wake enqueue() callers waiting for space
            cond.unlock()

            _drainOne(row)

            cond.lock()
            inFlight -= 1
            if current?.id == row.id { current = nil }
            _rearmLocked()
            cond.broadcast()
            cond.unlock()
        }
    }

    private func _drainOne(_ row: AuditRow) {
        var attempt = 0
        while true {
            attempt += 1
            do {
                try store.insert(row)
                _onSuccess(row)
                return
            } catch {
                cond.lock()
                let isStopped = stopped
                cond.unlock()
                // After a stop each row gets this one attempt (spec §10).
                if isStopped { _onLostAtStop(row, error); return }
                let msg = describeError(error)
                if attempt >= maxAttempts {
                    _onDeadLetter(row, attempt: attempt, error: msg)
                    return
                }
                _onFailure(msg)
                _waitBackoff()
            }
        }
    }

    private func _onSuccess(_ row: AuditRow) {
        cond.lock()
        if current?.id == row.id { current = nil }
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
            sysLog("info", "audit_drain_recovered",
                   ["recovery_after_seconds": round3(Date().timeIntervalSince(s))])
        }
    }

    private func _onFailure(_ msg: String) {
        cond.lock()
        let isFirst = retryCount == 0
        if isFirst { failureBurstStart = Date() }
        retryCount += 1
        lastError   = msg
        let delayMs = _backoffMs(retryCount)
        inBackoffUntil = Date().addingTimeInterval(delayMs / 1000.0)
        let crossedDegraded = retryCount >= DEGRADED_AFTER && !degradedFired
        if crossedDegraded { degradedFired = true }
        let rc = retryCount
        cond.unlock()
        if isFirst {
            sysLog("warn", "audit_drain_failed", ["error": msg])
        }
        if crossedDegraded {
            sysLog("error", "audit_drain_degraded", [
                "retry_count": rc,
                "in_backoff_seconds": round3(delayMs / 1000.0),
                "last_error": msg,
            ])
        }
    }

    private func _onDeadLetter(_ row: AuditRow, attempt: Int, error: String) {
        cond.lock()
        if current?.id == row.id { current = nil }
        deadLetteredTotal += 1
        retryCount         = 0
        inBackoffUntil     = .distantPast
        lastError          = error
        if dlq.count >= 10 { dlq.removeFirst() }
        dlq.append(row)
        cond.broadcast()
        cond.unlock()
        sysLog("error", "audit_drain_dead_letter",
               ["row_id": row.id, "attempt_count": attempt, "last_error": error])
    }

    private func _onLostAtStop(_ row: AuditRow, _ error: Error) {
        cond.lock()
        // close() may have reported it already, on timeout.
        let report = current?.id == row.id
        if report {
            current = nil
            lostTotal += 1
            cond.broadcast()
        }
        cond.unlock()
        if report {
            sysLog("error", "audit_drain_lost_at_stop",
                   ["error_type": "\(type(of: error))", "row_id": row.id])
        }
    }

    // Spec §8, with n = retry_count.
    private func _backoffMs(_ n: Int) -> Double {
        var delay = retryInitialMs * pow(2.0, Double(max(0, n - 1)))
        if delay > retryMaxMs { delay = retryMaxMs }
        if retryJitter {
            let j = delay * 0.2
            delay += Double.random(in: -j...j)
            if delay < 0 { delay = 0 }
        }
        return delay
    }

    // A stop cuts the wait short; the next attempt is the row's last.
    private func _waitBackoff() {
        cond.lock()
        while !stopped && Date() < inBackoffUntil {
            cond.wait(until: inBackoffUntil)
        }
        cond.unlock()
    }
}
