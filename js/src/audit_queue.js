/**
 * P1-15: bounded audit queue + background drainer for Node.
 *
 * When `init({ auditStoreFailureStrategy: 'queue' })` is set (the v1.0
 * default), `emit()` pushes audit rows onto an in-memory queue and a
 * setImmediate-driven drainer writes them to the store with
 * exponential backoff (100 ms → 60 s, ±20 % jitter). Store failures
 * stay off the request path.
 *
 * **Cross-language deviation.** Node is single-threaded; emit() cannot
 * synchronously block on a counting semaphore the way Python / Go can.
 * `queueCapacity` is therefore the *high-water signal* threshold, not
 * a hard cap — emit() stays synchronous. The drainer issues
 * `audit_queue_high_water` (≥ 50 %) and `audit_queue_near_full`
 * (≥ 80 %) sys lines so adopters see the saturation through the same
 * channel they already monitor. `audit_drain_*` events match Python
 * exactly.
 */

const HW_WARN_PCT = 0.50;
const HW_ERR_PCT = 0.80;
const DEGRADED_AFTER = 5;

export class AuditStoreError extends Error {
    constructor(cause) {
        super(`fasten audit store: ${cause?.message ?? cause}`);
        this.name = 'AuditStoreError';
        this.cause = cause;
    }
}

class AuditQueueDrainer {
    constructor({ store, sysLog, capacity, retryInitialMs, retryMaxMs, retryJitter }) {
        this._store = store;
        this._sysLog = sysLog;
        this._capacity = capacity;
        this._retryInitialMs = retryInitialMs;
        this._retryMaxMs = retryMaxMs;
        this._retryJitter = retryJitter;

        this._q = [];
        this._inFlight = 0;       // row popped but insert not yet resolved
        this._stopped = false;

        // Stats
        this._highWater = 0;
        this._drainedTotal = 0;
        this._retryCount = 0;
        this._inBackoffUntilMs = 0;
        this._lastError = null;
        this._failureBurstStartedAt = null;

        // Threshold debouncing
        this._warnHWFired = false;
        this._errHWFired = false;
        this._degradedFired = false;

        // Kick the drainer loop.
        setImmediate(() => this._tick());
    }

    put(row) {
        this._q.push(row);
        const used = this._q.length + this._inFlight;
        if (used > this._highWater) this._highWater = used;
        if (this._capacity > 0) {
            const pct = used / this._capacity;
            if (pct >= HW_ERR_PCT && !this._errHWFired) {
                this._errHWFired = true;
                this._sysLog('error', 'audit_queue_near_full',
                    { depth: used, capacity: this._capacity });
            } else if (pct >= HW_WARN_PCT && !this._warnHWFired) {
                this._warnHWFired = true;
                this._sysLog('warn', 'audit_queue_high_water',
                    { depth: used, capacity: this._capacity });
            } else if (pct < HW_WARN_PCT) {
                this._warnHWFired = false;
                this._errHWFired = false;
            }
        }
    }

    stats() {
        const remMs = this._inBackoffUntilMs - Date.now();
        return {
            depth: this._q.length + this._inFlight,
            capacity: this._capacity,
            high_water: this._highWater,
            drained_total: this._drainedTotal,
            retry_count_active: this._retryCount,
            in_backoff_seconds: remMs > 0 ? Math.round(remMs) / 1000 : 0,
            last_error: this._lastError,
        };
    }

    async flush(timeoutMs = 5000) {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            if (this._q.length === 0 && this._retryCount === 0 && this._inFlight === 0) {
                return true;
            }
            await new Promise(r => setTimeout(r, 10));
        }
        return this._q.length === 0 && this._inFlight === 0;
    }

    stop() {
        this._stopped = true;
    }

    async _tick() {
        while (!this._stopped) {
            if (this._q.length === 0) {
                await new Promise(r => setImmediate(r));
                continue;
            }
            const row = this._q.shift();
            this._inFlight++;
            try {
                await this._drainOne(row);
            } finally {
                this._inFlight--;
            }
        }
    }

    async _drainOne(row) {
        for (;;) {
            try {
                await this._store.insert(row);
                this._onSuccess();
                return;
            } catch (err) {
                this._onFailure(err);
                if (this._stopped) return;
                const cont = await this._waitBackoff();
                if (!cont) return;
            }
        }
    }

    _onFailure(err) {
        const msg = `${err?.name ?? 'Error'}: ${err?.message ?? err}`;
        const first = this._retryCount === 0;
        if (first) this._failureBurstStartedAt = Date.now();
        this._retryCount++;
        this._lastError = msg;
        const crossedDegraded =
            this._retryCount >= DEGRADED_AFTER && !this._degradedFired;
        if (crossedDegraded) this._degradedFired = true;

        if (first) {
            this._sysLog('warn', 'audit_drain_failed', { error: msg });
        }
        if (crossedDegraded) {
            const remMs = this._inBackoffUntilMs - Date.now();
            this._sysLog('error', 'audit_drain_degraded', {
                retry_count: this._retryCount,
                in_backoff_seconds: remMs > 0 ? Math.round(remMs) / 1000 : 0,
                last_error: msg,
            });
        }
    }

    _onSuccess() {
        let recoveredAfter = null;
        if (this._retryCount > 0 && this._failureBurstStartedAt !== null) {
            recoveredAfter = (Date.now() - this._failureBurstStartedAt) / 1000;
        }
        this._retryCount = 0;
        this._inBackoffUntilMs = 0;
        this._failureBurstStartedAt = null;
        this._lastError = null;
        this._degradedFired = false;
        this._drainedTotal++;
        if (recoveredAfter !== null) {
            this._sysLog('info', 'audit_drain_recovered',
                { recovery_after_seconds: Math.round(recoveredAfter * 1000) / 1000 });
        }
    }

    async _waitBackoff() {
        const n = this._retryCount;
        let delay = this._retryInitialMs * Math.pow(2, Math.max(0, n - 1));
        if (delay > this._retryMaxMs) delay = this._retryMaxMs;
        if (this._retryJitter) {
            const j = delay * 0.2;
            delay += (Math.random() * 2 - 1) * j;
            if (delay < 0) delay = 0;
        }
        this._inBackoffUntilMs = Date.now() + delay;
        // Sleep, but check _stopped frequently so shutdown is prompt.
        const stepMs = Math.min(delay, 50);
        const end = Date.now() + delay;
        while (Date.now() < end) {
            if (this._stopped) return false;
            await new Promise(r => setTimeout(r, Math.min(stepMs, end - Date.now())));
        }
        return !this._stopped;
    }
}

// ── Module-level singleton ─────────────────────────────────────────────────

let _drainer = null;

export function installDrainer({
    store, sysLog, capacity = 100,
    retryInitialMs = 100, retryMaxMs = 60_000, retryJitter = true,
}) {
    if (_drainer) {
        // Best-effort flush before swap so re-init doesn't lose rows.
        const old = _drainer;
        _drainer = null;
        old.flush(5000).then(() => old.stop());
    }
    _drainer = new AuditQueueDrainer({
        store, sysLog, capacity,
        retryInitialMs, retryMaxMs, retryJitter,
    });
    return _drainer;
}

export function uninstallDrainer() {
    if (_drainer) {
        _drainer.stop();
        _drainer = null;
    }
}

export function activeDrainer() { return _drainer; }

/**
 * queueStats — snapshot of queue + drainer state. Returns null in raise
 * mode (no drainer running).
 */
export function queueStats() {
    return _drainer ? _drainer.stats() : null;
}

/**
 * flush — block (await) until pending audit rows drain or timeout.
 * Returns true iff drained. No-op + true in raise mode.
 */
export async function flush(timeoutMs = 5000) {
    if (!_drainer) return true;
    return _drainer.flush(timeoutMs);
}
