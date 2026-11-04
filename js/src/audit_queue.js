/**
 * In queue mode (the default) emit() puts rows on an in-memory queue and
 * this drainer writes them to the store, retrying with exponential backoff
 * (100 ms to 60 s, 20% jitter), so store failures don't reach the caller.
 *
 * Unlike Python and Go, emit() can't block when the queue is full, so
 * `queueCapacity` only sets the warning thresholds: `audit_queue_high_water`
 * at 50% and `audit_queue_near_full` at 80%.
 */

const HW_WARN_PCT = 0.5;
const HW_ERR_PCT = 0.8;
const DEGRADED_AFTER = 5;

export class AuditStoreError extends Error {
	constructor(cause) {
		super(`fasten audit store: ${cause?.message ?? cause}`);
		this.name = "AuditStoreError";
		this.cause = cause;
	}
}

class AuditQueueDrainer {
	constructor({
		store,
		sysLog,
		capacity,
		retryInitialMs,
		retryMaxMs,
		retryJitter,
		maxAttempts = 50,
	}) {
		this._store = store;
		this._sysLog = sysLog;
		this._capacity = capacity;
		this._retryInitialMs = retryInitialMs;
		this._retryMaxMs = retryMaxMs;
		this._retryJitter = retryJitter;
		this._maxAttempts = maxAttempts;

		this._q = [];
		this._inFlight = 0; // row popped but insert not yet resolved
		this._current = null; // that row, until stop() gives up on it
		this._stopped = false;

		// Stats
		this._highWater = 0;
		this._drainedTotal = 0;
		this._retryCount = 0;
		this._inBackoffUntilMs = 0;
		this._lastError = null;
		this._failureBurstStartedAt = null;
		this._deadLetteredTotal = 0;
		this._dlq = []; // bounded ring, max 10 entries
		this._lostTotal = 0; // rows not stored at stop (audit_drain_lost_at_stop)

		// Threshold debouncing
		this._warnHWFired = false;
		this._errHWFired = false;
		this._degradedFired = false;

		// Kick the drainer loop. stop() resolves when it has finished.
		this._done = new Promise((resolve) => {
			setImmediate(() => this._tick().then(resolve));
		});
	}

	put(row) {
		// After stop() nothing drains the queue, so log the row as abandoned
		// instead of queueing it.
		if (this._stopped) {
			this._sysLog("error", "audit_drain_abandoned", {
				reason: "drainer_stopped",
				row_id: row?.id ?? null,
			});
			return;
		}
		this._q.push(row);
		const used = this._q.length + this._inFlight;
		if (used > this._highWater) this._highWater = used;
		if (this._capacity > 0) {
			const pct = used / this._capacity;
			if (pct >= HW_ERR_PCT && !this._errHWFired) {
				this._errHWFired = true;
				this._sysLog("error", "audit_queue_near_full", {
					depth: used,
					capacity: this._capacity,
				});
			} else if (pct >= HW_WARN_PCT && !this._warnHWFired) {
				this._warnHWFired = true;
				this._sysLog("warn", "audit_queue_high_water", {
					depth: used,
					capacity: this._capacity,
				});
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
			dead_lettered_total: this._deadLetteredTotal,
			dead_letter_depth: this._dlq.length,
			capacity_semantics: "warn_only",
		};
	}

	async flush(timeoutMs = 5000) {
		// Wait only for rows queued before this call (spec §6), so new rows
		// can't keep flush() waiting forever. A dead-lettered or lost row
		// counts as done.
		const done = () =>
			this._drainedTotal + this._deadLetteredTotal + this._lostTotal;
		const target = done() + this._q.length + this._inFlight;
		if (done() >= target) return true;
		const deadline = Date.now() + timeoutMs;
		while (Date.now() < deadline) {
			if (done() >= target) return true;
			await new Promise((r) => setTimeout(r, 10));
		}
		return done() >= target;
	}

	// Spec §10: rows still queued get one attempt each. A row that fails it,
	// or is still unstored after timeoutMs, is reported lost
	// (audit_drain_lost_at_stop). Resolves false if a row was lost.
	stop(timeoutMs = 5000) {
		this._stopped = true;
		const lost = this._lostTotal;
		let timer;
		const timeout = new Promise((r) => {
			timer = setTimeout(() => {
				this._loseUnstored();
				r(false);
			}, timeoutMs);
		});
		return Promise.race([
			this._done.then(() => this._lostTotal === lost),
			timeout,
		]).finally(() => clearTimeout(timer));
	}

	async _tick() {
		while (!this._stopped || this._q.length > 0) {
			if (this._q.length === 0) {
				await new Promise((r) => setImmediate(r));
				continue;
			}
			const row = this._q.shift();
			this._inFlight++;
			this._current = row;
			try {
				await this._drainOne(row);
			} finally {
				this._inFlight--;
				this._current = null;
			}
		}
	}

	async _drainOne(row) {
		let attempt = 0;
		for (;;) {
			attempt++;
			try {
				await this._store.insert(row);
				this._onSuccess();
				return;
			} catch (err) {
				if (this._stopped) {
					// stop() may have reported it already, on timeout.
					if (this._current === row) this._onLostAtStop(row, err);
					return;
				}
				if (attempt >= this._maxAttempts) {
					this._onDeadLetter(row, attempt, err);
					return;
				}
				this._onFailure(err);
				// A stop cuts the wait short; the next pass is the row's last.
				await this._waitBackoff();
			}
		}
	}

	_onDeadLetter(row, attempt, err) {
		const msg = `${err?.name ?? "Error"}: ${err?.message ?? err}`;
		this._deadLetteredTotal++;
		this._retryCount = 0;
		this._inBackoffUntilMs = 0;
		this._lastError = msg;
		if (this._dlq.length >= 10) this._dlq.shift();
		this._dlq.push(row);
		this._sysLog("error", "audit_drain_dead_letter", {
			row_id: row?.id ?? null,
			attempt_count: attempt,
			last_error: msg,
		});
	}

	_onLostAtStop(row, err) {
		this._lostTotal++;
		this._sysLog("error", "audit_drain_lost_at_stop", {
			error_type: err?.name ?? "Error",
			row_id: row?.id ?? null,
		});
	}

	// stop() timed out: what is still queued or in flight is reported lost
	// now, since the process may exit before it is tried.
	_loseUnstored() {
		const timedOut = { name: "TimeoutError" };
		if (this._current) {
			this._onLostAtStop(this._current, timedOut);
			this._current = null;
		}
		for (const row of this._q.splice(0)) this._onLostAtStop(row, timedOut);
	}

	_onFailure(err) {
		const msg = `${err?.name ?? "Error"}: ${err?.message ?? err}`;
		const first = this._retryCount === 0;
		if (first) this._failureBurstStartedAt = Date.now();
		this._retryCount++;
		this._lastError = msg;
		const crossedDegraded =
			this._retryCount >= DEGRADED_AFTER && !this._degradedFired;
		if (crossedDegraded) this._degradedFired = true;
		// Set before the degraded event so it reports this retry's wait.
		this._inBackoffUntilMs = Date.now() + this._backoffMs();

		if (first) {
			this._sysLog("warn", "audit_drain_failed", { error: msg });
		}
		if (crossedDegraded) {
			const remMs = this._inBackoffUntilMs - Date.now();
			this._sysLog("error", "audit_drain_degraded", {
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
			this._sysLog("info", "audit_drain_recovered", {
				recovery_after_seconds: Math.round(recoveredAfter * 1000) / 1000,
			});
		}
	}

	_backoffMs() {
		const n = this._retryCount;
		let delay = this._retryInitialMs * 2 ** Math.max(0, n - 1);
		if (delay > this._retryMaxMs) delay = this._retryMaxMs;
		if (this._retryJitter) {
			const j = delay * 0.2;
			delay += (Math.random() * 2 - 1) * j;
			if (delay < 0) delay = 0;
		}
		return delay;
	}

	// Sleeps until _inBackoffUntilMs, checking _stopped so shutdown is prompt.
	async _waitBackoff() {
		const end = this._inBackoffUntilMs;
		while (Date.now() < end && !this._stopped) {
			await new Promise((r) => setTimeout(r, Math.min(50, end - Date.now())));
		}
	}
}

// Module-level helpers that act on the default Engine (set by index.js).

export { AuditQueueDrainer };

let _defaultEngine = null;
export function _setDefaultEngine(engine) {
	_defaultEngine = engine;
}

export function installDrainer(opts) {
	_defaultEngine?._installDrainer(opts);
	return _defaultEngine?._drainer ?? null;
}

export function uninstallDrainer(timeoutMs) {
	return _defaultEngine?._uninstallDrainer(timeoutMs) ?? Promise.resolve(true);
}

export function activeDrainer() {
	return _defaultEngine?._drainer ?? null;
}

export function queueStats() {
	return _defaultEngine?.queueStats() ?? null;
}

export async function flush(timeoutMs = 5000) {
	return _defaultEngine ? _defaultEngine.flush(timeoutMs) : true;
}
