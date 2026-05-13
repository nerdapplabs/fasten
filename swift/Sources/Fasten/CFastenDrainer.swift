import Foundation
import CFastenCore

public enum FailureStrategy { case queue, raise }

// ── StoreRef: keeps an AuditStore alive through the C ABI boundary ────────────

private final class StoreRef {
    let store: any AuditStore
    init(_ store: any AuditStore) { self.store = store }
}

// ── C-callable bridge: no captures → satisfies FastenInsertCallbackFn ─────────

private func fastenInsertBridge(
    _ rowJSON: UnsafePointer<CChar>?,
    _ userdata: UnsafeMutableRawPointer?
) -> Int32 {
    guard let rowJSON, let userdata else { return 1 }
    let ref = Unmanaged<StoreRef>.fromOpaque(userdata).takeUnretainedValue()
    let jsonStr = String(cString: rowJSON)
    guard let data = jsonStr.data(using: .utf8),
          let row = try? JSONDecoder().decode(AuditRow.self, from: data) else { return 1 }
    do {
        try ref.store.insert(row)
        return 0
    } catch {
        return 1
    }
}

// ── CFastenDrainer: wraps the shared fasten-core C ABI drainer ────────────────

final class CFastenDrainer: @unchecked Sendable {

    private let storeHandle: OpaquePointer
    private let storeRef:    Unmanaged<StoreRef>
    private var isClosed     = false
    private let closeLock    = Lock()

    init(
        store:          any AuditStore,
        capacity:       UInt64,
        retryInitialMs: UInt64,
        retryMaxMs:     UInt64,
        retryJitter:    Bool,
        maxAttempts:    UInt32
    ) throws {
        let ref       = StoreRef(store)
        let unmanaged = Unmanaged.passRetained(ref)

        var errStr: UnsafeMutablePointer<CChar>? = nil
        guard let ptr = fasten_store_from_callback(
            fastenInsertBridge,
            unmanaged.toOpaque(),
            &errStr
        ) else {
            unmanaged.release()
            var msg = "fasten_store_from_callback failed"
            if let e = errStr { msg = String(cString: e); fasten_store_free_str(e) }
            throw CFastenError(msg)
        }

        let jitter: Int32 = retryJitter ? 1 : 0
        let rc = fasten_drainer_install(
            ptr, capacity, retryInitialMs, retryMaxMs, jitter, maxAttempts, &errStr
        )
        guard rc == 0 else {
            var msg = "fasten_drainer_install failed"
            if let e = errStr { msg = String(cString: e); fasten_store_free_str(e) }
            fasten_store_close(ptr)
            unmanaged.release()
            throw CFastenError(msg)
        }

        self.storeHandle = ptr
        self.storeRef    = unmanaged
    }

    func enqueue(_ row: AuditRow) {
        guard let data = try? JSONEncoder().encode(row),
              let jsonStr = String(data: data, encoding: .utf8) else { return }
        jsonStr.withCString { cs in
            var errStr: UnsafeMutablePointer<CChar>? = nil
            fasten_drainer_enqueue(storeHandle, cs, &errStr)
            if let e = errStr { fasten_store_free_str(e) }
        }
    }

    @discardableResult
    func flush(timeout: TimeInterval) -> Bool {
        let ms = UInt64(max(0, timeout * 1_000))
        var drained: Int32 = 0
        fasten_drainer_flush(storeHandle, ms, &drained, nil)
        return drained != 0
    }

    var statsJSON: String {
        var outJSON: UnsafeMutablePointer<CChar>? = nil
        var errStr:  UnsafeMutablePointer<CChar>? = nil
        fasten_drainer_stats_json(storeHandle, &outJSON, &errStr)
        if let e = errStr { fasten_store_free_str(e) }
        guard let j = outJSON else { return "null" }
        let result = String(cString: j)
        fasten_store_free_str(j)
        return result
    }

    func close() {
        var shouldClose = false
        closeLock.withLock {
            if !isClosed {
                isClosed = true
                shouldClose = true
            }
        }
        guard shouldClose else { return }
        fasten_drainer_close(storeHandle)
        storeRef.release()  // safe: background thread has stopped after drainer_close
        fasten_store_close(storeHandle)
    }

    deinit { close() }
}

struct CFastenError: Error, CustomStringConvertible {
    let description: String
    init(_ msg: String) { description = msg }
}
