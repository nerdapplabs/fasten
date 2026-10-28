package fasten

/*
#cgo CFLAGS: -I${SRCDIR}/../fasten-core/include
#cgo LDFLAGS: -L${SRCDIR}/../fasten-core/target/release -lfasten_core
#include "fasten_core.h"
#include <stdlib.h>
#include <stdint.h>

// Forward declaration so CGo can resolve C.goInsertCallback below.
// Note: CGo generates char* (not const char*) for *C.char parameters.
extern int32_t goInsertCallback(char* row_json, void* userdata);

// Pass a cgo.Handle (a uintptr) as the void* userdata. The uintptr->void*
// cast happens here in C, so the Go side never does unsafe.Pointer(uintptr(...))
// — which `go vet` flags as a possible misuse of unsafe.Pointer.
static inline FastenStore* fasten_store_from_handle(
    FastenInsertCallbackFn fn, uintptr_t h, char** out_err) {
    return fasten_store_from_callback(fn, (void*)h, out_err);
}
*/
import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/cgo"
	"sort"
	"sync"
	"time"
	"unsafe"
)

// goInsertCallback is the C-callable insert callback that bridges the shared
// fasten-core drainer to a Go AuditRepository. userdata is a cgo.Handle for
// the *cFastenDrainer.
//
// Each insert crosses the CGo boundary twice (Go → Rust drainer → C callback → Go store).
// The ~100 ns/call CGo overhead is acceptable at audit volumes but rules out
// high-frequency non-audit use of this path.
//
//export goInsertCallback
func goInsertCallback(rowJSON *C.char, userdata unsafe.Pointer) (rc C.int32_t) {
	// A Go panic must not unwind through the C frames.
	defer func() {
		if recover() != nil {
			rc = 1
		}
	}()
	d, ok := cgo.Handle(uintptr(userdata)).Value().(*cFastenDrainer)
	if !ok || !d.insert(C.GoString(rowJSON)) {
		return 1
	}
	return 0
}

// pendingRow is a row the drainer holds. The callback stores this row, not
// fasten-core's JSON copy, so the store seals what was emitted (spec §2.1).
type pendingRow struct {
	row      Row
	order    uint64
	attempts int
}

// cFastenDrainer wraps a FastenStore* + Drainer (C ABI) together with the
// cgo.Handle the callback uses to reach it.
type cFastenDrainer struct {
	handle      unsafe.Pointer // *FastenStoreHandle
	goHandle    cgo.Handle
	engine      *Engine
	store       AuditRepository
	maxAttempts int

	pendingMu sync.Mutex
	pending   map[string]*pendingRow
	next      uint64

	// use guards the handle: calls hold it for reading, and retire takes it
	// for writing before it closes the handle.
	use    sync.RWMutex
	closed bool
}

func newCFastenDrainer(
	e *Engine,
	store AuditRepository,
	capacity int,
	retryInitialMs, retryMaxMs int64,
	retryJitter bool,
	maxAttempts int,
) (*cFastenDrainer, error) {
	d := &cFastenDrainer{
		engine:      e,
		store:       store,
		maxAttempts: maxAttempts,
		pending:     map[string]*pendingRow{},
	}
	h := cgo.NewHandle(d)

	var errStr *C.char
	storePtr := C.fasten_store_from_handle(
		C.FastenInsertCallbackFn(C.goInsertCallback),
		C.uintptr_t(h),
		&errStr,
	)
	if storePtr == nil {
		h.Delete()
		msg := "unknown"
		if errStr != nil {
			msg = C.GoString(errStr)
			C.fasten_store_free_str(errStr)
		}
		return nil, fmt.Errorf("fasten_store_from_callback: %s", msg)
	}

	jitter := C.int(0)
	if retryJitter {
		jitter = 1
	}
	rc := C.fasten_drainer_install(
		storePtr,
		C.uint64_t(capacity),
		C.uint64_t(retryInitialMs),
		C.uint64_t(retryMaxMs),
		jitter,
		C.uint32_t(maxAttempts),
		&errStr,
	)
	if rc != C.FASTEN_OK {
		msg := "unknown"
		if errStr != nil {
			msg = C.GoString(errStr)
			C.fasten_store_free_str(errStr)
		}
		C.fasten_store_close(storePtr)
		h.Delete()
		return nil, fmt.Errorf("fasten_drainer_install: %s", msg)
	}

	d.handle = unsafe.Pointer(storePtr)
	d.goHandle = h
	return d, nil
}

// insert stores the pending row named in rowJSON. It reports false so the
// drainer retries; at maxAttempts the drainer dead-letters the row.
func (d *cFastenDrainer) insert(rowJSON string) bool {
	var head struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(rowJSON), &head); err != nil {
		return false
	}
	d.pendingMu.Lock()
	p := d.pending[head.ID]
	if p != nil {
		p.attempts++
	}
	d.pendingMu.Unlock()
	if p == nil {
		// Already settled here; nothing to store.
		d.engine.drainerSysLog("error", "audit_drain_row_not_pending", map[string]any{"row_id": head.ID})
		return true
	}
	if err := d.storeRow(p.row); err != nil {
		if p.attempts >= d.maxAttempts {
			d.settle(head.ID)
			d.engine.markWriteLost(d.store)
		}
		return false
	}
	d.settle(head.ID)
	return true
}

func (d *cFastenDrainer) settle(id string) {
	d.pendingMu.Lock()
	delete(d.pending, id)
	d.pendingMu.Unlock()
}

// storeRow seals and stores row; a panicking store counts as a failed insert.
func (d *cFastenDrainer) storeRow(row Row) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("store panicked: %v", r)
		}
	}()
	_, err = d.engine.allocateAndStore(context.Background(), d.store, row)
	return err
}

// testHookEnqueue, when set, runs at the start of enqueue.
var testHookEnqueue func()

// enqueue hands row to the drainer. It returns false when the row was not
// queued, and the caller stores it itself.
func (d *cFastenDrainer) enqueue(row Row) bool {
	if testHookEnqueue != nil {
		testHookEnqueue()
	}
	d.use.RLock()
	defer d.use.RUnlock()
	if d.closed {
		return false
	}
	b, err := json.Marshal(row)
	if err != nil {
		return false
	}
	d.pendingMu.Lock()
	d.next++
	d.pending[row.ID] = &pendingRow{row: row, order: d.next}
	d.pendingMu.Unlock()

	cs := C.CString(string(b))
	defer C.free(unsafe.Pointer(cs))
	var errStr *C.char
	rc := C.fasten_drainer_enqueue((*C.FastenStore)(d.handle), cs, &errStr)
	if errStr != nil {
		C.fasten_store_free_str(errStr)
	}
	if rc != C.FASTEN_OK {
		d.settle(row.ID)
		return false
	}
	return true
}

// flush blocks until the queue drains or timeout elapses.
func (d *cFastenDrainer) flush(timeout time.Duration) bool {
	d.use.RLock()
	defer d.use.RUnlock()
	if d.closed {
		return true
	}
	ms := C.uint64_t(timeout.Milliseconds())
	var drained C.int
	C.fasten_drainer_flush((*C.FastenStore)(d.handle), ms, &drained, nil)
	return drained != 0
}

// statsJSON returns the drainer health snapshot as a JSON string,
// or "null" when no drainer is active.
func (d *cFastenDrainer) statsJSON() string {
	d.use.RLock()
	defer d.use.RUnlock()
	if d.closed {
		return "null"
	}
	var outJSON, errStr *C.char
	C.fasten_drainer_stats_json((*C.FastenStore)(d.handle), &outJSON, &errStr)
	if errStr != nil {
		C.fasten_store_free_str(errStr)
	}
	if outJSON == nil {
		return "null"
	}
	result := C.GoString(outJSON)
	C.fasten_store_free_str(outJSON)
	return result
}

// retire stops a drainer that is no longer installed and stores the rows it
// did not write. flushFor > 0 gives it that long to drain first.
func (d *cFastenDrainer) retire(flushFor time.Duration) {
	if flushFor > 0 {
		d.flush(flushFor)
	}
	// Close refuses new rows and waits for the drain thread, so the callback
	// is not called after it returns. Calls still using the handle get an
	// error and store their row inline.
	C.fasten_drainer_close((*C.FastenStore)(d.handle))
	// Held until the leftovers are stored, so a call waiting on the handle
	// sees closed only once nothing more will be written.
	d.use.Lock()
	defer d.use.Unlock()
	d.closed = true
	d.goHandle.Delete()
	C.fasten_store_close((*C.FastenStore)(d.handle))

	// Rows still pending were not stored: the drainer abandoned them or gave
	// them one try at shutdown, and may have reported them lost.
	d.pendingMu.Lock()
	rows := make([]*pendingRow, 0, len(d.pending))
	for _, p := range d.pending {
		rows = append(rows, p)
	}
	d.pending = map[string]*pendingRow{}
	d.pendingMu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].order < rows[j].order })
	var recovered []string
	for _, p := range rows {
		if err := d.storeRow(p.row); err != nil {
			d.engine.markWriteLost(d.store)
			d.engine.drainerSysLog("error", "audit_drain_lost_at_stop", map[string]any{
				"error_type": fmt.Sprintf("%T", err),
				"row_id":     p.row.ID,
			})
			continue
		}
		recovered = append(recovered, p.row.ID)
	}
	if len(recovered) > 0 {
		d.engine.drainerSysLog("info", "audit_drain_recovered_at_stop", map[string]any{"row_ids": recovered})
	}
}
