package fasten

/*
#cgo CFLAGS: -I${SRCDIR}/../fasten-core/include
#cgo LDFLAGS: -L${SRCDIR}/../fasten-core/target/release -lfasten_core
#include "fasten_core.h"
#include <stdlib.h>

// Forward declaration so CGo can resolve C.goInsertCallback below.
// Note: CGo generates char* (not const char*) for *C.char parameters.
extern int32_t goInsertCallback(char* row_json, void* userdata);
*/
import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"runtime/cgo"
	"time"
	"unsafe"
)

// goInsertCallback is the C-callable insert callback that bridges
// the shared fasten-core drainer to a Go AuditRepository.
// The store is passed via userdata as a cgo.Handle (uintptr).
//
// Each insert crosses the CGo boundary twice (Go → Rust drainer → C callback → Go store).
// The ~100 ns/call CGo overhead is acceptable at audit volumes but rules out
// high-frequency non-audit use of this path.
//
//export goInsertCallback
func goInsertCallback(rowJSON *C.char, userdata unsafe.Pointer) C.int32_t {
	h := cgo.Handle(uintptr(userdata))
	store, ok := h.Value().(AuditRepository)
	if !ok {
		return 1
	}
	jsonStr := C.GoString(rowJSON)
	var row Row
	if err := json.Unmarshal([]byte(jsonStr), &row); err != nil {
		return 1
	}
	if err := store.Insert(context.Background(), row); err != nil {
		return 1
	}
	return 0
}

// cFastenDrainer wraps a FastenStore* + Drainer (C ABI) together
// with the cgo.Handle that keeps the Go AuditRepository alive for
// the drainer's background thread.
type cFastenDrainer struct {
	handle   unsafe.Pointer // *FastenStoreHandle
	goHandle cgo.Handle     // holds the Go AuditRepository alive
}

func newCFastenDrainer(
	store AuditRepository,
	capacity int,
	retryInitialMs, retryMaxMs int64,
	retryJitter bool,
	maxAttempts uint32,
) (*cFastenDrainer, error) {
	// Create a cgo.Handle so the C callback can reach the Go store.
	h := cgo.NewHandle(store)

	var errStr *C.char
	storePtr := C.fasten_store_from_callback(
		C.FastenInsertCallbackFn(C.goInsertCallback),
		unsafe.Pointer(uintptr(h)),
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

	return &cFastenDrainer{handle: unsafe.Pointer(storePtr), goHandle: h}, nil
}

// enqueue serialises a Row to JSON and hands it to the shared drainer.
func (d *cFastenDrainer) enqueue(row Row) {
	b, err := json.Marshal(row)
	if err != nil {
		return
	}
	cs := C.CString(string(b))
	defer C.free(unsafe.Pointer(cs))
	var errStr *C.char
	C.fasten_drainer_enqueue((*C.FastenStore)(d.handle), cs, &errStr)
	if errStr != nil {
		C.fasten_store_free_str(errStr)
	}
}

// flush blocks until the queue drains or timeout elapses.
func (d *cFastenDrainer) flush(timeout time.Duration) bool {
	ms := C.uint64_t(timeout.Milliseconds())
	var drained C.int
	C.fasten_drainer_flush((*C.FastenStore)(d.handle), ms, &drained, nil)
	return drained != 0
}

// statsJSON returns the drainer health snapshot as a JSON string,
// or "null" when no drainer is active.
func (d *cFastenDrainer) statsJSON() string {
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

// close stops the drainer thread and releases all C resources.
// The cgo.Handle is deleted AFTER drainer_close() so the background
// thread cannot call into a freed Go store.
func (d *cFastenDrainer) close() {
	C.fasten_drainer_close((*C.FastenStore)(d.handle))
	d.goHandle.Delete()
	C.fasten_store_close((*C.FastenStore)(d.handle))
}
