package fasten

/*
#cgo CFLAGS: -I${SRCDIR}/../fasten-core/include
#cgo LDFLAGS: -L${SRCDIR}/../fasten-core/target/release -lfasten_core
#include "fasten_core.h"
#include <stdlib.h>
#include <stdint.h>

// cgo generates char* (not const char*) for *C.char parameters.
extern int32_t goInsertCallback(char* row_json, void* userdata);

// Passes a cgo.Handle as the void* userdata. Doing the cast in C avoids the
// unsafe.Pointer(uintptr(...)) conversion that go vet warns about.
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
	"time"
	"unsafe"
)

// goInsertCallback is called by the fasten-core drainer to insert one row
// into the Go AuditRepository passed as a cgo.Handle in userdata. Each row
// crosses cgo twice, which is fine at audit volumes.
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

// cFastenDrainer holds the C store and drainer, plus the cgo.Handle that
// keeps the Go AuditRepository reachable from the drainer thread.
type cFastenDrainer struct {
	handle   unsafe.Pointer // *C.FastenStore
	goHandle cgo.Handle
}

func newCFastenDrainer(
	store AuditRepository,
	capacity int,
	retryInitialMs, retryMaxMs int64,
	retryJitter bool,
	maxAttempts uint32,
) (*cFastenDrainer, error) {
	h := cgo.NewHandle(store)

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

	return &cFastenDrainer{handle: unsafe.Pointer(storePtr), goHandle: h}, nil
}

// enqueue hands a row to the drainer as JSON.
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

// statsJSON returns the drainer stats as JSON, or "null" if there are none.
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

// close stops the drainer and frees the C store. The handle is deleted only
// after the drainer thread has stopped, so it can't reach a deleted handle.
func (d *cFastenDrainer) close() {
	C.fasten_drainer_close((*C.FastenStore)(d.handle))
	d.goHandle.Delete()
	C.fasten_store_close((*C.FastenStore)(d.handle))
}
