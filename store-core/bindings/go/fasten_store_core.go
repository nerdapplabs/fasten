// Package fastenstore provides Go bindings for libfasten_store_core.
//
// Build the library first:
//
//	cd fasten/store-core && cargo build --release --features all
//
// Then compile your Go program with cgo:
//
//	CGO_CFLAGS="-I/path/to/fasten/store-core/include"
//	CGO_LDFLAGS="-L/path/to/target/release -lfasten_store_core -Wl,-rpath,..."
//
// Example:
//
//	store, err := fastenstore.Open("sqlite", ":memory:", "audit_log")
//	if err != nil { log.Fatal(err) }
//	defer store.Close()
//
//	if err := store.Insert(row); err != nil { log.Fatal(err) }
package fastenstore

/*
#cgo CFLAGS:  -I${SRCDIR}/../../../include
#cgo LDFLAGS: -lfasten_store_core

#include "fasten_store_core.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"unsafe"
)

// ── Error handling ────────────────────────────────────────────────────────────

// takeError reads and frees an out-err string returned by the library.
// Must be called even when rc == 0 to avoid leaking the pointer slot.
func takeError(raw *C.char) error {
	if raw == nil {
		return errors.New("fasten-store-core: unknown error")
	}
	msg := C.GoString(raw)
	C.fasten_store_free_str(raw)
	return fmt.Errorf("fasten-store-core: %s", msg)
}

// ── Store ─────────────────────────────────────────────────────────────────────

// Store wraps a FastenStore handle. It is safe to use concurrently.
type Store struct {
	handle *C.FastenStore
}

// Open connects to an audit store.
//
//   - backend: "sqlite" or "postgres"
//   - connstr: SQLite path (or ":memory:") / PostgreSQL DSN
//   - table:   plain or schema-qualified table name (e.g. "audit.audit_log")
func Open(backend, connstr, table string) (*Store, error) {
	cBackend := C.CString(backend)
	cConnstr := C.CString(connstr)
	cTable   := C.CString(table)
	defer C.free(unsafe.Pointer(cBackend))
	defer C.free(unsafe.Pointer(cConnstr))
	defer C.free(unsafe.Pointer(cTable))

	var outErr *C.char
	handle := C.fasten_store_open(cBackend, cConnstr, cTable, &outErr)
	if handle == nil {
		return nil, takeError(outErr)
	}
	return &Store{handle: handle}, nil
}

// Insert persists one audit row. Duplicate IDs are silently ignored.
// row must be JSON-serialisable and match the fasten wire schema.
func (s *Store) Insert(row any) error {
	data, err := json.Marshal(row)
	if err != nil {
		return fmt.Errorf("fastenstore: marshal: %w", err)
	}
	return s.InsertJSON(string(data))
}

// InsertJSON persists one audit row from a pre-serialised JSON string.
func (s *Store) InsertJSON(rowJSON string) error {
	cJSON := C.CString(rowJSON)
	defer C.free(unsafe.Pointer(cJSON))

	var outErr *C.char
	rc := C.fasten_store_insert(s.handle, cJSON, &outErr)
	if rc != 0 {
		return takeError(outErr)
	}
	return nil
}

// Ping verifies the backend is reachable.
func (s *Store) Ping() error {
	var outErr *C.char
	rc := C.fasten_store_ping(s.handle, &outErr)
	if rc != 0 {
		return takeError(outErr)
	}
	return nil
}

// Close releases all resources. The store is unusable after this call.
func (s *Store) Close() {
	if s.handle != nil {
		C.fasten_store_close(s.handle)
		s.handle = nil
	}
}

// Version returns the library version string.
func Version() string {
	return C.GoString(C.fasten_store_version())
}
