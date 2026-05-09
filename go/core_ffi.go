package fasten

/*
#cgo CFLAGS: -I${SRCDIR}/../store-core/include
#cgo LDFLAGS: -L${SRCDIR}/../store-core/target/release -lfasten_store_core
#include "fasten_store_core.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// coreRedactJSON passes in_json through the Rust redaction engine and
// returns the redacted JSON string.
func coreRedactJSON(inJSON string) (string, error) {
	cs := C.CString(inJSON)
	defer C.free(unsafe.Pointer(cs))
	var outJSON, outErr *C.char
	rc := C.fasten_redact(cs, &outJSON, &outErr)
	if outErr != nil {
		defer C.fasten_store_free_str(outErr)
	}
	if outJSON != nil {
		defer C.fasten_store_free_str(outJSON)
	}
	if rc != C.FASTEN_OK {
		msg := "redact failed"
		if outErr != nil {
			msg = C.GoString(outErr)
		}
		return "", fmt.Errorf("fasten: %s", msg)
	}
	if outJSON == nil {
		return inJSON, nil
	}
	return C.GoString(outJSON), nil
}

// coreRegisterCodes delegates code registration to the Rust catalog engine.
// On validation failure the Rust error string is returned as a Go error.
func coreRegisterCodes(domain, codesJSON string) error {
	cDomain := C.CString(domain)
	defer C.free(unsafe.Pointer(cDomain))
	cCodes := C.CString(codesJSON)
	defer C.free(unsafe.Pointer(cCodes))
	var outErr *C.char
	rc := C.fasten_register_codes(cDomain, cCodes, &outErr)
	if outErr != nil {
		defer C.fasten_store_free_str(outErr)
	}
	if rc != C.FASTEN_OK {
		msg := "register failed"
		if outErr != nil {
			msg = C.GoString(outErr)
		}
		return fmt.Errorf("fasten.Register: %s", msg)
	}
	return nil
}

// coreMetaOfJSON looks up a single code in the Rust registry and returns
// its JSON representation, or "{}" when not found.
func coreMetaOfJSON(code string) (string, error) {
	cs := C.CString(code)
	defer C.free(unsafe.Pointer(cs))
	var outJSON, outErr *C.char
	rc := C.fasten_meta_of(cs, &outJSON, &outErr)
	if outErr != nil {
		defer C.fasten_store_free_str(outErr)
	}
	if outJSON != nil {
		defer C.fasten_store_free_str(outJSON)
	}
	if rc != C.FASTEN_OK {
		return "{}", nil
	}
	if outJSON == nil {
		return "{}", nil
	}
	return C.GoString(outJSON), nil
}

// coreRegistryClear wipes the Rust global registry. Call in test teardown
// whenever programmatic Register() calls must be rolled back.
func coreRegistryClear() {
	C.fasten_registry_clear()
}
