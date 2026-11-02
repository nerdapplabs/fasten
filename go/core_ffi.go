package fasten

/*
#cgo CFLAGS: -I${SRCDIR}/../fasten-core/include
#cgo LDFLAGS: -L${SRCDIR}/../fasten-core/target/release -lfasten_core
#include "fasten_core.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// coreRedactJSON redacts inJSON with fasten-core's default rules.
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

// coreRedactJSONFull redacts with extra key patterns added to the built-in
// ones. extraKeysJSON is a JSON array of patterns ("" for none); replacement
// is used for key matches ("" means the core default "***").
func coreRedactJSONFull(inJSON, extraKeysJSON, replacement string) (string, error) {
	cIn := C.CString(inJSON)
	defer C.free(unsafe.Pointer(cIn))
	var cKeys, cRepl *C.char
	if extraKeysJSON != "" {
		cKeys = C.CString(extraKeysJSON)
		defer C.free(unsafe.Pointer(cKeys))
	}
	if replacement != "" {
		cRepl = C.CString(replacement)
		defer C.free(unsafe.Pointer(cRepl))
	}
	var outJSON, outErr *C.char
	rc := C.fasten_redact_full(cIn, cKeys, cRepl, nil, &outJSON, &outErr)
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

// coreRegisterCodes registers codes in fasten-core's catalog. Validation
// errors from the core are returned as Go errors.
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

// coreMetaOfJSON returns the code's metadata as JSON, or "{}" if unknown.
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

// coreRegistryClear empties fasten-core's catalog. Used by tests.
func coreRegistryClear() {
	C.fasten_registry_clear()
}
