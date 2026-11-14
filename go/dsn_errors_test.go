package fasten

import (
	"strings"
	"testing"
)

// Errors about a stream DSN name no part of it.
func TestStreamDSNErrorsOmitDSN(t *testing.T) {
	for _, dsn := range []string{
		"postgres://app:s3cret@db/audit",
		"sqlite://app:s3cret@db/%zz",
		"sqlite://app:s3cret@",
	} {
		_, _, err := parseStreamDSN(dsn, "sys")
		if err == nil {
			t.Fatalf("%s: want an error", dsn)
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("error quotes the DSN: %v", err)
		}
	}
}
