package fasten

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// ARCH #3 mirror-sync check. go:embed can't reach outside the module tree,
// so go/internal/spec/ is a byte-for-byte mirror of ../spec/. This test
// fails if someone edits the canonical spec/ files and forgets to run
// spec/sync-to-go.sh before committing.
//
// Runs only when the parent spec/ dir is reachable (i.e. checked out
// alongside the go module in the same repo). CI runs the whole tree so
// the check always fires there; consumers who only vendor go/ get a
// clean skip rather than a false failure.
func TestAuditDDLMirrorMatchesCanonical(t *testing.T) {
	pairs := []struct {
		canonical string
		mirror    string
		embedded  string
	}{
		{"../spec/audit_log.sqlite.sql", "internal/spec/audit_log.sqlite.sql", auditLogSqliteDDL},
		{"../spec/audit_log.postgres.sql", "internal/spec/audit_log.postgres.sql", auditLogPostgresDDL},
	}
	for _, p := range pairs {
		canonical, err := os.ReadFile(filepath.FromSlash(p.canonical))
		if err != nil {
			t.Skipf("canonical spec not reachable (%s) — skipping mirror check", err)
			return
		}
		mirror, err := os.ReadFile(filepath.FromSlash(p.mirror))
		if err != nil {
			t.Fatalf("mirror missing: %v", err)
		}
		cH := sha256.Sum256(canonical)
		mH := sha256.Sum256(mirror)
		if cH != mH {
			t.Fatalf("mirror %s drifted from canonical %s\n"+
				"  canonical sha256: %s\n"+
				"  mirror    sha256: %s\n"+
				"Run: bash spec/sync-to-go.sh (from repo root)",
				p.mirror, p.canonical,
				hex.EncodeToString(cH[:]), hex.EncodeToString(mH[:]))
		}
		// Also verify the embedded content matches the mirror on disk.
		eH := sha256.Sum256([]byte(p.embedded))
		if eH != mH {
			t.Fatalf("embedded DDL for %s does not match mirror on disk", p.mirror)
		}
	}
}
