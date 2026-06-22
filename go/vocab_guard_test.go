package fasten

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoAppSpecificVocabulary guards fasten's app-agnosticism: no consumer-specific
// product name may appear anywhere in the repo. fasten is a general-purpose audit
// library — downstream applications reference fasten, never the reverse. A leak in
// code/tests/docs/reference-YAMLs couples the library to one consumer.
//
// This test scans the whole repo (all SDKs), so it fails CI regardless of which
// language job runs it.
func TestNoAppSpecificVocabulary(t *testing.T) {
	forbidden := regexp.MustCompile(`(?i)edge-manager|edge_manager|edgebits`)
	const self = "vocab_guard_test.go"
	srcExt := map[string]bool{
		".go": true, ".py": true, ".rs": true, ".java": true, ".js": true,
		".mjs": true, ".ts": true, ".swift": true, ".cpp": true, ".cc": true,
		".h": true, ".hpp": true, ".yaml": true, ".yml": true, ".md": true,
		".toml": true, ".json": true, ".txt": true,
	}
	root := ".." // this test lives in go/; scan the whole fasten repo

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "target", "node_modules", ".venv", "__pycache__", "dist", "build":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, self) || !srcExt[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return nil
		}
		if loc := forbidden.FindIndex(b); loc != nil {
			end := loc[0] + 48
			if end > len(b) {
				end = len(b)
			}
			t.Errorf("app-specific vocabulary leak in %s: %q (fasten must stay app-agnostic)",
				path, strings.TrimSpace(string(b[loc[0]:end])))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
