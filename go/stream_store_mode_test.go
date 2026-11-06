//go:build !windows

package fasten

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

func TestOpenStreamStore_NewFileIs0600(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	path := filepath.Join(t.TempDir(), "streams.db")
	s, err := OpenStreamStore(path, "api_stream")
	if err != nil {
		t.Fatalf("OpenStreamStore: %v", err)
	}
	defer s.db.Close()
	if err := s.Insert(map[string]any{"request_id": "r1", "event": "e"}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if m := fileMode(t, path); m != 0o600 {
		t.Errorf("store file mode = %o, want 600", m)
	}
	if m := fileMode(t, path+"-wal"); m != 0o600 {
		t.Errorf("wal file mode = %o, want 600", m)
	}
}

func TestOpenStreamStore_ExistingFileKeepsMode(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	path := filepath.Join(t.TempDir(), "streams.db")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStreamStore(path, "api_stream")
	if err != nil {
		t.Fatalf("OpenStreamStore: %v", err)
	}
	defer s.db.Close()
	if m := fileMode(t, path); m != 0o644 {
		t.Errorf("store file mode = %o, want 644", m)
	}
}

func TestOpenStreamStore_FileURIIs0600(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	path := filepath.Join(t.TempDir(), "my store.db")
	s, err := OpenStreamStore("file:"+strings.ReplaceAll(path, " ", "%20")+"?cache=private", "api_stream")
	if err != nil {
		t.Fatalf("OpenStreamStore: %v", err)
	}
	defer s.db.Close()
	if m := fileMode(t, path); m != 0o600 {
		t.Errorf("store file mode = %o, want 600", m)
	}
}

func TestOpenStreamStore_ReadOnlyFileURICreatesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "streams.db")
	if s, err := OpenStreamStore("file:"+path+"?mode=ro", "api_stream"); err == nil {
		s.db.Close()
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("read-only URI created %s (stat err %v)", path, err)
	}
}
