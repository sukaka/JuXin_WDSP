//go:build linux

package pcapevidence

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestEvidenceWriterIdentityIsThreadLocalAndRestored(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires the explicitly configured restricted test root")
	}
	root := t.TempDir()
	if err := os.Chmod(filepath.Dir(root), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	restore, err := restrictEvidenceWriter(1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "restricted"), []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "restricted"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Sys().(*syscall.Stat_t).Uid; got != 1000 {
		t.Fatalf("evidence file uid=%d want 1000", got)
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "restored"), []byte("restore"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(filepath.Join(root, "restored"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Sys().(*syscall.Stat_t).Uid; got != 0 {
		t.Fatalf("restored file uid=%d want 0", got)
	}
}
