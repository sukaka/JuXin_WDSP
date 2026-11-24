package fsperm

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMkdirPrivateAndSecureFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatalf("MkdirPrivate failed: %v", err)
	}
	file := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(file, []byte("secret"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := SecureFile(file, 0o600); err != nil {
		t.Fatalf("SecureFile failed: %v", err)
	}
	if runtime.GOOS != "windows" {
		dfi, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if dfi.Mode().Perm() != 0o700 {
			t.Fatalf("dir perm = %o, want 0700", dfi.Mode().Perm())
		}
		ffi, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if ffi.Mode().Perm() != 0o600 {
			t.Fatalf("file perm = %o, want 0600", ffi.Mode().Perm())
		}
	}
	data, err := os.ReadFile(file)
	if err != nil || string(data) != "secret" {
		t.Fatalf("owner cannot read secured file: data=%q err=%v", data, err)
	}
}
