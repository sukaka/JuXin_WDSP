//go:build linux

package pcapevidence

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
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
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != 1000 || stat.Gid != 1000 {
		t.Fatalf("evidence file uid:gid=%d:%d want 1000:1000", stat.Uid, stat.Gid)
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
	stat = info.Sys().(*syscall.Stat_t)
	if stat.Uid != 0 || stat.Gid != 0 {
		t.Fatalf("restored file uid:gid=%d:%d want 0:0", stat.Uid, stat.Gid)
	}
}

func TestRestrictEvidenceWriterAlreadyMatchingIdentityIsNoOp(t *testing.T) {
	locked := false
	calledSyscall := false
	ops := fsidOps{
		geteuid: func() int { return 1000 },
		getegid: func() int { return 1000 },
		setfsuid: func(uintptr) (uintptr, unix.Errno) {
			calledSyscall = true
			return 1000, 0
		},
		setfsgid: func(uintptr) (uintptr, unix.Errno) {
			calledSyscall = true
			return 1000, 0
		},
		lock:   func() { locked = true },
		unlock: func() { locked = false },
	}
	restore, err := restrictEvidenceWriterWith(1000, 1000, ops)
	if err != nil {
		t.Fatalf("already-matching uid:gid should succeed without error: %v", err)
	}
	if locked || calledSyscall {
		t.Fatalf("already-matching uid:gid should be a no-op: locked=%t syscall=%t", locked, calledSyscall)
	}
	if err := restore(); err != nil {
		t.Fatalf("no-op restore failed: %v", err)
	}
}

func TestRestrictEvidenceWriterDetectsSilentSetFSGIDFailure(t *testing.T) {
	locks := 0
	var curGID uintptr = 0
	ops := fsidOps{
		geteuid: func() int { return 0 },
		getegid: func() int { return 0 },
		setfsgid: func(gid uintptr) (uintptr, unix.Errno) {
			// Simulate Linux kernel without CAP_SETGID: errno==0, fsgid stays 0.
			return curGID, 0
		},
		setfsuid: func(uid uintptr) (uintptr, unix.Errno) {
			t.Fatal("setfsuid should not be called after setfsgid verification fails")
			return 0, 0
		},
		lock:   func() { locks++ },
		unlock: func() { locks-- },
	}
	_, err := restrictEvidenceWriterWith(1000, 1000, ops)
	if err == nil || !strings.Contains(err.Error(), "fsgid") {
		t.Fatalf("expected silent setfsgid failure error, got: %v", err)
	}
	if locks != 0 {
		t.Fatalf("OS thread lock imbalance: %d", locks)
	}
}

func TestRestrictEvidenceWriterDetectsSilentSetFSUIDFailureAndRestoresGID(t *testing.T) {
	locks := 0
	var curUID uintptr = 0
	var curGID uintptr = 0
	ops := fsidOps{
		geteuid: func() int { return 0 },
		getegid: func() int { return 0 },
		setfsgid: func(gid uintptr) (uintptr, unix.Errno) {
			prev := curGID
			if gid != ^uintptr(0) {
				curGID = gid
			}
			return prev, 0
		},
		setfsuid: func(uid uintptr) (uintptr, unix.Errno) {
			// Simulate Linux kernel without CAP_SETUID: errno==0, fsuid stays 0.
			return curUID, 0
		},
		lock:   func() { locks++ },
		unlock: func() { locks-- },
	}
	_, err := restrictEvidenceWriterWith(1000, 1000, ops)
	if err == nil || !strings.Contains(err.Error(), "fsuid") {
		t.Fatalf("expected silent setfsuid failure error, got: %v", err)
	}
	if curGID != 0 {
		t.Fatalf("fsgid was not restored after setfsuid failure: got %d want 0", curGID)
	}
	if locks != 0 {
		t.Fatalf("OS thread lock imbalance: %d", locks)
	}
}

func TestRestrictEvidenceWriterVerifiesRestore(t *testing.T) {
	locks := 0
	var curUID uintptr = 0
	var curGID uintptr = 0
	failRestoreUID := false
	ops := fsidOps{
		geteuid: func() int { return 0 },
		getegid: func() int { return 0 },
		setfsgid: func(gid uintptr) (uintptr, unix.Errno) {
			prev := curGID
			if gid != ^uintptr(0) {
				curGID = gid
			}
			return prev, 0
		},
		setfsuid: func(uid uintptr) (uintptr, unix.Errno) {
			prev := curUID
			if uid != ^uintptr(0) && !(failRestoreUID && uid == 0) {
				curUID = uid
			}
			return prev, 0
		},
		lock:   func() { locks++ },
		unlock: func() { locks-- },
	}

	restore, err := restrictEvidenceWriterWith(1000, 1000, ops)
	if err != nil {
		t.Fatalf("restrict failed: %v", err)
	}
	if curUID != 1000 || curGID != 1000 || locks != 1 {
		t.Fatalf("unexpected restricted state uid=%d gid=%d locks=%d", curUID, curGID, locks)
	}
	if err := restore(); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	if curUID != 0 || curGID != 0 || locks != 0 {
		t.Fatalf("unexpected restored state uid=%d gid=%d locks=%d", curUID, curGID, locks)
	}

	// Now simulate silent restore failure: must return error and NOT unlock tainted thread.
	restore, err = restrictEvidenceWriterWith(1000, 1000, ops)
	if err != nil {
		t.Fatalf("second restrict failed: %v", err)
	}
	failRestoreUID = true
	if err := restore(); err == nil || !strings.Contains(err.Error(), "restore evidence writer uid failed") {
		t.Fatalf("expected restore uid verification error, got: %v", err)
	}
	if locks != 1 {
		t.Fatalf("tainted thread should stay locked on failed restore, locks=%d", locks)
	}
}
