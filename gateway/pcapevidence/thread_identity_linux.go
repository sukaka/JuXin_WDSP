//go:build linux

package pcapevidence

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func restrictEvidenceWriter(uid, gid int) (func() error, error) {
	if uid == 0 && gid == 0 {
		return func() error { return nil }, nil
	}
	if os.Geteuid() != 0 && os.Geteuid() != uid {
		return nil, fmt.Errorf("evidence writer requires root with restricted capabilities or uid %d", uid)
	}
	runtime.LockOSThread()
	previousGID, _, errno := unix.Syscall(unix.SYS_SETFSGID, uintptr(gid), 0, 0)
	if errno != 0 {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("restrict evidence writer gid: %w", errno)
	}
	previousUID, _, errno := unix.Syscall(unix.SYS_SETFSUID, uintptr(uid), 0, 0)
	if errno != 0 {
		_, _, restoreErrno := unix.Syscall(unix.SYS_SETFSGID, previousGID, 0, 0)
		runtime.UnlockOSThread()
		return nil, errors.Join(fmt.Errorf("restrict evidence writer uid: %w", errno), restoreErrno)
	}
	return func() error {
		_, _, uidErrno := unix.Syscall(unix.SYS_SETFSUID, previousUID, 0, 0)
		_, _, gidErrno := unix.Syscall(unix.SYS_SETFSGID, previousGID, 0, 0)
		runtime.UnlockOSThread()
		if uidErrno != 0 || gidErrno != 0 {
			return errors.Join(uidErrno, gidErrno)
		}
		return nil
	}, nil
}
