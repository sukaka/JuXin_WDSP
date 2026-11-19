//go:build linux

package pcapevidence

import (
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

type fsidOps struct {
	geteuid  func() int
	getegid  func() int
	setfsuid func(uid uintptr) (uintptr, unix.Errno)
	setfsgid func(gid uintptr) (uintptr, unix.Errno)
	lock     func()
	unlock   func()
}

var defaultFSIDOps = fsidOps{
	geteuid: os.Geteuid,
	getegid: os.Getegid,
	setfsuid: func(uid uintptr) (uintptr, unix.Errno) {
		prev, _, errno := unix.Syscall(unix.SYS_SETFSUID, uid, 0, 0)
		return prev, errno
	},
	setfsgid: func(gid uintptr) (uintptr, unix.Errno) {
		prev, _, errno := unix.Syscall(unix.SYS_SETFSGID, gid, 0, 0)
		return prev, errno
	},
	lock:   runtime.LockOSThread,
	unlock: runtime.UnlockOSThread,
}

var restrictEvidenceWriterFn = restrictEvidenceWriter

func restrictEvidenceWriter(uid, gid int) (func() error, error) {
	return restrictEvidenceWriterWith(uid, gid, defaultFSIDOps)
}

func restrictEvidenceWriterWith(uid, gid int, ops fsidOps) (func() error, error) {
	if uid < 0 || gid < 0 || uint64(uid) >= math.MaxUint32 || uint64(gid) >= math.MaxUint32 {
		return nil, fmt.Errorf("invalid evidence writer identity uid=%d gid=%d", uid, gid)
	}
	if uid == 0 && gid == 0 {
		return func() error { return nil }, nil
	}
	if ops.geteuid() == uid && ops.getegid() == gid {
		return func() error { return nil }, nil
	}
	if ops.geteuid() != 0 && ops.geteuid() != uid {
		return nil, fmt.Errorf("evidence writer requires root with restricted capabilities or uid %d", uid)
	}

	ops.lock()
	previousGID, errno := ops.setfsgid(uintptr(gid))
	if errno != 0 {
		ops.unlock()
		return nil, fmt.Errorf("restrict evidence writer gid: %w", errno)
	}
	curGID, queryErrno := ops.setfsgid(^uintptr(0))
	if queryErrno != 0 {
		ops.unlock()
		return nil, fmt.Errorf("verify evidence writer gid: %w", queryErrno)
	}
	if int(curGID) != gid {
		var restoreErr error
		if curGID != previousGID {
			restoreErr = restoreFSGID(ops, previousGID)
		}
		if restoreErr == nil {
			ops.unlock()
		}
		return nil, errors.Join(fmt.Errorf("restrict evidence writer gid failed: current fsgid=%d want %d", curGID, gid), restoreErr)
	}

	previousUID, errno := ops.setfsuid(uintptr(uid))
	if errno != 0 {
		restoreErr := restoreFSGID(ops, previousGID)
		if restoreErr == nil {
			ops.unlock()
		}
		return nil, errors.Join(fmt.Errorf("restrict evidence writer uid: %w", errno), restoreErr)
	}
	curUID, queryErrno := ops.setfsuid(^uintptr(0))
	if queryErrno != 0 {
		restoreErr := restoreFSGID(ops, previousGID)
		if restoreErr == nil {
			ops.unlock()
		}
		return nil, errors.Join(fmt.Errorf("verify evidence writer uid: %w", queryErrno), restoreErr)
	}
	if int(curUID) != uid {
		var restoreUIDErr error
		if curUID != previousUID {
			restoreUIDErr = restoreFSUID(ops, previousUID)
		}
		restoreGIDErr := restoreFSGID(ops, previousGID)
		if restoreUIDErr == nil && restoreGIDErr == nil {
			ops.unlock()
		}
		return nil, errors.Join(
			fmt.Errorf("restrict evidence writer uid failed: current fsuid=%d want %d", curUID, uid),
			restoreUIDErr,
			restoreGIDErr,
		)
	}

	restored := false
	return func() error {
		if restored {
			return nil
		}
		restored = true
		uidErr := restoreFSUID(ops, previousUID)
		gidErr := restoreFSGID(ops, previousGID)
		if uidErr != nil || gidErr != nil {
			return errors.Join(uidErr, gidErr)
		}
		ops.unlock()
		return nil
	}, nil
}

func restoreFSUID(ops fsidOps, target uintptr) error {
	if _, errno := ops.setfsuid(target); errno != 0 {
		return fmt.Errorf("restore evidence writer uid: %w", errno)
	}
	curUID, errno := ops.setfsuid(^uintptr(0))
	if errno != 0 {
		return fmt.Errorf("verify restored evidence writer uid: %w", errno)
	}
	if curUID != target {
		return fmt.Errorf("restore evidence writer uid failed: current fsuid=%d want %d", curUID, target)
	}
	return nil
}

func restoreFSGID(ops fsidOps, target uintptr) error {
	if _, errno := ops.setfsgid(target); errno != 0 {
		return fmt.Errorf("restore evidence writer gid: %w", errno)
	}
	curGID, errno := ops.setfsgid(^uintptr(0))
	if errno != 0 {
		return fmt.Errorf("verify restored evidence writer gid: %w", errno)
	}
	if curGID != target {
		return fmt.Errorf("restore evidence writer gid failed: current fsgid=%d want %d", curGID, target)
	}
	return nil
}
