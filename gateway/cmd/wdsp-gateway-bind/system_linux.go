//go:build linux

package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	prSetKeepCaps    = 8
	prCapBSetDrop    = 24
	prSetNoNewPrivs  = 38
	prCapAmbient     = 47
	prAmbientRaise   = 2
	capabilityVers3  = 0x20080522
	capabilityLast   = "/proc/sys/kernel/cap_last_cap"
	processStatusRef = "/proc/self/status"
)

type linuxSystem struct{}

type capabilityHeader struct {
	version uint32
	pid     int32
}

type capabilityData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

func newPlatformSystem() (system, error) {
	runtime.LockOSThread()
	return linuxSystem{}, nil
}

func (linuxSystem) EffectiveUID() int {
	return syscall.Geteuid()
}

func (linuxSystem) SetNoNewPrivileges() error {
	return prctl(prSetNoNewPrivs, 1, 0, 0, 0)
}

func (linuxSystem) ClearSupplementaryGroups() error {
	return syscall.Setgroups(nil)
}

func (linuxSystem) PreserveCapabilitiesAcrossSetUID() error {
	return prctl(prSetKeepCaps, 1, 0, 0, 0)
}

func (linuxSystem) DropOtherBoundingCapabilities() error {
	raw, err := os.ReadFile(capabilityLast)
	if err != nil {
		return fmt.Errorf("read %s: %w", capabilityLast, err)
	}
	last, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("parse %s: %w", capabilityLast, err)
	}
	if last < capNetBindService {
		return fmt.Errorf("kernel last capability %d is below CAP_NET_BIND_SERVICE", last)
	}
	for capability := 0; capability <= last; capability++ {
		if capability == capNetBindService {
			continue
		}
		if err := prctl(prCapBSetDrop, uintptr(capability), 0, 0, 0); err != nil {
			return fmt.Errorf("drop bounding capability %d: %w", capability, err)
		}
	}
	return nil
}

func (linuxSystem) SetGID(gid int) error {
	return syscall.Setresgid(gid, gid, gid)
}

func (linuxSystem) SetUID(uid int) error {
	return syscall.Setresuid(uid, uid, uid)
}

func (linuxSystem) SetNetBindServiceCapability() error {
	header := capabilityHeader{version: capabilityVers3}
	data := [2]capabilityData{}
	data[0].effective = uint32(expectedCapability)
	data[0].permitted = uint32(expectedCapability)
	data[0].inheritable = uint32(expectedCapability)
	_, _, errno := syscall.Syscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (linuxSystem) RaiseNetBindServiceAmbient() error {
	return prctl(prCapAmbient, prAmbientRaise, capNetBindService, 0, 0)
}

func (linuxSystem) ReadState() (processState, error) {
	file, err := os.Open(processStatusRef)
	if err != nil {
		return processState{}, err
	}
	defer file.Close()
	return parseProcessStatus(file)
}

func (linuxSystem) Exec(path string, argv, env []string) error {
	return syscall.Exec(path, argv, env)
}

func prctl(option, arg2, arg3, arg4, arg5 uintptr) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, option, arg2, arg3, arg4, arg5, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
