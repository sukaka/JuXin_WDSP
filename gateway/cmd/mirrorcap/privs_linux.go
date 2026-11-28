//go:build linux

package main

import (
	"bufio"
	"fmt"
	"log"
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

type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

type linuxHealthcheckPrivOps struct{}

func (linuxHealthcheckPrivOps) Geteuid() int                { return syscall.Geteuid() }
func (linuxHealthcheckPrivOps) ReadCapPrm() (uint64, error) { return readCapPrm() }
func (linuxHealthcheckPrivOps) SetNoNewPrivs() error        { return prctl(prSetNoNewPrivs, 1, 0, 0, 0) }
func (linuxHealthcheckPrivOps) ClearGroups() error          { return syscall.Setgroups(nil) }
func (linuxHealthcheckPrivOps) DropAllBoundingCaps() error  { return dropOtherBoundingCaps(0) }
func (linuxHealthcheckPrivOps) Setresgid(gid int) error     { return syscall.Setresgid(gid, gid, gid) }
func (linuxHealthcheckPrivOps) Setresuid(uid int) error     { return syscall.Setresuid(uid, uid, uid) }
func (linuxHealthcheckPrivOps) ClearCapabilities() error {
	hdr := capHeader{version: capabilityVers3}
	var data [2]capData
	if _, _, errno := syscall.Syscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return errno
	}
	return nil
}

// maybeDropHealthcheckPrivileges 在 --healthcheck 路径降权至 UID/GID 1000（零 capability），
// 并在当前锁定 OS 线程上同步完成后续只读目录校验后退出。
func maybeDropHealthcheckPrivileges() error {
	if !shouldDropPrivileges() || syscall.Geteuid() != 0 {
		return nil
	}
	runtime.LockOSThread()
	return dropHealthcheckPrivilegesWith(linuxHealthcheckPrivOps{})
}

// maybeDropPrivileges 在生产容器（MIRROR_DROP_PRIVS=1 且以 root 启动）中将进程
// 降权至 UID/GID 1000 并通过 ambient capability 仅保留 CAP_NET_RAW/CAP_NET_ADMIN，
// 随后重新 exec 自身使全部 Go 运行时线程处于同一 UID 1000 身份。
// 这样 mirrorcap 写出的日志属主与 caddy/api/logrotator（1000:1000）完全一致，
// 且不持有 CAP_DAC_OVERRIDE 或 root 权限。
func maybeDropPrivileges() error {
	if !shouldDropPrivileges() {
		return nil
	}
	if syscall.Geteuid() != 0 {
		return nil
	}

	runtime.LockOSThread()

	// 在降权前解析自身可执行路径，避免 Setresuid 后进程变为 non-dumpable 时
	// 严格 LSM/SELinux 下执行 /proc/self/exe 受限。
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("drop-privs resolve executable: %w", err)
	}

	permitted, err := readCapPrm()
	if err != nil {
		return fmt.Errorf("drop-privs read CapPrm: %w", err)
	}
	wantCaps := []int{}
	var keepMask uint64
	for _, c := range []int{capNetRaw, capNetAdmin} {
		if permitted&(1<<uint(c)) != 0 {
			wantCaps = append(wantCaps, c)
			keepMask |= 1 << uint(c)
		}
	}
	if keepMask&(1<<capNetRaw) == 0 {
		return fmt.Errorf("drop-privs: 缺少必需的 CAP_NET_RAW（CapPrm=%016X）", permitted)
	}

	if err := prctl(prSetNoNewPrivs, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("drop-privs PR_SET_NO_NEW_PRIVS: %w", err)
	}
	if err := syscall.Setgroups(nil); err != nil {
		return fmt.Errorf("drop-privs Setgroups: %w", err)
	}
	if err := prctl(prSetKeepCaps, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("drop-privs PR_SET_KEEPCAPS: %w", err)
	}
	if err := dropOtherBoundingCaps(keepMask); err != nil {
		return fmt.Errorf("drop-privs drop bounding caps: %w", err)
	}
	if err := syscall.Setresgid(mirrorTargetGID, mirrorTargetGID, mirrorTargetGID); err != nil {
		return fmt.Errorf("drop-privs Setresgid(%d): %w", mirrorTargetGID, err)
	}
	if err := syscall.Setresuid(mirrorTargetUID, mirrorTargetUID, mirrorTargetUID); err != nil {
		return fmt.Errorf("drop-privs Setresuid(%d): %w", mirrorTargetUID, err)
	}

	hdr := capHeader{version: capabilityVers3}
	var data [2]capData
	data[0].effective = uint32(keepMask)
	data[0].permitted = uint32(keepMask)
	data[0].inheritable = uint32(keepMask)
	if _, _, errno := syscall.Syscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return fmt.Errorf("drop-privs capset: %w", errno)
	}
	for _, c := range wantCaps {
		if err := prctl(prCapAmbient, prAmbientRaise, uintptr(c), 0, 0); err != nil {
			return fmt.Errorf("drop-privs PR_CAP_AMBIENT_RAISE(%d): %w", c, err)
		}
	}

	log.Printf("[mirrorcap] privilege transition verified uid=%d gid=%d cap_mask=%016X; re-execing %s",
		mirrorTargetUID, mirrorTargetGID, keepMask, exePath)
	if err := syscall.Exec(exePath, os.Args, os.Environ()); err != nil {
		return fmt.Errorf("drop-privs exec %s: %w", exePath, err)
	}
	return nil
}

func readCapPrm() (uint64, error) {
	f, err := os.Open(processStatusRef)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "CapPrm:") {
			raw := strings.TrimSpace(strings.TrimPrefix(line, "CapPrm:"))
			return strconv.ParseUint(raw, 16, 64)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("CapPrm not found in %s", processStatusRef)
}

func dropOtherBoundingCaps(keepMask uint64) error {
	raw, err := os.ReadFile(capabilityLast)
	if err != nil {
		return err
	}
	last, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return err
	}
	for c := 0; c <= last; c++ {
		if c < 64 && keepMask&(1<<uint(c)) != 0 {
			continue
		}
		if err := prctl(prCapBSetDrop, uintptr(c), 0, 0, 0); err != nil {
			return fmt.Errorf("cap %d: %w", c, err)
		}
	}
	return nil
}

func prctl(option, arg2, arg3, arg4, arg5 uintptr) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, option, arg2, arg3, arg4, arg5, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
