//go:build linux

// SO_ORIGINAL_DST 读取（Linux netfilter 专有）：对经 nat/PREROUTING REDIRECT
// 牵引到本机的连接，从 conntrack 取出 NAT 改写前的原始目的地址。
package tproxyd

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// soOriginalDst SO_ORIGINAL_DST（linux/uapi 固定值 80，netfilter_ipv4）。
const soOriginalDst = 80

// originalDst 读取被 REDIRECT 牵引连接的原始目的地址。
// 仅使用标准库 syscall（CGO_ENABLED=0 纯静态产物，无新增依赖）。
func originalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("SyscallConn: %w", err)
	}
	var sa syscall.RawSockaddrInet4
	size := uint32(syscall.SizeofSockaddrInet4)
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd,
			syscall.SOL_IP, soOriginalDst,
			uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&size)), 0)
		if errno != 0 {
			sockErr = errno
		}
	}); err != nil {
		return nil, fmt.Errorf("getsockopt 控制入口: %w", err)
	}
	if sockErr != nil {
		return nil, fmt.Errorf("getsockopt(SO_ORIGINAL_DST): %w", sockErr)
	}
	return DecodeOriginalDst(sa.Family, sa.Port, sa.Addr)
}
