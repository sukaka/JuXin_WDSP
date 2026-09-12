//go:build linux

// AF_PACKET 以太网接收句柄（裸 syscall 实现，CGO_ENABLED=0）。
//
// 存在理由（D-06）：gopacket v1.1.19 `pcapgo.NewEthernetHandle` 以接口 MTU 建
// 接收缓冲，生产 Linux 默认开启 TSO/GSO/GRO，抓包点会看到 >MTU 的聚合超帧
// （实测 5116B），被 recvmsg 静默截断且 pcapgo 不暴露 socket 级配置（fd 私有，
// 无法设 SO_RCVBUF）。本实现与 pcapgo.EthernetHandle 语义等价（SOCK_RAW +
// recvmsg + PACKET_AUXDATA + 内核时间戳 + PACKET_STATISTICS），但：
//   - 单帧接收缓冲 64KB（覆盖 TSO/GRO 聚合超帧上限）；
//   - SO_RCVBUF 目标 4MB（高带宽突发下降低内核丢包；内核按 rmem_max 钳制，
//     回读实际值记日志）；
//   - 线上真实长度经 MSG_TRUNC/auxdata 双通道取得，供 DecodePacket 截断检测；
//   - SO_RCVTIMEO 周期超时（AF_PACKET 的 shutdown 为空实现，close 无法唤醒
//     阻塞中的 recvmsg；周期 EAGAIN 让抓包循环得以及时响应 Close/重建）。
//
// 内存语义：readFrame 返回的切片指向句柄内部缓冲，仅在下一次 readFrame 前有效
// （与 pcapgo NoCopy 路径相同，消费方跨 goroutine 须拷贝）。
package capture

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"golang.org/x/sys/unix"
)

// 接收缓冲策略（D-06）。
const (
	// ethFrameBufSize 单帧接收缓冲：64KB，覆盖 TSO/GRO 聚合超帧实际上限。
	ethFrameBufSize = 64 << 10
	// ethSocketRcvBuf SO_RCVBUF 目标值：4MB。内核按 net.core.rmem_max 钳制
	// （不报错），回读实际值记日志；高带宽下仍不足时内核丢包由
	// PACKET_STATISTICS 计入 kernel_drops（既有通路上报）。
	ethSocketRcvBuf = 4 << 20
	// ethRcvTimeout SO_RCVTIMEO：recvmsg 周期超时，供抓包循环响应停止信号。
	ethRcvTimeout = time.Second
)

// errFrameTimeout 接收周期超时（非错误：无流量空转，抓包循环继续）。
var errFrameTimeout = errors.New("capture: 接收周期超时")

// htons 主机序→网络序（16 位）。
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// ethHandle AF_PACKET 接收句柄。
type ethHandle struct {
	fd     int
	iface  string
	buffer []byte // 单帧接收缓冲（复用，NoCopy 语义）
	oob    []byte // auxdata/timestamp 控制消息缓冲
}

// newEthHandle 打开接口的 AF_PACKET 句柄（需要 CAP_NET_RAW；接口须存在且 UP）。
func newEthHandle(iface string, log *slog.Logger) (*ethHandle, error) {
	intf, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("查询接口 %s: %w", iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("创建 packet socket: %w", err)
	}
	h := &ethHandle{fd: fd, iface: iface, buffer: make([]byte, ethFrameBufSize)}
	fail := func(err error) (*ethHandle, error) {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: intf.Index}); err != nil {
		return fail(fmt.Errorf("绑定接口 %s: %w", iface, err))
	}

	ooblen := 0
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1); err == nil {
		ooblen += unix.CmsgSpace(int(unsafe.Sizeof(unix.TpacketAuxdata{})))
	} else {
		log.Warn("PACKET_AUXDATA 设置失败，截断检测退化（仅以 MSG_TRUNC 长度判定）", "iface", iface, "err", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err == nil {
		ooblen += unix.CmsgSpace(int(unsafe.Sizeof(unix.Timespec{})))
	} else if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMP, 1); err == nil {
		ooblen += unix.CmsgSpace(int(unsafe.Sizeof(unix.Timeval{})))
	}
	h.oob = make([]byte, ooblen)

	// socket 接收缓冲（D-06：高带宽突发降低内核丢包）。优先 SO_RCVBUFFORCE
	// （需 CAP_NET_ADMIN，不受 rmem_max 钳制），无权限时回落 SO_RCVBUF
	// （内核按 rmem_max 静默钳制，回读生效值记日志）。
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, ethSocketRcvBuf); err != nil {
		if err2 := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, ethSocketRcvBuf); err2 != nil {
			log.Warn("SO_RCVBUF 设置失败（按内核默认运行）", "iface", iface, "err", err2)
		}
	}
	if got, gerr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF); gerr == nil {
		log.Info("AF_PACKET 接收缓冲已配置", "iface", iface,
			"frame_buf", ethFrameBufSize, "so_rcvbuf_target", ethSocketRcvBuf, "so_rcvbuf_effective", got)
	}

	// 接收周期超时：AF_PACKET 的 shutdown 是空实现（sock_no_shutdown），
	// close 也无法唤醒阻塞中的 recvmsg；周期 EAGAIN 让循环及时响应 Close。
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO,
		&unix.Timeval{Sec: int64(ethRcvTimeout / time.Second)}); err != nil {
		log.Warn("SO_RCVTIMEO 设置失败（Close 延迟可能延长）", "iface", iface, "err", err)
	}

	// 混杂模式（非致命：本机定向流量仍可捕获，沿用 mirrorcap 语义）
	mreq := unix.PacketMreq{Ifindex: int32(intf.Index), Type: unix.PACKET_MR_PROMISC}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
		log.Warn("混杂模式设置失败，仅本机定向流量可捕获", "iface", iface, "err", err)
	}
	return h, nil
}

// readFrame 阻塞读取一帧；返回帧字节（NoCopy，见包注释）与 CaptureInfo
// （Length=线上真实长度，CaptureLength=实际捕获长度；Length>CaptureLength 即截断）。
func (h *ethHandle) readFrame() ([]byte, gopacket.CaptureInfo, error) {
	var ci gopacket.CaptureInfo
	for {
		var msg unix.Msghdr
		var sa unix.RawSockaddrLinklayer
		msg.Name = (*byte)(unsafe.Pointer(&sa))
		msg.Namelen = uint32(unsafe.Sizeof(sa))
		var iov unix.Iovec
		iov.Base = &h.buffer[0]
		iov.SetLen(len(h.buffer))
		msg.Iov = &iov
		msg.Iovlen = 1
		if len(h.oob) > 0 {
			msg.Control = &h.oob[0]
			msg.SetControllen(len(h.oob))
		}
		// MSG_TRUNC：返回值 n 为线上真实长度（即使超缓冲）
		n, _, e := unix.Syscall(unix.SYS_RECVMSG, uintptr(h.fd), uintptr(unsafe.Pointer(&msg)), uintptr(unix.MSG_TRUNC))
		if e != 0 {
			if e == unix.EINTR {
				continue
			}
			if e == unix.EAGAIN || e == unix.EWOULDBLOCK {
				return nil, ci, errFrameTimeout // SO_RCVTIMEO 周期超时，非错误
			}
			return nil, ci, fmt.Errorf("recvmsg: %w", e)
		}
		ci.Length = int(n)
		ci.CaptureLength = int(n)
		h.parseOOB(msg.Controllen, &ci)
		if ci.CaptureLength > len(h.buffer) {
			ci.CaptureLength = len(h.buffer) // 超缓冲截断（Length 仍为线上真实长度）
		}
		if ci.Timestamp.IsZero() {
			ci.Timestamp = time.Now()
		}
		ci.InterfaceIndex = int(sa.Ifindex)
		return h.buffer[:ci.CaptureLength], ci, nil
	}
}

// parseOOB 解析控制消息（PACKET_AUXDATA / SO_TIMESTAMPNS / SO_TIMESTAMP）。
func (h *ethHandle) parseOOB(controllen uint64, ci *gopacket.CaptureInfo) {
	if controllen == 0 || len(h.oob) == 0 {
		return
	}
	hdrLen := unix.CmsgLen(0)
	oob := h.oob[:controllen]
	auxSize := int(unsafe.Sizeof(unix.TpacketAuxdata{}))
	tsSize := int(unsafe.Sizeof(unix.Timespec{}))
	tvSize := int(unsafe.Sizeof(unix.Timeval{}))
	for len(oob) >= hdrLen {
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		if int(hdr.Len) < hdrLen || int(hdr.Len) > len(oob) {
			break
		}
		payload := oob[hdrLen:]
		switch {
		case hdr.Level == unix.SOL_PACKET && hdr.Type == unix.PACKET_AUXDATA && len(payload) >= auxSize:
			aux := (*unix.TpacketAuxdata)(unsafe.Pointer(&payload[0]))
			ci.Length = int(aux.Len) // 线上真实长度（权威来源）
		case hdr.Level == unix.SOL_SOCKET && hdr.Type == unix.SO_TIMESTAMPNS && len(payload) >= tsSize:
			ts := (*unix.Timespec)(unsafe.Pointer(&payload[0]))
			ci.Timestamp = time.Unix(int64(ts.Sec), int64(ts.Nsec))
		case hdr.Level == unix.SOL_SOCKET && hdr.Type == unix.SO_TIMESTAMP && len(payload) >= tvSize:
			tv := (*unix.Timeval)(unsafe.Pointer(&payload[0]))
			ci.Timestamp = time.Unix(int64(tv.Sec), int64(tv.Usec)*1000)
		}
		advance := unix.CmsgSpace(int(hdr.Len) - hdrLen)
		if advance <= 0 || advance > len(oob) {
			break
		}
		oob = oob[advance:]
	}
}

// stats 内核 socket 统计（自上次调用起的 packets/drops 差值语义，同 pcapgo）。
func (h *ethHandle) stats() (packets, drops uint32, err error) {
	st, err := unix.GetsockoptTpacketStats(h.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return 0, 0, err
	}
	return st.Packets, st.Drops, nil
}

// close 关闭 socket（幂等）。阻塞中的 recvmsg 由 SO_RCVTIMEO 周期超时自行退出
// （AF_PACKET 的 shutdown 为空实现，close 不唤醒阻塞 recvmsg），无需在此干预。
func (h *ethHandle) close() {
	if h.fd >= 0 {
		_ = unix.Close(h.fd)
		h.fd = -1
	}
}
