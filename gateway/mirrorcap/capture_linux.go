//go:build linux

// 抓包层（Linux）：AF_PACKET 纯 syscall raw socket（零 cgo，静态编译）。
//
// 实现要点：
//   - 64KB 单帧接收缓冲：修复 pcapgo.NewEthernetHandle 按 intf.MTU（1500B）分配导致
//     标准 1514B 以太网帧、1518B 802.1Q SPAN VLAN 帧及 Linux GRO/TSO 聚合超帧被静默截断的问题；
//   - SO_RCVBUFFORCE（回退 SO_RCVBUF）目标 4MB：高带宽突发下降低内核丢包；
//   - SO_RCVTIMEO 1s 周期超时：AF_PACKET 的 close 不唤醒阻塞中的 recvmsg，通过周期
//     EAGAIN 让单协程 Run() 及时响应 Close()，避免 goroutine 永久泄漏与 fd 复用竞态；
//   - 单协程拥有 tcpassembly.Assembler：Run() 退出 defer 中冲刷关闭全部重组流并关闭 socket，
//     Close() 仅关闭 stopCh，消除 Close 与 Run 并发操作 Assembler 的数据竞争；
//   - 角色分流：纯检测句柄按目的端口集合过滤；承担发现角色的句柄放宽为全量 TCP，
//     检测端口过滤下沉到流工厂分流（共享同一原子端口集合指针，SetPorts 热更新一致生效）。
package mirrorcap

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"golang.org/x/sys/unix"
)

const (
	// ethFrameBufSize 单帧接收缓冲：64KB，覆盖满帧以太网、802.1Q/QinQ VLAN 及 GRO/TSO 聚合超帧。
	ethFrameBufSize = 64 << 10
	// ethSocketRcvBuf SO_RCVBUF 目标值：4MB（优先 SO_RCVBUFFORCE，无权时回落 SO_RCVBUF）。
	ethSocketRcvBuf = 4 << 20
	// ethRcvTimeout SO_RCVTIMEO：recvmsg 周期超时，使 Run() 及时响应 Close() 退出。
	ethRcvTimeout = time.Second
)

var errFrameTimeout = errors.New("mirrorcap: capture read timeout")

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// ethHandle AF_PACKET 原始套接字句柄。
type ethHandle struct {
	mu     sync.Mutex // 保护 fd 关闭与并发 stats 读取
	fd     int
	iface  string
	buffer []byte
	oob    []byte
}

func newEthHandle(ifname string) (*ethHandle, error) {
	intf, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("查询接口 %s: %w", ifname, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("创建 packet socket: %w", err)
	}
	fail := func(err error) (*ethHandle, error) {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  intf.Index,
	}); err != nil {
		return fail(fmt.Errorf("绑定接口 %s: %w", ifname, err))
	}

	ooblen := 0
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1); err == nil {
		ooblen += unix.CmsgSpace(int(unsafe.Sizeof(unix.TpacketAuxdata{})))
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err == nil {
		ooblen += unix.CmsgSpace(int(unsafe.Sizeof(unix.Timespec{})))
	} else if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMP, 1); err == nil {
		ooblen += unix.CmsgSpace(int(unsafe.Sizeof(unix.Timeval{})))
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, ethSocketRcvBuf); err != nil {
		if err2 := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, ethSocketRcvBuf); err2 != nil {
			log.Printf("[mirrorcap] warn: 接口 %s SO_RCVBUF 设置失败（按内核默认运行）: %v", ifname, err2)
		}
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO,
		&unix.Timeval{Sec: int64(ethRcvTimeout / time.Second)}); err != nil {
		log.Printf("[mirrorcap] warn: 接口 %s SO_RCVTIMEO 设置失败: %v", ifname, err)
	}

	// SPAN/镜像口流量目的 MAC 非本机，开启混杂模式；失败不致命（本机定向流量仍可捕获）
	mreq := unix.PacketMreq{Ifindex: int32(intf.Index), Type: unix.PACKET_MR_PROMISC}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
		log.Printf("[mirrorcap] warn: 接口 %s 混杂模式设置失败: %v（仅本机定向流量可捕获）", ifname, err)
	}

	return &ethHandle{
		fd:     fd,
		iface:  ifname,
		buffer: make([]byte, ethFrameBufSize),
		oob:    make([]byte, ooblen),
	}, nil
}

// shouldSkipPacketType 跳过 PACKET_OUTGOING 出向帧：透明网桥双 TRAFFIC 口同时抓包时，
// 同一转发帧在入网口以非 OUTGOING 捕获、在出网口以 PACKET_OUTGOING 再次出现；跳过出向帧避免双计 hits。
func shouldSkipPacketType(pkttype uint8) bool {
	return pkttype == unix.PACKET_OUTGOING
}

// readFrame 读取单帧以太网报文（仅在 Run() 单协程调用）。
func (h *ethHandle) readFrame() ([]byte, gopacket.CaptureInfo, error) {
	for {
		var ci gopacket.CaptureInfo
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

		n, _, e := unix.Syscall(unix.SYS_RECVMSG, uintptr(h.fd), uintptr(unsafe.Pointer(&msg)), uintptr(unix.MSG_TRUNC))
		if e != 0 {
			if e == unix.EINTR {
				continue
			}
			if e == unix.EAGAIN || e == unix.EWOULDBLOCK {
				return nil, ci, errFrameTimeout
			}
			return nil, ci, fmt.Errorf("recvmsg(%s): %w", h.iface, e)
		}
		if shouldSkipPacketType(sa.Pkttype) {
			continue
		}
		ci.Length = int(n)
		ci.CaptureLength = int(n)
		h.parseOOB(uint64(msg.Controllen), &ci)
		if ci.CaptureLength > len(h.buffer) {
			ci.CaptureLength = len(h.buffer)
		}
		if ci.Timestamp.IsZero() {
			ci.Timestamp = time.Now()
		}
		ci.InterfaceIndex = int(sa.Ifindex)
		return h.buffer[:ci.CaptureLength], ci, nil
	}
}

func (h *ethHandle) parseOOB(controllen uint64, ci *gopacket.CaptureInfo) {
	if controllen == 0 || len(h.oob) == 0 {
		return
	}
	if controllen > uint64(len(h.oob)) {
		controllen = uint64(len(h.oob))
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
			ci.Length = int(aux.Len)
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

// stats 读取内核自上次调用以来的 packets/drops 周期增量（goroutine 安全）。
func (h *ethHandle) stats() (packets, drops uint32, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fd < 0 {
		return 0, 0, errors.New("socket closed")
	}
	st, err := unix.GetsockoptTpacketStats(h.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return 0, 0, err
	}
	return st.Packets, st.Drops, nil
}

// close 关闭底层 socket（幂等，goroutine 安全）。
func (h *ethHandle) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fd >= 0 {
		_ = unix.Close(h.fd)
		h.fd = -1
	}
}

// Capture 抓包→重组主循环（Linux）。
type Capture struct {
	cfg        Config
	ports      atomic.Pointer[map[uint16]struct{}] // 检测端口集合（与流工厂共享；SetPorts 热更新，feed 无锁读）
	captureAll bool                                // 承担发现角色：抓包层不按端口过滤（全量 TCP 进重组）
	handle     *ethHandle
	assembler  *tcpassembly.Assembler
	stats      *Stats
	stopCh     chan struct{}
	stopOnce   sync.Once
}

// NewCapture 打开镜像接口（需要 CAP_NET_RAW；混杂模式与大缓冲需要 CAP_NET_ADMIN）。
// consumer 为本接口流消费组合（检测/发现/双角色；发现角色开启时抓全量 TCP）。
func NewCapture(cfg Config, consumer IfaceConsumer, stats *Stats) (*Capture, error) {
	h, err := newEthHandle(cfg.Iface)
	if err != nil {
		return nil, fmt.Errorf("打开镜像接口 %s: %w（需要 cap_net_raw；接口须存在且 UP）", cfg.Iface, err)
	}
	if cfg.StreamIdleTimeout <= 0 {
		cfg.StreamIdleTimeout = defaultStreamIdle
	}
	c := &Capture{
		cfg:        cfg,
		handle:     h,
		stats:      stats,
		stopCh:     make(chan struct{}),
		captureAll: consumer.Sniff != nil,
	}
	ports := cfg.PortSet()
	c.ports.Store(&ports)
	pool := tcpassembly.NewStreamPool(newIfaceStreamFactory(consumer, &c.ports, cfg.BodyMax, cfg.MaxStreamConns, stats))
	c.assembler = tcpassembly.NewAssembler(pool)
	return c, nil
}

// SetPorts 热更新目标端口过滤集合（配置文件端口变化时由 Supervisor 调用；
// 整表原子替换，feed 与流工厂分流同一指针无锁读，句柄不重启、在途流不中断）。
func (c *Capture) SetPorts(ports []uint16) {
	m := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		m[p] = struct{}{}
	}
	c.ports.Store(&m)
}

// StatsFunc 返回内核 socket 统计读取闭包（供 Stats.Logger 周期采集丢包增量）。
func (c *Capture) StatsFunc() func() (packets, drops uint32, err error) {
	return c.handle.stats
}

// Run 主循环：同步读帧 → 端口过滤（发现角色句柄不过滤）→ TCP 重组；周期冲刷空闲流。
// 退出时由本协程独占收尾：冲刷关闭全部重组流并关闭底层 socket（零数据竞争、零协程泄漏）。
func (c *Capture) Run() error {
	defer func() {
		c.assembler.FlushWithOptions(tcpassembly.FlushOptions{T: time.Now(), CloseAll: true})
		c.handle.close()
	}()

	flushInterval := c.cfg.StreamIdleTimeout / 2
	if flushInterval < time.Second {
		flushInterval = time.Second
	}
	lastFlush := time.Now()
	decodeOpts := gopacket.DecodeOptions{Lazy: true, NoCopy: true}

	for {
		select {
		case <-c.stopCh:
			return nil
		default:
		}

		raw, ci, err := c.handle.readFrame()
		now := time.Now()
		if now.Sub(lastFlush) >= flushInterval {
			c.assembler.FlushWithOptions(tcpassembly.FlushOptions{
				T: now.Add(-c.cfg.StreamIdleTimeout),
			})
			lastFlush = now
		}

		if err != nil {
			if errors.Is(err, errFrameTimeout) {
				continue
			}
			select {
			case <-c.stopCh:
				return nil
			default:
			}
			return err
		}

		// 拷贝帧字节后交由 gopacket/tcpassembly 持有，避免下一次 readFrame 覆写共享接收缓冲
		owned := make([]byte, len(raw))
		copy(owned, raw)
		pkt := gopacket.NewPacket(owned, layers.LayerTypeEthernet, decodeOpts)
		m := pkt.Metadata()
		m.CaptureInfo = ci
		m.Truncated = ci.CaptureLength < ci.Length
		c.feed(pkt)
	}
}

// feed 解析单包并送入重组器。纯检测句柄仅放行 TCP 且目的端口命中集合的包；
// 发现角色句柄放行全量 TCP（端口过滤下沉到流工厂分流）。
func (c *Capture) feed(pkt gopacket.Packet) {
	if c.stats != nil {
		c.stats.PacketsCaptured.Add(1)
	}
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		if c.stats != nil {
			c.stats.PacketsFiltered.Add(1)
		}
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)
	if !c.captureAll {
		ports := c.ports.Load()
		if _, ok := (*ports)[uint16(tcp.DstPort)]; !ok {
			// 仅重组 client→server 方向；响应方向（源端口命中）与非目标端口一并过滤
			if c.stats != nil {
				c.stats.PacketsFiltered.Add(1)
			}
			return
		}
	}
	nl := pkt.NetworkLayer()
	if nl == nil {
		if c.stats != nil {
			c.stats.PacketsFiltered.Add(1)
		}
		return
	}
	ts := pkt.Metadata().Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	c.assembler.AssembleWithTimestamp(nl.NetworkFlow(), tcp, ts)
}

// Close 通知抓包循环停止（幂等、goroutine 安全）；资源释放由 Run() defer 确定性完成。
func (c *Capture) Close() error {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	return nil
}

// 确保 io.Closer 语义可用（防未来重构误删 Close）。
var _ io.Closer = (*Capture)(nil)

// 确保 *Capture 满足 Supervisor 的 Runner 抽象（编译期检查）。
var _ Runner = (*Capture)(nil)
