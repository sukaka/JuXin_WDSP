//go:build windows

// Windows 原生 Winsock IPv4 Raw Socket（SIO_RCVALL）旁路只读抓包回退后端。
//
// 适用场景：目标 Windows 主机未安装 Npcap 时，由 auto 回退链自动启用（零驱动、零 CGO）。
// 如实边界（跨平台契约 §3.2）：
//   - 仅支持 IPv4（不含 IPv6）；
//   - 无二层以太网头（直接 IPv4 解码，NonEthernet=true，RAW WDP1 跳过不伪造假头）；
//   - 需要管理员/SYSTEM 权限，且受本机 Windows 防火墙入站/出站策略影响；
//   - 不提供内核丢包统计（KernelStats 返回 ErrStatsUnsupported）。
package capture

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

func init() {
	RegisterRawSocketFactory(newRawSocketBackend)
}

const (
	sioRcvAll        = 0x98000001
	rcvallOn  uint32 = 1
	rawBufLen        = 64 << 10
	rawRcvBuf        = 4 << 20
	rawTimeoutMs     = 1000
)

type rawSockHandle struct {
	iface    string
	ip       string
	fd       windows.Handle
	filt     *filter.Filter
	consumer func(Packet)
	stats    *Stats
	log      *slog.Logger

	mu     sync.Mutex
	closed bool
	stopCh chan struct{}
	doneCh chan struct{}
}

type rawSocketBackend struct {
	cfg     BackendConfig
	mu      sync.Mutex
	handles map[string]*rawSockHandle
}

func newRawSocketBackend(cfg BackendConfig) (Backend, error) {
	if len(cfg.Ifaces) == 0 {
		return nil, errors.New("capture(rawsocket): 无抓包接口")
	}
	return &rawSocketBackend{cfg: cfg, handles: make(map[string]*rawSockHandle)}, nil
}

func findInterfaceIPv4(name string) (net.IP, error) {
	if ip := net.ParseIP(name); ip != nil && ip.To4() != nil {
		return ip.To4(), nil
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("查询网卡 %s: %w", name, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, fmt.Errorf("读取网卡 %s 地址: %w", name, err)
	}
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("网卡 %s 无可用非回环 IPv4 地址", name)
}

func (b *rawSocketBackend) Start() error {
	var lastErr error
	for _, name := range b.cfg.Ifaces {
		ip4, err := findInterfaceIPv4(name)
		if err != nil {
			lastErr = err
			if b.cfg.Log != nil {
				b.cfg.Log.Warn("Windows Raw Socket 跳过接口（无 IPv4）", "iface", name, "err", err)
			}
			continue
		}
		h, err := openRawSockHandle(name, ip4, b.cfg.Filter, b.cfg.Consumer, b.cfg.Stats, b.cfg.Log)
		if err != nil {
			lastErr = err
			if b.cfg.Log != nil {
				b.cfg.Log.Warn("Windows Raw Socket 打开失败（跳过该接口，Fail-Open）", "iface", name, "ip", ip4.String(), "err", err)
			}
			continue
		}
		b.mu.Lock()
		b.handles[name] = h
		b.mu.Unlock()
		go h.run()
		if b.cfg.Log != nil {
			b.cfg.Log.Info("Windows IPv4 Raw Socket 回退抓包已启动（仅 IPv4，生产建议安装 Npcap）",
				"iface", name, "ip", ip4.String())
		}
	}
	b.mu.Lock()
	n := len(b.handles)
	b.mu.Unlock()
	if n == 0 {
		if lastErr == nil {
			lastErr = ErrRawSocketUnavailable
		}
		return fmt.Errorf("Windows Raw Socket 全部接口启动失败（需要管理员权限）: %w", lastErr)
	}
	return nil
}

func (b *rawSocketBackend) Close() error {
	b.mu.Lock()
	handles := make([]*rawSockHandle, 0, len(b.handles))
	for name, h := range b.handles {
		handles = append(handles, h)
		delete(b.handles, name)
	}
	b.mu.Unlock()
	for _, h := range handles {
		_ = h.close()
	}
	return nil
}

func (b *rawSocketBackend) SetPorts(ports []uint16) {
	b.cfg.Filter.SetPorts(ports)
}

func (b *rawSocketBackend) KernelStats() (uint32, uint32, error) {
	return 0, 0, ErrStatsUnsupported
}

func openRawSockHandle(iface string, ip4 net.IP, filt *filter.Filter, consumer func(Packet), st *Stats, log *slog.Logger) (*rawSockHandle, error) {
	fd, err := windows.Socket(windows.AF_INET, windows.SOCK_RAW, windows.IPPROTO_IP)
	if err != nil {
		return nil, fmt.Errorf("Socket(AF_INET, SOCK_RAW): %w", err)
	}
	fail := func(err error) (*rawSockHandle, error) {
		_ = windows.Closesocket(fd)
		return nil, err
	}

	var addr [4]byte
	copy(addr[:], ip4.To4())
	if err := windows.Bind(fd, &windows.SockaddrInet4{Port: 0, Addr: addr}); err != nil {
		return fail(fmt.Errorf("Bind(%s): %w", ip4.String(), err))
	}

	_ = windows.SetsockoptInt(fd, windows.SOL_SOCKET, windows.SO_RCVBUF, rawRcvBuf)
	// Windows SO_RCVTIMEO 接收毫秒整数（DWORD）
	if err := windows.SetsockoptInt(fd, windows.SOL_SOCKET, windows.SO_RCVTIMEO, rawTimeoutMs); err != nil && log != nil {
		log.Warn("Windows Raw Socket SO_RCVTIMEO 设置失败", "iface", iface, "err", err)
	}

	inVal := rcvallOn
	var bytesRet uint32
	if err := windows.WSAIoctl(
		fd,
		sioRcvAll,
		(*byte)(unsafe.Pointer(&inVal)),
		uint32(unsafe.Sizeof(inVal)),
		nil,
		0,
		&bytesRet,
		nil,
		0,
	); err != nil {
		return fail(fmt.Errorf("WSAIoctl(SIO_RCVALL): %w", err))
	}

	return &rawSockHandle{
		iface:    iface,
		ip:       ip4.String(),
		fd:       fd,
		filt:     filt,
		consumer: consumer,
		stats:    st,
		log:      log,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}, nil
}

func (h *rawSockHandle) run() {
	defer close(h.doneCh)
	defer func() {
		if r := recover(); r != nil && h.log != nil {
			h.log.Error("Windows Raw Socket 抓包 panic 已捕获（Fail-Open）", "iface", h.iface, "panic", r)
		}
	}()
	buf := make([]byte, rawBufLen)
	for {
		select {
		case <-h.stopCh:
			return
		default:
		}
		n, _, err := windows.Recvfrom(h.fd, buf, 0)
		if err != nil {
			if errors.Is(err, windows.WSAETIMEDOUT) || errors.Is(err, windows.WSAEINTR) {
				continue
			}
			select {
			case <-h.stopCh:
				return
			default:
			}
			if h.log != nil {
				h.log.Warn("Windows Raw Socket 读取异常，停止该接口采集（Fail-Open）", "iface", h.iface, "err", err)
			}
			return
		}
		if n <= 0 {
			continue
		}
		if p, keep := DecodeRawIPv4Frame(buf[:n], time.Now(), h.filt, h.stats); keep {
			h.consume(p)
		}
	}
}

func (h *rawSockHandle) consume(p Packet) {
	defer func() {
		if r := recover(); r != nil && h.log != nil {
			h.log.Error("Windows Raw Socket 消费回调 panic 已捕获", "iface", h.iface, "panic", r)
		}
	}()
	h.consumer(p)
}

func (h *rawSockHandle) close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	close(h.stopCh)
	fd := h.fd
	h.fd = windows.InvalidHandle
	h.mu.Unlock()

	if fd != windows.InvalidHandle {
		_ = windows.Closesocket(fd)
	}
	<-h.doneCh
	return nil
}
