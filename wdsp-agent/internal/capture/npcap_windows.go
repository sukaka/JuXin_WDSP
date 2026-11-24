//go:build windows

// Windows Npcap（wpcap.dll）动态只读加载抓包后端（零 CGO、零专有驱动捆绑）。
//
// 安全与合规红线：
//   - Npcap 属专有许可，本系统严禁随包分发 Npcap 安装器或 wpcap.dll；
//   - 仅在运行期从 %SystemRoot%\System32\Npcap\wpcap.dll 动态加载，且强制使用
//     LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR 防止 DLL 劫持；
//   - 仅绑定只读抓包导出符号，刻意不绑定 pcap_sendpacket / pcap_inject 等写接口；
//   - 宿主机未安装 Npcap 时返回 ErrNpcapUnavailable，由 StartBackend 自动回退 rawsocket。
package capture

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/windows"

	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

func init() {
	RegisterNpcapFactory(newNpcapBackend)
}

const (
	npcapSnaplen    = 65535
	npcapBufferSize = 4 << 20
	npcapTimeoutMs  = 500
	npcapMaxCapLen  = 256 << 10
)

// winPcapPktHdr 匹配 Windows LLP64 struct pcap_pkthdr（timeval 在 Win64 上为 int32+int32）。
type winPcapPktHdr struct {
	Sec    int32
	Usec   int32
	CapLen uint32
	Len    uint32
}

// winPcapStat 匹配 struct pcap_stat（累计计数）。
type winPcapStat struct {
	Recv   uint32
	Drop   uint32
	IfDrop uint32
}

// npcapAPI 仅绑定只读符号（绝不绑定发包/注入符号）。
type npcapAPI struct {
	dll              windows.Handle
	pcapCreate       uintptr
	pcapSetSnaplen   uintptr
	pcapSetPromisc   uintptr
	pcapSetTimeout   uintptr
	pcapSetBufSize   uintptr
	pcapActivate     uintptr
	pcapDatalink     uintptr
	pcapNextEx       uintptr
	pcapStats        uintptr
	pcapBreakloop    uintptr
	pcapClose        uintptr
}

var (
	npcapOnce   sync.Once
	npcapLoaded *npcapAPI
	npcapLoadEr error
)

func loadNpcapAPI() (*npcapAPI, error) {
	npcapOnce.Do(func() {
		paths := BuildNpcapDLLPaths(os.Getenv("SystemRoot"))
		var lastErr error
		for _, p := range paths {
			if !sanitizeNpcapPath(p) {
				continue
			}
			// 安全加载标志：仅允许 System32 与 wpcap.dll 所在 Npcap 目录，绝不搜索当前工作目录
			h, err := windows.LoadLibraryEx(p, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32|windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR)
			if err != nil {
				lastErr = err
				continue
			}
			api, err := bindNpcapReadOnlySymbols(h)
			if err != nil {
				_ = windows.FreeLibrary(h)
				lastErr = err
				continue
			}
			npcapLoaded = api
			return
		}
		if lastErr != nil {
			npcapLoadEr = fmt.Errorf("%w: 未检测到宿主 Npcap (%v)", ErrNpcapUnavailable, lastErr)
		} else {
			npcapLoadEr = ErrNpcapUnavailable
		}
	})
	return npcapLoaded, npcapLoadEr
}

func bindNpcapReadOnlySymbols(h windows.Handle) (*npcapAPI, error) {
	resolve := func(name string) (uintptr, error) {
		p, err := windows.GetProcAddress(h, name)
		if err != nil {
			return 0, fmt.Errorf("wpcap.dll 缺少只读符号 %s: %w", name, err)
		}
		return p, nil
	}
	api := &npcapAPI{dll: h}
	var err error
	if api.pcapCreate, err = resolve("pcap_create"); err != nil {
		return nil, err
	}
	if api.pcapSetSnaplen, err = resolve("pcap_set_snaplen"); err != nil {
		return nil, err
	}
	if api.pcapSetPromisc, err = resolve("pcap_set_promisc"); err != nil {
		return nil, err
	}
	if api.pcapSetTimeout, err = resolve("pcap_set_timeout"); err != nil {
		return nil, err
	}
	if api.pcapSetBufSize, err = resolve("pcap_set_buffer_size"); err != nil {
		return nil, err
	}
	if api.pcapActivate, err = resolve("pcap_activate"); err != nil {
		return nil, err
	}
	if api.pcapDatalink, err = resolve("pcap_datalink"); err != nil {
		return nil, err
	}
	if api.pcapNextEx, err = resolve("pcap_next_ex"); err != nil {
		return nil, err
	}
	if api.pcapStats, err = resolve("pcap_stats"); err != nil {
		return nil, err
	}
	if api.pcapBreakloop, err = resolve("pcap_breakloop"); err != nil {
		return nil, err
	}
	if api.pcapClose, err = resolve("pcap_close"); err != nil {
		return nil, err
	}
	return api, nil
}

func pcapActivateErrText(rc int32) string {
	switch rc {
	case -3:
		return "PCAP_ERROR_NOT_ACTIVATED"
	case -4:
		return "PCAP_ERROR_ACTIVATED"
	case -5:
		return "PCAP_ERROR_NO_SUCH_DEVICE"
	case -8:
		return "PCAP_ERROR_PERM_DENIED"
	case -9:
		return "PCAP_ERROR_IFACE_NOT_UP"
	case -11:
		return "PCAP_ERROR_PROMISC_PERM_DENIED"
	default:
		return fmt.Sprintf("PCAP_ERROR(%d)", rc)
	}
}

func listWindowsAdapters() ([]WindowsAdapterInfo, error) {
	var size uint32 = 16 << 10
	buf := make([]byte, size)
	for i := 0; i < 3; i++ {
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) && size > 0 {
			buf = make([]byte, size)
			continue
		}
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}
	var out []WindowsAdapterInfo
	for cur := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); cur != nil; cur = cur.Next {
		info := WindowsAdapterInfo{
			FriendlyName: windows.UTF16PtrToString(cur.FriendlyName),
			AdapterGUID:  windows.BytePtrToString(cur.AdapterName),
		}
		for ua := cur.FirstUnicastAddress; ua != nil; ua = ua.Next {
			if ua.Address.Sockaddr == nil {
				continue
			}
			sa, err := ua.Address.Sockaddr.Sockaddr()
			if err != nil {
				continue
			}
			if sa4, ok := sa.(*syscall.SockaddrInet4); ok {
				info.IPv4s = append(info.IPv4s, net.IP(sa4.Addr[:]).String())
			}
		}
		out = append(out, info)
	}
	return out, nil
}

type npcapHandle struct {
	iface    string
	device   string
	api      *npcapAPI
	handle   uintptr
	linkType gopacket.LayerType
	filt     *filter.Filter
	consumer func(Packet)
	stats    *Stats
	log      *slog.Logger

	mu     sync.Mutex
	closed bool
	delta  CounterDelta
	stopCh chan struct{}
	doneCh chan struct{}
}

type npcapBackend struct {
	cfg     BackendConfig
	api     *npcapAPI
	mu      sync.Mutex
	handles map[string]*npcapHandle
}

func newNpcapBackend(cfg BackendConfig) (Backend, error) {
	if len(cfg.Ifaces) == 0 {
		return nil, errors.New("capture(npcap): 无抓包接口")
	}
	api, err := loadNpcapAPI()
	if err != nil {
		return nil, err
	}
	return &npcapBackend{cfg: cfg, api: api, handles: make(map[string]*npcapHandle)}, nil
}

func (b *npcapBackend) Start() error {
	adapters, err := listWindowsAdapters()
	if err != nil && b.cfg.Log != nil {
		b.cfg.Log.Warn("Windows 适配器枚举失败，将按原始接口名尝试 Npcap 打开", "err", err)
	}
	var lastErr error
	for _, name := range b.cfg.Ifaces {
		devName := FormatNpcapDeviceName(name)
		if matched, ok := MatchWindowsAdapter(name, adapters); ok && matched.AdapterGUID != "" {
			devName = FormatNpcapDeviceName(matched.AdapterGUID)
		}
		h, err := openNpcapHandle(b.api, name, devName, b.cfg.Filter, b.cfg.Consumer, b.cfg.Stats, b.cfg.Log)
		if err != nil {
			lastErr = err
			if b.cfg.Log != nil {
				b.cfg.Log.Warn("Npcap 打开接口失败（跳过该接口，Fail-Open）", "iface", name, "device", devName, "err", err)
			}
			continue
		}
		b.mu.Lock()
		b.handles[name] = h
		b.mu.Unlock()
		go h.run()
		if b.cfg.Log != nil {
			b.cfg.Log.Info("Windows Npcap 抓包已启动", "iface", name, "device", devName, "link_type", h.linkType.String())
		}
	}
	b.mu.Lock()
	n := len(b.handles)
	b.mu.Unlock()
	if n == 0 {
		if lastErr == nil {
			lastErr = ErrNpcapUnavailable
		}
		return fmt.Errorf("Windows Npcap 全部接口启动失败: %w", lastErr)
	}
	return nil
}

func (b *npcapBackend) Close() error {
	b.mu.Lock()
	handles := make([]*npcapHandle, 0, len(b.handles))
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

func (b *npcapBackend) SetPorts(ports []uint16) {
	b.cfg.Filter.SetPorts(ports)
}

func (b *npcapBackend) KernelStats() (packets, drops uint32, err error) {
	b.mu.Lock()
	handles := make([]*npcapHandle, 0, len(b.handles))
	for _, h := range b.handles {
		handles = append(handles, h)
	}
	b.mu.Unlock()
	var lastErr error
	ok := false
	for _, h := range handles {
		p, d, herr := h.kernelStats()
		if herr != nil {
			lastErr = herr
			continue
		}
		packets += p
		drops += d
		ok = true
	}
	if !ok {
		if lastErr == nil {
			lastErr = errors.New("capture(npcap): 无活动句柄")
		}
		return 0, 0, lastErr
	}
	return packets, drops, nil
}

func openNpcapHandle(api *npcapAPI, iface, devName string, filt *filter.Filter, consumer func(Packet), st *Stats, log *slog.Logger) (*npcapHandle, error) {
	devPtr, err := syscall.BytePtrFromString(devName)
	if err != nil {
		return nil, fmt.Errorf("构造设备名失败: %w", err)
	}
	errBuf := make([]byte, 512)
	hPtr, _, _ := syscall.SyscallN(api.pcapCreate, uintptr(unsafe.Pointer(devPtr)), uintptr(unsafe.Pointer(&errBuf[0])))
	if hPtr == 0 {
		return nil, fmt.Errorf("pcap_create(%s): %s", devName, windows.BytePtrToString(&errBuf[0]))
	}
	closeOnFail := func(err error) (*npcapHandle, error) {
		_, _, _ = syscall.SyscallN(api.pcapClose, hPtr)
		return nil, err
	}

	_, _, _ = syscall.SyscallN(api.pcapSetSnaplen, hPtr, uintptr(npcapSnaplen))
	_, _, _ = syscall.SyscallN(api.pcapSetPromisc, hPtr, 1)
	_, _, _ = syscall.SyscallN(api.pcapSetTimeout, hPtr, uintptr(npcapTimeoutMs))
	_, _, _ = syscall.SyscallN(api.pcapSetBufSize, hPtr, uintptr(npcapBufferSize))

	rc, _, _ := syscall.SyscallN(api.pcapActivate, hPtr)
	if int32(rc) < 0 {
		return closeOnFail(fmt.Errorf("pcap_activate(%s) rc=%d (%s)", devName, int32(rc), pcapActivateErrText(int32(rc))))
	}

	dlt, _, _ := syscall.SyscallN(api.pcapDatalink, hPtr)
	var linkType gopacket.LayerType
	switch int32(dlt) {
	case 1: // DLT_EN10MB
		linkType = layers.LayerTypeEthernet
	case 0: // DLT_NULL
		linkType = layers.LayerTypeLoopback
	case 12, 101: // DLT_RAW
		linkType = layers.LayerTypeIPv4
	default:
		return closeOnFail(fmt.Errorf("Npcap 不支持的数据链路类型 DLT=%d", int32(dlt)))
	}

	return &npcapHandle{
		iface:    iface,
		device:   devName,
		api:      api,
		handle:   hPtr,
		linkType: linkType,
		filt:     filt,
		consumer: consumer,
		stats:    st,
		log:      log,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}, nil
}

func (h *npcapHandle) run() {
	defer close(h.doneCh)
	defer func() {
		if r := recover(); r != nil && h.log != nil {
			h.log.Error("Npcap 抓包 panic 已捕获（Fail-Open）", "iface", h.iface, "panic", r)
		}
	}()
	for {
		select {
		case <-h.stopCh:
			return
		default:
		}
		var hdr *winPcapPktHdr
		var data *byte
		rc, _, _ := syscall.SyscallN(
			h.api.pcapNextEx,
			h.handle,
			uintptr(unsafe.Pointer(&hdr)),
			uintptr(unsafe.Pointer(&data)),
		)
		res := int32(rc)
		switch {
		case res == 0:
			// 超时无包：继续循环检查 stopCh
			continue
		case res == 1:
			if hdr == nil || data == nil {
				continue
			}
			if hdr.CapLen == 0 || hdr.CapLen > npcapMaxCapLen {
				continue
			}
			frame := unsafe.Slice(data, hdr.CapLen)
			ts := time.Unix(int64(hdr.Sec), int64(hdr.Usec)*1000)
			pkt := gopacket.NewPacket(frame, h.linkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			pkt.Metadata().Timestamp = ts
			pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{
				Timestamp:     ts,
				CaptureLength: int(hdr.CapLen),
				Length:        int(hdr.Len),
			}
			if p, keep := DecodePacket(pkt, h.filt, h.stats); keep {
				h.consume(p)
			}
		case res == -2:
			// pcap_breakloop 唤醒
			return
		default:
			select {
			case <-h.stopCh:
				return
			default:
			}
			if h.log != nil {
				h.log.Warn("Npcap 读取返回错误，停止该接口采集（Fail-Open）", "iface", h.iface, "rc", res)
			}
			return
		}
	}
}

func (h *npcapHandle) consume(p Packet) {
	defer func() {
		if r := recover(); r != nil && h.log != nil {
			h.log.Error("Npcap 消费回调 panic 已捕获", "iface", h.iface, "panic", r)
		}
	}()
	h.consumer(p)
}

func (h *npcapHandle) kernelStats() (uint32, uint32, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.handle == 0 {
		return 0, 0, errors.New("Npcap 句柄已关闭")
	}
	var st winPcapStat
	rc, _, _ := syscall.SyscallN(h.api.pcapStats, h.handle, uintptr(unsafe.Pointer(&st)))
	if int32(rc) != 0 {
		return 0, 0, fmt.Errorf("pcap_stats 失败 rc=%d", int32(rc))
	}
	dRecv, dDrop := h.delta.Diff(st.Recv, st.Drop+st.IfDrop)
	return dRecv, dDrop, nil
}

func (h *npcapHandle) close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	close(h.stopCh)
	ptr := h.handle
	h.mu.Unlock()

	if ptr != 0 {
		// 先唤醒阻塞中的 pcap_next_ex，等读循环完全退出后再 pcap_close 防 UAF
		_, _, _ = syscall.SyscallN(h.api.pcapBreakloop, ptr)
	}
	<-h.doneCh

	h.mu.Lock()
	if h.handle != 0 {
		_, _, _ = syscall.SyscallN(h.api.pcapClose, h.handle)
		h.handle = 0
	}
	h.mu.Unlock()
	return nil
}
