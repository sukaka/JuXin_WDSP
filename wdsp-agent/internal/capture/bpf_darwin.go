//go:build darwin

// macOS 原生 BPF（/dev/bpf*）旁路只读抓包后端（零 CGO、零新增依赖）。
//
// 安全红线：
//   - 强制 unix.O_RDONLY | unix.O_NONBLOCK 打开 /dev/bpfN，内核级物理保证绝无发包/注入能力；
//   - 使用 unix.Poll + 唤醒管道（wakePipe）实现零延迟优雅关闭，避免多线程 Close/Read 竞态；
//   - 全部 goroutine recover() 保护，失败降级不退出进程。
package capture

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"

	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

func init() {
	RegisterBPFFactory(newBPFBackend)
}

const (
	bpfMaxDevices     = 256
	bpfPollTimeoutMs  = 250
	bpfReadTimeoutSec = 1
)

// darwinIfreq 匹配 BSD struct ifreq（ifr_name[16] + union 16B = 32B）。
type darwinIfreq struct {
	Name [16]byte
	Pad  [16]byte
}

type bpfHandle struct {
	iface    string
	fd       int
	wakeR    int
	wakeW    int
	buf      []byte
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

type bpfBackend struct {
	cfg BackendConfig

	mu      sync.Mutex
	handles map[string]*bpfHandle
}

func newBPFBackend(cfg BackendConfig) (Backend, error) {
	if len(cfg.Ifaces) == 0 {
		return nil, errors.New("capture(bpf): 无抓包接口")
	}
	return &bpfBackend{cfg: cfg, handles: make(map[string]*bpfHandle)}, nil
}

func (b *bpfBackend) Start() error {
	var lastErr error
	for _, name := range b.cfg.Ifaces {
		h, err := openBPFHandle(name, b.cfg.Filter, b.cfg.Consumer, b.cfg.Stats, b.cfg.Log)
		if err != nil {
			lastErr = err
			if b.cfg.Log != nil {
				b.cfg.Log.Warn("macOS BPF 打开接口失败（跳过该接口，Fail-Open）", "iface", name, "err", err)
			}
			continue
		}
		b.mu.Lock()
		b.handles[name] = h
		b.mu.Unlock()
		go h.run()
		if b.cfg.Log != nil {
			b.cfg.Log.Info("macOS BPF 抓包已启动", "iface", name, "buf_len", len(h.buf), "link_type", h.linkType.String())
		}
	}
	b.mu.Lock()
	n := len(b.handles)
	b.mu.Unlock()
	if n == 0 {
		if lastErr == nil {
			lastErr = ErrBPFUnavailable
		}
		return fmt.Errorf("macOS BPF 全部接口启动失败（需要 root 或 access_bpf 权限）: %w", lastErr)
	}
	return nil
}

func (b *bpfBackend) Close() error {
	b.mu.Lock()
	handles := make([]*bpfHandle, 0, len(b.handles))
	for name, h := range b.handles {
		handles = append(handles, h)
		delete(b.handles, name)
	}
	b.mu.Unlock()

	var wg sync.WaitGroup
	for _, h := range handles {
		wg.Add(1)
		go func(handle *bpfHandle) {
			defer wg.Done()
			_ = handle.close()
		}(h)
	}
	wg.Wait()
	return nil
}

func (b *bpfBackend) SetPorts(ports []uint16) {
	b.cfg.Filter.SetPorts(ports)
}

func (b *bpfBackend) KernelStats() (packets, drops uint32, err error) {
	b.mu.Lock()
	handles := make([]*bpfHandle, 0, len(b.handles))
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
			lastErr = errors.New("capture(bpf): 无活动句柄")
		}
		return 0, 0, lastErr
	}
	return packets, drops, nil
}

func openFreeBPFDevice() (int, error) {
	var lastErr error
	for i := 0; i < bpfMaxDevices; i++ {
		path := fmt.Sprintf("/dev/bpf%d", i)
		// 强制 O_RDONLY|O_NONBLOCK：内核级只读保证，且配合 Poll 无阻塞退出
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			return fd, nil
		}
		lastErr = err
		if errors.Is(err, unix.EBUSY) {
			continue
		}
		if errors.Is(err, unix.ENOENT) {
			break
		}
		return -1, fmt.Errorf("打开 %s 失败: %w", path, err)
	}
	if lastErr == nil {
		lastErr = errors.New("无可用 /dev/bpf 设备")
	}
	return -1, lastErr
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

func openBPFHandle(iface string, filt *filter.Filter, consumer func(Packet), st *Stats, log *slog.Logger) (*bpfHandle, error) {
	if len(iface) == 0 || len(iface) >= 16 {
		return nil, fmt.Errorf("非法接口名 %q", iface)
	}
	fd, err := openFreeBPFDevice()
	if err != nil {
		return nil, err
	}
	var pipeFds [2]int
	if err := unix.Pipe(pipeFds[:]); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("创建唤醒管道失败: %w", err)
	}
	unix.CloseOnExec(pipeFds[0])
	unix.CloseOnExec(pipeFds[1])
	_ = unix.SetNonblock(pipeFds[0], true)
	_ = unix.SetNonblock(pipeFds[1], true)

	fail := func(err error) (*bpfHandle, error) {
		_ = unix.Close(fd)
		_ = unix.Close(pipeFds[0])
		_ = unix.Close(pipeFds[1])
		return nil, err
	}

	// 1. 尝试调大 BPF 内核缓冲
	for _, want := range []uint32{1 << 20, 512 << 10, 256 << 10, 65536} {
		v := want
		if err := ioctlPtr(fd, unix.BIOCSBLEN, unsafe.Pointer(&v)); err == nil {
			break
		}
	}

	// 2. 绑定目标网卡
	var ifr darwinIfreq
	copy(ifr.Name[:], iface)
	if err := ioctlPtr(fd, unix.BIOCSETIF, unsafe.Pointer(&ifr)); err != nil {
		return fail(fmt.Errorf("BIOCSETIF(%s): %w", iface, err))
	}

	// 3. 启用 Immediate 模式（收到包即交付）
	one := uint32(1)
	if err := ioctlPtr(fd, unix.BIOCIMMEDIATE, unsafe.Pointer(&one)); err != nil {
		return fail(fmt.Errorf("BIOCIMMEDIATE: %w", err))
	}

	// 4. 兜底读超时
	tv := unix.Timeval{Sec: bpfReadTimeoutSec}
	_ = ioctlPtr(fd, unix.BIOCSRTIMEOUT, unsafe.Pointer(&tv))

	// 5. 尽力启用混杂模式（非致命）
	if err := ioctlPtr(fd, unix.BIOCPROMISC, nil); err != nil && log != nil {
		log.Warn("macOS BPF 混杂模式设置失败，仅本机定向流量可见", "iface", iface, "err", err)
	}

	// 6. 读取数据链路类型
	var dlt uint32
	if err := ioctlPtr(fd, unix.BIOCGDLT, unsafe.Pointer(&dlt)); err != nil {
		return fail(fmt.Errorf("BIOCGDLT: %w", err))
	}
	var linkType gopacket.LayerType
	switch dlt {
	case unix.DLT_EN10MB:
		linkType = layers.LayerTypeEthernet
		attachEthernetIPFilter(fd, iface, log)
	case unix.DLT_NULL:
		linkType = layers.LayerTypeLoopback
	default:
		return fail(fmt.Errorf("不支持的数据链路类型 DLT=%d（iface=%s）", dlt, iface))
	}

	// 7. 回读最终生效的 BPF 缓冲区长度
	var blen uint32
	if err := ioctlPtr(fd, unix.BIOCGBLEN, unsafe.Pointer(&blen)); err != nil || blen == 0 {
		return fail(fmt.Errorf("BIOCGBLEN 失败: %v", err))
	}

	return &bpfHandle{
		iface:    iface,
		fd:       fd,
		wakeR:    pipeFds[0],
		wakeW:    pipeFds[1],
		buf:      make([]byte, blen),
		linkType: linkType,
		filt:     filt,
		consumer: consumer,
		stats:    st,
		log:      log,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}, nil
}

// attachEthernetIPFilter 挂载轻量内核 BPF 程序过滤非 IP 帧。
func attachEthernetIPFilter(fd int, iface string, log *slog.Logger) {
	insns := []unix.BpfInsn{
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 12},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 3, Jf: 0, K: 0x0800},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 2, Jf: 0, K: 0x86dd},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, Jf: 0, K: 0x8100},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0x00040000},
	}
	prog := unix.BpfProgram{
		Len:   uint32(len(insns)),
		Insns: &insns[0],
	}
	if err := ioctlPtr(fd, unix.BIOCSETF, unsafe.Pointer(&prog)); err != nil && log != nil {
		log.Warn("macOS BPF 内核预过滤挂载失败（降级全帧用户态过滤）", "iface", iface, "err", err)
	}
}

func (h *bpfHandle) run() {
	defer close(h.doneCh)
	defer func() {
		if r := recover(); r != nil && h.log != nil {
			h.log.Error("macOS BPF 抓包 panic 已捕获（Fail-Open）", "iface", h.iface, "panic", r)
		}
	}()
	fds := []unix.PollFd{
		{Fd: int32(h.fd), Events: unix.POLLIN},
		{Fd: int32(h.wakeR), Events: unix.POLLIN},
	}
	for {
		select {
		case <-h.stopCh:
			return
		default:
		}
		fds[0].Revents = 0
		fds[1].Revents = 0
		nReady, err := unix.Poll(fds, bpfPollTimeoutMs)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			select {
			case <-h.stopCh:
				return
			default:
			}
			if h.log != nil {
				h.log.Warn("macOS BPF poll 异常，停止该接口采集（Fail-Open）", "iface", h.iface, "err", err)
			}
			return
		}
		if fds[1].Revents != 0 {
			return // 收到唤醒管道关闭/写入信号，立即退出
		}
		if nReady == 0 || fds[0].Revents&unix.POLLIN == 0 {
			continue
		}

		n, err := unix.Read(h.fd, h.buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			select {
			case <-h.stopCh:
				return
			default:
			}
			if h.log != nil {
				h.log.Warn("macOS BPF 读取异常，停止该接口采集（Fail-Open）", "iface", h.iface, "err", err)
			}
			return
		}
		if n <= 0 {
			continue
		}
		ParseBPFBuffer(h.buf[:n], unix.BPF_ALIGNMENT, func(frame BPFFrame) {
			pkt := gopacket.NewPacket(frame.Data, h.linkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			pkt.Metadata().Timestamp = frame.Timestamp
			pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{
				Timestamp:     frame.Timestamp,
				CaptureLength: frame.CapLen,
				Length:        frame.OrigLen,
			}
			if p, keep := DecodePacket(pkt, h.filt, h.stats); keep {
				h.consume(p)
			}
		})
	}
}

func (h *bpfHandle) consume(p Packet) {
	defer func() {
		if r := recover(); r != nil && h.log != nil {
			h.log.Error("macOS BPF 消费回调 panic 已捕获", "iface", h.iface, "panic", r)
		}
	}()
	h.consumer(p)
}

func (h *bpfHandle) kernelStats() (uint32, uint32, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.fd < 0 {
		return 0, 0, errors.New("BPF 句柄已关闭")
	}
	var st unix.BpfStat
	if err := ioctlPtr(h.fd, unix.BIOCGSTATS, unsafe.Pointer(&st)); err != nil {
		return 0, 0, err
	}
	dRecv, dDrop := h.delta.Diff(st.Recv, st.Drop)
	return dRecv, dDrop, nil
}

func (h *bpfHandle) close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	close(h.stopCh)
	wakeW := h.wakeW
	h.wakeW = -1
	h.mu.Unlock()

	// 先关闭唤醒写端，瞬间唤醒 Poll，等待读协程退出后再释放 bpf fd 与 wakeR
	if wakeW >= 0 {
		_, _ = unix.Write(wakeW, []byte{1})
		_ = unix.Close(wakeW)
	}
	<-h.doneCh

	h.mu.Lock()
	if h.fd >= 0 {
		_ = unix.Close(h.fd)
		h.fd = -1
	}
	if h.wakeR >= 0 {
		_ = unix.Close(h.wakeR)
		h.wakeR = -1
	}
	h.mu.Unlock()
	return nil
}
