//go:build linux

// eBPF/TC 抓包后端用户态（Linux）。
//
// 挂载模型：cilium/ebpf TCX link（bpf_link，内核 ≥ 6.6）逐网卡挂
// ingress+egress 两个 hook。TCX 为 fd 生命周期：进程退出/句柄关闭内核
// 自动摘钩，不会残留影响业务（Fail-Open 红线；区别于 clsact qdisc 持久挂载）。
// 说明：任务书表述为 "TC clsact"，因直接依赖限定 cilium/ebpf（不含 netlink
// 库），clsact 挂载需要 netlink tfilter 消息，故采用官方替代的 TCX
// （同为 TC 层 ingress/egress 挂点），详见 README「偏离声明」。
//
// Fail-Open：加载/挂载任何失败只返回错误（上层回退 AF_PACKET），
// 读循环 recover 保护，绝不退出进程；C 程序恒返回 TC_ACT_OK，不丢业务包。
package ebpfcapture

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/jiuzhang-waf/wdsp-agent/internal/capture"
)

// init 把 eBPF 后端工厂注入 capture 包（agent 经 capture.StartBackend 选择）。
func init() {
	capture.RegisterEBPFFactory(NewBackend)
}

// Backend eBPF/TC 抓包后端（单实例覆盖多网卡、双方向 hook）。
type Backend struct {
	cfg          capture.BackendConfig
	snaplen      int
	ringbufBytes int

	mu     sync.Mutex
	objs   tcCaptureObjects
	links  []link.Link
	rd     *ringbuf.Reader
	ports  map[uint16]struct{}
	loaded bool

	// 内核计数上次读数：BPF 侧为累计值，内部差分后对外暴露「自上次调用
	// 起的差值」，与 AF_PACKET PACKET_STATISTICS 读后清零语义对齐
	lastSubmitted uint64
	lastDropped   uint64

	baseMonoNs int64 // 启动基准：CLOCK_MONOTONIC（/proc/uptime）
	baseWallNs int64 // 启动基准：墙钟

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
	started  bool
}

// NewBackend 创建后端（不启动）；任何加载/挂载失败在 Start 返回错误，
// 由 capture.StartBackend 按 Fail-Open 回退 AF_PACKET。
func NewBackend(cfg capture.BackendConfig) (capture.Backend, error) {
	if len(cfg.Ifaces) == 0 {
		return nil, errors.New("ebpfcapture: 无抓包接口")
	}
	return &Backend{
		cfg:          cfg,
		snaplen:      ClampSnaplen(cfg.Snaplen),
		ringbufBytes: normalizeRingbufBytes(cfg.RingbufBytes),
		ports:        make(map[uint16]struct{}),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}, nil
}

// Start 加载 eBPF 对象、写配置、逐网卡挂载 TCX hook 并启动读循环。
// 任何一个 hook 都挂不上才返回错误；单网卡/单方向失败降级（日志）继续。
func (b *Backend) Start() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	spec, err := loadTcCapture()
	if err != nil {
		return fmt.Errorf("加载 eBPF spec 失败: %w", err)
	}
	spec.Maps["events"].MaxEntries = uint32(b.ringbufBytes)
	if err := spec.LoadAndAssign(&b.objs, nil); err != nil {
		return fmt.Errorf("加载 eBPF 程序失败（需内核 ≥6.6、BTF、CAP_BPF+CAP_NET_ADMIN）: %w", err)
	}
	b.loaded = true

	// snaplen 下发（idx 0）
	if err := b.objs.CaptureCfg.Put(uint32(0), uint32(b.snaplen)); err != nil {
		b.closeLocked()
		return fmt.Errorf("写入 snaplen 配置失败: %w", err)
	}
	// 初始端口集合（与共享 filter 一致）
	if err := b.syncPortsLocked(b.cfg.Filter.Ports()); err != nil {
		b.closeLocked()
		return fmt.Errorf("初始化端口 map 失败: %w", err)
	}

	// 逐网卡挂载 ingress+egress
	hooks := 0
	for _, ifname := range b.cfg.Ifaces {
		iface, ierr := net.InterfaceByName(ifname)
		if ierr != nil {
			b.cfg.Log.Error("eBPF 挂载：接口不存在（跳过，Fail-Open）", "iface", ifname, "err", ierr)
			continue
		}
		for _, hook := range []struct {
			name   string
			attach ebpf.AttachType
			prog   *ebpf.Program
		}{
			{"ingress", ebpf.AttachTCXIngress, b.objs.CaptureIngress},
			{"egress", ebpf.AttachTCXEgress, b.objs.CaptureEgress},
		} {
			l, aerr := link.AttachTCX(link.TCXOptions{
				Interface: iface.Index,
				Program:   hook.prog,
				Attach:    hook.attach,
			})
			if aerr != nil {
				b.cfg.Log.Error("eBPF TCX 挂载失败（跳过该 hook，Fail-Open）",
					"iface", ifname, "hook", hook.name, "err", aerr)
				continue
			}
			b.links = append(b.links, l)
			hooks++
		}
	}
	if hooks == 0 {
		b.closeLocked()
		return errors.New("ebpfcapture: 所有网卡 TCX 挂载均失败（TCX 需内核 ≥6.6）")
	}

	b.baseMonoNs, b.baseWallNs = timeBase()

	rd, rerr := ringbuf.NewReader(b.objs.Events)
	if rerr != nil {
		b.closeLocked()
		return fmt.Errorf("创建 ringbuf reader 失败: %w", rerr)
	}
	b.rd = rd
	b.started = true
	go b.run()
	b.cfg.Log.Info("eBPF 抓包已启动",
		"ifaces", b.cfg.Ifaces, "hooks", hooks,
		"snaplen", b.snaplen, "ringbuf_bytes", b.ringbufBytes)
	return nil
}

// run 读循环外套：panic/异常 → recover 后按退避降级重试，绝不退出进程。
func (b *Backend) run() {
	defer close(b.doneCh)
	backoff := time.Second
	for {
		select {
		case <-b.stopCh:
			return
		default:
		}
		crashed := b.loop()
		select {
		case <-b.stopCh:
			return
		case <-time.After(backoff):
		}
		if crashed {
			b.cfg.Log.Error("eBPF 读循环异常，降级后重试", "retry_in", backoff)
			if backoff < 60*time.Second {
				backoff *= 2
			}
		}
	}
}

// loop ringbuf 读取主循环；返回 true 表示因 panic/错误退出（需降级重试）。
func (b *Backend) loop() (crashed bool) {
	defer func() {
		if r := recover(); r != nil {
			b.cfg.Log.Error("eBPF 读循环 panic 已捕获（Fail-Open，不影响业务）", "panic", r)
			crashed = true
		}
	}()
	var rec ringbuf.Record
	for {
		select {
		case <-b.stopCh:
			return false
		default:
		}
		b.mu.Lock()
		rd := b.rd
		b.mu.Unlock()
		if rd == nil {
			return true
		}
		rd.SetDeadline(time.Now().Add(time.Second))
		if err := rd.ReadInto(&rec); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			if errors.Is(err, ringbuf.ErrClosed) {
				return false // Close 路径
			}
			b.cfg.Log.Warn("ringbuf 读取错误，重建读循环", "err", err)
			return true
		}
		ev, err := decodeEvent(rec.RawSample)
		if err != nil {
			b.cfg.Log.Debug("ringbuf 事件畸形，跳过", "err", err)
			continue
		}
		pkt := gopacket.NewPacket(ev.Data, layers.LayerTypeEthernet,
			gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		pkt.Metadata().Timestamp = b.wallTime(ev.TsNs)
		pkt.Metadata().CaptureInfo.Length = int(ev.OrigLen)
		pkt.Metadata().CaptureInfo.CaptureLength = len(ev.Data)
		// 复用与 AF_PACKET 完全相同的解码过滤（端口/方向语义单一来源）
		p, keep := capture.DecodePacket(pkt, b.cfg.Filter, b.cfg.Stats)
		if keep {
			b.consume(p)
		}
	}
}

// consume 消费回调（recover 保护：单个消费方 panic 不拖垮读循环）。
func (b *Backend) consume(p capture.Packet) {
	defer func() {
		if r := recover(); r != nil {
			b.cfg.Log.Error("消费回调 panic 已捕获", "panic", r)
		}
	}()
	b.cfg.Consumer(p)
}

// wallTime ktime（CLOCK_MONOTONIC ns）→ 墙钟；基准不可读时退化为收到时间。
func (b *Backend) wallTime(tsNs uint64) time.Time {
	if b.baseWallNs == 0 {
		return time.Now()
	}
	return time.Unix(0, b.baseWallNs-b.baseMonoNs+int64(tsNs))
}

// SetPorts 热更新端口集合（两阶段：先加后删；抓包不中断）。
func (b *Backend) SetPorts(ports []uint16) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.loaded {
		return
	}
	if err := b.syncPortsLocked(ports); err != nil {
		b.cfg.Log.Error("eBPF 端口 map 热更新失败（保留旧集合，Fail-Open）", "err", err)
	}
}

// syncPortsLocked 端口 map 增量同步（先加新端口，再删失效端口）。
func (b *Backend) syncPortsLocked(desired []uint16) error {
	current := make([]uint16, 0, len(b.ports))
	for p := range b.ports {
		current = append(current, p)
	}
	add, del := portsUpdate(current, desired)
	for _, p := range add {
		if err := b.objs.CapturePorts.Put(p, uint8(1)); err != nil {
			return fmt.Errorf("写入端口 %d: %w", p, err)
		}
	}
	for _, p := range del {
		if err := b.objs.CapturePorts.Delete(p); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("删除端口 %d: %w", p, err)
		}
	}
	b.ports = make(map[uint16]struct{}, len(desired))
	for _, p := range desired {
		b.ports[p] = struct{}{}
	}
	return nil
}

// KernelStats 读取内核计数（submitted/dropped）。
// dropped = ringbuf 满导致内核丢事件数（C 程序自统计；用户态消费慢的背压体现）。
// BPF 侧计数为加载起累计，此处内部差分，对外返回自上次调用起的差值——
// 与 AF_PACKET PACKET_STATISTICS 读后清零语义一致（capture.Backend 契约）。
func (b *Backend) KernelStats() (packets, drops uint32, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.loaded || b.objs.CaptureStats == nil {
		return 0, 0, errNotLoaded
	}
	var submitted, dropped uint64
	if err := b.objs.CaptureStats.Lookup(uint32(0), &submitted); err != nil {
		return 0, 0, fmt.Errorf("读取 submitted 计数: %w", err)
	}
	if err := b.objs.CaptureStats.Lookup(uint32(1), &dropped); err != nil {
		return 0, 0, fmt.Errorf("读取 dropped 计数: %w", err)
	}
	// 差分（计数回退/重置按 0 处理，防御性）
	p, d := uint64(0), uint64(0)
	if submitted >= b.lastSubmitted {
		p = submitted - b.lastSubmitted
	}
	if dropped >= b.lastDropped {
		d = dropped - b.lastDropped
	}
	b.lastSubmitted, b.lastDropped = submitted, dropped
	return uint32(p), uint32(d), nil
}

// Close 摘钩并释放全部资源（幂等）。TCX link 为 fd 生命周期：
// 即使进程异常退出，内核也会自动摘钩，不会残留影响业务流量。
func (b *Backend) Close() error {
	b.stopOnce.Do(func() { close(b.stopCh) })
	b.mu.Lock()
	rd := b.rd
	b.mu.Unlock()
	if rd != nil {
		_ = rd.Close() // 唤醒阻塞的 Read
	}
	b.mu.Lock()
	started := b.started
	b.mu.Unlock()
	if started {
		<-b.doneCh
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeLocked()
	return nil
}

// closeLocked 摘钩 + 关闭 eBPF 对象（须在 mu 下调用；幂等）。
func (b *Backend) closeLocked() {
	for _, l := range b.links {
		_ = l.Close()
	}
	b.links = nil
	if b.loaded {
		_ = b.objs.Close()
		b.loaded = false
	}
	b.rd = nil
}

// timeBase 读取时间基准：/proc/uptime（boottime）近似 CLOCK_MONOTONIC
// （bpf_ktime_get_ns 基准；差异仅在系统挂起时长，服务器场景可忽略），
// wall 为当前墙钟。读取失败返回零值（wallTime 退化为收到时间）。
func timeBase() (monoNs, wallNs int64) {
	f, err := os.Open("/proc/uptime")
	if err != nil {
		return 0, 0
	}
	defer f.Close() //nolint:errcheck // 只读文件
	var up float64
	if _, err := fmt.Fscan(f, &up); err != nil {
		return 0, 0
	}
	return int64(up * 1e9), time.Now().UnixNano()
}
