// 抓包后端抽象与选择（Phase 2：AF_PACKET / eBPF-TC 双后端）。
//
// 红线（设计 §20/§72）：后端选择与回退绝不导致进程退出——eBPF 加载/挂载
// 任何失败（无 BTF、权限不足、内核过低）只降级回退 AF_PACKET 并记录原因。
package capture

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

// 后端名称（配置 capture.backend 合法值）。
const (
	BackendAFPacket = "afpacket"
	BackendEBPF     = "ebpf"
	BackendAuto     = "auto"
)

// ErrEBPFUnavailable eBPF 后端不可用（未注入实现 / 非 Linux / 加载失败前的统一哨兵）。
var ErrEBPFUnavailable = errors.New("capture: eBPF 后端不可用")

// Backend 抓包后端统一抽象（参考 gateway/mirrorcap Runner 思路，适配本包
// 自管理 goroutine 模型：Start 非阻塞启动内部 goroutine，Close 等待回收）。
//
// 生命周期红线与 Handle 相同：内部 goroutine recover 保护，任何内部错误
// 只降级不退出进程。
type Backend interface {
	// Start 打开后端资源并启动抓包 goroutine；返回错误由调用方按 Fail-Open 处理。
	Start() error
	// Close 停止抓包并释放资源（幂等）。
	Close() error
	// SetPorts 热更新端口过滤集合（抓包不中断、在途流不受影响）。
	SetPorts(ports []uint16)
	// KernelStats 内核侧统计（收包/丢包；不支持时返回错误）。统一为「自上次
	// 调用起的差值」语义：AF_PACKET PACKET_STATISTICS 读后即清零天然是差值
	// （同 pcapgo SocketStats）；eBPF 后端内部对累计计数差分。调用方直接
	// 累加每次读数即可，不得再做二次差分。
	KernelStats() (packets, drops uint32, err error)
}

// BackendConfig 后端创建参数。
type BackendConfig struct {
	Ifaces       []string       // 抓包接口集合（eBPF 单实例多接口挂载；AF_PACKET 每接口一句柄）
	Filter       *filter.Filter // 共享用户态过滤器（方向判定与二次过滤单一语义源）
	Consumer     func(Packet)   // 与 AF_PACKET 路径同一 consumer
	Stats        *Stats         // 共享抓包计数
	Log          *slog.Logger   // 日志
	Snaplen      int            // eBPF 单事件最大截取字节（0=后端默认；>0 时由后端钳制到上限内）
	RingbufBytes int            // eBPF ring buffer 字节数（0=后端默认，须 2 的幂）
}

// BackendFactory 后端工厂（创建不启动）。
type BackendFactory func(cfg BackendConfig) (Backend, error)

// 工厂注入点（包级变量，仅在进程启动前/测试中替换，运行期不并发写）。
var (
	// afpacketFactory AF_PACKET 后端工厂；测试可替换为 fake。
	afpacketFactory BackendFactory = newAFPacketBackend
	// ebpfFactory eBPF 后端工厂：Linux 下由 ebpfcapture 包 init() 注入；
	// 未注入（非 Linux 或未导入实现包）时返回 ErrEBPFUnavailable。
	ebpfFactory BackendFactory = func(BackendConfig) (Backend, error) {
		return nil, ErrEBPFUnavailable
	}
)

// RegisterEBPFFactory 注入 eBPF 后端实现（由 ebpfcapture init 或测试调用）。
// 非并发安全：只允许在抓包启动前调用。
func RegisterEBPFFactory(f BackendFactory) { ebpfFactory = f }

// NormalizeBackend 归一化后端名：空或非法值按 auto 处理（不拒绝，Fail-Open）。
func NormalizeBackend(s string) string {
	switch s {
	case BackendAFPacket, BackendEBPF, BackendAuto:
		return s
	default:
		return BackendAuto
	}
}

// ResolveBackend 生效后端决策：本地 agent.json 显式值（afpacket|ebpf）优先，
// 其次服务端策略 policy.capture.backend，其余（空/auto/非法）按 auto。
// 本地配置代表主机运维意志（内核能力因机而异），故优先于策略下发。
func ResolveBackend(local, policy string) string {
	if n := NormalizeBackend(local); n != BackendAuto {
		return n
	}
	if n := NormalizeBackend(policy); n != BackendAuto {
		return n
	}
	return BackendAuto
}

// Selection 后端选择结果。
type Selection struct {
	Backend  Backend
	Name     string // 实际生效后端（afpacket|ebpf）
	Fallback bool   // 请求 ebpf/auto 但回退到了 afpacket
	Reason   string // 回退原因（eBPF 失败错误摘要），无回退时为空
}

// StartBackend 按请求后端创建并启动抓包（Fail-Open 决策核心）：
//   - afpacket：直接启动 AF_PACKET；
//   - ebpf / auto：先尝试 eBPF，任何创建/启动失败回退 AF_PACKET，
//     Warn 记录原因并体现在 Selection.Fallback/Reason；绝不因 eBPF 失败返回错误，
//     仅当 AF_PACKET 也不可用（如非 Linux 平台）时才返回错误。
func StartBackend(requested string, cfg BackendConfig) (*Selection, error) {
	name := NormalizeBackend(requested)
	if name == BackendAFPacket {
		b, err := startFactory(afpacketFactory, cfg)
		if err != nil {
			return nil, err
		}
		return &Selection{Backend: b, Name: BackendAFPacket}, nil
	}
	// ebpf 或 auto：先试 eBPF
	b, err := startFactory(ebpfFactory, cfg)
	if err == nil {
		return &Selection{Backend: b, Name: BackendEBPF}, nil
	}
	cfg.Log.Warn("eBPF 抓包后端不可用，回退 AF_PACKET（Fail-Open）",
		"requested", name, "err", err)
	reason := err.Error()
	b, err = startFactory(afpacketFactory, cfg)
	if err != nil {
		return nil, err
	}
	return &Selection{Backend: b, Name: BackendAFPacket, Fallback: true, Reason: reason}, nil
}

// startFactory 创建并启动后端；启动失败时尽力回收已建资源。
func startFactory(f BackendFactory, cfg BackendConfig) (Backend, error) {
	b, err := f(cfg)
	if err != nil {
		return nil, err
	}
	if err := b.Start(); err != nil {
		_ = b.Close()
		return nil, err
	}
	return b, nil
}

// ── AF_PACKET 多接口后端适配 ────────────────────────────────

// afpacketBackend 把既有单接口 Handle 适配为多接口 Backend。
// 单接口失败只跳过（Fail-Open，与原逐接口语义一致）；全部失败才返回错误。
type afpacketBackend struct {
	cfg BackendConfig

	mu      sync.Mutex
	handles map[string]*Handle
}

func newAFPacketBackend(cfg BackendConfig) (Backend, error) {
	if len(cfg.Ifaces) == 0 {
		return nil, errors.New("capture: 无抓包接口")
	}
	return &afpacketBackend{cfg: cfg, handles: make(map[string]*Handle)}, nil
}

// Start 逐接口启动抓包句柄；单接口失败跳过，全部失败返回聚合错误。
func (b *afpacketBackend) Start() error {
	var lastErr error
	for _, name := range b.cfg.Ifaces {
		h, err := Start(name, b.cfg.Filter, b.cfg.Consumer, b.cfg.Stats, b.cfg.Log)
		if err != nil {
			lastErr = err
			if errors.Is(err, ErrUnsupported) {
				// 平台不支持：不必逐接口重试
				return ErrUnsupported
			}
			b.cfg.Log.Error("启动抓包失败（跳过该接口，Fail-Open）", "iface", name, "err", err)
			continue
		}
		b.handles[name] = h
		b.cfg.Log.Info("抓包已启动", "iface", name, "backend", BackendAFPacket)
	}
	if len(b.handles) == 0 {
		if lastErr == nil {
			lastErr = errors.New("capture: 无可用抓包接口")
		}
		return fmt.Errorf("AF_PACKET 后端全部接口启动失败: %w", lastErr)
	}
	return nil
}

// Close 停全部接口句柄（幂等）。
func (b *afpacketBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for name, h := range b.handles {
		_ = h.Close()
		delete(b.handles, name)
	}
	return nil
}

// SetPorts 热更新端口集合（共享 filter 原子替换，句柄不重启）。
func (b *afpacketBackend) SetPorts(ports []uint16) {
	b.cfg.Filter.SetPorts(ports)
}

// KernelStats 聚合各接口句柄内核统计；全部句柄不可读时返回错误。
func (b *afpacketBackend) KernelStats() (packets, drops uint32, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var lastErr error
	ok := false
	for _, h := range b.handles {
		p, d, herr := h.KernelStats()
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
			lastErr = errors.New("capture: 无抓包句柄")
		}
		return 0, 0, lastErr
	}
	return packets, drops, nil
}
