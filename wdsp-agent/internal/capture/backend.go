// 抓包后端抽象与跨平台选择（Linux: eBPF/AF_PACKET；macOS: BPF；Windows: Npcap/RawSocket）。
//
// 红线（设计 §20/§72 / 跨平台契约 §1）：后端选择与回退绝不导致进程退出——
// 任何后端加载/挂载失败均 Fail-Open 顺次尝试平台下一后端，全部不可用时
// 返回错误由上层降级为仅控制通道运行，并如实上报 backend_fallback_reason。
package capture

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"

	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

// 后端名称（配置 capture.backend 合法值）。
const (
	BackendAFPacket  = "afpacket"
	BackendEBPF      = "ebpf"
	BackendBPF       = "bpf"
	BackendNpcap     = "npcap"
	BackendRawSocket = "rawsocket"
	BackendAuto      = "auto"
)

// 各后端不可用哨兵错误。
var (
	ErrEBPFUnavailable      = errors.New("capture: eBPF 后端不可用")
	ErrBPFUnavailable       = errors.New("capture: macOS BPF 后端不可用")
	ErrNpcapUnavailable     = errors.New("capture: Windows Npcap 后端不可用")
	ErrRawSocketUnavailable = errors.New("capture: Windows Raw Socket 后端不可用")
)

// Backend 抓包后端统一抽象：
// Start 非阻塞启动内部 goroutine，Close 幂等停止并等待回收。
// 内部 goroutine 全部 recover 保护，任何内部错误只降级不退出进程。
type Backend interface {
	Start() error
	Close() error
	SetPorts(ports []uint16)
	// KernelStats 内核侧统计（自上次调用起的收包/丢包差值语义）。
	KernelStats() (packets, drops uint32, err error)
}

// BackendConfig 后端创建参数。
type BackendConfig struct {
	Ifaces       []string       // 抓包接口集合
	Filter       *filter.Filter // 共享用户态过滤器（方向判定与端口过滤单一语义源）
	Consumer     func(Packet)   // 统一包消费回调
	Stats        *Stats         // 共享抓包计数
	Log          *slog.Logger   // 日志
	Snaplen      int            // eBPF 单事件最大截取字节（0=后端默认）
	RingbufBytes int            // eBPF ring buffer 字节数（0=后端默认，须 2 的幂）
}

// BackendFactory 后端工厂（创建不启动）。
type BackendFactory func(cfg BackendConfig) (Backend, error)

// 当前目标操作系统（默认 runtime.GOOS，单测可临时替换验证全平台回退链）。
var platformOS = runtime.GOOS

// 工厂注入点（包级变量，仅在进程启动前/测试中替换，运行期不并发写）。
var (
	afpacketFactory BackendFactory = newAFPacketBackend
	ebpfFactory     BackendFactory = func(BackendConfig) (Backend, error) {
		return nil, ErrEBPFUnavailable
	}
	bpfFactory BackendFactory = func(BackendConfig) (Backend, error) {
		return nil, ErrBPFUnavailable
	}
	npcapFactory BackendFactory = func(BackendConfig) (Backend, error) {
		return nil, ErrNpcapUnavailable
	}
	rawSocketFactory BackendFactory = func(BackendConfig) (Backend, error) {
		return nil, ErrRawSocketUnavailable
	}
)

// RegisterEBPFFactory 注入 Linux eBPF 后端（由 ebpfcapture init 调用）。
func RegisterEBPFFactory(f BackendFactory) { ebpfFactory = f }

// RegisterBPFFactory 注入 macOS BPF 后端（由 bpf_darwin.go init 调用）。
func RegisterBPFFactory(f BackendFactory) { bpfFactory = f }

// RegisterNpcapFactory 注入 Windows Npcap 后端（由 npcap_windows.go init 调用）。
func RegisterNpcapFactory(f BackendFactory) { npcapFactory = f }

// RegisterRawSocketFactory 注入 Windows Raw Socket 后端（由 rawsocket_windows.go init 调用）。
func RegisterRawSocketFactory(f BackendFactory) { rawSocketFactory = f }

// NormalizeBackend 归一化后端名：空或非法值按 auto 处理（不拒绝，Fail-Open）。
func NormalizeBackend(s string) string {
	switch s {
	case BackendAFPacket, BackendEBPF, BackendBPF, BackendNpcap, BackendRawSocket, BackendAuto:
		return s
	default:
		return BackendAuto
	}
}

// ResolveBackend 生效后端决策：本地 agent.json 显式值优先，其次服务端策略，其余按 auto。
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
	Name     string // 实际生效后端名
	Fallback bool   // 是否发生回退
	Reason   string // 回退原因摘要，无回退为空
}

func factoryFor(name string) BackendFactory {
	switch name {
	case BackendAFPacket:
		return afpacketFactory
	case BackendEBPF:
		return ebpfFactory
	case BackendBPF:
		return bpfFactory
	case BackendNpcap:
		return npcapFactory
	case BackendRawSocket:
		return rawSocketFactory
	default:
		return nil
	}
}

// planBackends 返回目标 OS + 请求后端的有序尝试链与跨平台不匹配提示。
func planBackends(goos, requested string) (chain []string, mismatchReason string) {
	switch goos {
	case "linux":
		switch requested {
		case BackendAFPacket:
			return []string{BackendAFPacket}, ""
		case BackendEBPF, BackendAuto:
			return []string{BackendEBPF, BackendAFPacket}, ""
		default:
			return []string{BackendEBPF, BackendAFPacket},
				fmt.Sprintf("请求后端 %s 不适用于 Linux，自动回退平台默认链", requested)
		}
	case "darwin":
		switch requested {
		case BackendBPF, BackendAuto:
			return []string{BackendBPF}, ""
		default:
			return []string{BackendBPF},
				fmt.Sprintf("请求后端 %s 不适用于 macOS，自动回退 bpf", requested)
		}
	case "windows":
		switch requested {
		case BackendRawSocket:
			return []string{BackendRawSocket}, ""
		case BackendNpcap, BackendAuto:
			return []string{BackendNpcap, BackendRawSocket}, ""
		default:
			return []string{BackendNpcap, BackendRawSocket},
				fmt.Sprintf("请求后端 %s 不适用于 Windows，自动回退平台默认链", requested)
		}
	default:
		return nil, ""
	}
}

// StartBackend 按当前平台和请求后端顺次尝试创建并启动抓包（Fail-Open 决策核心）。
func StartBackend(requested string, cfg BackendConfig) (*Selection, error) {
	name := NormalizeBackend(requested)
	chain, mismatch := planBackends(platformOS, name)
	if len(chain) == 0 {
		return nil, ErrUnsupported
	}
	if mismatch != "" && cfg.Log != nil {
		cfg.Log.Warn("抓包后端与当前平台不匹配，自动回退（Fail-Open）",
			"os", platformOS, "requested", name, "reason", mismatch)
	}

	var firstErr error
	var lastErr error
	for i, candidate := range chain {
		f := factoryFor(candidate)
		if f == nil {
			lastErr = ErrUnsupported
			if firstErr == nil {
				firstErr = lastErr
			}
			continue
		}
		b, err := startFactory(f, cfg)
		if err == nil {
			fallback := i > 0 || mismatch != ""
			reason := ""
			if fallback {
				if firstErr != nil {
					reason = firstErr.Error()
				} else {
					reason = mismatch
				}
			}
			return &Selection{
				Backend:  b,
				Name:     candidate,
				Fallback: fallback,
				Reason:   reason,
			}, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		lastErr = err
		if i+1 < len(chain) && cfg.Log != nil {
			cfg.Log.Warn("抓包后端不可用，自动尝试下一回退后端（Fail-Open）",
				"failed_backend", candidate, "next_backend", chain[i+1], "err", err)
		}
	}
	if lastErr == nil {
		lastErr = ErrUnsupported
	}
	return nil, lastErr
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

// ── AF_PACKET 多接口后端适配（Linux） ────────────────────────────────

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

func (b *afpacketBackend) Start() error {
	var lastErr error
	for _, name := range b.cfg.Ifaces {
		h, err := Start(name, b.cfg.Filter, b.cfg.Consumer, b.cfg.Stats, b.cfg.Log)
		if err != nil {
			lastErr = err
			if errors.Is(err, ErrUnsupported) {
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

func (b *afpacketBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for name, h := range b.handles {
		_ = h.Close()
		delete(b.handles, name)
	}
	return nil
}

func (b *afpacketBackend) SetPorts(ports []uint16) {
	b.cfg.Filter.SetPorts(ports)
}

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
