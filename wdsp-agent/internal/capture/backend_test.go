package capture

import (
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

// fakeBackend 测试桩后端。
type fakeBackend struct {
	startErr error
	started  atomic.Int32
	closed   atomic.Int32
	ports    []uint16
}

func (f *fakeBackend) Start() error {
	f.started.Add(1)
	return f.startErr
}
func (f *fakeBackend) Close() error { f.closed.Add(1); return nil }
func (f *fakeBackend) SetPorts(ports []uint16) {
	f.ports = append([]uint16(nil), ports...)
}
func (f *fakeBackend) KernelStats() (uint32, uint32, error) { return 0, 0, nil }

// withFactories 替换后端工厂并在测试结束恢复。
func withFactories(t *testing.T, af, eb BackendFactory) {
	t.Helper()
	oldAF, oldEB := afpacketFactory, ebpfFactory
	afpacketFactory, ebpfFactory = af, eb
	t.Cleanup(func() { afpacketFactory, ebpfFactory = oldAF, oldEB })
}

func testCfg() BackendConfig {
	return BackendConfig{
		Ifaces:   []string{"eth0"},
		Filter:   filter.New([]uint16{80}, filter.Both),
		Consumer: func(Packet) {},
		Stats:    &Stats{},
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestNormalizeBackend(t *testing.T) {
	for in, want := range map[string]string{
		"afpacket": BackendAFPacket,
		"ebpf":     BackendEBPF,
		"auto":     BackendAuto,
		"":         BackendAuto,
		"EBPF":     BackendAuto, // 大小写不猜测，未知值一律 auto（Fail-Open）
		"dpdk":     BackendAuto,
	} {
		if got := NormalizeBackend(in); got != want {
			t.Errorf("NormalizeBackend(%q)=%s, want %s", in, got, want)
		}
	}
}

func TestResolveBackend(t *testing.T) {
	cases := []struct {
		local, policy, want string
	}{
		{"", "", BackendAuto},                 // 全无指定 → auto
		{"afpacket", "ebpf", BackendAFPacket}, // 本地显式优先于策略
		{"ebpf", "afpacket", BackendEBPF},
		{"", "ebpf", BackendEBPF},     // 策略通道可指定
		{"auto", "ebpf", BackendEBPF}, // 本地 auto 不锁定，策略生效
		{"", "garbage", BackendAuto},  // 策略非法值 → auto
		{"afpacket", "", BackendAFPacket},
	}
	for _, c := range cases {
		if got := ResolveBackend(c.local, c.policy); got != c.want {
			t.Errorf("ResolveBackend(%q,%q)=%s, want %s", c.local, c.policy, got, c.want)
		}
	}
}

func TestStartBackendExplicitAFPacket(t *testing.T) {
	af := &fakeBackend{}
	eb := &fakeBackend{}
	withFactories(t,
		func(BackendConfig) (Backend, error) { return af, nil },
		func(BackendConfig) (Backend, error) { return eb, nil })
	sel, err := StartBackend(BackendAFPacket, testCfg())
	if err != nil {
		t.Fatal(err)
	}
	if sel.Name != BackendAFPacket || sel.Fallback || sel.Reason != "" {
		t.Fatalf("unexpected selection: %+v", sel)
	}
	if af.started.Load() != 1 || eb.started.Load() != 0 {
		t.Fatalf("应只启动 afpacket: af=%d eb=%d", af.started.Load(), eb.started.Load())
	}
}

func TestStartBackendEBPFPreferred(t *testing.T) {
	af := &fakeBackend{}
	eb := &fakeBackend{}
	withFactories(t,
		func(BackendConfig) (Backend, error) { return af, nil },
		func(BackendConfig) (Backend, error) { return eb, nil })
	for _, req := range []string{BackendEBPF, BackendAuto, "", "bogus"} {
		sel, err := StartBackend(req, testCfg())
		if err != nil {
			t.Fatal(err)
		}
		if sel.Name != BackendEBPF || sel.Fallback {
			t.Fatalf("requested=%q 应选中 ebpf: %+v", req, sel)
		}
	}
	if eb.started.Load() != 4 || af.started.Load() != 0 {
		t.Fatalf("ebpf 应被选中 4 次: eb=%d af=%d", eb.started.Load(), af.started.Load())
	}
}

// TestStartBackendFallback ebpf/auto 下 eBPF 任意失败（创建或启动）回退 AF_PACKET，
// 记录原因，绝不返回 eBPF 错误（Fail-Open 决策路径，macOS 可测）。
func TestStartBackendFallback(t *testing.T) {
	af := &fakeBackend{}
	withFactories(t,
		func(BackendConfig) (Backend, error) { return af, nil },
		func(BackendConfig) (Backend, error) { return nil, errors.New("no BTF") })
	for _, req := range []string{BackendEBPF, BackendAuto} {
		sel, err := StartBackend(req, testCfg())
		if err != nil {
			t.Fatalf("回退路径不得返回 eBPF 错误: %v", err)
		}
		if sel.Name != BackendAFPacket || !sel.Fallback || sel.Reason == "" {
			t.Fatalf("requested=%q 应回退 afpacket 并记录原因: %+v", req, sel)
		}
	}
	// eBPF 创建成功但 Start 失败（如 TCX 挂载失败）同样回退
	ebBroken := &fakeBackend{startErr: errors.New("tcx attach: kernel too old")}
	withFactories(t,
		func(BackendConfig) (Backend, error) { return af, nil },
		func(BackendConfig) (Backend, error) { return ebBroken, nil })
	sel, err := StartBackend(BackendEBPF, testCfg())
	if err != nil {
		t.Fatal(err)
	}
	if sel.Name != BackendAFPacket || !sel.Fallback {
		t.Fatalf("Start 失败应回退: %+v", sel)
	}
	if ebBroken.closed.Load() != 1 {
		t.Fatal("启动失败的 eBPF 后端应被回收")
	}
}

// TestStartBackendBothFail eBPF 失败且 AF_PACKET 也不可用（如非 Linux）→ 返回错误，
// 由上层降级为仅控制通道运行（进程不退出）。
func TestStartBackendBothFail(t *testing.T) {
	withFactories(t,
		func(BackendConfig) (Backend, error) { return nil, ErrUnsupported },
		func(BackendConfig) (Backend, error) { return nil, ErrEBPFUnavailable })
	if _, err := StartBackend(BackendAuto, testCfg()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("双后端不可用应返回 AF_PACKET 侧错误: %v", err)
	}
}

// TestAFPacketBackendSetPorts 端口热更委托共享 filter（句柄不重启）。
func TestAFPacketBackendSetPorts(t *testing.T) {
	f := filter.New([]uint16{80}, filter.Both)
	cfg := testCfg()
	cfg.Filter = f
	b, err := newAFPacketBackend(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b.SetPorts([]uint16{8080, 443})
	got := f.Ports()
	if len(got) != 2 {
		t.Fatalf("filter 端口未热更: %v", got)
	}
	if _, ok := f.Match(12345, 8080); !ok {
		t.Fatal("新端口应命中")
	}
	if _, ok := f.Match(12345, 80); ok {
		t.Fatal("旧端口应失效")
	}
}

// TestAFPacketBackendNoIfaces 无接口直接报错（不启动）。
func TestAFPacketBackendNoIfaces(t *testing.T) {
	cfg := testCfg()
	cfg.Ifaces = nil
	if _, err := newAFPacketBackend(cfg); err == nil {
		t.Fatal("无接口应报错")
	}
}
