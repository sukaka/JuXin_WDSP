package tproxyd

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ---------- 测试桩 ----------

// fakeServer 牵引服务桩：Serve 阻塞直到 Shutdown 或 kill。
type fakeServer struct {
	addr      string
	mu        sync.Mutex
	shutdownN int
	lastGrace time.Duration
	stopped   bool
	stop      chan struct{}
	killCh    chan error
}

func newFakeServer(addr string) *fakeServer {
	return &fakeServer{addr: addr, stop: make(chan struct{}), killCh: make(chan error, 1)}
}

func (f *fakeServer) Addr() string { return f.addr }

func (f *fakeServer) Serve() error {
	select {
	case <-f.stop:
		return nil
	case err := <-f.killCh:
		return err
	}
}

func (f *fakeServer) Shutdown(grace time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shutdownN++
	f.lastGrace = grace
	if !f.stopped {
		f.stopped = true
		close(f.stop)
	}
}

func (f *fakeServer) shutdowns() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.shutdownN
}

func (f *fakeServer) grace() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastGrace
}

// kill 模拟服务意外退出（监听被外部关闭等）。
func (f *fakeServer) kill(err error) {
	select {
	case f.killCh <- err:
	default:
	}
}

// serverFactoryRec 记录每次服务创建的配置，支持注入创建错误。
type serverFactoryRec struct {
	mu      sync.Mutex
	servers []*fakeServer
	cfgs    []Config
	err     error
}

func (f *serverFactoryRec) make(cfg Config, st *Stats) (ServerRunner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfgs = append(f.cfgs, cfg)
	if f.err != nil {
		return nil, f.err
	}
	s := newFakeServer(cfg.Listen)
	f.servers = append(f.servers, s)
	return s, nil
}

func (f *serverFactoryRec) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cfgs)
}

func (f *serverFactoryRec) last() *fakeServer {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.servers) == 0 {
		return nil
	}
	return f.servers[len(f.servers)-1]
}

func (f *serverFactoryRec) cfgAt(i int) Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfgs[i]
}

func (f *serverFactoryRec) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// ---------- 监督器测试辅助 ----------

func waitForSup(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", what)
}

func supRunning(s *Supervisor) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.srv != nil
}

type supFixture struct {
	sup     *Supervisor
	factory *serverFactoryRec
	runDone chan struct{}
}

// newSupFixture 构建设施但不启动（便于启动前注入故障）；start 开始轮询。
func newSupFixture(t *testing.T, base Config, baseErr error, filePath string) *supFixture {
	t.Helper()
	fx := &supFixture{factory: &serverFactoryRec{}, runDone: make(chan struct{})}
	fx.sup = NewSupervisor(base, baseErr, filePath, 15*time.Millisecond, &Stats{}, fx.factory.make)
	t.Cleanup(func() { fx.sup.Close() })
	return fx
}

func (fx *supFixture) start() {
	go func() { fx.sup.Run(); close(fx.runDone) }()
}

func startSup(t *testing.T, base Config, baseErr error, filePath string) *supFixture {
	fx := newSupFixture(t, base, baseErr, filePath)
	fx.start()
	return fx
}

func testBase() Config {
	cfg := Defaults()
	cfg.Listen = "127.0.0.1:15000"
	cfg.Target = "127.0.0.1:8080"
	cfg.ShutdownGrace = 300 * time.Millisecond
	return cfg
}

// ---------- 用例 ----------

// env 模式（无配置文件）：按 env 基线起监听；重复轮询幂等（不重启服务）。
func TestSupervisorEnvModeStartsAndIdempotent(t *testing.T) {
	fx := startSup(t, testBase(), nil, filepath.Join(t.TempDir(), "tproxyd.json"))

	waitForSup(t, "env 模式起监听", func() bool { return supRunning(fx.sup) })
	srv := fx.factory.last()
	if srv == nil {
		t.Fatal("应有在运服务")
	}
	if cfg := fx.factory.cfgAt(0); cfg.Listen != "127.0.0.1:15000" || cfg.Target != "127.0.0.1:8080" {
		t.Fatalf("服务配置应来自 env 基线: %+v", cfg)
	}

	time.Sleep(120 * time.Millisecond)
	if fx.factory.calls() != 1 || srv.shutdowns() != 0 {
		t.Fatalf("重复轮询不应重启服务: calls=%d shutdowns=%d", fx.factory.calls(), srv.shutdowns())
	}
}

// 文件出现且 listen/target 与 env 相同：切换 source 但不重启（已监听同地址）。
func TestSupervisorFileSameAddrNoRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sidecars", "tproxyd.json")
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "env 模式起监听", func() bool { return supRunning(fx.sup) })
	srv := fx.factory.last()

	writeFile(t, path, `{"enabled":true,"listen":"127.0.0.1:15000","target":"127.0.0.1:8080","ports":[80]}`)
	time.Sleep(120 * time.Millisecond)
	if srv.shutdowns() != 0 || fx.factory.calls() != 1 {
		t.Fatalf("同地址同下游不应重启: shutdowns=%d calls=%d", srv.shutdowns(), fx.factory.calls())
	}
}

// 文件 listen/target 变化：先优雅停旧服务（宽限取配置值）再起新服务。
func TestSupervisorFileChangeRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tproxyd.json")
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "env 模式起监听", func() bool { return supRunning(fx.sup) })
	old := fx.factory.last()

	writeFile(t, path, `{"enabled":true,"listen":"0.0.0.0:16000","target":"127.0.0.1:18080","ports":[80,8081]}`)
	waitForSup(t, "切换到文件配置", func() bool { return fx.factory.calls() == 2 })

	if old.shutdowns() != 1 {
		t.Fatalf("旧服务应被优雅关闭一次, got %d", old.shutdowns())
	}
	if old.grace() != 300*time.Millisecond {
		t.Fatalf("关闭宽限应取配置 ShutdownGrace, got %v", old.grace())
	}
	cfg := fx.factory.cfgAt(1)
	if cfg.Listen != "0.0.0.0:16000" || cfg.Target != "127.0.0.1:18080" {
		t.Fatalf("新服务配置应来自文件: %+v", cfg)
	}
}

// enabled=false：关监听进入空转（进程不退出）；重新 enabled=true 后恢复监听。
func TestSupervisorDisableAndReenable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tproxyd.json")
	writeFile(t, path, `{"enabled":true,"listen":"127.0.0.1:15000","target":"127.0.0.1:8080"}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "文件模式起监听", func() bool { return supRunning(fx.sup) })

	writeFile(t, path, `{"enabled":false}`)
	waitForSup(t, "进入空转", func() bool { return !supRunning(fx.sup) })
	if fx.factory.last().shutdowns() != 1 {
		t.Fatal("停用时服务应被优雅关闭")
	}

	calls := fx.factory.calls()
	time.Sleep(100 * time.Millisecond)
	if fx.factory.calls() != calls {
		t.Fatal("空转期间不应重建服务")
	}
	select {
	case <-fx.runDone:
		t.Fatal("配置变化不应导致进程退出")
	default:
	}

	writeFile(t, path, `{"enabled":true,"listen":"127.0.0.1:15000","target":"127.0.0.1:8080"}`)
	waitForSup(t, "重新启用后恢复监听", func() bool { return fx.factory.calls() == calls+1 && supRunning(fx.sup) })
}

// 文件曾生效后被删除：发布方收回配置 → 关监听进入空转，且不再回落 env。
func TestSupervisorFileDeletedStaysIdle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tproxyd.json")
	writeFile(t, path, `{"enabled":true,"listen":"127.0.0.1:15000","target":"127.0.0.1:8080"}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "文件模式起监听", func() bool { return supRunning(fx.sup) })

	if err := os.Remove(path); err != nil {
		t.Fatalf("删除配置文件: %v", err)
	}
	waitForSup(t, "删除后进入空转", func() bool { return !supRunning(fx.sup) })

	calls := fx.factory.calls()
	time.Sleep(100 * time.Millisecond)
	if fx.factory.calls() != calls {
		t.Fatal("文件删除后不应回落 env 重建服务")
	}
}

// 文件损坏：保留上一份生效配置（last-good），修复后收敛。
func TestSupervisorInvalidFileKeepsLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tproxyd.json")
	writeFile(t, path, `{"enabled":true,"listen":"127.0.0.1:15000","target":"127.0.0.1:8080"}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "文件模式起监听", func() bool { return supRunning(fx.sup) })
	srv := fx.factory.last()

	writeFile(t, path, `{"enabled": true, "listen":`) // 截断的坏 JSON
	time.Sleep(100 * time.Millisecond)
	if srv.shutdowns() != 0 {
		t.Fatal("坏文件不应影响当前生效服务（last-good）")
	}

	writeFile(t, path, `{"enabled":true,"listen":"127.0.0.1:16000","target":"127.0.0.1:8080"}`)
	waitForSup(t, "修复后按新 listen 重建", func() bool { return fx.factory.calls() == 2 })
	if srv.shutdowns() != 1 {
		t.Fatal("旧服务应被关闭")
	}
}

// env 不可用且无文件：空转等待；文件到达后按文件起监听。
func TestSupervisorEnvInvalidWaitsForFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tproxyd.json")
	fx := startSup(t, Defaults(), errors.New("TPROXY_MAX_CONNS 非法"), path)

	time.Sleep(80 * time.Millisecond)
	if supRunning(fx.sup) {
		t.Fatal("env 不可用且无文件时应空转")
	}
	select {
	case <-fx.runDone:
		t.Fatal("env 不可用不应导致进程退出")
	default:
	}

	writeFile(t, path, `{"enabled":true,"listen":"127.0.0.1:15001","target":"127.0.0.1:8081"}`)
	waitForSup(t, "文件到达后起监听", func() bool { return supRunning(fx.sup) })
	if cfg := fx.factory.cfgAt(0); cfg.Listen != "127.0.0.1:15001" || cfg.Target != "127.0.0.1:8081" {
		t.Fatalf("服务配置应来自文件: %+v", cfg)
	}
}

// 服务创建失败（端口被占等）：告警并下周期重试，恢复后收敛。
func TestSupervisorStartErrorRetried(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tproxyd.json")
	fx := newSupFixture(t, testBase(), nil, path)
	// 启动前注入故障（避免与首轮 tick 竞争）
	fx.factory.setErr(errors.New("监听 127.0.0.1:15000 失败: address already in use"))
	fx.start()

	time.Sleep(80 * time.Millisecond)
	if supRunning(fx.sup) {
		t.Fatal("创建失败不应有在运服务")
	}
	if fx.factory.calls() < 2 {
		t.Fatalf("应周期重试创建, 实际 %d 次", fx.factory.calls())
	}

	fx.factory.setErr(nil)
	waitForSup(t, "故障恢复后起监听", func() bool { return supRunning(fx.sup) })
}

// 服务意外退出：告警并按当前配置重建。
func TestSupervisorDeadServerRecreated(t *testing.T) {
	fx := startSup(t, testBase(), nil, filepath.Join(t.TempDir(), "tproxyd.json"))
	waitForSup(t, "env 模式起监听", func() bool { return supRunning(fx.sup) })
	old := fx.factory.last()

	old.kill(errors.New("listener closed unexpectedly"))
	waitForSup(t, "意外退出后重建", func() bool { return fx.factory.calls() == 2 && supRunning(fx.sup) })
}

// Close 幂等：重复调用不 panic，在运服务只关闭一次，Run 退出。
func TestSupervisorCloseIdempotent(t *testing.T) {
	fx := startSup(t, testBase(), nil, filepath.Join(t.TempDir(), "tproxyd.json"))
	waitForSup(t, "env 模式起监听", func() bool { return supRunning(fx.sup) })
	srv := fx.factory.last()

	fx.sup.Close()
	fx.sup.Close()
	if srv.shutdowns() != 1 {
		t.Fatalf("服务应只关闭一次, got %d", srv.shutdowns())
	}
	select {
	case <-fx.runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close 后 Run 应退出")
	}
}

// 真实 Server 冒烟：监督器经真实工厂绑定监听（验证生产接线，动态端口）。
func TestSupervisorRealServerSmoke(t *testing.T) {
	base := testBase()
	base.Listen = "127.0.0.1:0"
	sup := NewSupervisor(base, nil, filepath.Join(t.TempDir(), "tproxyd.json"), 15*time.Millisecond, &Stats{},
		func(cfg Config, st *Stats) (ServerRunner, error) { return NewServer(cfg, st) })
	runDone := make(chan struct{})
	go func() { sup.Run(); close(runDone) }()
	t.Cleanup(sup.Close)

	waitForSup(t, "真实服务起监听", func() bool { return supRunning(sup) })
	sup.mu.Lock()
	addr := sup.srv.Addr()
	sup.mu.Unlock()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("应能连上真实监听 %s: %v", addr, err)
	}
	_ = conn.Close()

	sup.Close()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close 后 Run 应退出")
	}
}
