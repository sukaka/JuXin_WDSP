package mirrorcap

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
)

// ---------- 测试桩 ----------

// noopHandler 空检测器桩（避免加载 Coraza 规则集）。
type noopHandler struct{}

func (noopHandler) HandleRequest(req *http.Request, meta FlowMeta, bodyTruncated bool) {}

// fakeRunner 单接口抓包句柄桩：Run 阻塞直到 Close 或 kill。
type fakeRunner struct {
	mu     sync.Mutex
	ports  []uint16
	closed bool
	closeN int
	stop   chan struct{}
	killCh chan error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{stop: make(chan struct{}), killCh: make(chan error, 1)}
}

func (f *fakeRunner) Run() error {
	select {
	case <-f.stop:
		return nil
	case err := <-f.killCh:
		return err
	}
}

func (f *fakeRunner) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeN++
	if !f.closed {
		f.closed = true
		close(f.stop)
	}
	return nil
}

func (f *fakeRunner) SetPorts(ports []uint16) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ports = append([]uint16(nil), ports...)
}

// StatsFunc 返回 nil（模拟非 Linux 平台；聚合层跳过 nil）。
func (f *fakeRunner) StatsFunc() func() (packets, drops uint32, err error) { return nil }

func (f *fakeRunner) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeRunner) closeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeN
}

func (f *fakeRunner) curPorts() []uint16 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint16(nil), f.ports...)
}

// kill 模拟句柄异常退出（接口抖动等）。
func (f *fakeRunner) kill(err error) {
	select {
	case f.killCh <- err:
	default:
	}
}

// runnerFactoryRec 记录每次句柄创建的完整配置，支持按接口注入创建错误。
type runnerFactoryRec struct {
	mu        sync.Mutex
	runners   []*fakeRunner
	cfgs      []Config
	consumers []IfaceConsumer
	fail      map[string]error
	byIface   map[string][]*fakeRunner
}

func newRunnerFactoryRec() *runnerFactoryRec {
	return &runnerFactoryRec{fail: map[string]error{}, byIface: map[string][]*fakeRunner{}}
}

func (f *runnerFactoryRec) make(cfg Config, c IfaceConsumer, st *Stats) (Runner, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfgs = append(f.cfgs, cfg)
	f.consumers = append(f.consumers, c)
	if err, ok := f.fail[cfg.Iface]; ok {
		return nil, err
	}
	r := newFakeRunner()
	f.runners = append(f.runners, r)
	f.byIface[cfg.Iface] = append(f.byIface[cfg.Iface], r)
	return r, nil
}

func (f *runnerFactoryRec) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runners)
}

func (f *runnerFactoryRec) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cfgs)
}

func (f *runnerFactoryRec) last(iface string) *fakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	rs := f.byIface[iface]
	if len(rs) == 0 {
		return nil
	}
	return rs[len(rs)-1]
}

func (f *runnerFactoryRec) cfgFor(i int) Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfgs[i]
}

// consumerFor 最近一次为指定接口创建句柄时的消费组合（角色断言用）。
func (f *runnerFactoryRec) consumerFor(iface string) IfaceConsumer {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.cfgs) - 1; i >= 0; i-- {
		if f.cfgs[i].Iface == iface {
			return f.consumers[i]
		}
	}
	return IfaceConsumer{}
}

// detectorFactoryRec 记录检测器构建次数。
type detectorFactoryRec struct {
	mu sync.Mutex
	n  int
}

func (d *detectorFactoryRec) make(cfg Config, e *apievents.Logger, st *Stats) (RequestHandler, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.n++
	return noopHandler{}, nil
}

func (d *detectorFactoryRec) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.n
}

// eventsRec 事件日志工厂记录器：真实 Logger 重定向到临时目录（断言路径/节点参数与关闭行为）。
type eventsRec struct {
	mu      sync.Mutex
	calls   [][2]string
	loggers []*apievents.Logger
}

func (e *eventsRec) factory(dir string) EventsFactory {
	return func(path, node string) (*apievents.Logger, error) {
		l, err := apievents.NewLogger(filepath.Join(dir, filepath.Base(path)), node)
		if err != nil {
			return nil, err
		}
		e.mu.Lock()
		e.calls = append(e.calls, [2]string{path, node})
		e.loggers = append(e.loggers, l)
		e.mu.Unlock()
		return l, nil
	}
}

func (e *eventsRec) lastCall() (string, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.calls) == 0 {
		return "", ""
	}
	c := e.calls[len(e.calls)-1]
	return c[0], c[1]
}

func (e *eventsRec) last() *apievents.Logger {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.loggers) == 0 {
		return nil
	}
	return e.loggers[len(e.loggers)-1]
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

func supRunnerCount(s *Supervisor) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen == nil {
		return 0
	}
	return len(s.gen.runners)
}

func supRunner(s *Supervisor, iface string) Runner {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen == nil {
		return nil
	}
	if h, ok := s.gen.runners[iface]; ok {
		return h.runner
	}
	return nil
}

func supIdle(s *Supervisor) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen == nil
}

// supFixture 一套监督器测试设施。
type supFixture struct {
	sup     *Supervisor
	runners *runnerFactoryRec
	detect  *detectorFactoryRec
	events  *eventsRec
	runDone chan struct{}
}

// newSupFixture 构建设施但不启动（便于启动前注入故障）；start 开始轮询。
func newSupFixture(t *testing.T, base Config, baseErr error, filePath string) *supFixture {
	t.Helper()
	fx := &supFixture{
		runners: newRunnerFactoryRec(),
		detect:  &detectorFactoryRec{},
		events:  &eventsRec{},
		runDone: make(chan struct{}),
	}
	fx.sup = NewSupervisor(base, baseErr, filePath, 15*time.Millisecond, &Stats{},
		fx.events.factory(t.TempDir()), fx.detect.make, fx.runners.make)
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
	cfg.Iface = "eth-env"
	cfg.Ports = []uint16{80}
	cfg.EventsLog = "/virtual/env-events.log"
	cfg.NodeName = "env-node"
	return cfg
}

// ---------- 用例 ----------

// env 模式（无配置文件）：按 env 基线启动抓包；重复轮询幂等（不重启句柄）。
func TestSupervisorEnvModeStartsAndIdempotent(t *testing.T) {
	fx := startSup(t, testBase(), nil, filepath.Join(t.TempDir(), "mirrorcap.json"))

	waitForSup(t, "env 模式启动抓包", func() bool { return supRunnerCount(fx.sup) == 1 })
	r := fx.runners.last("eth-env")
	if r == nil {
		t.Fatal("应有 eth-env 句柄")
	}
	if cfg := fx.runners.cfgFor(0); cfg.Iface != "eth-env" || len(cfg.Ports) != 1 || cfg.Ports[0] != 80 {
		t.Fatalf("句柄配置=%+v 应来自 env 基线", cfg)
	}
	if path, node := fx.events.lastCall(); path != "/virtual/env-events.log" || node != "env-node" {
		t.Fatalf("事件日志参数=(%q,%q) 应来自 env 基线", path, node)
	}

	// 多轮轮询后：句柄不重建、事件日志不重开（幂等）
	time.Sleep(120 * time.Millisecond)
	if fx.runners.calls() != 1 || fx.detect.count() != 1 {
		t.Fatalf("重复轮询不应重启资源: runners=%d detect=%d", fx.runners.calls(), fx.detect.count())
	}
	if r.isClosed() {
		t.Fatal("运行中的句柄不应被关闭")
	}
	// 内核统计聚合闭包可用（无句柄统计时返回全零不报错）
	if _, _, err := fx.sup.StatsFunc()(); err != nil {
		t.Fatalf("StatsFunc: %v", err)
	}
}

// 文件出现：切换到文件配置（文件优先），env 句柄被替换；多接口各一个句柄。
func TestSupervisorFileAppearsSwitchesToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sidecars", "mirrorcap.json")
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "env 模式启动", func() bool { return supRunnerCount(fx.sup) == 1 })
	envRunner := fx.runners.last("eth-env")

	writeFile(t, path, `{"enabled":true,"node":"node-a","interfaces":["eth2","eth3"],"ports":[8081],"events_log":"/virtual/file-events.log"}`)
	waitForSup(t, "切换到文件配置两个接口", func() bool { return supRunnerCount(fx.sup) == 2 })

	if !envRunner.isClosed() {
		t.Fatal("env 句柄应被关闭（切换到文件配置）")
	}
	for _, ifs := range []string{"eth2", "eth3"} {
		r := fx.runners.last(ifs)
		if r == nil || r.isClosed() {
			t.Fatalf("接口 %s 句柄应在运行", ifs)
		}
	}
	if cfg := fx.runners.cfgFor(fx.runners.calls() - 1); len(cfg.Ports) != 1 || cfg.Ports[0] != 8081 {
		t.Fatalf("文件端口未生效: %+v", cfg)
	}
	if p, node := fx.events.lastCall(); p != "/virtual/file-events.log" || node != "node-a" {
		t.Fatalf("事件日志应切换到文件配置, got (%q,%q)", p, node)
	}
}

// 接口集合变化：增量起停——移出的关闭、新增的建立、保留的实例不动。
func TestSupervisorInterfaceIncrementalUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{"enabled":true,"interfaces":["a","b"],"ports":[80],"events_log":"/virtual/e.log"}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "文件模式两接口", func() bool { return supRunnerCount(fx.sup) == 2 })
	before := fx.runners.calls()
	runnerB := fx.runners.last("b")

	writeFile(t, path, `{"enabled":true,"interfaces":["b","c"],"ports":[80],"events_log":"/virtual/e.log"}`)
	waitForSup(t, "接口 c 建立", func() bool { return supRunner(fx.sup, "c") != nil })

	if !fx.runners.last("a").isClosed() {
		t.Fatal("移出的接口 a 应被关闭")
	}
	if runnerB.isClosed() || supRunner(fx.sup, "b") != runnerB {
		t.Fatal("保留的接口 b 句柄实例不应变化")
	}
	if fx.runners.calls() != before+1 {
		t.Fatalf("应只新建 1 个句柄, 实际 %d→%d", before, fx.runners.calls())
	}
	if fx.detect.count() != 1 {
		t.Fatal("事件输出未变，检测器不应重建")
	}
}

// 端口集合变化：热更新过滤，句柄实例不动、不重建。
func TestSupervisorPortsHotUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e.log"}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "文件模式启动", func() bool { return supRunnerCount(fx.sup) == 1 })
	runner := fx.runners.last("a")
	before := fx.runners.calls()

	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80,443],"events_log":"/virtual/e.log"}`)
	waitForSup(t, "端口热更新", func() bool { return len(runner.curPorts()) == 2 })

	if runner.isClosed() || supRunner(fx.sup, "a") != runner {
		t.Fatal("端口变化不应重启句柄")
	}
	if fx.runners.calls() != before {
		t.Fatal("端口变化不应新建句柄")
	}
}

// enabled=false：停止抓包进入空转（进程不退出）；事件文件等资源释放。
func TestSupervisorDisableIdlesWithoutExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e.log"}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "文件模式启动", func() bool { return supRunnerCount(fx.sup) == 1 })
	runner := fx.runners.last("a")
	logger := fx.events.last()

	writeFile(t, path, `{"enabled":false}`)
	waitForSup(t, "进入空转", func() bool { return supIdle(fx.sup) })

	if !runner.isClosed() {
		t.Fatal("停用时句柄应关闭")
	}
	if runner.closeCount() != 1 {
		t.Fatalf("句柄应只被关闭一次, got %d", runner.closeCount())
	}
	// 事件文件已关闭：Emit 应报错（资源释放验证，写已关闭文件返回错误而非静默）
	if err := logger.Emit(apievents.Record{RequestID: "x", EndpointKey: "GET /"}); err == nil {
		t.Fatal("停用后事件文件应已关闭")
	}
	// 空转稳定：多轮轮询不重建资源，进程不退出
	calls := fx.runners.calls()
	time.Sleep(100 * time.Millisecond)
	if fx.runners.calls() != calls {
		t.Fatal("空转期间不应重建句柄")
	}
	select {
	case <-fx.runDone:
		t.Fatal("配置变化不应导致进程退出")
	default:
	}
}

// 文件曾生效后被删除：发布方收回配置 → 停止抓包进入空转，且不再回落 env。
func TestSupervisorFileDeletedStaysIdle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e.log"}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "文件模式启动", func() bool { return supRunnerCount(fx.sup) == 1 })

	if err := os.Remove(path); err != nil {
		t.Fatalf("删除配置文件: %v", err)
	}
	waitForSup(t, "删除后进入空转", func() bool { return supIdle(fx.sup) })

	calls := fx.runners.calls()
	time.Sleep(100 * time.Millisecond)
	if fx.runners.calls() != calls {
		t.Fatal("文件删除后不应回落 env 重建句柄")
	}
}

// 文件损坏：保留上一份生效配置（last-good），修复后收敛到新配置。
func TestSupervisorInvalidFileKeepsLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e.log"}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "文件模式启动", func() bool { return supRunnerCount(fx.sup) == 1 })
	runner := fx.runners.last("a")

	writeFile(t, path, `{"enabled": true, "interfaces": [`) // 截断的坏 JSON
	time.Sleep(100 * time.Millisecond)
	if runner.isClosed() || supRunner(fx.sup, "a") != runner {
		t.Fatal("坏文件不应影响当前生效配置（last-good）")
	}

	writeFile(t, path, `{"enabled":true,"interfaces":["b"],"ports":[80],"events_log":"/virtual/e.log"}`)
	waitForSup(t, "修复后收敛到接口 b", func() bool { return supRunner(fx.sup, "b") != nil })
	if !runner.isClosed() {
		t.Fatal("旧接口 a 应被关闭")
	}
}

// env 不可用（如 MIRROR_IFACE 未设置）且无文件：空转等待；文件到达后按文件启动。
func TestSupervisorEnvInvalidWaitsForFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	fx := startSup(t, Defaults(), errors.New("MIRROR_IFACE 未设置"), path)

	time.Sleep(80 * time.Millisecond)
	if !supIdle(fx.sup) {
		t.Fatal("env 不可用且无文件时应空转")
	}
	select {
	case <-fx.runDone:
		t.Fatal("env 不可用不应导致进程退出")
	default:
	}

	writeFile(t, path, `{"enabled":true,"interfaces":["x"],"ports":[8080],"events_log":"/virtual/e.log","node":"n1"}`)
	waitForSup(t, "文件到达后启动", func() bool { return supRunnerCount(fx.sup) == 1 })
	if cfg := fx.runners.cfgFor(0); cfg.Iface != "x" || cfg.Ports[0] != 8080 {
		t.Fatalf("句柄配置应来自文件: %+v", cfg)
	}
}

// 句柄创建失败（接口不存在等）：告警并下周期重试，恢复后收敛。
func TestSupervisorRunnerErrorRetried(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{"enabled":true,"interfaces":["bad0"],"ports":[80],"events_log":"/virtual/e.log"}`)
	fx := newSupFixture(t, testBase(), nil, path)
	// 启动前注入故障（避免与首轮 tick 竞争）
	fx.runners.mu.Lock()
	fx.runners.fail["bad0"] = errors.New("打开镜像接口 bad0: 不存在")
	fx.runners.mu.Unlock()
	fx.start()

	time.Sleep(80 * time.Millisecond)
	if supRunnerCount(fx.sup) != 0 {
		t.Fatal("创建失败不应有运行句柄")
	}
	if fx.runners.calls() < 2 {
		t.Fatalf("应周期重试创建, 实际调用 %d 次", fx.runners.calls())
	}

	fx.runners.mu.Lock()
	delete(fx.runners.fail, "bad0")
	fx.runners.mu.Unlock()
	waitForSup(t, "故障恢复后句柄建立", func() bool { return supRunnerCount(fx.sup) == 1 })
}

// 句柄异常退出：告警并重建（接口抖动自愈）。
func TestSupervisorDeadRunnerRecreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e.log"}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "文件模式启动", func() bool { return supRunnerCount(fx.sup) == 1 })
	old := fx.runners.last("a")

	old.kill(errors.New("抓包通道关闭"))
	waitForSup(t, "异常退出后重建", func() bool {
		return fx.runners.count() == 2 && supRunner(fx.sup, "a") != old && supRunner(fx.sup, "a") != nil
	})
}

// 事件输出路径变化：整代重建（旧句柄关闭、新事件文件生效）。
func TestSupervisorEventsLogChangeRebuilds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e1.log"}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "文件模式启动", func() bool { return supRunnerCount(fx.sup) == 1 })
	oldRunner := fx.runners.last("a")
	oldLogger := fx.events.last()

	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e2.log"}`)
	waitForSup(t, "事件输出切换", func() bool {
		p, _ := fx.events.lastCall()
		return p == "/virtual/e2.log" && supRunnerCount(fx.sup) == 1
	})
	if !oldRunner.isClosed() {
		t.Fatal("整代重建应关闭旧句柄")
	}
	if err := oldLogger.Emit(apievents.Record{RequestID: "x", EndpointKey: "GET /"}); err == nil {
		t.Fatal("旧事件文件应已关闭")
	}
	if fx.detect.count() != 2 {
		t.Fatalf("检测器应随代重建, 构建次数 %d", fx.detect.count())
	}
}

// Close 幂等：重复调用不 panic，句柄只关闭一次，Run 退出。
func TestSupervisorCloseIdempotent(t *testing.T) {
	fx := startSup(t, testBase(), nil, filepath.Join(t.TempDir(), "mirrorcap.json"))
	waitForSup(t, "env 模式启动", func() bool { return supRunnerCount(fx.sup) == 1 })
	runner := fx.runners.last("eth-env")

	fx.sup.Close()
	fx.sup.Close()
	if runner.closeCount() != 1 {
		t.Fatalf("句柄应只关闭一次, got %d", runner.closeCount())
	}
	select {
	case <-fx.runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close 后 Run 应退出")
	}
}
