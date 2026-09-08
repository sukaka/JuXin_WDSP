// 站点发现与检测双功能监督测试：独立启停、共享句柄、注入/撤销、last-good 纪律。
package mirrorcap

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
)

// observerHandler 实现 DiscoveryObserver 的检测桩：记录注入的聚合器序列。
type observerHandler struct {
	noopHandler
	seen atomic.Int32 // SetDiscovery 非 nil 注入次数
	agg  atomic.Pointer[DiscoveryAggregator]
}

func (h *observerHandler) SetDiscovery(a *DiscoveryAggregator) {
	h.agg.Store(a)
	if a != nil {
		h.seen.Add(1)
	}
}

// observerDetectorFactory 每次构建返回新的 observerHandler，并记录实例。
type observerDetectorFactory struct {
	handlers []*observerHandler
}

func (f *observerDetectorFactory) make(cfg Config, e *apievents.Logger, st *Stats) (RequestHandler, error) {
	h := &observerHandler{}
	f.handlers = append(f.handlers, h)
	return h, nil
}

func (f *observerDetectorFactory) last() *observerHandler {
	if len(f.handlers) == 0 {
		return nil
	}
	return f.handlers[len(f.handlers)-1]
}

// supDiscoveryRunning 发现资源是否运行中。
func supDiscoveryRunning(s *Supervisor) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen != nil && s.gen.disc != nil
}

// 双功能同接口：只建一个句柄（共享 socket），消费组合同时携带检测与发现。
func TestSupervisorDiscoverySharedHandle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mirrorcap.json")
	discLog := filepath.Join(dir, "site-discovery.jsonl")
	writeFile(t, path, `{"enabled":true,"interfaces":["eth0"],"ports":[80],"events_log":"/virtual/e.log",
		"discovery":{"enabled":true,"interfaces":[{"name":"eth0","mode":"ROUTED"},{"name":"eth2","mode":"MIRROR"}],
		"flush_interval_sec":3600,"log":"`+discLog+`"}}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "检测+发现句柄建立", func() bool {
		return supRunnerCount(fx.sup) == 2 && supDiscoveryRunning(fx.sup)
	})

	// eth0 双角色：仅一个句柄，同时携带检测与发现消费者
	c := fx.runners.consumerFor("eth0")
	if c.Detect == nil || c.Sniff == nil {
		t.Fatalf("eth0 应双角色共用句柄: %+v", c)
	}
	if c.Sniff.mode != "ROUTED" {
		t.Errorf("eth0 嗅探器 mode=%q want ROUTED（按接口 mode 映射）", c.Sniff.mode)
	}
	// eth2 发现独占：仅嗅探消费者
	c2 := fx.runners.consumerFor("eth2")
	if c2.Detect != nil || c2.Sniff == nil {
		t.Fatalf("eth2 应仅发现角色: %+v", c2)
	}
	if c2.Sniff.mode != "MIRROR" {
		t.Errorf("eth2 嗅探器 mode=%q want MIRROR", c2.Sniff.mode)
	}
	// 双功能共用一个检测器与一个聚合器（各建一次）
	if fx.detect.count() != 1 {
		t.Errorf("检测器构建次数=%d want 1", fx.detect.count())
	}
	// 多轮轮询幂等：不重建句柄与发现资源
	calls := fx.runners.calls()
	time.Sleep(100 * time.Millisecond)
	if fx.runners.calls() != calls {
		t.Fatal("双功能稳定态不应重建句柄")
	}
}

// 仅发现（检测 enabled=false）：不建检测资源，发现口正常抓包。
func TestSupervisorDiscoveryOnlyWithoutDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mirrorcap.json")
	writeFile(t, path, `{"enabled":false,
		"discovery":{"enabled":true,"interfaces":[{"name":"eth9"}],"log":"`+filepath.Join(dir, "d.jsonl")+`"}}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "发现句柄建立", func() bool { return supRunnerCount(fx.sup) == 1 })

	if fx.detect.count() != 0 {
		t.Fatalf("检测禁用不应构建检测器, got %d", fx.detect.count())
	}
	if len(fx.events.calls) != 0 {
		t.Fatalf("检测禁用不应打开事件日志, got %v", fx.events.calls)
	}
	c := fx.runners.consumerFor("eth9")
	if c.Detect != nil || c.Sniff == nil {
		t.Fatalf("eth9 应仅发现角色: %+v", c)
	}
	// 停用发现：句柄关闭、聚合器停止，进程保持空转不退出
	writeFile(t, path, `{"enabled":false,"discovery":{"enabled":false}}`)
	waitForSup(t, "双功能全禁进入空转", func() bool { return supIdle(fx.sup) })
	select {
	case <-fx.runDone:
		t.Fatal("配置变化不应导致进程退出")
	default:
	}
}

// 发现单独禁用：检测保持运行，发现句柄关闭；检测器注入被撤销。
func TestSupervisorDiscoveryDisableKeepsDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mirrorcap.json")
	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e.log",
		"discovery":{"enabled":true,"interfaces":[{"name":"b","mode":"MIRROR"}],"log":"`+filepath.Join(dir, "d.jsonl")+`"}}`)
	df := &observerDetectorFactory{}
	fx := newSupFixture(t, testBase(), nil, path)
	fx.sup = NewSupervisor(testBase(), nil, path, 15*time.Millisecond, &Stats{},
		fx.events.factory(dir), df.make, fx.runners.make)
	t.Cleanup(func() { fx.sup.Close() })
	fx.start()
	waitForSup(t, "双功能启动", func() bool { return supRunnerCount(fx.sup) == 2 && supDiscoveryRunning(fx.sup) })

	// 检测器已注入聚合器（顺带发现）
	if df.last() == nil || df.last().agg.Load() == nil || df.last().seen.Load() != 1 {
		t.Fatal("发现启用时检测器应注入聚合器")
	}
	runnerB := fx.runners.last("b")

	// 仅关发现
	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e.log",
		"discovery":{"enabled":false}}`)
	waitForSup(t, "发现停止", func() bool { return !supDiscoveryRunning(fx.sup) })

	if !runnerB.isClosed() {
		t.Fatal("发现接口句柄应关闭")
	}
	if fx.runners.last("a").isClosed() || supRunner(fx.sup, "a") == nil {
		t.Fatal("检测接口句柄应保持运行")
	}
	if df.last().agg.Load() != nil {
		t.Fatal("发现禁用后检测器注入应被撤销")
	}
	if len(df.handlers) != 1 {
		t.Fatalf("发现启停不应重建检测器, got %d", len(df.handlers))
	}
}

// 检测单独禁用：发现保持运行。
func TestSupervisorDetectionDisableKeepsDiscovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mirrorcap.json")
	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e.log",
		"discovery":{"enabled":true,"interfaces":[{"name":"b"}],"log":"`+filepath.Join(dir, "d.jsonl")+`"}}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "双功能启动", func() bool { return supRunnerCount(fx.sup) == 2 })

	writeFile(t, path, `{"enabled":false,
		"discovery":{"enabled":true,"interfaces":[{"name":"b"}],"log":"`+filepath.Join(dir, "d.jsonl")+`"}}`)
	waitForSup(t, "检测关闭", func() bool { return supRunnerCount(fx.sup) == 1 })

	if !fx.runners.last("a").isClosed() {
		t.Fatal("检测接口句柄应关闭")
	}
	if !supDiscoveryRunning(fx.sup) {
		t.Fatal("发现应保持运行")
	}
	c := fx.runners.consumerFor("b")
	if c.Detect != nil || c.Sniff == nil {
		t.Fatalf("b 应仅发现角色: %+v", c)
	}
	// 事件文件已关闭
	if err := fx.events.last().Emit(apievents.Record{RequestID: "x", EndpointKey: "GET /"}); err == nil {
		t.Fatal("检测禁用后事件文件应已关闭")
	}
}

// 双角色接口角色剥离：文件把 eth0 从「检测+发现」改为仅检测 → 句柄重建一次。
func TestSupervisorRoleChangeRebuildsHandle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mirrorcap.json")
	writeFile(t, path, `{"enabled":true,"interfaces":["eth0"],"ports":[80],"events_log":"/virtual/e.log",
		"discovery":{"enabled":true,"interfaces":[{"name":"eth0"}],"log":"`+filepath.Join(dir, "d.jsonl")+`"}}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "双角色启动", func() bool { return supRunnerCount(fx.sup) == 1 })
	old := fx.runners.last("eth0")
	before := fx.runners.calls()

	writeFile(t, path, `{"enabled":true,"interfaces":["eth0"],"ports":[80],"events_log":"/virtual/e.log"}`)
	waitForSup(t, "角色剥离重建", func() bool {
		return supRunner(fx.sup, "eth0") != old && supRunner(fx.sup, "eth0") != nil
	})
	if !old.isClosed() {
		t.Fatal("旧双角色句柄应关闭")
	}
	if fx.runners.calls() != before+1 {
		t.Fatalf("应只重建 1 个句柄, %d→%d", before, fx.runners.calls())
	}
	if c := fx.runners.consumerFor("eth0"); c.Detect == nil || c.Sniff != nil {
		t.Fatalf("剥离后应仅检测角色: %+v", c)
	}
}

// 发现输出路径变更：发现资源重建（旧聚合器最终冲刷落盘），检测器换绑新聚合器。
func TestSupervisorDiscoveryLogChangeRebuilds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mirrorcap.json")
	log1 := filepath.Join(dir, "d1.jsonl")
	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e.log",
		"discovery":{"enabled":true,"interfaces":[{"name":"b"}],"log":"`+log1+`"}}`)
	df := &observerDetectorFactory{}
	fx := newSupFixture(t, testBase(), nil, path)
	fx.sup = NewSupervisor(testBase(), nil, path, 15*time.Millisecond, &Stats{},
		fx.events.factory(dir), df.make, fx.runners.make)
	t.Cleanup(func() { fx.sup.Close() })
	fx.start()
	waitForSup(t, "双功能启动", func() bool { return supRunnerCount(fx.sup) == 2 })
	runnerB := fx.runners.last("b")
	// 旧聚合器写入一条观察（验证换出时最终冲刷）
	fx.sup.mu.Lock()
	oldAgg := fx.sup.gen.disc.agg
	fx.sup.mu.Unlock()
	oldAgg.Observe("old.example.com", FlowMeta{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", DstPort: 443}, protoHTTPS)

	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e.log",
		"discovery":{"enabled":true,"interfaces":[{"name":"b"}],"log":"`+filepath.Join(dir, "d2.jsonl")+`"}}`)
	waitForSup(t, "发现输出切换", func() bool { return df.last().seen.Load() == 2 })

	if !runnerB.isClosed() {
		t.Fatal("发现句柄应随资源重建")
	}
	// 旧聚合器 Close 时最终冲刷：观察已落盘到旧文件
	recs := readDiscoveryRecords(t, log1)
	if len(recs) != 1 || recs[0].Domain != "old.example.com" {
		t.Fatalf("旧聚合器最终冲刷应落盘: %+v", recs)
	}
}

// 文件删除：双功能全部停止进入空转（发现不例外）。
func TestSupervisorFileDeletedStopsDiscovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mirrorcap.json")
	writeFile(t, path, `{"enabled":false,
		"discovery":{"enabled":true,"interfaces":[{"name":"z"}],"log":"`+filepath.Join(dir, "d.jsonl")+`"}}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "发现启动", func() bool { return supRunnerCount(fx.sup) == 1 })

	if err := os.Remove(path); err != nil {
		t.Fatalf("删除配置文件: %v", err)
	}
	waitForSup(t, "删除后进入空转", func() bool { return supIdle(fx.sup) })
}

// 发现输出路径不可写：发现资源启动失败下周期重试，检测不受影响。
func TestSupervisorDiscoveryBadLogRetried(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mirrorcap.json")
	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e.log",
		"discovery":{"enabled":true,"interfaces":[{"name":"b"}],"log":"/nonexistent-dir-xyz/d.jsonl"}}`)
	fx := startSup(t, testBase(), nil, path)
	waitForSup(t, "检测启动", func() bool { return supRunnerCount(fx.sup) == 1 })

	time.Sleep(80 * time.Millisecond)
	if supDiscoveryRunning(fx.sup) {
		t.Fatal("输出不可写时发现不应启动")
	}
	if supRunner(fx.sup, "a") == nil {
		t.Fatal("发现失败不应影响检测句柄")
	}
	// 修复路径后收敛
	writeFile(t, path, `{"enabled":true,"interfaces":["a"],"ports":[80],"events_log":"/virtual/e.log",
		"discovery":{"enabled":true,"interfaces":[{"name":"b"}],"log":"`+filepath.Join(dir, "ok.jsonl")+`"}}`)
	waitForSup(t, "修复后发现启动", func() bool {
		return supDiscoveryRunning(fx.sup) && supRunner(fx.sup, "b") != nil
	})
}

// env 模式携带发现配置：SITE_DISCOVERY_* 基线生效。
func TestSupervisorEnvModeDiscovery(t *testing.T) {
	dir := t.TempDir()
	base := testBase()
	base.Discovery.Enabled = true
	base.Discovery.Ifaces = []DiscoveryIface{{Name: "ethD", Mode: "ROUTED"}}
	base.Discovery.Log = filepath.Join(dir, "d.jsonl")
	base.Discovery.FlushInterval = time.Hour

	fx := startSup(t, base, nil, filepath.Join(dir, "mirrorcap.json"))
	waitForSup(t, "env 双功能启动", func() bool { return supRunnerCount(fx.sup) == 2 })
	c := fx.runners.consumerFor("ethD")
	if c.Sniff == nil || c.Sniff.mode != "ROUTED" {
		t.Fatalf("env 发现接口应生效: %+v", c)
	}
}

// HandleRequest 顺带发现集成：检测器处理配置端口流量时聚合器收到观察（hostOnly 归一）。
func TestDetectorObserveIntegration(t *testing.T) {
	dir := t.TempDir()
	agg, err := NewDiscoveryAggregator("gw-test", "MIRROR", filepath.Join(dir, "d.jsonl"), time.Hour, &Stats{})
	if err != nil {
		t.Fatalf("NewDiscoveryAggregator: %v", err)
	}
	t.Cleanup(func() { _ = agg.Close() })
	d := newTestDetector(t, filepath.Join(dir, "events.log"))
	d.SetDiscovery(agg)

	req, err := httpReadRaw("GET /a HTTP/1.1\r\nHost: API.Example.com:8443\r\n\r\n")
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	d.HandleRequest(req, FlowMeta{SrcIP: "10.1.1.1", SrcPort: 50000, DstIP: "10.2.2.2", DstPort: 8443}, false)

	if err := agg.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	recs := readDiscoveryRecords(t, agg.path)
	if len(recs) != 1 {
		t.Fatalf("记录数=%d want 1", len(recs))
	}
	if recs[0].Domain != "api.example.com" || recs[0].Protocol != protoHTTP || recs[0].Port != 8443 {
		t.Errorf("rec=%+v", recs[0])
	}

	// nil 注入（未启用发现）：不 panic、不产出
	d2 := newTestDetector(t, filepath.Join(dir, "events2.log"))
	req2, _ := httpReadRaw("GET /b HTTP/1.1\r\nHost: x.com\r\n\r\n")
	d2.HandleRequest(req2, FlowMeta{SrcIP: "10.1.1.1", DstIP: "10.2.2.2", DstPort: 80}, false)

	// 撤销注入：不再产出
	d.SetDiscovery(nil)
	req3, _ := httpReadRaw("GET /c HTTP/1.1\r\nHost: y.com\r\n\r\n")
	d.HandleRequest(req3, FlowMeta{SrcIP: "10.1.1.1", DstIP: "10.2.2.2", DstPort: 80}, false)
	if err := agg.flush(); err != nil {
		t.Fatalf("flush2: %v", err)
	}
	if recs := readDiscoveryRecords(t, agg.path); len(recs) != 1 {
		t.Fatalf("撤销注入后不应新增记录, got %d", len(recs))
	}
}

// 确保 observerHandler 实现 RequestHandler（编译期检查）。
var _ RequestHandler = (*observerHandler)(nil)
