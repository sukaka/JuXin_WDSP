package systemalerts

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/metrics"
)

// fakeEndpointPerf 是 EndpointPerfStatsStore 的可编程内存实现。
type fakeEndpointPerf struct {
	rows []EndpointMinuteStat
	err  error

	calls     int
	lastStart time.Time
	lastEnd   time.Time
}

func (f *fakeEndpointPerf) EndpointMinuteStats(_ context.Context, start, end time.Time) ([]EndpointMinuteStat, error) {
	f.calls++
	f.lastStart, f.lastEnd = start, end
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

// newEndpointPerfEngine 创建注入端点统计源的引擎（可控时钟）。
func newEndpointPerfEngine(store *fakeStore, perf *fakeEndpointPerf, settings SettingsReader, now *time.Time) *Engine {
	return NewEngine(store, EngineOptions{
		Now:           func() time.Time { return *now },
		Cooldown:      time.Minute,
		FlapWindow:    10 * time.Minute,
		FlapThreshold: 3,
		MaxOpen:       500,
		EndpointPerf:  perf,
		Settings:      settings,
	})
}

// epNow 固定评估时刻：窗口终点 end=12:04:00（整体上移 1 分钟），起点 11:59:00，
// 窗口分钟桶为 11:59/12:00/12:01/12:02/12:03，最近 3 桶为 12:01-12:03。
var epNow = time.Date(2026, 8, 30, 12, 5, 30, 0, time.UTC)

func epBucket(i int) time.Time { // i=0 为窗口最早桶 11:59
	return time.Date(2026, 8, 30, 11, 59, 0, 0, time.UTC).Add(time.Duration(i) * time.Minute)
}

// slowDur 全部样本落 (2500,5000]ms 桶的直方图（p95 ≈ 4875ms）。
func slowDur(n int) []int {
	b := make([]int, len(metrics.DurationBucketsMs)+1)
	b[9] = n
	return b
}

// fastDur 全部样本落 ≤5ms 桶的直方图（p95 ≈ 4.75ms）。
func fastDur(n int) []int {
	b := make([]int, len(metrics.DurationBucketsMs)+1)
	b[0] = n
	return b
}

func epRow(app, endpoint string, bucket time.Time, requests, err5xx float64, dur []int) EndpointMinuteStat {
	return EndpointMinuteStat{App: app, Endpoint: endpoint, BucketStart: bucket, Requests: requests, Err5xx: err5xx, DurBuckets: dur}
}

// allSlowRows 5 个分钟桶全部慢（每桶 20 请求，可选每桶 5xx 数）。
func allSlowRows(app, endpoint string, perBucket int, errPerBucket float64) []EndpointMinuteStat {
	var rows []EndpointMinuteStat
	for i := 0; i < 5; i++ {
		rows = append(rows, epRow(app, endpoint, epBucket(i), float64(perBucket), errPerBucket, slowDur(perBucket)))
	}
	return rows
}

// findAlert 按类型找告警。
func findAlert(store *fakeStore, alertType string) *Alert {
	for _, a := range store.alerts {
		if a.AlertType == alertType {
			return a
		}
	}
	return nil
}

// TestEvaluateEndpointLatencyHigh 慢端点：持续超阈触发 → 合并 → 回落自动恢复。
func TestEvaluateEndpointLatencyHigh(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	perf := &fakeEndpointPerf{rows: allSlowRows("shop", "GET /api/{id}", 20, 0)}
	now := epNow
	e := newEndpointPerfEngine(store, perf, nil, &now)

	if err := e.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("EvaluateEndpointPerf: %v", err)
	}
	a := findAlert(store, TypeEndpointLatencyHigh)
	if a == nil {
		t.Fatal("持续慢端点应触发 ENDPOINT_LATENCY_HIGH")
	}
	if a.Component != "shop/GET /api/{id}" {
		t.Errorf("component = %q, want %q", a.Component, "shop/GET /api/{id}")
	}
	if a.Severity != SeverityMedium {
		t.Errorf("等级 = %s, want MEDIUM", a.Severity)
	}
	for _, want := range []string{"shop", "GET /api/{id}", "4875ms", "2000ms", "100 次", "连续 3 分钟"} {
		if !strings.Contains(a.Message, want) {
			t.Errorf("message 应含 %q: %q", want, a.Message)
		}
	}

	// 持续超阈 → 合并不新建
	if err := e.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("再次评估: %v", err)
	}
	if n := store.countByStatus(StatusOpen); n != 1 {
		t.Fatalf("持续触发应合并为同一条, got %d 条 OPEN", n)
	}

	// 窗口回落（全部变快）→ 自动恢复
	perf.rows = nil
	var rows []EndpointMinuteStat
	for i := 0; i < 5; i++ {
		rows = append(rows, epRow("shop", "GET /api/{id}", epBucket(i), 20, 0, fastDur(20)))
	}
	perf.rows = rows
	if err := e.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("回落评估: %v", err)
	}
	got := store.get(a.ID)
	if got.Status != StatusResolved || got.ResolveType == nil || *got.ResolveType != ResolveRecovered {
		t.Errorf("回落后应 RESOLVED(RECOVERED), got status=%s", got.Status)
	}
}

// TestEvaluateEndpointErrorRateHigh 端点 5xx 错误率持续超阈触发 HIGH 告警。
func TestEvaluateEndpointErrorRateHigh(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	// 每桶 20 请求 5 个 5xx（25% ≥ 默认 20%）
	perf := &fakeEndpointPerf{rows: allSlowRows("shop", "POST /pay", 20, 5)}
	now := epNow
	e := newEndpointPerfEngine(store, perf, nil, &now)

	if err := e.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("EvaluateEndpointPerf: %v", err)
	}
	a := findAlert(store, TypeEndpointErrorRateHigh)
	if a == nil {
		t.Fatal("持续高错误率应触发 ENDPOINT_ERROR_RATE_HIGH")
	}
	if a.Severity != SeverityHigh {
		t.Errorf("等级 = %s, want HIGH", a.Severity)
	}
	for _, want := range []string{"POST /pay", "25.0%", "20.0%", "5xx 25 次"} {
		if !strings.Contains(a.Message, want) {
			t.Errorf("message 应含 %q: %q", want, a.Message)
		}
	}
}

// TestEndpointMinRequestsGuard 最小请求量护栏：窗口总量低于阈值不告警（低流量端点
// 单次错误不误报）；settings 覆盖降低护栏后可触发。
func TestEndpointMinRequestsGuard(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	// 3 桶 × 10 请求 = 30 < 默认 60（即便全部慢且全 5xx）
	var rows []EndpointMinuteStat
	for i := 2; i < 5; i++ {
		rows = append(rows, epRow("shop", "GET /rare", epBucket(i), 10, 10, slowDur(10)))
	}
	perf := &fakeEndpointPerf{rows: rows}
	now := epNow
	e := newEndpointPerfEngine(store, perf, nil, &now)

	if err := e.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("EvaluateEndpointPerf: %v", err)
	}
	if n := store.countByStatus(StatusOpen); n != 0 {
		t.Fatalf("窗口请求 30 < 护栏 60 不应告警, got %d", n)
	}

	// settings 覆盖 min_requests=30 → 达护栏触发
	e2 := newEndpointPerfEngine(store, perf, &fakeSettings{ints: map[string]int{
		apmAlertSettingsGroup + "/" + apmAlertKeyMinRequests: 30,
	}}, &now)
	if err := e2.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("覆盖后评估: %v", err)
	}
	if findAlert(store, TypeEndpointLatencyHigh) == nil || findAlert(store, TypeEndpointErrorRateHigh) == nil {
		t.Error("min_requests=30 覆盖后应触发两类告警")
	}
}

// TestEndpointSustainGuard 持续窗口护栏：窗口级超阈但最近连续桶不足 sustain 不告警；
// 连续桶补齐后告警。
func TestEndpointSustainGuard(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	// 窗口 120 请求（80 快 40 慢，窗口 p95≈4625 ≥ 2000），但最近 3 桶中 12:01 为快桶
	rows := []EndpointMinuteStat{
		epRow("shop", "GET /mixed", epBucket(0), 30, 0, fastDur(30)),
		epRow("shop", "GET /mixed", epBucket(1), 30, 0, fastDur(30)),
		epRow("shop", "GET /mixed", epBucket(2), 20, 0, fastDur(20)),
		epRow("shop", "GET /mixed", epBucket(3), 20, 0, slowDur(20)),
		epRow("shop", "GET /mixed", epBucket(4), 20, 0, slowDur(20)),
	}
	perf := &fakeEndpointPerf{rows: rows}
	now := epNow
	e := newEndpointPerfEngine(store, perf, nil, &now)

	if err := e.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("EvaluateEndpointPerf: %v", err)
	}
	if findAlert(store, TypeEndpointLatencyHigh) != nil {
		t.Error("最近 3 桶未全部超阈（12:01 快桶中断连续）不应告警")
	}

	// 12:01 也转慢 → 连续 3 桶超阈 → 告警
	perf.rows[2] = epRow("shop", "GET /mixed", epBucket(2), 20, 0, slowDur(20))
	if err := e.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("再次评估: %v", err)
	}
	if findAlert(store, TypeEndpointLatencyHigh) == nil {
		t.Error("最近 3 桶连续超阈后应告警")
	}
}

// TestEndpointSustainBrokenByNoTraffic 最新分钟桶无流量（缺失）即中断连续，不告警。
func TestEndpointSustainBrokenByNoTraffic(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	// 最早 3 桶慢且足量，但 12:02/12:03 无数据（流量停止）
	var rows []EndpointMinuteStat
	for i := 0; i < 3; i++ {
		rows = append(rows, epRow("shop", "GET /gone", epBucket(i), 25, 0, slowDur(25)))
	}
	perf := &fakeEndpointPerf{rows: rows}
	now := epNow
	e := newEndpointPerfEngine(store, perf, nil, &now)

	if err := e.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("EvaluateEndpointPerf: %v", err)
	}
	if n := store.countByStatus(StatusOpen); n != 0 {
		t.Fatalf("最新分钟桶缺失应中断连续不告警, got %d", n)
	}
}

// TestEndpointPseudoEndpointSkip 伪端点保留桶（__OTHER__/__UNCLASSIFIED__）跳过评估。
func TestEndpointPseudoEndpointSkip(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	perf := &fakeEndpointPerf{rows: append(
		allSlowRows("shop", aggregations.EndpointOther, 20, 5),
		allSlowRows("shop", aggregations.EndpointUnclassified, 20, 5)...,
	)}
	now := epNow
	e := newEndpointPerfEngine(store, perf, nil, &now)

	if err := e.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("EvaluateEndpointPerf: %v", err)
	}
	if perf.calls != 1 {
		t.Errorf("评估应读取一次统计, got %d", perf.calls)
	}
	if n := store.countByStatus(StatusOpen); n != 0 {
		t.Errorf("伪端点不应产生告警, got %d", n)
	}
}

// TestEndpointPerfSettingsOverride 阈值 settings 覆盖与非法值回退。
func TestEndpointPerfSettingsOverride(t *testing.T) {
	ctx := context.Background()
	now := epNow

	// p95 阈值提高到 6000：p95≈4875 不再超阈
	store := newFakeStore()
	perf := &fakeEndpointPerf{rows: allSlowRows("shop", "GET /a", 20, 5)}
	e := newEndpointPerfEngine(store, perf, &fakeSettings{
		ints:   map[string]int{apmAlertSettingsGroup + "/" + apmAlertKeyEndpointP95Ms: 6000},
		floats: map[string]float64{apmAlertSettingsGroup + "/" + apmAlertKeyEndpointErrorRate: 0.5},
	}, &now)
	if err := e.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("EvaluateEndpointPerf: %v", err)
	}
	if n := store.countByStatus(StatusOpen); n != 0 {
		t.Errorf("p95 阈值 6000 / 错误率阈值 0.5 下不应告警, got %d", n)
	}

	// 非法值（0 / >1 / sustain 超窗口）→ 回退默认后照常触发
	store2 := newFakeStore()
	e2 := newEndpointPerfEngine(store2, perf, &fakeSettings{
		ints: map[string]int{
			apmAlertSettingsGroup + "/" + apmAlertKeyEndpointP95Ms:  0,
			apmAlertSettingsGroup + "/" + apmAlertKeySustainMinutes: 9, // > 窗口 5 分钟
		},
		floats: map[string]float64{apmAlertSettingsGroup + "/" + apmAlertKeyEndpointErrorRate: 2},
	}, &now)
	if err := e2.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("非法配置评估: %v", err)
	}
	if findAlert(store2, TypeEndpointLatencyHigh) == nil || findAlert(store2, TypeEndpointErrorRateHigh) == nil {
		t.Error("非法配置应回退默认并照常触发")
	}
}

// TestEndpointPerfAutoRecoverVanished 窗口内已无流量的端点其未关闭告警自动恢复
// （ListOpenByTypes 恢复扫描路径）。
func TestEndpointPerfAutoRecoverVanished(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	perf := &fakeEndpointPerf{rows: allSlowRows("shop", "GET /api/{id}", 20, 0)}
	now := epNow
	e := newEndpointPerfEngine(store, perf, nil, &now)

	if err := e.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("EvaluateEndpointPerf: %v", err)
	}
	a := findAlert(store, TypeEndpointLatencyHigh)
	if a == nil {
		t.Fatal("应先触发告警")
	}
	// 端点从聚合数据消失（无流量）
	perf.rows = nil
	if err := e.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("空窗评估: %v", err)
	}
	if got := store.get(a.ID); got.Status != StatusResolved {
		t.Errorf("端点无数据后应自动恢复, got status=%s", got.Status)
	}
}

// TestEvaluateEndpointPerfStoreError 统计读数失败：如实返回错误，不产生/清动告警。
func TestEvaluateEndpointPerfStoreError(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	perf := &fakeEndpointPerf{err: errors.New("db down")}
	now := epNow
	e := newEndpointPerfEngine(store, perf, nil, &now)

	if err := e.EvaluateEndpointPerf(ctx); err == nil {
		t.Fatal("读数失败应返回错误")
	}
	if n := store.countByStatus(StatusOpen); n != 0 {
		t.Errorf("读数失败不应产生告警, got %d", n)
	}
}

// TestEvaluateEndpointPerfNilSource 未注入统计源时不执行（APM_ENABLED 关闭的装配形态）。
func TestEvaluateEndpointPerfNilSource(t *testing.T) {
	e := NewEngine(newFakeStore(), EngineOptions{})
	if err := e.EvaluateEndpointPerf(context.Background()); err != nil {
		t.Fatalf("未注入统计源应为无操作, got %v", err)
	}
}

// TestEndpointPerfWindowBounds 评估窗口：仅取已完成且定稿的分钟桶（整体上移 1 分钟）。
func TestEndpointPerfWindowBounds(t *testing.T) {
	store := newFakeStore()
	perf := &fakeEndpointPerf{}
	now := epNow // 12:05:30
	e := newEndpointPerfEngine(store, perf, nil, &now)
	if err := e.EvaluateEndpointPerf(context.Background()); err != nil {
		t.Fatalf("EvaluateEndpointPerf: %v", err)
	}
	wantEnd := time.Date(2026, 8, 30, 12, 4, 0, 0, time.UTC)
	wantStart := wantEnd.Add(-5 * time.Minute)
	if !perf.lastEnd.Equal(wantEnd) || !perf.lastStart.Equal(wantStart) {
		t.Errorf("窗口 = [%s, %s), want [%s, %s)", perf.lastStart, perf.lastEnd, wantStart, wantEnd)
	}
}

// TestLoadEndpointPerfConfig 配置读取：nil 全默认、合法覆盖、边界与非法回退。
func TestLoadEndpointPerfConfig(t *testing.T) {
	ctx := context.Background()

	cfg := loadEndpointPerfConfig(ctx, nil)
	if cfg.P95Ms != defaultEndpointP95Ms || cfg.ErrorRate != defaultEndpointErrorRate ||
		cfg.MinRequests != defaultEndpointMinRequests || cfg.Sustain != defaultEndpointSustainMin {
		t.Errorf("默认配置错误: %+v", cfg)
	}

	cfg = loadEndpointPerfConfig(ctx, &fakeSettings{
		ints: map[string]int{
			apmAlertSettingsGroup + "/" + apmAlertKeyEndpointP95Ms:  1500,
			apmAlertSettingsGroup + "/" + apmAlertKeyMinRequests:    100,
			apmAlertSettingsGroup + "/" + apmAlertKeySustainMinutes: 5, // 上限=窗口分钟数
		},
		floats: map[string]float64{apmAlertSettingsGroup + "/" + apmAlertKeyEndpointErrorRate: 0.05},
	})
	if cfg.P95Ms != 1500 || cfg.ErrorRate != 0.05 || cfg.MinRequests != 100 || cfg.Sustain != 5 {
		t.Errorf("覆盖配置未生效: %+v", cfg)
	}

	bad := &fakeSettings{
		ints: map[string]int{
			apmAlertSettingsGroup + "/" + apmAlertKeyEndpointP95Ms:  -1,
			apmAlertSettingsGroup + "/" + apmAlertKeyMinRequests:    0,
			apmAlertSettingsGroup + "/" + apmAlertKeySustainMinutes: 6, // 超窗口
		},
		floats: map[string]float64{apmAlertSettingsGroup + "/" + apmAlertKeyEndpointErrorRate: 1.5},
	}
	cfg = loadEndpointPerfConfig(ctx, bad)
	if cfg.P95Ms != defaultEndpointP95Ms || cfg.ErrorRate != defaultEndpointErrorRate ||
		cfg.MinRequests != defaultEndpointMinRequests || cfg.Sustain != defaultEndpointSustainMin {
		t.Errorf("非法配置应回退默认: %+v", cfg)
	}
}

// TestEndpointPerfComponent 组件标识：短键直通、控制字符清洗、超长截断+摘要后缀
// （≤40 字符适配 system_alerts.component VARCHAR(40)，截断不碰撞）。
func TestEndpointPerfComponent(t *testing.T) {
	short := endpointPerfComponent("shop", "GET /api/{id}")
	if short != "shop/GET /api/{id}" {
		t.Errorf("短键应直通, got %q", short)
	}
	if got := endpointPerfComponent("sh\top", "GET /x\ny"); strings.ContainsAny(got, "\t\n") {
		t.Errorf("控制字符应清洗, got %q", got)
	}

	longEndpoint := "GET /" + strings.Repeat("很长的路径段", 20) + "/{id}"
	c1 := endpointPerfComponent("shop", longEndpoint)
	if utf8.RuneCountInString(c1) != endpointComponentMaxLen {
		t.Errorf("超长键应截断为 %d 字符, got %d", endpointComponentMaxLen, utf8.RuneCountInString(c1))
	}
	if c1 != endpointPerfComponent("shop", longEndpoint) {
		t.Error("同输入应得同去重键（确定性）")
	}
	c2 := endpointPerfComponent("shop", longEndpoint+"v2")
	if c1 == c2 {
		t.Error("截断后不同长键不应碰撞（摘要后缀）")
	}
}

// TestEndpointPerfAlertTypes 新告警类型注册与默认等级（防回归：未注册引擎会拒绝 Raise）。
func TestEndpointPerfAlertTypes(t *testing.T) {
	cases := []struct {
		alertType string
		severity  string
	}{
		{TypeEndpointLatencyHigh, SeverityMedium},
		{TypeEndpointErrorRateHigh, SeverityHigh},
	}
	for _, c := range cases {
		if !IsValidType(c.alertType) {
			t.Errorf("%s 未注册为合法告警类型", c.alertType)
		}
		if got := SeverityFor(c.alertType); got != c.severity {
			t.Errorf("%s 等级 = %s, want %s", c.alertType, got, c.severity)
		}
	}
}
