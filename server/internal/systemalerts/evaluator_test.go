package systemalerts

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/runtimehealth"
)

// fakeStore 是 EngineStore + ParseStatsStore 的内存实现。
type fakeStore struct {
	mu          sync.Mutex
	alerts      map[uuid.UUID]*Alert
	openTotal   *int // 非 nil 时覆盖 CountOpen（模拟上限）
	failures    int64
	processed   int64
	silencedNow *time.Time // 非 nil 时 HasActiveSilence 用此时刻判定（可控时钟）
}

func newFakeStore() *fakeStore {
	return &fakeStore{alerts: map[uuid.UUID]*Alert{}}
}

func (f *fakeStore) FindOpen(_ context.Context, alertType, component string) (*Alert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var best *Alert
	for _, a := range f.alerts {
		if a.AlertType == alertType && a.Component == component && IsOpenStatus(a.Status) {
			if best == nil || a.LastSeenAt.After(best.LastSeenAt) {
				best = a
			}
		}
	}
	if best == nil {
		return nil, nil
	}
	cp := *best
	return &cp, nil
}

func (f *fakeStore) Insert(_ context.Context, a *Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a.ID = uuid.New()
	a.CreatedAt = a.FirstSeenAt
	cp := *a
	f.alerts[a.ID] = &cp
	return nil
}

func (f *fakeStore) Merge(_ context.Context, id uuid.UUID, message, severity string, updateMessage bool, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.alerts[id]
	if !ok || !IsOpenStatus(a.Status) {
		return ErrNotFound
	}
	a.OccurrenceCount++
	a.LastSeenAt = now
	if updateMessage {
		a.Message = message
		a.Severity = severity
	}
	return nil
}

func (f *fakeStore) CountOpen(_ context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.openTotal != nil {
		return *f.openTotal, nil
	}
	n := 0
	for _, a := range f.alerts {
		if a.Status == StatusOpen {
			n++
		}
	}
	return n, nil
}

func (f *fakeStore) ListOpenByComponent(_ context.Context, component string, alertTypes []string) ([]Alert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Alert
	for _, a := range f.alerts {
		if a.Component != component || !IsOpenStatus(a.Status) {
			continue
		}
		if len(alertTypes) > 0 {
			match := false
			for _, t := range alertTypes {
				if a.AlertType == t {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeenAt.After(out[j].LastSeenAt) })
	return out, nil
}

func (f *fakeStore) ListOpenByTypes(_ context.Context, alertTypes []string) ([]Alert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Alert
	for _, a := range f.alerts {
		if !IsOpenStatus(a.Status) {
			continue
		}
		match := false
		for _, t := range alertTypes {
			if a.AlertType == t {
				match = true
				break
			}
		}
		if match {
			out = append(out, *a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeenAt.After(out[j].LastSeenAt) })
	return out, nil
}

func (f *fakeStore) ResolveRecovered(_ context.Context, id uuid.UUID, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.alerts[id]
	if !ok || !IsOpenStatus(a.Status) {
		return ErrNotFound
	}
	a.Status = StatusResolved
	a.ResolvedAt = &now
	rt := ResolveRecovered
	a.ResolveType = &rt
	return nil
}

func (f *fakeStore) ParseFailureRate(_ context.Context, _ time.Duration) (int64, int64, error) {
	return f.failures, f.processed, nil
}

// HasActiveSilence 内存实现：同指纹（alert_type+component）存在 silenced_until 晚于
// 当前时刻的告警即为静默中（含已关闭行，与 Store SQL 口径一致）；silencedNow 为
// 测试注入的当前时刻（nil 时用真实时钟）。
func (f *fakeStore) HasActiveSilence(_ context.Context, alertType, component string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.silencedNow != nil {
		now = *f.silencedNow
	}
	for _, a := range f.alerts {
		if a.AlertType == alertType && a.Component == component &&
			a.SilencedUntil != nil && a.SilencedUntil.After(now) {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) get(id uuid.UUID) Alert {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.alerts[id]
}

func (f *fakeStore) countByStatus(status string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, a := range f.alerts {
		if a.Status == status {
			n++
		}
	}
	return n
}

// testEngine 创建可控时钟的引擎。
func testEngine(store *fakeStore, now *time.Time) *Engine {
	return NewEngine(store, EngineOptions{
		Now:           func() time.Time { return *now },
		Cooldown:      time.Minute,
		FlapWindow:    10 * time.Minute,
		FlapThreshold: 3,
		MaxOpen:       500,
		ParseStats:    store,
	})
}

func raiseGatewayDown(e *Engine, ctx context.Context) (*Alert, error) {
	return e.Raise(ctx, RaiseRequest{
		AlertType: TypeGatewayDown,
		Component: runtimehealth.ComponentGateway,
		Title:     "防护网关不可用",
		Message:   "网关 Admin Socket 不可达",
	})
}

// TestRaiseCreatesNewAlert 新建 OPEN 告警。
func TestRaiseCreatesNewAlert(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	e := testEngine(store, &now)
	a, err := raiseGatewayDown(e, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != StatusOpen {
		t.Errorf("状态 = %s，期望 OPEN", a.Status)
	}
	if a.Severity != SeverityCritical {
		t.Errorf("等级 = %s，期望 CRITICAL（规则默认值）", a.Severity)
	}
	if a.OccurrenceCount != 1 {
		t.Errorf("occurrence_count = %d，期望 1", a.OccurrenceCount)
	}
}

// TestRaiseInvalidType 非法类型/等级校验。
func TestRaiseInvalidType(t *testing.T) {
	store := newFakeStore()
	now := time.Now()
	e := testEngine(store, &now)
	if _, err := e.Raise(context.Background(), RaiseRequest{AlertType: "BOGUS"}); err == nil {
		t.Error("非法类型应报错")
	}
	if _, err := e.Raise(context.Background(), RaiseRequest{
		AlertType: TypeGatewayDown, Severity: "WARN",
	}); err == nil {
		t.Error("非法等级应报错")
	}
}

// TestRaiseMergeAndCooldown 合并：occurrence_count+1、last_seen_at 更新；冷却期内不更新 message。
func TestRaiseMergeAndCooldown(t *testing.T) {
	store := newFakeStore()
	ctx := context.Background()
	now := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	e := testEngine(store, &now)

	first, err := raiseGatewayDown(e, ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 冷却期内（30 秒后）再次触发：合并但不更新 message
	now = now.Add(30 * time.Second)
	merged, err := e.Raise(ctx, RaiseRequest{
		AlertType: TypeGatewayDown, Component: runtimehealth.ComponentGateway,
		Title: "防护网关不可用", Message: "新的错误详情",
	})
	if err != nil {
		t.Fatal(err)
	}
	if merged.ID != first.ID {
		t.Error("同 type+component 应合并到既有告警")
	}
	got := store.get(first.ID)
	if got.OccurrenceCount != 2 {
		t.Errorf("occurrence_count = %d，期望 2", got.OccurrenceCount)
	}
	if !got.LastSeenAt.Equal(now) {
		t.Errorf("last_seen_at 未更新到 %v", now)
	}
	if got.Message != "网关 Admin Socket 不可达" {
		t.Errorf("冷却期内 message 不应更新，实际 %q", got.Message)
	}
	// 冷却期后（再 61 秒）：message 更新
	now = now.Add(61 * time.Second)
	if _, err := e.Raise(ctx, RaiseRequest{
		AlertType: TypeGatewayDown, Component: runtimehealth.ComponentGateway,
		Title: "防护网关不可用", Message: "新的错误详情",
	}); err != nil {
		t.Fatal(err)
	}
	got = store.get(first.ID)
	if got.Message != "新的错误详情" {
		t.Errorf("冷却期后 message 应更新，实际 %q", got.Message)
	}
	if got.OccurrenceCount != 3 {
		t.Errorf("occurrence_count = %d，期望 3", got.OccurrenceCount)
	}
}

// TestMaxOpenProtection OPEN 总数超限时 LOW/INFO 新告警直接 IGNORED，高级别仍正常创建。
func TestMaxOpenProtection(t *testing.T) {
	store := newFakeStore()
	cap501 := 501
	store.openTotal = &cap501
	now := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	e := testEngine(store, &now)
	ctx := context.Background()

	low, err := e.Raise(ctx, RaiseRequest{
		AlertType: TypeCertificateExpiring, Component: runtimehealth.ComponentCertificate,
		Title: "证书即将到期", Message: "证书剩余 20 天", Severity: SeverityLow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if low.Status != StatusIgnored {
		t.Errorf("LOW 告警在超限时状态 = %s，期望 IGNORED", low.Status)
	}
	if !strings.Contains(store.get(low.ID).Message, "未关闭告警超过上限") {
		t.Errorf("被忽略告警 message 应记原因，实际 %q", store.get(low.ID).Message)
	}

	high, err := e.Raise(ctx, RaiseRequest{
		AlertType: TypeGatewayDown, Component: runtimehealth.ComponentGateway,
		Title: "防护网关不可用", Message: "网关不可达",
	})
	if err != nil {
		t.Fatal(err)
	}
	if high.Status != StatusOpen {
		t.Errorf("CRITICAL 告警不受上限保护影响，状态 = %s，期望 OPEN", high.Status)
	}
}

// TestFlapSuppression 抖动抑制：10 分钟内翻转 ≥3 次后告警保持 OPEN 且 message 含"抖动"。
func TestFlapSuppression(t *testing.T) {
	store := newFakeStore()
	ctx := context.Background()
	now := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	e := testEngine(store, &now)

	// 第 1 次故障 → 创建（翻转 1）
	first, err := raiseGatewayDown(e, ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 1 分钟后恢复（翻转 2）
	now = now.Add(time.Minute)
	n, err := e.AutoRecover(ctx, runtimehealth.ComponentGateway, TypeGatewayDown)
	if err != nil || n != 1 {
		t.Fatalf("第一次恢复应成功 n=%d err=%v", n, err)
	}
	// 1 分钟后再次故障（翻转 3，达到阈值）
	now = now.Add(time.Minute)
	second, err := raiseGatewayDown(e, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID == first.ID {
		t.Error("恢复后重新触发应新建告警")
	}
	// 抖动状态下尝试自动恢复：应保持 OPEN 且标记抖动
	now = now.Add(30 * time.Second)
	n, err = e.AutoRecover(ctx, runtimehealth.ComponentGateway, TypeGatewayDown)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("抖动中不应自动恢复，实际恢复 %d 条", n)
	}
	got := store.get(second.ID)
	if got.Status != StatusOpen {
		t.Errorf("抖动中应保持 OPEN，实际 %s", got.Status)
	}
	if !strings.Contains(got.Message, "抖动") {
		t.Errorf("抖动中 message 应含\"抖动\"，实际 %q", got.Message)
	}
	// 窗口翻转计数过期后（11 分钟无事件），恢复正常自动恢复
	now = now.Add(11 * time.Minute)
	n, err = e.AutoRecover(ctx, runtimehealth.ComponentGateway, TypeGatewayDown)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("翻转计数过期后应正常恢复，实际 %d", n)
	}
	if got := store.get(second.ID); got.Status != StatusResolved {
		t.Errorf("恢复后状态 = %s，期望 RESOLVED", got.Status)
	}
}

// TestAutoRecover 组件恢复时 OPEN/ACKNOWLEDGED 告警自动 RESOLVED(RECOVERED)。
func TestAutoRecover(t *testing.T) {
	store := newFakeStore()
	ctx := context.Background()
	now := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	e := testEngine(store, &now)

	a, err := raiseGatewayDown(e, ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 无翻转历史，直接恢复
	now = now.Add(2 * time.Minute)
	n, err := e.AutoRecover(ctx, runtimehealth.ComponentGateway, TypeGatewayDown)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("应恢复 1 条，实际 %d", n)
	}
	got := store.get(a.ID)
	if got.Status != StatusResolved {
		t.Errorf("状态 = %s，期望 RESOLVED", got.Status)
	}
	if got.ResolveType == nil || *got.ResolveType != ResolveRecovered {
		t.Errorf("resolve_type = %v，期望 RECOVERED", got.ResolveType)
	}
}

// TestEvaluateSnapshots 健康快照→告警规则映射。
func TestEvaluateSnapshots(t *testing.T) {
	store := newFakeStore()
	ctx := context.Background()
	now := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	e := testEngine(store, &now)

	snaps := []runtimehealth.Snapshot{
		{Component: runtimehealth.ComponentGateway, Status: runtimehealth.StatusDown, Message: "网关 Admin Socket 不可达", Metrics: map[string]interface{}{}},
		{Component: runtimehealth.ComponentPostgres, Status: runtimehealth.StatusUp, Metrics: map[string]interface{}{
			runtimehealth.MetricDBCapacityPercent: 91.5,
		}},
		{Component: runtimehealth.ComponentValkey, Status: runtimehealth.StatusDown, Message: "Valkey 不可达", Metrics: map[string]interface{}{}},
		{Component: runtimehealth.ComponentCertificate, Status: runtimehealth.StatusDegraded, Metrics: map[string]interface{}{
			runtimehealth.MetricMinDaysRemaining: 5,
			runtimehealth.MetricExpiredCount:     0,
		}},
		{Component: runtimehealth.ComponentDisk, Status: runtimehealth.StatusDegraded, Metrics: map[string]interface{}{
			runtimehealth.MetricDiskFreePercent: 8.2,
		}},
		{Component: runtimehealth.ComponentUpstream, Status: runtimehealth.StatusDegraded, Message: "源站健康 1/3", Metrics: map[string]interface{}{}},
		{Component: runtimehealth.ComponentEventCollector, Status: runtimehealth.StatusUp, Metrics: map[string]interface{}{}},
	}
	if err := e.Evaluate(ctx, snaps); err != nil {
		t.Fatal(err)
	}
	expect := map[string]string{
		TypeGatewayDown:          SeverityCritical,
		TypeDatabaseCapacityHigh: SeverityMedium,
		TypeValkeyUnavailable:    SeverityHigh,
		TypeCertificateExpiring:  SeverityMedium, // 剩 5 天 ≤7
		TypeDiskSpaceLow:         SeverityHigh,
		TypeSourceUnhealthy:      SeverityMedium,
	}
	for alertType, sev := range expect {
		found := false
		store.mu.Lock()
		for _, al := range store.alerts {
			if al.AlertType == alertType && IsOpenStatus(al.Status) {
				found = true
				if al.Severity != sev {
					t.Errorf("%s 等级 = %s，期望 %s", alertType, al.Severity, sev)
				}
			}
		}
		store.mu.Unlock()
		if !found {
			t.Errorf("应产生 %s 告警", alertType)
		}
	}
	// EVENT_COLLECTOR UP 不应产生滞后告警
	store.mu.Lock()
	for _, al := range store.alerts {
		if al.AlertType == TypeEventCollectorLag {
			t.Error("采集正常不应产生 EVENT_COLLECTOR_LAG")
		}
	}
	store.mu.Unlock()

	// 网关恢复 UP → GATEWAY_DOWN 自动恢复（翻转计数 1，未达阈值）
	now = now.Add(time.Minute)
	if err := e.Evaluate(ctx, []runtimehealth.Snapshot{
		{Component: runtimehealth.ComponentGateway, Status: runtimehealth.StatusUp, Metrics: map[string]interface{}{}},
	}); err != nil {
		t.Fatal(err)
	}
	open, err := store.ListOpenByComponent(ctx, runtimehealth.ComponentGateway, []string{TypeGatewayDown})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 0 {
		t.Errorf("网关恢复后 GATEWAY_DOWN 应自动解决，仍有 %d 条未关闭", len(open))
	}
}

// TestEvaluateParseFailures 解析失败率评估。
func TestEvaluateParseFailures(t *testing.T) {
	store := newFakeStore()
	ctx := context.Background()
	now := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	e := testEngine(store, &now)

	// 失败 10 条 / 总量 100 条 = 10% 失败率 → 触发
	store.failures, store.processed = 10, 90
	if err := e.EvaluateParseFailures(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := store.FindOpen(ctx, TypeParseFailureRateHigh, runtimehealth.ComponentEventCollector)
	if err != nil {
		t.Fatal(err)
	}
	if a == nil {
		t.Fatal("失败率达阈应产生 EVENT_PARSE_FAILURE_RATE_HIGH")
	}
	if a.Severity != SeverityMedium {
		t.Errorf("等级 = %s，期望 MEDIUM", a.Severity)
	}
	// 失败率回落 → 自动恢复
	now = now.Add(time.Minute)
	store.failures, store.processed = 1, 999
	if err := e.EvaluateParseFailures(ctx); err != nil {
		t.Fatal(err)
	}
	a, err = store.FindOpen(ctx, TypeParseFailureRateHigh, runtimehealth.ComponentEventCollector)
	if err != nil {
		t.Fatal(err)
	}
	if a != nil {
		t.Error("失败率回落后应自动恢复")
	}
}

// TestDecideRaisePure 纯函数：合并/冷却/上限保护/抖动决策。
func TestDecideRaisePure(t *testing.T) {
	now := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	base := raiseInput{
		Now: now, Severity: SeverityHigh, OpenTotal: 0, MaxOpen: 500,
		FlapThreshold: 3, Cooldown: 5 * time.Minute,
	}
	// 无既有 → 新建
	d := decideRaise(base)
	if d.action != actionCreate {
		t.Errorf("无既有告警应新建，实际 action=%d", d.action)
	}
	// 有既有 → 合并；从未更新 message 时应更新
	in := base
	in.HasExisting = true
	d = decideRaise(in)
	if d.action != actionMerge || !d.updateMessage {
		t.Errorf("有既有应合并且首次更新 message，实际 action=%d update=%v", d.action, d.updateMessage)
	}
	// 冷却期内不更新 message
	in.LastMessageUpdate = now.Add(-time.Minute)
	d = decideRaise(in)
	if d.updateMessage {
		t.Error("冷却期内不应更新 message")
	}
	// 冷却期后更新
	in.LastMessageUpdate = now.Add(-6 * time.Minute)
	d = decideRaise(in)
	if !d.updateMessage {
		t.Error("冷却期后应更新 message")
	}
	// 上限保护：仅 LOW/INFO
	in = base
	in.OpenTotal = 500
	in.Severity = SeverityLow
	d = decideRaise(in)
	if d.action != actionCreateIgnored {
		t.Errorf("OPEN 达上限时 LOW 应直接 IGNORED，实际 action=%d", d.action)
	}
	in.Severity = SeverityCritical
	d = decideRaise(in)
	if d.action != actionCreate {
		t.Errorf("CRITICAL 不受上限保护，实际 action=%d", d.action)
	}
	// 抖动判定
	in = base
	in.FlapCount = 3
	d = decideRaise(in)
	if !d.flapping {
		t.Error("翻转达阈值应判定抖动")
	}
}

// TestParseFailureRatePure 失败率计算与判定纯函数。
func TestParseFailureRatePure(t *testing.T) {
	if got := parseFailureRate(0, 0); got != 0 {
		t.Errorf("无数据失败率 = %v，期望 0", got)
	}
	if got := parseFailureRate(10, 90); got != 10.0 {
		t.Errorf("失败率 = %v，期望 10", got)
	}
	if !parseFailureRateHigh(5, 12, 5, 10) {
		t.Error("失败数与失败率双达阈应判定过高")
	}
	if parseFailureRateHigh(4, 50, 5, 10) {
		t.Error("失败数未达下限不应判定过高（防小样本误报）")
	}
	if parseFailureRateHigh(100, 5, 5, 10) {
		t.Error("失败率未达阈不应判定过高")
	}
}
