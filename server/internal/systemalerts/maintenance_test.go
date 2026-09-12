package systemalerts

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/runtimehealth"
)

// fakeMaintenanceStore 是 MaintenanceStore 的内存实现。
type fakeMaintenanceStore struct {
	mu          sync.Mutex
	windows     []MaintenanceWindow
	suppressed  map[uuid.UUID]int
	findErr     error
	suppressErr error
}

func newFakeMaintenanceStore(windows ...MaintenanceWindow) *fakeMaintenanceStore {
	return &fakeMaintenanceStore{windows: windows, suppressed: map[uuid.UUID]int{}}
}

func (f *fakeMaintenanceStore) FindActiveMaintenanceWindows(_ context.Context, now time.Time, alertType, component string) ([]MaintenanceWindow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.findErr != nil {
		return nil, f.findErr
	}
	var out []MaintenanceWindow
	for _, w := range f.windows {
		if w.ActiveAt(now) && w.Matches(alertType, component) {
			out = append(out, w)
		}
	}
	return out, nil
}

func (f *fakeMaintenanceStore) RecordMaintenanceSuppression(_ context.Context, ids []uuid.UUID, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.suppressErr != nil {
		return f.suppressErr
	}
	for _, id := range ids {
		f.suppressed[id]++
	}
	return nil
}

func (f *fakeMaintenanceStore) suppressedTotal(id uuid.UUID) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.suppressed[id]
}

func onceWindow(start, end time.Time) MaintenanceWindow {
	return MaintenanceWindow{
		ID: uuid.New(), Name: "停机维护", Scope: MaintScopeAll,
		Recurrence: MaintRecurrenceOnce, StartsAt: start, EndsAt: end, Enabled: true,
	}
}

func dailyWindow(start, end time.Time, startMin, endMin int) MaintenanceWindow {
	return MaintenanceWindow{
		ID: uuid.New(), Name: "每日维护", Scope: MaintScopeAll,
		Recurrence: MaintRecurrenceDaily, StartsAt: start, EndsAt: end,
		DailyStartMinute: &startMin, DailyEndMinute: &endMin, Enabled: true,
	}
}

// TestMaintenanceWindowActiveAtOnce 一次性窗口边界：起止时刻含边界，窗口外/禁用不生效。
func TestMaintenanceWindowActiveAtOnce(t *testing.T) {
	start := time.Date(2026, 9, 10, 2, 0, 0, 0, time.UTC)
	end := time.Date(2026, 9, 10, 4, 0, 0, 0, time.UTC)
	w := onceWindow(start, end)
	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"开始前一分钟", start.Add(-time.Minute), false},
		{"开始时刻", start, true},
		{"窗口内", start.Add(time.Hour), true},
		{"结束时刻", end, true},
		{"结束后一分钟", end.Add(time.Minute), false},
	}
	for _, c := range cases {
		if got := w.ActiveAt(c.now); got != c.want {
			t.Errorf("%s: ActiveAt = %v，期望 %v", c.name, got, c.want)
		}
	}
	disabled := w
	disabled.Enabled = false
	if disabled.ActiveAt(start.Add(time.Hour)) {
		t.Error("禁用窗口不应生效")
	}
}

// TestMaintenanceWindowActiveAtDaily 每日时段窗口：时段内/外、跨零点、日期跨度外。
func TestMaintenanceWindowActiveAtDaily(t *testing.T) {
	start := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 9, 12, 23, 59, 0, 0, time.UTC)
	// 每日 02:00-04:00（UTC）
	w := dailyWindow(start, end, 120, 240)
	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"时段起点", time.Date(2026, 9, 10, 2, 0, 0, 0, time.UTC), true},
		{"时段内", time.Date(2026, 9, 11, 3, 30, 0, 0, time.UTC), true},
		{"时段终点（不含）", time.Date(2026, 9, 10, 4, 0, 0, 0, time.UTC), false},
		{"时段外", time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC), false},
		{"跨度开始前", start.Add(-time.Hour), false},
		{"跨度结束后", end.Add(time.Minute), false},
	}
	for _, c := range cases {
		if got := w.ActiveAt(c.now); got != c.want {
			t.Errorf("%s: ActiveAt = %v，期望 %v", c.name, got, c.want)
		}
	}
	// 跨零点：每日 23:00-01:00
	cross := dailyWindow(start, end, 23*60, 60)
	for _, c := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{"跨零点-当日晚", time.Date(2026, 9, 10, 23, 30, 0, 0, time.UTC), true},
		{"跨零点-次日早", time.Date(2026, 9, 11, 0, 30, 0, 0, time.UTC), true},
		{"跨零点-时段外", time.Date(2026, 9, 11, 2, 0, 0, 0, time.UTC), false},
	} {
		if got := cross.ActiveAt(c.now); got != c.want {
			t.Errorf("%s: ActiveAt = %v，期望 %v", c.name, got, c.want)
		}
	}
	// DAILY 缺时段字段不生效（数据异常时宁可放行告警，不静默）
	noMinutes := dailyWindow(start, end, 120, 240)
	noMinutes.DailyStartMinute = nil
	if noMinutes.ActiveAt(time.Date(2026, 9, 10, 3, 0, 0, 0, time.UTC)) {
		t.Error("DAILY 缺时段字段不应生效")
	}
}

// TestMaintenanceWindowMatches 作用范围匹配：ALL 全覆盖；CUSTOM 空维度通配、命中过滤。
func TestMaintenanceWindowMatches(t *testing.T) {
	all := onceWindow(time.Now(), time.Now().Add(time.Hour))
	if !all.Matches(TypeGatewayDown, runtimehealth.ComponentGateway) {
		t.Error("ALL 范围应覆盖任意告警")
	}
	custom := onceWindow(time.Now(), time.Now().Add(time.Hour))
	custom.Scope = MaintScopeCustom
	custom.AlertTypes = []string{TypeFDUsageHigh}
	if !custom.Matches(TypeFDUsageHigh, "API") {
		t.Error("CUSTOM 类型命中应匹配")
	}
	if custom.Matches(TypeGatewayDown, "API") {
		t.Error("CUSTOM 类型未命中不应匹配（组件维度空=通配）")
	}
	custom.Components = []string{"API"}
	if custom.Matches(TypeFDUsageHigh, "GATEWAY") {
		t.Error("CUSTOM 组件未命中不应匹配")
	}
	if !custom.Matches(TypeFDUsageHigh, "API") {
		t.Error("CUSTOM 两维度均命中应匹配")
	}
}

// TestMaintenanceWindowInputValidate 创建入参校验与归一化。
func TestMaintenanceWindowInputValidate(t *testing.T) {
	start := time.Date(2026, 9, 10, 2, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)
	valid := maintenanceWindowInput{Name: "停机维护", StartsAt: start, EndsAt: end}
	if msg := valid.validate(); msg != "" {
		t.Fatalf("合法入参被拒：%s", msg)
	}
	if valid.Scope != MaintScopeAll || valid.Recurrence != MaintRecurrenceOnce {
		t.Errorf("缺省归一化 = %s/%s，期望 ALL/ONCE", valid.Scope, valid.Recurrence)
	}

	cases := []struct {
		name string
		mut  func(in *maintenanceWindowInput)
		want string // 错误文案子串
	}{
		{"名称为空", func(in *maintenanceWindowInput) { in.Name = "  " }, "名称必填"},
		{"名称超长", func(in *maintenanceWindowInput) { in.Name = strings.Repeat("x", 101) }, "名称必填"},
		{"结束早于开始", func(in *maintenanceWindowInput) { in.EndsAt = in.StartsAt }, "结束时间必须晚于开始时间"},
		{"缺起止时间", func(in *maintenanceWindowInput) { in.StartsAt = time.Time{} }, "起止时间必填"},
		{"非法范围", func(in *maintenanceWindowInput) { in.Scope = "PART" }, "无效的作用范围"},
		{"非法周期", func(in *maintenanceWindowInput) { in.Recurrence = "WEEKLY" }, "无效的周期类型"},
		{"DAILY 缺时段", func(in *maintenanceWindowInput) { in.Recurrence = "daily" }, "必须提供 daily_start_minute"},
		{"CUSTOM 无维度", func(in *maintenanceWindowInput) { in.Scope = "custom" }, "至少指定一类"},
		{"CUSTOM 非法类型", func(in *maintenanceWindowInput) {
			in.Scope = "CUSTOM"
			in.AlertTypes = []string{"BOGUS"}
		}, "无效的告警类型"},
	}
	for _, c := range cases {
		in := maintenanceWindowInput{Name: "x", StartsAt: start, EndsAt: end}
		c.mut(&in)
		msg := in.validate()
		if msg == "" || !strings.Contains(msg, c.want) {
			t.Errorf("%s: validate = %q，期望含 %q", c.name, msg, c.want)
		}
	}
	// DAILY 起止分钟相同拒绝；越界拒绝
	in := maintenanceWindowInput{Name: "x", Recurrence: "DAILY", StartsAt: start, EndsAt: end}
	s, e := 120, 120
	in.DailyStartMinute, in.DailyEndMinute = &s, &e
	if msg := in.validate(); !strings.Contains(msg, "不能相同") {
		t.Errorf("相同时段应拒绝，实际 %q", msg)
	}
	bad := 1440
	in.DailyEndMinute = &bad
	if msg := in.validate(); !strings.Contains(msg, "0~1439") {
		t.Errorf("时段越界应拒绝，实际 %q", msg)
	}
}

// TestRaiseSuppressedByMaintenanceWindow 维护窗口内告警抑制：不建告警、计数可观测；
// 窗口结束后同指纹告警正常创建。
func TestRaiseSuppressedByMaintenanceWindow(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 9, 10, 3, 0, 0, 0, time.UTC)
	w := onceWindow(now.Add(-time.Hour), now.Add(time.Hour))
	mw := newFakeMaintenanceStore(w)
	e := testEngine(store, &now)
	e.maintenance = mw
	ctx := context.Background()

	a, err := raiseGatewayDown(e, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if a != nil {
		t.Errorf("窗口内 Raise 应被抑制（返回 nil），实际 %+v", a)
	}
	if n := store.countByStatus(StatusOpen); n != 0 {
		t.Errorf("窗口内不应产生告警，实际 OPEN %d 条", n)
	}
	if n := mw.suppressedTotal(w.ID); n != 1 {
		t.Errorf("抑制计数 = %d，期望 1", n)
	}
	// 窗口内重复触发只累计抑制，不产生告警
	if _, err := raiseGatewayDown(e, ctx); err != nil {
		t.Fatal(err)
	}
	if n := mw.suppressedTotal(w.ID); n != 2 {
		t.Errorf("重复抑制计数 = %d，期望 2", n)
	}
	// 窗口结束后恢复创建
	now = now.Add(2 * time.Hour)
	a, err = raiseGatewayDown(e, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if a == nil || a.Status != StatusOpen {
		t.Errorf("窗口结束后应正常创建告警，实际 %+v", a)
	}
	if n := mw.suppressedTotal(w.ID); n != 2 {
		t.Errorf("窗口结束后不应再累计抑制，实际 %d", n)
	}
}

// TestRaiseSuppressionScope CUSTOM 范围不匹配时不抑制。
func TestRaiseSuppressionScope(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 9, 10, 3, 0, 0, 0, time.UTC)
	w := onceWindow(now.Add(-time.Hour), now.Add(time.Hour))
	w.Scope = MaintScopeCustom
	w.AlertTypes = []string{TypeFDUsageHigh} // 只抑制 FD_USAGE_HIGH
	mw := newFakeMaintenanceStore(w)
	e := testEngine(store, &now)
	e.maintenance = mw
	ctx := context.Background()

	// GATEWAY_DOWN 不在窗口范围 → 正常创建
	a, err := raiseGatewayDown(e, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if a == nil || a.Status != StatusOpen {
		t.Errorf("范围外告警不应抑制，实际 %+v", a)
	}
	// FD_USAGE_HIGH 命中范围 → 抑制
	a, err = e.Raise(ctx, RaiseRequest{
		AlertType: TypeFDUsageHigh, Component: runtimehealth.ComponentAPI,
		Title: "文件句柄使用率过高", Message: "文件句柄使用率 85.0%",
	})
	if err != nil {
		t.Fatal(err)
	}
	if a != nil {
		t.Errorf("范围内告警应抑制，实际 %+v", a)
	}
}

// TestRaiseMaintenanceCheckError 窗口查询/记账失败如实报错，不退化为放行。
func TestRaiseMaintenanceCheckError(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 9, 10, 3, 0, 0, 0, time.UTC)
	w := onceWindow(now.Add(-time.Hour), now.Add(time.Hour))
	mw := newFakeMaintenanceStore(w)
	e := testEngine(store, &now)
	e.maintenance = mw
	ctx := context.Background()

	mw.findErr = errors.New("db down")
	if _, err := raiseGatewayDown(e, ctx); err == nil || !strings.Contains(err.Error(), "maintenance windows") {
		t.Errorf("窗口查询失败应报错，实际 %v", err)
	}
	mw.findErr = nil
	mw.suppressErr = errors.New("db down")
	if _, err := raiseGatewayDown(e, ctx); err == nil || !strings.Contains(err.Error(), "maintenance suppression") {
		t.Errorf("抑制记账失败应报错，实际 %v", err)
	}
	if n := store.countByStatus(StatusOpen); n != 0 {
		t.Errorf("失败路径不应落告警，实际 OPEN %d 条", n)
	}
}

// TestEvaluateFDUsageHigh FD_USAGE_HIGH 端到端挂接：API 组件 DEGRADED 且带
// fd_usage_percent 指标 → 触发；指标缺失不触发；恢复 UP → 自动恢复。
func TestEvaluateFDUsageHigh(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 9, 10, 3, 0, 0, 0, time.UTC)
	e := testEngine(store, &now)
	ctx := context.Background()

	degraded := runtimehealth.Snapshot{
		Component: runtimehealth.ComponentAPI,
		Status:    runtimehealth.StatusDegraded,
		Message:   "文件句柄使用率 85.0%（阈值 80%）",
		Metrics:   map[string]interface{}{runtimehealth.MetricFDUsagePercent: 85.0},
	}
	if err := e.Evaluate(ctx, []runtimehealth.Snapshot{degraded}); err != nil {
		t.Fatal(err)
	}
	open, err := store.FindOpen(ctx, TypeFDUsageHigh, runtimehealth.ComponentAPI)
	if err != nil {
		t.Fatal(err)
	}
	if open == nil {
		t.Fatal("API DEGRADED + fd_usage_percent 达阈应触发 FD_USAGE_HIGH")
	}
	if open.Severity != SeverityHigh {
		t.Errorf("FD_USAGE_HIGH 等级 = %s，期望 HIGH", open.Severity)
	}
	if !strings.Contains(open.Message, "85.0%") {
		t.Errorf("message 应含使用率，实际 %q", open.Message)
	}
	// 无 fd 指标的 DEGRADED（如采集不可用）不触发 FD_USAGE_HIGH
	store2 := newFakeStore()
	e2 := testEngine(store2, &now)
	degradedNoFD := runtimehealth.Snapshot{
		Component: runtimehealth.ComponentAPI,
		Status:    runtimehealth.StatusDegraded,
		Metrics:   map[string]interface{}{},
	}
	if err := e2.Evaluate(ctx, []runtimehealth.Snapshot{degradedNoFD}); err != nil {
		t.Fatal(err)
	}
	if n := store2.countByStatus(StatusOpen); n != 0 {
		t.Errorf("无 fd 指标不应触发告警，实际 OPEN %d 条", n)
	}
	// 恢复 UP → FD_USAGE_HIGH 自动恢复
	up := runtimehealth.Snapshot{
		Component: runtimehealth.ComponentAPI,
		Status:    runtimehealth.StatusUp,
		Metrics:   map[string]interface{}{runtimehealth.MetricFDUsagePercent: 42.0},
	}
	if err := e.Evaluate(ctx, []runtimehealth.Snapshot{up}); err != nil {
		t.Fatal(err)
	}
	if got := store.get(open.ID); got.Status != StatusResolved {
		t.Errorf("恢复后状态 = %s，期望 RESOLVED", got.Status)
	}
	if rt := store.get(open.ID).ResolveType; rt == nil || *rt != ResolveRecovered {
		t.Errorf("恢复方式应为 RECOVERED，实际 %+v", rt)
	}
	// MANAGEMENT_API_DOWN 不受 fd 分支影响：DOWN 仍触发
	if err := e.Evaluate(ctx, []runtimehealth.Snapshot{{
		Component: runtimehealth.ComponentAPI, Status: runtimehealth.StatusDown,
		Message: "管理 API 进程异常", Metrics: map[string]interface{}{},
	}}); err != nil {
		t.Fatal(err)
	}
	down, err := store.FindOpen(ctx, TypeManagementAPIDown, runtimehealth.ComponentAPI)
	if err != nil {
		t.Fatal(err)
	}
	if down == nil {
		t.Error("API DOWN 应触发 MANAGEMENT_API_DOWN")
	}
}
