// circuit_test.go AI 运营计划连续失败熔断测试（MemStore 驱动真实 Sweeper/Store 语义）：
// 失败计数 +1、成功清零、达阈熔断（停用 + 清游标 + 熔断原因）+ 系统告警与操作审计各一次、
// 已熔断重复失败不重复告警、手动启用复位熔断状态、阈值设置夹取 [1,10]。
package apiops

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

// fakeAlerter 熔断告警 spy。
type fakeAlerter struct {
	calls []alertCall
}

type alertCall struct {
	alertType, component, title, message string
}

func (f *fakeAlerter) NotifyFailure(_ context.Context, alertType, component, title, message string) (*systemalerts.Alert, error) {
	f.calls = append(f.calls, alertCall{alertType, component, title, message})
	return &systemalerts.Alert{}, nil
}

// fakeAudits 操作审计 spy。
type fakeAudits struct {
	records []audits.RecordInput
}

func (f *fakeAudits) Record(_ context.Context, in audits.RecordInput) error {
	f.records = append(f.records, in)
	return nil
}

// TestRecordRunOutcomeCounting 连续失败计数：失败 +1、成功清零、last_* 轨迹同步回填。
func TestRecordRunOutcomeCounting(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	sc := newDueSchedule(t, store, TaskRiskDigest)

	// 失败两次：计数递增、不熔断（阈值 3）
	for i := 1; i <= 2; i++ {
		got, opened, err := store.RecordRunOutcome(ctx, sc.ID, testNow, RunStatusFailed, "db down", 3)
		if err != nil || opened {
			t.Fatalf("failure #%d: opened=%v err=%v", i, opened, err)
		}
		if got.ConsecutiveFailures != i || !got.Enabled || got.CircuitOpenedAt != nil {
			t.Fatalf("failure #%d: %+v", i, got)
		}
		if got.LastStatus != RunStatusFailed || got.LastError != "db down" || got.LastRunAt == nil {
			t.Fatalf("trajectory not recorded: %+v", got)
		}
	}
	// 成功清零
	got, opened, err := store.RecordRunOutcome(ctx, sc.ID, testNow, RunStatusSuccess, "", 3)
	if err != nil || opened || got.ConsecutiveFailures != 0 || got.LastStatus != RunStatusSuccess {
		t.Fatalf("success reset: opened=%v got=%+v err=%v", opened, got, err)
	}
}

// TestRecordRunOutcomeCircuitOpen 达阈熔断：同事务停用 + 清游标 + 熔断原因；已熔断重复失败不重开。
func TestRecordRunOutcomeCircuitOpen(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	sc := newDueSchedule(t, store, TaskShadowReview)

	var got *Schedule
	opened := false
	for i := 1; i <= 3; i++ {
		var err error
		got, opened, err = store.RecordRunOutcome(ctx, sc.ID, testNow, RunStatusFailed, "source boom", 3)
		if err != nil {
			t.Fatalf("failure #%d: %v", i, err)
		}
	}
	if !opened {
		t.Fatal("3rd consecutive failure should open circuit")
	}
	if got.Enabled || got.NextRunAt != nil || got.CircuitOpenedAt == nil {
		t.Fatalf("circuit state: %+v", got)
	}
	if !strings.Contains(got.CircuitReason, "连续失败 3 次") || !strings.Contains(got.CircuitReason, "source boom") {
		t.Fatalf("circuit reason: %q", got.CircuitReason)
	}
	// 已熔断（已停用）再失败：计数继续但不重复触发熔断
	got, opened, err := store.RecordRunOutcome(ctx, sc.ID, testNow, RunStatusFailed, "source boom", 3)
	if err != nil || opened {
		t.Fatalf("already-open circuit must not re-open: opened=%v err=%v", opened, err)
	}
	if got.ConsecutiveFailures != 4 {
		t.Fatalf("failures keep counting while open: %d", got.ConsecutiveFailures)
	}

	// 手动启用复位：计数清零、熔断现场清空、游标按 cron 重建（由调用方传入）
	next := testNow.Add(24 * time.Hour)
	got, err = store.SetScheduleEnabled(ctx, sc.ID, true, &next)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !got.Enabled || got.ConsecutiveFailures != 0 || got.CircuitOpenedAt != nil || got.CircuitReason != "" {
		t.Fatalf("manual enable must reset circuit: %+v", got)
	}
	if got.NextRunAt == nil || !got.NextRunAt.Equal(next) {
		t.Fatalf("enable must restore cursor: %v", got.NextRunAt)
	}
}

// TestRecordRunOutcomeThresholdClamps 阈值 <1 归一为 1（首次失败即熔断）。
func TestRecordRunOutcomeThresholdClamps(t *testing.T) {
	store := NewMemStore()
	sc := newDueSchedule(t, store, TaskRiskDigest)
	got, opened, err := store.RecordRunOutcome(context.Background(), sc.ID, testNow, RunStatusFailed, "x", 0)
	if err != nil || !opened || got.Enabled {
		t.Fatalf("threshold clamped to 1 should open on first failure: opened=%v got=%+v err=%v", opened, got, err)
	}
}

// TestSweeperCircuitOpenEndToEnd 调度器熔断端到端：阈值 2，连续两次 RunNow 失败后
// 计划自动停用，系统告警（AI_OPS_SCHEDULE_CIRCUIT_OPEN/HIGH/AI_OPS）与高风险审计各报一次。
func TestSweeperCircuitOpenEndToEnd(t *testing.T) {
	store := NewMemStore()
	sc := newDueSchedule(t, store, TaskRiskDigest)
	src := &fakeSource{err: errors.New("model gateway down")}
	alerter := &fakeAlerter{}
	rec := &fakeAudits{}
	s := NewSweeper(store, src).
		SetSettings(fakeSettings{enabled: true, circuitThreshold: 2}).
		SetClock(func() time.Time { return testNow }).
		SetAlerter(alerter).
		SetAudits(rec)

	for i := 1; i <= 2; i++ {
		if _, err := s.RunNow(context.Background(), sc.ID); err == nil {
			t.Fatalf("run #%d should fail", i)
		}
	}
	got, _ := store.GetSchedule(context.Background(), sc.ID)
	if got.Enabled || got.ConsecutiveFailures != 2 || got.CircuitOpenedAt == nil {
		t.Fatalf("schedule should be circuit-broken: %+v", got)
	}
	// 告警一次：类型/组件/内容口径
	if len(alerter.calls) != 1 {
		t.Fatalf("alert calls=%d want 1: %+v", len(alerter.calls), alerter.calls)
	}
	call := alerter.calls[0]
	if call.alertType != systemalerts.TypeAIOpsScheduleCircuitOpen || call.component != "AI_OPS" {
		t.Fatalf("alert = %+v", call)
	}
	if !strings.Contains(call.message, sc.Name) || !strings.Contains(call.message, "连续失败 2 次") {
		t.Fatalf("alert message = %q", call.message)
	}
	// 审计一次：系统动作、高风险、对象与原因可追溯
	if len(rec.records) != 1 {
		t.Fatalf("audit records=%d want 1: %+v", len(rec.records), rec.records)
	}
	ar := rec.records[0]
	if ar.Action != "ai_schedule_circuit_open" || ar.Module != "api_ai_ops" ||
		ar.Username != "system" || ar.RiskLevel != audits.RiskHigh ||
		ar.ObjectID != sc.ID.String() || !strings.Contains(ar.AfterSummary, "熔断") {
		t.Fatalf("audit = %+v", ar)
	}

	// 第三次失败（已熔断停用）：不重复告警/审计
	if _, err := s.RunNow(context.Background(), sc.ID); err == nil {
		t.Fatal("run #3 should fail")
	}
	if len(alerter.calls) != 1 || len(rec.records) != 1 {
		t.Fatalf("duplicate circuit must not re-alert: alerts=%d audits=%d", len(alerter.calls), len(rec.records))
	}
}

// TestSweeperCircuitThresholdDefault 阈值设置缺省/越界夹取（默认 3，[1,10]）。
func TestSweeperCircuitThresholdDefault(t *testing.T) {
	s := NewSweeper(NewMemStore(), &fakeSource{})
	if got := s.circuitThreshold(context.Background()); got != DefaultCircuitThreshold {
		t.Fatalf("nil settings threshold=%d want %d", got, DefaultCircuitThreshold)
	}
	for raw, want := range map[int]int{0: DefaultCircuitThreshold, 1: 1, 5: 5, 10: 10, 99: 10, -3: 1} {
		s2 := NewSweeper(NewMemStore(), &fakeSource{}).SetSettings(fakeSettings{enabled: true, circuitThreshold: raw})
		if got := s2.circuitThreshold(context.Background()); got != want {
			t.Fatalf("raw=%d threshold=%d want %d", raw, got, want)
		}
	}
}

// TestSweepOnceCircuitOnCronFailure cron 失效（执行前失败）同样计入熔断计数。
func TestSweepOnceCircuitOnCronFailure(t *testing.T) {
	store := NewMemStore()
	past := testNow.Add(-time.Minute)
	sc := &Schedule{TaskType: TaskRiskDigest, Name: "坏cron熔断", CronExpr: "not-a-cron",
		Enabled: true, NextRunAt: &past}
	if err := store.CreateSchedule(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	s := NewSweeper(store, &fakeSource{}).
		SetSettings(fakeSettings{enabled: true, circuitThreshold: 1}).
		SetClock(func() time.Time { return testNow })
	stats, err := s.SweepOnce(context.Background())
	if err != nil || stats.Failed != 1 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	got, _ := store.GetSchedule(context.Background(), sc.ID)
	if got.Enabled || got.CircuitOpenedAt == nil || got.ConsecutiveFailures != 1 {
		t.Fatalf("cron failure should count toward circuit: %+v", got)
	}
}

// 防止序列化回归：熔断字段随计划 DTO 输出（API 契约）。
func TestScheduleDTOCarriesCircuitFields(t *testing.T) {
	store := NewMemStore()
	sc := newDueSchedule(t, store, TaskRiskDigest)
	if _, _, err := store.RecordRunOutcome(context.Background(), sc.ID, testNow, RunStatusFailed, "boom", 1); err != nil {
		t.Fatal(err)
	}
	got, _ := store.GetSchedule(context.Background(), sc.ID)
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"consecutive_failures", "circuit_opened_at", "circuit_reason"} {
		if !strings.Contains(string(raw), `"`+key+`"`) {
			t.Fatalf("schedule DTO missing %s: %s", key, raw)
		}
	}
}
