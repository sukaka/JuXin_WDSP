// scheduler_test.go 调度器测试（MemStore + fakeSource 驱动真实 Sweeper）：
// 全局开关门控、到期执行与游标推进、未到期不触发、失败落 FAILED run + last_error、
// RUNNING 防重入、立即执行、cron 失效兜底、LLM 润色接入与降级。
package apiops

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeSettings 测试设置源。
type fakeSettings struct {
	enabled  bool
	interval int
}

func (f fakeSettings) GetBool(_ context.Context, group, key string, def bool) bool {
	if group == settingsGroup && key == settingsKeyEnabled {
		return f.enabled
	}
	return def
}

func (f fakeSettings) GetInt(_ context.Context, group, key string, def int) int {
	if group == settingsGroup && key == settingsKeyIntervalSec && f.interval > 0 {
		return f.interval
	}
	return def
}

// newDueSchedule 造一个到期 ENABLED 计划（next_run_at 已过）。
func newDueSchedule(t *testing.T, store Repository, taskType string) *Schedule {
	t.Helper()
	past := testNow.Add(-time.Minute)
	sc := &Schedule{
		TaskType: taskType, Name: "测试计划-" + taskType, CronExpr: "0 9 * * *",
		Enabled: true, Config: json.RawMessage(`{"window_hours":24,"limit":20}`), NextRunAt: &past,
	}
	if err := store.CreateSchedule(context.Background(), sc); err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	return sc
}

func newTestSweeper(store Repository, src Source, enabled bool) *Sweeper {
	return NewSweeper(store, src).
		SetSettings(fakeSettings{enabled: enabled}).
		SetClock(func() time.Time { return testNow })
}

func TestSweepOnceGlobalSwitchOff(t *testing.T) {
	store := NewMemStore()
	newDueSchedule(t, store, TaskRiskDigest)
	s := newTestSweeper(store, &fakeSource{risk: &RiskDigestData{}}, false)
	stats, err := s.SweepOnce(context.Background())
	if err != nil || stats.Due != 0 {
		t.Fatalf("switch off should idle: stats=%+v err=%v", stats, err)
	}
	runs, total, _ := store.ListRuns(context.Background(), store.mustAnyScheduleID(t), 1, 20)
	if total != 0 || len(runs) != 0 {
		t.Fatalf("switch off should produce no runs: total=%d", total)
	}
}

// mustAnyScheduleID 取首个计划 ID（测试辅助）。
func (m *MemStore) mustAnyScheduleID(t *testing.T) uuid.UUID {
	t.Helper()
	list, _, err := m.ListSchedules(context.Background(), ScheduleFilter{})
	if err != nil || len(list) == 0 {
		t.Fatalf("no schedule: %v", err)
	}
	return list[0].ID
}

func TestSweepOnceDueExecutes(t *testing.T) {
	store := NewMemStore()
	sc := newDueSchedule(t, store, TaskRiskDigest)
	src := &fakeSource{risk: &RiskDigestData{
		OpenHighTotal: 8, OpenCritical: 2, NewInWindow: 3,
		TypeDistribution: []TypeCount{{Type: "BOLA", Count: 5}},
	}}
	s := newTestSweeper(store, src, true)
	stats, err := s.SweepOnce(context.Background())
	if err != nil || stats.Due != 1 || stats.Succeeded != 1 || stats.Failed != 0 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	// 游标推进：次日 09:00（testNow 为 09:00，不含本身）
	got, _ := store.GetSchedule(context.Background(), sc.ID)
	if got.NextRunAt == nil || !got.NextRunAt.Equal(testNow.Add(24*time.Hour)) {
		t.Fatalf("next_run_at=%v, want next day 09:00", got.NextRunAt)
	}
	if got.LastStatus != RunStatusSuccess || got.LastRunAt == nil || got.LastError != "" {
		t.Fatalf("last state: status=%s err=%q", got.LastStatus, got.LastError)
	}
	// 执行记录：SUCCESS + 报告与摘要
	runs, total, _ := store.ListRuns(context.Background(), sc.ID, 1, 20)
	if total != 1 || len(runs) != 1 {
		t.Fatalf("runs total=%d", total)
	}
	run := runs[0]
	if run.Status != RunStatusSuccess || run.FinishedAt == nil {
		t.Fatalf("run: %+v", run)
	}
	if !strings.Contains(run.Summary, "共 8 项") {
		t.Fatalf("summary=%q", run.Summary)
	}
	var report map[string]any
	if err := json.Unmarshal(run.Report, &report); err != nil {
		t.Fatalf("report json: %v", err)
	}
	if report["open_high_total"].(float64) != 8 {
		t.Fatalf("report=%v", report)
	}
	// 第二轮（同一时刻游标已推进）不再触发
	stats, _ = s.SweepOnce(context.Background())
	if stats.Due != 0 {
		t.Fatalf("second sweep should idle: %+v", stats)
	}
}

func TestSweepOnceNotDue(t *testing.T) {
	store := NewMemStore()
	future := testNow.Add(time.Hour)
	sc := &Schedule{TaskType: TaskRiskDigest, Name: "未到期", CronExpr: "0 9 * * *",
		Enabled: true, NextRunAt: &future}
	if err := store.CreateSchedule(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	s := newTestSweeper(store, &fakeSource{risk: &RiskDigestData{}}, true)
	stats, err := s.SweepOnce(context.Background())
	if err != nil || stats.Due != 0 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	got, _ := store.GetSchedule(context.Background(), sc.ID)
	if got.NextRunAt == nil || !got.NextRunAt.Equal(future) {
		t.Fatalf("not-due schedule next_run_at changed: %v", got.NextRunAt)
	}
}

func TestSweepOnceTaskFailure(t *testing.T) {
	store := NewMemStore()
	sc := newDueSchedule(t, store, TaskRiskDigest)
	src := &fakeSource{err: errors.New("db down")}
	s := newTestSweeper(store, src, true)
	stats, err := s.SweepOnce(context.Background())
	if err != nil || stats.Failed != 1 || stats.Succeeded != 0 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	got, _ := store.GetSchedule(context.Background(), sc.ID)
	if got.LastStatus != RunStatusFailed || !strings.Contains(got.LastError, "db down") {
		t.Fatalf("last state: status=%s err=%q", got.LastStatus, got.LastError)
	}
	runs, _, _ := store.ListRuns(context.Background(), sc.ID, 1, 20)
	if len(runs) != 1 || runs[0].Status != RunStatusFailed || !strings.Contains(runs[0].Summary, "db down") {
		t.Fatalf("failed run: %+v", runs)
	}
}

func TestSweepOnceSkipsRunningConflict(t *testing.T) {
	store := NewMemStore()
	sc := newDueSchedule(t, store, TaskRiskDigest)
	// 预置 RUNNING 记录（模拟上一轮仍在执行）
	if err := store.CreateRun(context.Background(), &Run{ScheduleID: sc.ID, StartedAt: testNow.Add(-2 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	s := newTestSweeper(store, &fakeSource{risk: &RiskDigestData{}}, true)
	stats, err := s.SweepOnce(context.Background())
	if err != nil || stats.Skipped != 1 || stats.Succeeded != 0 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	// 游标仍被推进（claim 先行），不会因冲突每分钟重试
	got, _ := store.GetSchedule(context.Background(), sc.ID)
	if got.NextRunAt == nil || !got.NextRunAt.After(testNow) {
		t.Fatalf("next_run_at should advance on conflict: %v", got.NextRunAt)
	}
}

func TestSweepOnceUnschedulableCron(t *testing.T) {
	store := NewMemStore()
	// 旁路写入非法 cron（正常入口已校验，模拟库内数据被改写）
	past := testNow.Add(-time.Minute)
	sc := &Schedule{TaskType: TaskRiskDigest, Name: "坏cron", CronExpr: "not-a-cron",
		Enabled: true, NextRunAt: &past}
	if err := store.CreateSchedule(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	s := newTestSweeper(store, &fakeSource{risk: &RiskDigestData{}}, true)
	stats, err := s.SweepOnce(context.Background())
	if err != nil || stats.Failed != 1 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	got, _ := store.GetSchedule(context.Background(), sc.ID)
	if got.NextRunAt != nil || got.LastStatus != RunStatusFailed || got.LastError == "" {
		t.Fatalf("unschedulable: next=%v status=%s err=%q", got.NextRunAt, got.LastStatus, got.LastError)
	}
	runs, _, _ := store.ListRuns(context.Background(), sc.ID, 1, 20)
	if len(runs) != 1 || runs[0].Status != RunStatusFailed {
		t.Fatalf("runs: %+v", runs)
	}
}

func TestRunNow(t *testing.T) {
	store := NewMemStore()
	sc := newDueSchedule(t, store, TaskShadowReview)
	src := &fakeSource{shadow: &ShadowReviewData{OpenTotal: 5, NewInWindow: 2, Items: []FindingItem{}}}

	// 开关关闭 → ErrSchedulesDisabled
	off := newTestSweeper(store, src, false)
	if _, err := off.RunNow(context.Background(), sc.ID); !errors.Is(err, ErrSchedulesDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	// 开关开启 → 同步执行成功，排期游标不受影响（保持原到期值，由调度器接管）
	before, _ := store.GetSchedule(context.Background(), sc.ID)
	on := newTestSweeper(store, src, true)
	run, err := on.RunNow(context.Background(), sc.ID)
	if err != nil || run.Status != RunStatusSuccess {
		t.Fatalf("run now: %+v err=%v", run, err)
	}
	got, _ := store.GetSchedule(context.Background(), sc.ID)
	if got.NextRunAt == nil || before.NextRunAt == nil || !got.NextRunAt.Equal(*before.NextRunAt) {
		t.Fatalf("manual run must not touch schedule cursor: before=%v after=%v", before.NextRunAt, got.NextRunAt)
	}
	if got.LastStatus != RunStatusSuccess {
		t.Fatalf("last_status=%s", got.LastStatus)
	}
	// 计划不存在 → ErrScheduleNotFound
	if _, err := on.RunNow(context.Background(), uuid.New()); !errors.Is(err, ErrScheduleNotFound) {
		t.Fatalf("not found: %v", err)
	}
	// RUNNING 冲突 → ErrRunConflict
	if err := store.CreateRun(context.Background(), &Run{ScheduleID: sc.ID, StartedAt: testNow}); err != nil {
		t.Fatal(err)
	}
	if _, err := on.RunNow(context.Background(), sc.ID); !errors.Is(err, ErrRunConflict) {
		t.Fatalf("conflict: %v", err)
	}
}

func TestRunNowWithSummarizer(t *testing.T) {
	store := NewMemStore()
	sc := newDueSchedule(t, store, TaskSensitiveDigest)
	src := &fakeSource{sensitive: &SensitiveDigestData{SensitiveEndpointCount: 6, NewFields: []SensitiveFieldItem{}}}
	// 润色接入：摘要采用 LLM 输出
	s := newTestSweeper(store, src, true).SetSummarizer(&fakeSummarizer{out: "AI 润色摘要"})
	run, err := s.RunNow(context.Background(), sc.ID)
	if err != nil || run.Summary != "AI 润色摘要" {
		t.Fatalf("polished run: %+v err=%v", run, err)
	}
	// 润色失败：回退模板摘要，执行仍为 SUCCESS
	s2 := newTestSweeper(store, src, true).SetSummarizer(&fakeSummarizer{err: errors.New("llm down")})
	run2, err := s2.RunNow(context.Background(), sc.ID)
	if err != nil || run2.Status != RunStatusSuccess || !strings.Contains(run2.Summary, "涉敏端点 6 个") {
		t.Fatalf("degraded run: %+v err=%v", run2, err)
	}
}
