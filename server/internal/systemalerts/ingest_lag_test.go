// ingest_lag_test.go APM 数据面采集滞后告警评估单测（fakeStore + fake
// IngestLagStatsStore，可控时钟；触发/合并/自动恢复/无数据收口/失败中止/空转/
// 阈值读取语义）。
package systemalerts

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeIngestLag 是 IngestLagStatsStore 的可编程内存实现。
type fakeIngestLag struct {
	latest time.Time
	ok     bool
	err    error
	calls  int
}

func (f *fakeIngestLag) LatestIngestAt(context.Context) (time.Time, bool, error) {
	f.calls++
	if f.err != nil {
		return time.Time{}, false, f.err
	}
	return f.latest, f.ok, nil
}

var ingestLagNow = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

func newIngestLagEngine(store *fakeStore, src *fakeIngestLag, settings SettingsReader, now *time.Time) *Engine {
	return NewEngine(store, EngineOptions{
		Now:           func() time.Time { return *now },
		Cooldown:      time.Minute,
		FlapWindow:    10 * time.Minute,
		FlapThreshold: 3,
		MaxOpen:       500,
		IngestLag:     src,
		Settings:      settings,
	})
}

// TestAPMIngestLagTypeRegistered APM_INGEST_LAG 已注册规则矩阵（MEDIUM）。
func TestAPMIngestLagTypeRegistered(t *testing.T) {
	if !IsValidType(TypeAPMIngestLag) {
		t.Fatal("APM_INGEST_LAG 应为合法类型")
	}
	if got := SeverityFor(TypeAPMIngestLag); got != SeverityMedium {
		t.Errorf("APM_INGEST_LAG 等级 = %s, want MEDIUM", got)
	}
}

// TestEvaluateIngestLagNilSource 读数源未注入（APM_ENABLED 关闭/DSN 空形态）时空转。
func TestEvaluateIngestLagNilSource(t *testing.T) {
	e := NewEngine(newFakeStore(), EngineOptions{Now: func() time.Time { return ingestLagNow }})
	if err := e.EvaluateIngestLag(context.Background()); err != nil {
		t.Fatalf("nil source evaluate: %v", err)
	}
}

// TestEvaluateIngestLagRaiseMergeRecover 超阈触发 → 重复评估合并 → 恢复自动收口。
func TestEvaluateIngestLagRaiseMergeRecover(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	now := ingestLagNow
	src := &fakeIngestLag{latest: now.Add(-600 * time.Second), ok: true} // 滞后 600s > 默认 300s
	e := newIngestLagEngine(store, src, nil, &now)

	// 第一轮：触发（MEDIUM / component=clickhouse / message 含滞后与阈值）
	if err := e.EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	a := findAlert(store, TypeAPMIngestLag)
	if a == nil {
		t.Fatal("want APM_INGEST_LAG alert")
	}
	if a.Severity != SeverityMedium || a.Status != StatusOpen {
		t.Errorf("alert = %+v", a)
	}
	if a.Component != "clickhouse" {
		t.Errorf("component = %q, want clickhouse", a.Component)
	}
	if !strings.Contains(a.Message, "600 秒") || !strings.Contains(a.Message, "阈值 300 秒") {
		t.Errorf("message = %q, want 含滞后 600 秒与阈值 300 秒", a.Message)
	}

	// 第二轮仍超阈：合并而非新建
	src.latest = now.Add(-700 * time.Second)
	if err := e.EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("evaluate 2: %v", err)
	}
	if n := store.countByStatus(StatusOpen); n != 1 {
		t.Errorf("open count = %d, want 1（合并去重）", n)
	}

	// 第三轮恢复正常：自动收口为 RESOLVED(RECOVERED)
	src.latest = now.Add(-10 * time.Second)
	now = now.Add(time.Minute)
	if err := e.EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("evaluate 3: %v", err)
	}
	got := store.get(a.ID)
	if got.Status != StatusResolved || got.ResolveType == nil || *got.ResolveType != ResolveRecovered {
		t.Errorf("recovered alert = %+v", got)
	}
}

// TestEvaluateIngestLagThresholdBoundary 恰达阈值不触发（> 口径，与 accesslog 停滞同）；
// settings 覆盖阈值后按新阈值判定。
func TestEvaluateIngestLagThresholdBoundary(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	now := ingestLagNow
	src := &fakeIngestLag{latest: now.Add(-300 * time.Second), ok: true} // 恰达默认阈值
	e := newIngestLagEngine(store, src, nil, &now)
	if err := e.EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if a := findAlert(store, TypeAPMIngestLag); a != nil && a.Status == StatusOpen {
		t.Error("恰达阈值不应触发（> 口径）")
	}

	// settings 覆盖阈值为 60：滞后 100s 触发
	store2 := newFakeStore()
	src2 := &fakeIngestLag{latest: now.Add(-100 * time.Second), ok: true}
	e2 := newIngestLagEngine(store2, src2, &fakeSettings{ints: map[string]int{
		apmAlertSettingsGroup + "/" + apmAlertKeyIngestLagSeconds: 60,
	}}, &now)
	if err := e2.EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("evaluate override: %v", err)
	}
	a := findAlert(store2, TypeAPMIngestLag)
	if a == nil || a.Status != StatusOpen {
		t.Fatal("覆盖阈值 60 后滞后 100s 应触发")
	}
	if !strings.Contains(a.Message, "阈值 60 秒") {
		t.Errorf("message = %q, want 含阈值 60 秒", a.Message)
	}
}

// TestEvaluateIngestLagNoData 表空无数据（ok=false）：不触发；既有未关闭告警收口。
func TestEvaluateIngestLagNoData(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	now := ingestLagNow
	src := &fakeIngestLag{latest: now.Add(-600 * time.Second), ok: true}
	e := newIngestLagEngine(store, src, nil, &now)
	if err := e.EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if a := findAlert(store, TypeAPMIngestLag); a == nil || a.Status != StatusOpen {
		t.Fatal("want open alert")
	}

	// 本轮无数据（表空/TTL 清空）：滞后条件不成立，既有告警如实收口
	src.ok = false
	now = now.Add(time.Minute)
	if err := e.EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("evaluate no-data: %v", err)
	}
	if a := findAlert(store, TypeAPMIngestLag); a.Status != StatusResolved {
		t.Errorf("no-data status = %s, want RESOLVED", a.Status)
	}
}

// TestEvaluateIngestLagAbortOnReadError 读数失败整体中止：返回错误且不清动既有告警。
func TestEvaluateIngestLagAbortOnReadError(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	now := ingestLagNow
	src := &fakeIngestLag{latest: now.Add(-600 * time.Second), ok: true}
	e := newIngestLagEngine(store, src, nil, &now)
	if err := e.EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	src.err = errors.New("clickhouse down")
	if err := e.EvaluateIngestLag(ctx); err == nil {
		t.Fatal("want error on stats failure")
	}
	if a := findAlert(store, TypeAPMIngestLag); a.Status != StatusOpen {
		t.Errorf("status = %s, want OPEN（读数失败不误恢复）", a.Status)
	}
}

// TestIngestLagThresholdSeconds 阈值读取：默认 300；settings 合法覆盖；非法值回退默认。
func TestIngestLagThresholdSeconds(t *testing.T) {
	ctx := context.Background()
	if got := ingestLagThresholdSeconds(ctx, nil); got != defaultIngestLagSeconds {
		t.Errorf("nil settings = %v, want %d", got, defaultIngestLagSeconds)
	}
	if got := ingestLagThresholdSeconds(ctx, &fakeSettings{}); got != defaultIngestLagSeconds {
		t.Errorf("missing key = %v, want %d", got, defaultIngestLagSeconds)
	}
	s := &fakeSettings{ints: map[string]int{
		apmAlertSettingsGroup + "/" + apmAlertKeyIngestLagSeconds: 60,
	}}
	if got := ingestLagThresholdSeconds(ctx, s); got != 60 {
		t.Errorf("override = %v, want 60", got)
	}
	for _, bad := range []int{0, -1, minIngestLagSeconds - 1, maxIngestLagSeconds + 1} {
		s := &fakeSettings{ints: map[string]int{
			apmAlertSettingsGroup + "/" + apmAlertKeyIngestLagSeconds: bad,
		}}
		if got := ingestLagThresholdSeconds(ctx, s); got != defaultIngestLagSeconds {
			t.Errorf("bad value %d = %v, want %d（回退默认）", bad, got, defaultIngestLagSeconds)
		}
	}
}
