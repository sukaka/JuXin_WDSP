// worker_test.go SweepOnce 端到端测试：LLM 关闭路径、LLM 评分 + DRAFT 推荐路径、
// 事件源失败降级（PARTIAL/FAILED）、推荐去重。
package ainoise

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeSource 假事件源。
type fakeSource struct {
	waf    []EventInput
	api    []EventInput
	wafErr error
	apiErr error
}

func (f *fakeSource) FetchWAF(context.Context, time.Time, time.Time, int) ([]EventInput, error) {
	return f.waf, f.wafErr
}
func (f *fakeSource) FetchAPI(context.Context, time.Time, time.Time, int) ([]EventInput, error) {
	return f.api, f.apiErr
}

// fakeSettings 假设置读取。
type fakeSettings struct{ vals map[string]string }

func (f fakeSettings) GetString(_ context.Context, group, key, def string) string {
	if group == SettingsGroup {
		if v, ok := f.vals[key]; ok {
			return v
		}
	}
	return def
}

// fakeRecorder 假推荐落库（同时回写 MemStore 去重标记，模拟 ai_recommendations 行）。
type fakeRecorder struct {
	store    *MemStore
	recorded []string
}

func (f *fakeRecorder) RecordRecommendation(_ context.Context, _ *uuid.UUID, recType, targetType, targetID, _, _, _ string, evidence []string) (uuid.UUID, error) {
	f.recorded = append(f.recorded, recType+":"+targetID)
	id, _ := uuid.Parse(targetID)
	f.store.SetOpenRecommendation(id)
	return uuid.New(), nil
}

func burstEvents(n int, at time.Time) []EventInput {
	out := make([]EventInput, 0, n)
	rule := 942100
	for i := 0; i < n; i++ {
		out = append(out, EventInput{
			EventID: uuid.New(), Source: SourceWAF, Host: "a.com", RawURI: "/search",
			RuleID: &rule, ClientIP: "1.2.3.4", OccurredAt: at.Add(time.Duration(i) * time.Second),
		})
	}
	return out
}

func TestSweepOnceLLMDisabled(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	now := time.Now().UTC()
	src := &fakeSource{waf: burstEvents(5, now.Add(-time.Minute))}
	rec := &fakeRecorder{store: store}
	w := NewWorker(store, src, fakeSettings{vals: map[string]string{
		"enabled": "true", "sweep_window_minutes": "15", "min_events_threshold": "10",
	}}, nil, rec)

	stats := w.SweepOnce(ctx)
	if stats.Status != SweepSuccess {
		t.Fatalf("status=%s err=%s", stats.Status, stats.Error)
	}
	if stats.ScannedEvents != 5 || stats.NewClusters != 1 || stats.UpdatedClusters != 4 {
		t.Fatalf("stats=%+v", stats)
	}
	if stats.LLMCalls != 0 || stats.Recommendations != 0 {
		t.Fatalf("llm disabled should skip scoring/recommendation: %+v", stats)
	}
	// 阈值 10 > 5：不产生判定
	c, _ := store.Get(ctx, mustClusterID(t, store))
	if c.AIVerdict != VerdictUnknown {
		t.Fatalf("verdict=%s want UNKNOWN", c.AIVerdict)
	}
	// 扫描记录落库
	runs, total, _ := store.ListSweepRuns(ctx, 1, 10)
	if total != 1 || runs[0].Status != SweepSuccess || runs[0].ScannedEvents != 5 {
		t.Fatalf("runs=%+v", runs)
	}
}

func TestSweepOnceLLMVerdictAndRecommendation(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	now := time.Now().UTC()
	src := &fakeSource{waf: burstEvents(12, now.Add(-2*time.Minute))}
	rec := &fakeRecorder{store: store}
	gw := &fakeGateway{content: `{"verdict":"LIKELY_FALSE_POSITIVE","confidence":0.9,"reason":"单一低风险规则高频重复"}`}
	w := NewWorker(store, src, fakeSettings{vals: map[string]string{
		"enabled": "true", "sweep_window_minutes": "15", "min_events_threshold": "10",
		"llm_verdict_enabled": "true",
	}}, gw, rec)

	stats := w.SweepOnce(ctx)
	if stats.Status != SweepSuccess {
		t.Fatalf("status=%s err=%s", stats.Status, stats.Error)
	}
	if stats.LLMCalls != 1 || stats.TokensUsed != 15 {
		t.Fatalf("llm stats=%+v", stats)
	}
	if stats.Recommendations != 1 || len(rec.recorded) != 1 {
		t.Fatalf("recommendation not recorded: stats=%+v rec=%v", stats, rec.recorded)
	}
	clusterID := mustClusterID(t, store)
	c, _ := store.Get(ctx, clusterID)
	if c.AIVerdict != VerdictLikelyFalsePositive || c.AIConfidence == nil || *c.AIConfidence != 0.9 {
		t.Fatalf("cluster=%+v", c)
	}

	// 第二次扫描（新事件同指纹）：已有未决推荐 → 不重复推荐
	src.waf = burstEvents(2, now.Add(-30*time.Second))
	stats2 := w.SweepOnce(ctx)
	if stats2.Recommendations != 0 || len(rec.recorded) != 1 {
		t.Fatalf("duplicate recommendation: stats=%+v rec=%v", stats2, rec.recorded)
	}
}

func TestSweepOnceSourceFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	// 双源失败 → FAILED
	store := NewMemStore()
	w := NewWorker(store, &fakeSource{wafErr: errors.New("db down"), apiErr: errors.New("api down")},
		fakeSettings{vals: map[string]string{"enabled": "true"}}, nil, nil)
	stats := w.SweepOnce(ctx)
	if stats.Status != SweepFailed || stats.Error == "" {
		t.Fatalf("want FAILED, got %+v", stats)
	}
	runs, total, _ := store.ListSweepRuns(ctx, 1, 10)
	if total != 1 || runs[0].Status != SweepFailed {
		t.Fatalf("failed run not recorded: %+v", runs)
	}

	// 单源失败 → PARTIAL，已完成源仍聚类
	store2 := NewMemStore()
	w2 := NewWorker(store2, &fakeSource{waf: burstEvents(3, now.Add(-time.Minute)), apiErr: errors.New("api down")},
		fakeSettings{vals: map[string]string{"enabled": "true"}}, nil, nil)
	stats2 := w2.SweepOnce(ctx)
	if stats2.Status != SweepPartial || stats2.ScannedEvents != 3 {
		t.Fatalf("want PARTIAL with 3 scanned, got %+v", stats2)
	}
}

func TestSweepOnceUninitialized(t *testing.T) {
	w := NewWorker(nil, nil, nil, nil, nil)
	stats := w.SweepOnce(context.Background())
	if stats.Status != SweepFailed || stats.Error == "" {
		t.Fatalf("uninitialized worker should FAIL gracefully, got %+v", stats)
	}
}

func TestLoadConfig(t *testing.T) {
	// 默认值
	cfg := LoadConfig(context.Background(), fakeSettings{vals: map[string]string{}})
	if cfg.Enabled || cfg.Interval != DefaultIntervalSeconds*time.Second ||
		cfg.Window != DefaultSweepWindowMinutes*time.Minute ||
		cfg.MinEventsThreshold != DefaultMinEventsThreshold || cfg.LLMVerdictEnabled {
		t.Fatalf("default cfg=%+v", cfg)
	}
	// 合法覆盖
	cfg = LoadConfig(context.Background(), fakeSettings{vals: map[string]string{
		"enabled": "true", "interval_seconds": "60", "sweep_window_minutes": "30",
		"min_events_threshold": "50", "llm_verdict_enabled": "true",
	}})
	if !cfg.Enabled || cfg.Interval != time.Minute || cfg.Window != 30*time.Minute ||
		cfg.MinEventsThreshold != 50 || !cfg.LLMVerdictEnabled {
		t.Fatalf("override cfg=%+v", cfg)
	}
	// 非法值回退默认（不沿用、不崩溃）
	cfg = LoadConfig(context.Background(), fakeSettings{vals: map[string]string{
		"interval_seconds": "5", "sweep_window_minutes": "abc", "min_events_threshold": "0",
	}})
	if cfg.Interval != DefaultIntervalSeconds*time.Second ||
		cfg.Window != DefaultSweepWindowMinutes*time.Minute ||
		cfg.MinEventsThreshold != DefaultMinEventsThreshold {
		t.Fatalf("invalid should fall back to default, cfg=%+v", cfg)
	}
}

// mustClusterID 取唯一簇 ID。
func mustClusterID(t *testing.T, store *MemStore) uuid.UUID {
	t.Helper()
	list, total, err := store.List(context.Background(), ListFilter{})
	if err != nil || total != 1 {
		t.Fatalf("want exactly 1 cluster, total=%d err=%v", total, err)
	}
	return list[0].ID
}
