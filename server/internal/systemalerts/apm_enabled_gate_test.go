// apm_enabled_gate_test.go APM 运行期总开关于告警评估器的空转判定单测：
// EngineOptions.APMEnabled 返回 false 时 EndpointPerf/SLOBreach/IngestLag 三个
// 评估器空转（统计源零调用、零告警）；nil（未注入）视为恒 true 兼容既有口径。
package systemalerts

import (
	"context"
	"testing"
	"time"
)

func apmOffNow() time.Time { return time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC) }

// TestEvaluatorsIdleWhenAPMDisabled APMEnabled=false：三个 APM 评估器空转。
func TestEvaluatorsIdleWhenAPMDisabled(t *testing.T) {
	ctx := context.Background()
	apmOff := func(context.Context) bool { return false }

	perf := &fakeEndpointPerf{}
	slo := &fakeSLOBreach{}
	lag := &fakeIngestLag{latest: apmOffNow().Add(-time.Hour), ok: true}
	e := NewEngine(newFakeStore(), EngineOptions{
		Now:          apmOffNow,
		EndpointPerf: perf,
		SLOBreach:    slo,
		IngestLag:    lag,
		APMEnabled:   apmOff,
	})
	if err := e.EvaluateEndpointPerf(ctx); err != nil {
		t.Fatalf("endpoint perf: %v", err)
	}
	if err := e.EvaluateSLOBreach(ctx); err != nil {
		t.Fatalf("slo breach: %v", err)
	}
	if err := e.EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("ingest lag: %v", err)
	}
	if perf.calls != 0 || slo.calls != 0 || lag.calls != 0 {
		t.Errorf("关闭时统计源应零调用，got perf=%d slo=%d lag=%d", perf.calls, slo.calls, lag.calls)
	}
}

// TestEvaluatorsRunWhenAPMEnabledNil APMEnabled 未注入（nil）= 恒 true：
// 评估器正常运行（兼容既有装配与测试）。
func TestEvaluatorsRunWhenAPMEnabledNil(t *testing.T) {
	ctx := context.Background()
	lag := &fakeIngestLag{latest: apmOffNow(), ok: true}
	e := NewEngine(newFakeStore(), EngineOptions{
		Now:       apmOffNow,
		IngestLag: lag,
	})
	if err := e.EvaluateIngestLag(ctx); err != nil {
		t.Fatalf("ingest lag: %v", err)
	}
	if lag.calls != 1 {
		t.Errorf("nil APMEnabled 应视为恒 true（评估正常执行），lag.calls = %d", lag.calls)
	}
}
