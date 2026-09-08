package apiruntime

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// TestSampleVerdict 过滤规则矩阵（任务书 §25 数据可得子集；规则优先级即代码顺序）。
func TestSampleVerdict(t *testing.T) {
	cases := []struct {
		name       string
		rec        Record
		accepted   bool
		wantReason string
	}{
		{"放行通行", Record{FinalAction: "ALLOW", ResponseStatus: 200}, true, ""},
		{"状态码未知跳过状态规则", Record{FinalAction: "ALLOW", ResponseStatus: 0}, true, ""},
		{"401", Record{FinalAction: "ALLOW", ResponseStatus: 401}, false, "response_status_401"},
		{"403", Record{FinalAction: "ALLOW", ResponseStatus: 403}, false, "response_status_403"},
		{"429", Record{FinalAction: "ALLOW", ResponseStatus: 429}, false, "response_status_429"},
		{"500", Record{FinalAction: "ALLOW", ResponseStatus: 500}, false, "response_status_500"},
		{"502", Record{FinalAction: "ALLOW", ResponseStatus: 502}, false, "response_status_502"},
		{"499不参与", Record{FinalAction: "ALLOW", ResponseStatus: 499}, true, ""},
		{"BLOCK", Record{FinalAction: "BLOCK"}, false, ExcludeReasonBlockedByDecision},
		{"RATE_LIMIT按CC超限排除", Record{FinalAction: "RATE_LIMIT"}, false, ExcludeReasonBlockedByDecision},
		{"TEMP_BLOCK", Record{FinalAction: "TEMP_BLOCK"}, false, ExcludeReasonBlockedByDecision},
		{"OBSERVE放行", Record{FinalAction: "OBSERVE"}, true, ""},
		{"WAF命中", Record{FinalAction: "ALLOW", Details: []dsctx.DetectorMatch{{Detector: "waf", RuleID: "942100"}}}, false, ExcludeReasonWAFHit},
		{"schema偏离", Record{FinalAction: "ALLOW", Details: []dsctx.DetectorMatch{{Detector: "api_schema", RuleID: "schema.extra_field"}}}, false, ExcludeReasonSchemaDeviation},
		{"WAF优先于schema", Record{FinalAction: "ALLOW", Details: []dsctx.DetectorMatch{
			{Detector: "api_schema"}, {Detector: "waf"}}}, false, ExcludeReasonWAFHit},
		{"认证明细不排除", Record{FinalAction: "ALLOW", Details: []dsctx.DetectorMatch{{Detector: "authentication"}}}, true, ""},
		{"敏感数据明细不排除", Record{FinalAction: "ALLOW", Details: []dsctx.DetectorMatch{{Detector: "sensitive_data"}}}, true, ""},
		{"决策优先于状态码", Record{FinalAction: "BLOCK", ResponseStatus: 503}, false, ExcludeReasonBlockedByDecision},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			accepted, reason := sampleVerdict(&c.rec)
			if accepted != c.accepted || reason != c.wantReason {
				t.Fatalf("verdict=(%v,%q), want (%v,%q)", accepted, reason, c.accepted, c.wantReason)
			}
		})
	}
}

type fakeSampleRecorder struct {
	calls []apiassets.LearningSampleInput
	err   error
}

func (f *fakeSampleRecorder) RecordLearningSample(_ context.Context, in apiassets.LearningSampleInput) (bool, error) {
	f.calls = append(f.calls, in)
	return true, f.err
}

// TestCollectOnce_RecordsLearningSamples 采集挂钩：各排除原因落样、空 request_id 跳过、指纹透传。
func TestCollectOnce_RecordsLearningSamples(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	recs := []Record{
		{RequestID: "r-allow", EndpointKey: "GET /v1/a", Method: "GET", PathTemplate: "/v1/a",
			FinalAction: "ALLOW", ResponseStatus: 200, SourceFingerprint: "src1", IdentityFingerprint: "id1",
			IsAPI: true, OccurredAt: time.Now().UTC()},
		{RequestID: "r-block", EndpointKey: "GET /v1/a", Method: "GET", PathTemplate: "/v1/a",
			FinalAction: "BLOCK", ResponseStatus: 403, IsAPI: true, OccurredAt: time.Now().UTC()},
		{RequestID: "r-waf", EndpointKey: "GET /v1/a", Method: "GET", PathTemplate: "/v1/a",
			FinalAction: "ALLOW", IsAPI: true, OccurredAt: time.Now().UTC(),
			Details: []dsctx.DetectorMatch{{Detector: "waf", RuleID: "942100"}}},
		{RequestID: "r-schema", EndpointKey: "GET /v1/a", Method: "GET", PathTemplate: "/v1/a",
			FinalAction: "ALLOW", IsAPI: true, OccurredAt: time.Now().UTC(),
			Details: []dsctx.DetectorMatch{{Detector: "api_schema", RuleID: "schema.extra_field"}}},
		{RequestID: "r-5xx", EndpointKey: "GET /v1/a", Method: "GET", PathTemplate: "/v1/a",
			FinalAction: "ALLOW", ResponseStatus: 502, IsAPI: true, OccurredAt: time.Now().UTC()},
		// 空 request_id：无法幂等去重，不落样
		{RequestID: "", EndpointKey: "GET /v1/a", Method: "GET", PathTemplate: "/v1/a",
			FinalAction: "ALLOW", IsAPI: true, OccurredAt: time.Now().UTC()},
	}
	lines := make([]string, 0, len(recs))
	for _, r := range recs {
		lines = append(lines, mustJSON(t, r))
	}
	writeLines(t, logPath, lines)

	saver := &fakeSaver{}
	recorder := &fakeSampleRecorder{}
	c := NewCollector(saver, "test", logPath, cpPath, "node-1")
	c.SetSampleRecorder(recorder)

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != len(recs) {
		t.Fatalf("processed=%d, want %d", n, len(recs))
	}
	if len(recorder.calls) != 5 {
		t.Fatalf("sample calls=%d, want 5 (empty request_id skipped): %+v", len(recorder.calls), recorder.calls)
	}
	want := []struct {
		reqID    string
		accepted bool
		reason   string
	}{
		{"r-allow", true, ""},
		{"r-block", false, ExcludeReasonBlockedByDecision},
		{"r-waf", false, ExcludeReasonWAFHit},
		{"r-schema", false, ExcludeReasonSchemaDeviation},
		{"r-5xx", false, "response_status_502"},
	}
	for i, w := range want {
		got := recorder.calls[i]
		if got.RequestID != w.reqID || got.Accepted != w.accepted || got.ExcludeReason != w.reason {
			t.Fatalf("call[%d]=%+v, want reqID=%s accepted=%v reason=%q", i, got, w.reqID, w.accepted, w.reason)
		}
	}
	// 指纹与状态码透传
	first := recorder.calls[0]
	if first.SourceFingerprint != "src1" || first.IdentityFingerprint != "id1" ||
		first.ResponseStatus != 200 || first.EndpointKey != "GET /v1/a" {
		t.Fatalf("sample input fields lost: %+v", first)
	}
}

// TestCollectOnce_SampleRecorderErrorDoesNotBreak 落样失败仅记日志，采集与断点不受影响。
func TestCollectOnce_SampleRecorderErrorDoesNotBreak(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	writeLines(t, logPath, []string{mustJSON(t, Record{
		RequestID: "r-1", EndpointKey: "GET /v1/a", Method: "GET", PathTemplate: "/v1/a",
		FinalAction: "ALLOW", IsAPI: true, OccurredAt: time.Now().UTC(),
	})})

	saver := &fakeSaver{}
	recorder := &fakeSampleRecorder{err: errors.New("db down")}
	c := NewCollector(saver, "test", logPath, cpPath, "node-1")
	c.SetSampleRecorder(recorder)

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce should not fail on sample recorder error: %v", err)
	}
	if n != 1 || len(recorder.calls) != 1 {
		t.Fatalf("processed=%d calls=%d", n, len(recorder.calls))
	}
}

// TestCollectOnce_NoSampleRecorder 未注入 recorder：零开销跳过（纯 WAF 形态回归）。
func TestCollectOnce_NoSampleRecorder(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	writeLines(t, logPath, []string{mustJSON(t, Record{
		RequestID: "r-1", EndpointKey: "GET /v1/a", Method: "GET", PathTemplate: "/v1/a",
		FinalAction: "ALLOW", IsAPI: true, OccurredAt: time.Now().UTC(),
	})})

	c := NewCollector(&fakeSaver{}, "test", logPath, cpPath, "node-1")
	n, err := c.CollectOnce(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("CollectOnce without sample recorder: n=%d err=%v", n, err)
	}
}
