package apiruntime

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

type fakeViolationSaver struct{ inputs []ViolationInput }

func (f *fakeViolationSaver) SaveSchemaViolations(_ context.Context, in ViolationInput) error {
	f.inputs = append(f.inputs, in)
	return nil
}

func collectWithViolations(t *testing.T, saver ViolationSaver, recs ...Record) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	lines := make([]string, 0, len(recs))
	for i := range recs {
		lines = append(lines, mustJSON(t, recs[i]))
	}
	writeLines(t, logPath, lines)
	c := NewCollector(&fakeSaver{}, "test-violations", logPath, filepath.Join(dir, "cp"), "node-1")
	c.SetViolationSaver(saver)
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
}

// schema 类明细被过滤后交给 saver（其他 detector 不混入），携带端点键/request_id/final_action。
func TestRecordViolationsFiltersSchemaMatches(t *testing.T) {
	saver := &fakeViolationSaver{}
	rec := Record{
		RequestID: "r-v1", EndpointKey: "POST /v1/orders", Method: "POST", PathTemplate: "/v1/orders",
		IsAPI: true, FinalAction: "BLOCK", OccurredAt: time.Now().UTC(),
		Details: []dsctx.DetectorMatch{
			{Detector: "api_schema", RuleID: "schema.param_length", Category: "BLOCK",
				Evidence: map[string]string{"field": "name", "constraint": "max_length", "location": "BODY"}},
			{Detector: "waf", RuleID: "waf.sqli"},
			{Detector: "api_schema", RuleID: "schema.type_mismatch", Category: "BLOCK",
				Evidence: map[string]string{"field": "id", "want": "number", "got": "string"}},
		},
	}
	collectWithViolations(t, saver, rec)
	if len(saver.inputs) != 1 {
		t.Fatalf("want 1 violation input, got %d", len(saver.inputs))
	}
	in := saver.inputs[0]
	if in.RequestID != "r-v1" || in.EndpointKey != "POST /v1/orders" || in.FinalAction != "BLOCK" {
		t.Fatalf("bad input identity: %+v", in)
	}
	if len(in.Matches) != 2 {
		t.Fatalf("want 2 schema matches, got %+v", in.Matches)
	}
	for _, m := range in.Matches {
		if m.Detector != SchemaDetector {
			t.Fatalf("non-schema match leaked: %+v", m)
		}
	}
}

// 无 schema 明细 / 空 request_id：不落库；未注入 saver：零开销不报错。
func TestRecordViolationsSkips(t *testing.T) {
	saver := &fakeViolationSaver{}
	plain := Record{
		RequestID: "r-v2", EndpointKey: "GET /a", Method: "GET", PathTemplate: "/a",
		IsAPI: true, FinalAction: "ALLOW", OccurredAt: time.Now().UTC(),
		Details: []dsctx.DetectorMatch{
			{Detector: "sensitive", RuleID: "sensitive.in_query"},
		},
	}
	noReqID := Record{
		EndpointKey: "GET /b", Method: "GET", PathTemplate: "/b",
		IsAPI: true, FinalAction: "OBSERVE", OccurredAt: time.Now().UTC(),
		Details: []dsctx.DetectorMatch{
			{Detector: "api_schema", RuleID: "schema.missing_field"},
		},
	}
	collectWithViolations(t, saver, plain, noReqID)
	if len(saver.inputs) != 0 {
		t.Fatalf("no schema match / empty request_id must be skipped, got %+v", saver.inputs)
	}

	// 未注入 saver：同样两条记录不报错（nil 跳过路径）
	collectWithViolations(t, nil, plain, noReqID)
}

// 证据安全字段映射辅助：截断 rune 安全、首非空选取。
func TestViolationHelpers(t *testing.T) {
	if got := truncateRunes("你好世界", 2); got != "你好" {
		t.Fatalf("truncateRunes multibyte = %q", got)
	}
	if got := truncateRunes("abc", 5); got != "abc" {
		t.Fatalf("truncateRunes short = %q", got)
	}
	if got := firstNonEmpty("", "x", "y"); got != "x" {
		t.Fatalf("firstNonEmpty = %q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Fatalf("firstNonEmpty all empty = %q", got)
	}
}
