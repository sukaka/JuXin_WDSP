// recorder_test.go LLM 观测采集写入单元测试：findings 过滤口径 / 幂等主键 /
// 列宽截断（纯函数路径，SQL 落库由 server/tests 集成测试覆盖）。
package apillm

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// TestLLMFindingsFilter findings 口径：仅 llm.* 明细收录，其余检测器明细剔除；空归一 []。
func TestLLMFindingsFilter(t *testing.T) {
	details := []dsctx.DetectorMatch{
		{Detector: "llm", RuleID: "llm.prompt_injection", Evidence: map[string]string{"rule": "dan_mode"}},
		{Detector: "waf", RuleID: "942100"},
		{Detector: "sensitive_data", RuleID: "sensitive.field"},
		{Detector: "llm", RuleID: "llm.unauthorized_model", Evidence: map[string]string{"model": "x"}},
	}
	got := llmFindings(details)
	if len(got) != 2 || got[0].RuleID != "llm.prompt_injection" || got[1].RuleID != "llm.unauthorized_model" {
		t.Fatalf("filter: %+v", got)
	}
	if got := llmFindings(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil should be empty slice: %+v", got)
	}
}

// TestObservationIDIdempotent 幂等主键：同 request_id 恒得同 UUID（采集重放 DO NOTHING）；
// 不同 request_id 不同键；空 request_id 退化随机（每次不同）。
func TestObservationIDIdempotent(t *testing.T) {
	a := observationID("req-1")
	b := observationID("req-1")
	if a != b {
		t.Fatalf("same request_id must derive same id: %s vs %s", a, b)
	}
	if c := observationID("req-2"); c == a {
		t.Fatal("different request_id must derive different id")
	}
	// 版本/变体位成形（UUID v5 语义）
	if v := a.Version(); v != 5 {
		t.Fatalf("version=%d", v)
	}
	if x, y := observationID(""), observationID(""); x == y {
		t.Fatal("empty request_id must fall back to random id")
	}
}

// TestTruncateRunesLLM 列宽截断（按 rune，多字节不截断）。
func TestTruncateRunesLLM(t *testing.T) {
	if got := truncateRunesLLM("gpt-4o", 128); got != "gpt-4o" {
		t.Fatalf("short: %q", got)
	}
	long := strings.Repeat("模型", 70) // 140 runes
	if got := truncateRunesLLM(long, 128); len([]rune(got)) != 128 {
		t.Fatalf("runes=%d", len([]rune(got)))
	}
}

// TestRecordLLMObservationNilStore 空仓储/空端点键：缺失容忍跳过（不 panic、不报错）。
func TestRecordLLMObservationNilStore(t *testing.T) {
	var s *ObsStore
	if err := s.RecordLLMObservation(t.Context(), ObservationInput{EndpointKey: "POST /v1/chat/completions"}); err != nil {
		t.Fatal(err)
	}
	s = &ObsStore{}
	if err := s.RecordLLMObservation(t.Context(), ObservationInput{EndpointKey: ""}); err != nil {
		t.Fatal(err)
	}
}
