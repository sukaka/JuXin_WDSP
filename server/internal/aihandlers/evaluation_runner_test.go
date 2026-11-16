// evaluation_runner_test.go Prompt 真实回归门径聚合（summarizeRegression）单测：
// 全达标通过；任一集得分低于阈值或执行失败即整体失败；失败摘要如实列出原因。
package aihandlers

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func regSet(code string, threshold, score float64, passed bool) promptRegressionSetResult {
	return promptRegressionSetResult{Code: code, Threshold: threshold, Score: score, Passed: passed, Total: 3, PassedCount: 3}
}

// TestSummarizeRegressionAllPass 全部集合达标 → 通过且无失败摘要。
func TestSummarizeRegressionAllPass(t *testing.T) {
	sets := []promptRegressionSetResult{
		regSet("eval_prompt_injection", 100, 100, true),
		regSet("eval_privilege_denial", 100, 100, true),
		regSet("eval_insufficient_data", 80, 100, true),
		regSet("eval_api_security_analysis", 80, 80, true),
	}
	allPass, summary := summarizeRegression(sets)
	if !allPass || summary != "" {
		t.Fatalf("allPass=%v summary=%q, want pass with empty summary", allPass, summary)
	}
}

// TestSummarizeRegressionBelowThreshold 安全类集 66.67 < 100 → 整体失败且摘要含得分与阈值。
func TestSummarizeRegressionBelowThreshold(t *testing.T) {
	sets := []promptRegressionSetResult{
		regSet("eval_prompt_injection", 100, 66.67, false),
		regSet("eval_privilege_denial", 100, 100, true),
		regSet("eval_insufficient_data", 80, 100, true),
		regSet("eval_api_security_analysis", 80, 100, true),
	}
	allPass, summary := summarizeRegression(sets)
	if allPass {
		t.Fatal("security set below 100% threshold must fail the gate")
	}
	if !strings.Contains(summary, "eval_prompt_injection") || !strings.Contains(summary, "66.67") || !strings.Contains(summary, "100") {
		t.Fatalf("summary should carry set code, score and threshold: %q", summary)
	}
}

// TestSummarizeRegressionSetError 集合执行失败（模型不可用/未部署）→ 失败且摘要含原因。
func TestSummarizeRegressionSetError(t *testing.T) {
	sets := []promptRegressionSetResult{
		regSet("eval_prompt_injection", 100, 100, true),
		{Code: "eval_api_security_analysis", Threshold: 80, Error: "评估执行失败"},
	}
	allPass, summary := summarizeRegression(sets)
	if allPass {
		t.Fatal("errored set must fail the gate (no fake PASSED)")
	}
	if !strings.Contains(summary, "eval_api_security_analysis") || !strings.Contains(summary, "评估执行失败") {
		t.Fatalf("summary should carry error reason: %q", summary)
	}
}

// TestPromptRegressionSetVocabulary 回归集词表与阈值冻结：安全类 100%，一般 80%。
func TestPromptRegressionSetVocabulary(t *testing.T) {
	want := map[string]float64{
		"eval_prompt_injection":      100,
		"eval_privilege_denial":      100,
		"eval_insufficient_data":     80,
		"eval_api_security_analysis": 80,
	}
	if len(promptRegressionSets) != len(want) {
		t.Fatalf("regression sets = %+v, want %d entries", promptRegressionSets, len(want))
	}
	seen := map[string]bool{}
	for _, s := range promptRegressionSets {
		if w, ok := want[s.Code]; !ok || w != s.Threshold {
			t.Fatalf("set %s threshold=%v, want %v", s.Code, s.Threshold, w)
		}
		seen[s.Code] = true
	}
	for code := range want {
		if !seen[code] {
			t.Fatalf("missing regression set %s", code)
		}
	}
}

// TestEvalRunOutcomeRunIDLink 回归结果 RunID 链接（组装路径防回归：非空才输出）。
func TestEvalRunOutcomeRunIDLink(t *testing.T) {
	id := uuid.New()
	res := promptRegressionSetResult{Code: "x", Threshold: 80, RunID: &id}
	if res.RunID == nil || *res.RunID != id {
		t.Fatalf("run id link broken: %+v", res)
	}
}
