package aiagents

import (
	"context"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
)

func TestCCKeywordReWordBoundary(t *testing.T) {
	shouldMatch := []string{
		"cc",
		"cc阈值",
		"调整 cc",
		"调整cc阈值",
		"/cc/test",
		"cc_threshold",
	}
	for _, s := range shouldMatch {
		if !ccKeywordRe.MatchString(s) {
			t.Errorf("ccKeywordRe.MatchString(%q) = false, want true", s)
		}
	}

	shouldNotMatch := []string{
		"/account",
		"/access",
		"success",
		"access control",
		"/api/v1/accounts/profile",
	}
	for _, s := range shouldNotMatch {
		if ccKeywordRe.MatchString(s) {
			t.Errorf("ccKeywordRe.MatchString(%q) = true, want false", s)
		}
	}
}

func TestWafPolicyWhatIfAccountURIDoesNotTriggerCCBranch(t *testing.T) {
	agent := NewWafPolicyAgent(nil)
	res, err := agent.Analyze(context.Background(), &aiorchestrator.AnalyzeInput{
		TaskType: aiorchestrator.TaskWhatIf,
		Message:  "请模拟关闭 URI /account/access 下的规则",
	})
	if err != nil {
		t.Fatalf("Analyze returned unexpected error: %v", err)
	}
	if res == nil || !strings.Contains(res.FactsText, "请提供要模拟的规则 ID") {
		t.Fatalf("expected fallback prompt for missing ruleID rather than CC branch, got %+v", res)
	}
}
