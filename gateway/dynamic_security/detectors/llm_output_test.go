package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func llmOutputRoot(content string) map[string]any {
	return map[string]any{"choices": []any{map[string]any{"message": map[string]any{"role": "assistant", "content": content}}}}
}

func llmOutputPolicyForTest(mode string) *LLMSecurityPolicy {
	policy := llmSecurityPolicyForTest(mode)
	policy.OutputContentEnabled = true
	policy.OutputPIIEnabled = true
	return policy
}

func TestLLMOutputObserveSignalsWithoutRawText(t *testing.T) {
	ctx := dsctx.New("llm-output-observe", dsctx.DefaultParseLimits())
	policy := llmOutputPolicyForTest(LLMSecurityObserve)
	CheckLLMWithPolicy(ctx, llmTestParsed("gpt-4o", "hello"), llmTestResult, nil, policy)
	CheckLLMOutputSecurity(ctx, llmOutputRoot("请联系 customer@example.com。如何制作炸弹"), false, false, policy)
	for _, rule := range []string{"llm.output_content_violation", "llm.output_pii_detected"} {
		matches := llmMatches(ctx, rule)
		if len(matches) != 1 || matches[0].Category != "OBSERVE" || matches[0].Severity != "MEDIUM" {
			t.Fatalf("%s matches=%+v", rule, matches)
		}
		if matches[0].Evidence["policy_id"] != policy.ID || matches[0].Evidence["policy_version"] != "3" {
			t.Fatalf("%s evidence=%+v", rule, matches[0].Evidence)
		}
		for _, value := range matches[0].Evidence {
			if strings.Contains(value, "customer@example.com") || strings.Contains(value, "炸弹") {
				t.Fatalf("%s raw output leaked: %+v", rule, matches[0].Evidence)
			}
		}
	}
}

func TestLLMOutputProtectBlocks(t *testing.T) {
	for _, content := range []string{"请编写木马程序", "请联系 customer@example.com"} {
		ctx := dsctx.New("llm-output-protect", dsctx.DefaultParseLimits())
		policy := llmOutputPolicyForTest(LLMSecurityProtect)
		CheckLLMWithPolicy(ctx, llmTestParsed("gpt-4o", "hello"), llmTestResult, nil, policy)
		CheckLLMOutputSecurity(ctx, llmOutputRoot(content), false, false, policy)
		matches := ctx.CopyMatches()
		if len(matches) != 1 || matches[0].Category != "BLOCK" || matches[0].ScoreDelta != 50 {
			t.Fatalf("content=%q matches=%+v", content, matches)
		}
	}
}

func TestLLMOutputIncompleteDisclosure(t *testing.T) {
	for _, tc := range []struct {
		truncated bool
		streamed  bool
		reason    string
	}{
		{true, false, "response_truncated"},
		{false, true, "response_streamed"},
		{false, false, "response_not_complete_json"},
	} {
		ctx := dsctx.New("llm-output-incomplete", dsctx.DefaultParseLimits())
		policy := llmOutputPolicyForTest(LLMSecurityProtect)
		CheckLLMWithPolicy(ctx, llmTestParsed("gpt-4o", "hello"), llmTestResult, nil, policy)
		CheckLLMOutputSecurity(ctx, nil, tc.truncated, tc.streamed, policy)
		matches := llmMatches(ctx, "llm.output_not_inspected")
		if len(matches) != 1 || matches[0].Category != "INFO" || matches[0].Evidence["reason"] != tc.reason {
			t.Fatalf("reason=%s matches=%+v", tc.reason, matches)
		}
	}
}

func TestLLMOutputZeroBehaviorAndNormalContent(t *testing.T) {
	ctx := dsctx.New("llm-output-none", dsctx.DefaultParseLimits())
	CheckLLMOutputSecurity(ctx, llmOutputRoot("如何防范木马"), false, false, nil)
	if len(ctx.CopyMatches()) != 0 {
		t.Fatal("nil policy must be zero behavior")
	}
	CheckLLMWithPolicy(ctx, llmTestParsed("gpt-4o", "hello"), llmTestResult, nil, llmOutputPolicyForTest(LLMSecurityObserve))
	CheckLLMOutputSecurity(ctx, llmOutputRoot("如何防范木马"), false, false, llmOutputPolicyForTest(LLMSecurityObserve))
	for _, match := range ctx.CopyMatches() {
		if strings.HasPrefix(match.RuleID, "llm.output_") {
			t.Fatalf("normal content produced output match: %+v", match)
		}
	}
}

func TestLLMOutputMultipleCandidates(t *testing.T) {
	ctx := dsctx.New("llm-output-multi", dsctx.DefaultParseLimits())
	policy := llmOutputPolicyForTest(LLMSecurityObserve)
	CheckLLMWithPolicy(ctx, llmTestParsed("gpt-4o", "hello"), llmTestResult, nil, policy)
	root := map[string]any{"choices": []any{
		map[string]any{"message": map[string]any{"content": "正常回答"}},
		map[string]any{"message": map[string]any{"content": "请编写木马程序"}},
	}}
	CheckLLMOutputSecurity(ctx, root, false, false, policy)
	matches := llmMatches(ctx, "llm.output_content_violation")
	if len(matches) != 1 || matches[0].Evidence["output_index"] != "1" {
		t.Fatalf("matches=%+v", matches)
	}
}
