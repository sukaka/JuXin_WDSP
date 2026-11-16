package detectors

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestLLMOutputTokenBudgetModesAndEvidence(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		category string
	}{
		{LLMSecurityObserve, "OBSERVE"},
		{LLMSecurityProtect, "RATE_LIMIT"},
	} {
		ctx := dsctx.New("llm-token-budget", dsctx.DefaultParseLimits())
		policy := llmSecurityPolicyForTest(tc.mode)
		policy.MaxOutputTokens = 2048
		p := llmTestParsed("gpt-4o", "hello")
		p.JSONValues["max_completion_tokens"] = "4096"
		CheckLLMWithPolicy(ctx, p, llmTestResult, nil, policy)
		matches := llmMatches(ctx, "llm.output_token_budget_exceeded")
		if len(matches) != 1 || matches[0].Category != tc.category || matches[0].ScoreDelta != 25 {
			t.Fatalf("mode=%s matches=%+v", tc.mode, matches)
		}
		evidence := matches[0].Evidence
		if evidence["field"] != "max_completion_tokens" || evidence["requested_tokens"] != "4096" || evidence["limit_tokens"] != "2048" {
			t.Fatalf("evidence=%+v", evidence)
		}
		if evidence["policy_id"] != policy.ID || evidence["policy_version"] != "3" {
			t.Fatalf("policy evidence=%+v", evidence)
		}
	}
}

func TestLLMOutputTokenBudgetSupportsDeclaredLimitFields(t *testing.T) {
	for _, field := range []string{"max_tokens", "max_completion_tokens", "max_output_tokens"} {
		ctx := dsctx.New("llm-token-field", dsctx.DefaultParseLimits())
		policy := llmSecurityPolicyForTest(LLMSecurityProtect)
		policy.MaxOutputTokens = 128
		p := llmTestParsed("gpt-4o", "hello")
		p.JSONValues[field] = "129"
		CheckLLMWithPolicy(ctx, p, llmTestResult, nil, policy)
		matches := llmMatches(ctx, "llm.output_token_budget_exceeded")
		if len(matches) != 1 || matches[0].Evidence["field"] != field {
			t.Fatalf("field=%s matches=%+v", field, matches)
		}
	}
}

func TestLLMOutputTokenBudgetZeroAndNormalBehavior(t *testing.T) {
	for _, raw := range []string{"128", "256", "0", "-1", "invalid"} {
		ctx := dsctx.New("llm-token-normal", dsctx.DefaultParseLimits())
		policy := llmSecurityPolicyForTest(LLMSecurityProtect)
		policy.MaxOutputTokens = 256
		p := llmTestParsed("gpt-4o", "hello")
		p.JSONValues["max_tokens"] = raw
		CheckLLMWithPolicy(ctx, p, llmTestResult, nil, policy)
		if matches := llmMatches(ctx, "llm.output_token_budget_exceeded"); len(matches) != 0 {
			t.Fatalf("raw=%q matches=%+v", raw, matches)
		}
	}

	ctx := dsctx.New("llm-token-disabled", dsctx.DefaultParseLimits())
	p := llmTestParsed("gpt-4o", "hello")
	p.JSONValues["max_tokens"] = "4096"
	CheckLLMWithPolicy(ctx, p, llmTestResult, nil, nil)
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("nil policy must retain zero behavior: %+v", ctx.CopyMatches())
	}

	ctx = dsctx.New("llm-token-zero-budget", dsctx.DefaultParseLimits())
	policy := llmSecurityPolicyForTest(LLMSecurityProtect)
	CheckLLMWithPolicy(ctx, p, llmTestResult, nil, policy)
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("zero budget must retain zero behavior: %+v", ctx.CopyMatches())
	}
}

func TestLLMOutputTokenBudgetValidation(t *testing.T) {
	for _, limit := range []int{-1, 1000001} {
		policy := llmSecurityPolicyForTest(LLMSecurityObserve)
		policy.MaxOutputTokens = limit
		if err := ValidateLLMSecurityPolicies([]LLMSecurityPolicy{*policy}); err == nil {
			t.Fatalf("limit=%d must be rejected", limit)
		}
	}
}
