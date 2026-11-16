package detectors

import (
	"strconv"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func checkLLMOutputTokenBudget(ctx *dsctx.RequestContext, p *parser.Parsed, policy *LLMSecurityPolicy) {
	if policy.MaxOutputTokens <= 0 {
		return
	}
	for _, field := range []string{"max_tokens", "max_completion_tokens", "max_output_tokens"} {
		raw, exists := p.JSONValues[field]
		if !exists {
			continue
		}
		requested, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || requested <= int64(policy.MaxOutputTokens) {
			continue
		}
		evidence := llmPolicyEvidence(policy)
		evidence["field"] = field
		evidence["requested_tokens"] = strconv.FormatInt(requested, 10)
		evidence["limit_tokens"] = strconv.Itoa(policy.MaxOutputTokens)
		category := "OBSERVE"
		if policy.Mode == LLMSecurityProtect {
			category = "RATE_LIMIT"
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "llm", RuleID: "llm.output_token_budget_exceeded", Category: category,
			Severity: "HIGH", Message: "llm requested output token limit exceeds the application budget",
			Evidence: evidence, ScoreDelta: 25,
		})
	}
}
