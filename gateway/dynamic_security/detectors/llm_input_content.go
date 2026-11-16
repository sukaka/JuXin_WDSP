package detectors

import (
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func checkLLMInputContent(ctx *dsctx.RequestContext, p *parser.Parsed, policy *LLMSecurityPolicy) {
	if !policy.InputContentEnabled {
		return
	}
	for _, path := range llmPromptPaths(p) {
		for _, rule := range llmOutputContentRules {
			if !rule.re.MatchString(p.JSONValues[path]) {
				continue
			}
			evidence := llmPolicyEvidence(policy)
			evidence["field"] = path
			evidence["rule"] = rule.name
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "llm", RuleID: "llm.input_content_violation",
				Category: llmOutputCategory(policy), Severity: llmOutputSeverity(policy),
				Message: "llm prompt matches a harmful content rule", Evidence: evidence, ScoreDelta: llmOutputScore(policy),
			})
			break
		}
	}
}
