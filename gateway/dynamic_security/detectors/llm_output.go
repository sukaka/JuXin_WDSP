package detectors

import (
	"regexp"
	"strconv"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

const (
	maxLLMOutputTexts     = 32
	maxLLMOutputTextBytes = 64 << 10
)

var llmOutputContentRules = []struct {
	name string
	re   *regexp.Regexp
}{
	{"cn_build_explosive", regexp.MustCompile(`(?i)(如何|怎么|教我|请|帮我).{0,8}(制作|制造|合成).{0,8}(炸弹|爆炸物|炸药)`)},
	{"cn_malware", regexp.MustCompile(`(?i)(编写|生成|开发|制作).{0,12}(木马|病毒|勒索软件|恶意软件|恶意代码|恶意脚本)`)},
	{"cn_credential_theft", regexp.MustCompile(`(?i)(窃取|盗取|骗取).{0,12}(密码|口令|账号|凭据|身份信息)`)},
	{"cn_intrusion", regexp.MustCompile(`(?i)(入侵|攻陷|控制).{0,12}(服务器|系统|网站|内网|数据库)`)},
	{"en_malware", regexp.MustCompile(`(?i)(write|create|generate|build|develop).{0,24}(malware|ransomware|keylogger|trojan|malicious (code|script|payload))`)},
	{"en_credential_theft", regexp.MustCompile(`(?i)(steal|exfiltrate|phish).{0,24}(password|credential|account|identity|token)`)},
	{"en_explosive", regexp.MustCompile(`(?i)(build|make|assemble|synthesize).{0,24}(bomb|explosive)`)},
}

func CheckLLMOutputSecurity(ctx *dsctx.RequestContext, root any, truncated, streamed bool, policy *LLMSecurityPolicy) {
	if ctx == nil || policy == nil || ctx.GetLLMObservation() == nil || !policy.OutputContentEnabled && !policy.OutputPIIEnabled {
		return
	}
	if truncated || streamed || root == nil {
		reason := "response_not_complete_json"
		if truncated {
			reason = "response_truncated"
		} else if streamed {
			reason = "response_streamed"
		}
		evidence := llmPolicyEvidence(policy)
		evidence["reason"] = reason
		ctx.AddMatch(dsctx.DetectorMatch{Detector: "llm", RuleID: "llm.output_not_inspected", Category: "INFO",
			Severity: "INFO", Message: "llm output content was not available for complete inspection", Evidence: evidence})
		return
	}
	texts, scanTruncated := extractLLMOutputTexts(root)
	if scanTruncated {
		evidence := llmPolicyEvidence(policy)
		evidence["reason"] = "output_scan_budget_exceeded"
		ctx.AddMatch(dsctx.DetectorMatch{Detector: "llm", RuleID: "llm.output_partially_inspected", Category: "INFO",
			Severity: "INFO", Message: "llm output inspection reached the text budget", Evidence: evidence})
	}
	for index, text := range texts {
		if policy.OutputContentEnabled {
			checkLLMOutputContent(ctx, text, index, policy)
		}
		if policy.OutputPIIEnabled {
			checkLLMOutputPII(ctx, text, index, policy)
		}
	}
}

func checkLLMOutputContent(ctx *dsctx.RequestContext, text string, index int, policy *LLMSecurityPolicy) {
	for _, rule := range llmOutputContentRules {
		if !rule.re.MatchString(text) {
			continue
		}
		evidence := llmOutputEvidence(policy, index)
		evidence["rule"] = rule.name
		ctx.AddMatch(dsctx.DetectorMatch{Detector: "llm", RuleID: "llm.output_content_violation",
			Category: llmOutputCategory(policy), Severity: llmOutputSeverity(policy), Message: "llm output matches a harmful content rule",
			Evidence: evidence, ScoreDelta: llmOutputScore(policy)})
		return
	}
}

func checkLLMOutputPII(ctx *dsctx.RequestContext, text string, index int, policy *LLMSecurityPolicy) {
	for _, item := range llmPIIPatterns {
		if !item.re.MatchString(text) {
			continue
		}
		evidence := llmOutputEvidence(policy, index)
		evidence["data_type"] = item.dataType
		ctx.AddMatch(dsctx.DetectorMatch{Detector: "llm", RuleID: "llm.output_pii_detected",
			Category: llmOutputCategory(policy), Severity: llmOutputSeverity(policy), Message: "llm output contains a sensitive data pattern",
			Evidence: evidence, ScoreDelta: llmOutputScore(policy)})
	}
}

func llmOutputCategory(policy *LLMSecurityPolicy) string {
	if policy.Mode == LLMSecurityProtect {
		return "BLOCK"
	}
	return "OBSERVE"
}

func llmOutputSeverity(policy *LLMSecurityPolicy) string {
	if policy.Mode == LLMSecurityProtect {
		return "HIGH"
	}
	return "MEDIUM"
}

func llmOutputScore(policy *LLMSecurityPolicy) int {
	if policy.Mode == LLMSecurityProtect {
		return 50
	}
	return 15
}

func llmOutputEvidence(policy *LLMSecurityPolicy, index int) map[string]string {
	evidence := llmPolicyEvidence(policy)
	evidence["output_index"] = strconv.Itoa(index)
	return evidence
}

func extractLLMOutputTexts(root any) ([]string, bool) {
	texts := []string{}
	truncated := false
	add := func(value string) {
		if value == "" || len(texts) >= maxLLMOutputTexts {
			return
		}
		if len(value) > maxLLMOutputTextBytes {
			value = value[:maxLLMOutputTextBytes]
			truncated = true
		}
		texts = append(texts, value)
	}
	var walkContent func(any)
	walkContent = func(value any) {
		switch item := value.(type) {
		case string:
			add(item)
		case []any:
			for _, part := range item {
				if obj, ok := part.(map[string]any); ok {
					if text, ok := obj["text"].(string); ok {
						add(text)
					}
				}
			}
		}
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return texts, truncated
	}
	if text, ok := obj["output_text"].(string); ok {
		add(text)
	}
	for _, field := range []string{"choices", "output"} {
		items, ok := obj[field].([]any)
		if !ok {
			continue
		}
		for _, raw := range items {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if text, ok := item["text"].(string); ok {
				add(text)
			}
			if message, ok := item["message"].(map[string]any); ok {
				walkContent(message["content"])
			}
			walkContent(item["content"])
		}
	}
	if len(texts) >= maxLLMOutputTexts {
		truncated = true
	}
	return texts, truncated
}
