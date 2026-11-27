package detectors

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

const (
	LLMSecurityObserve = "OBSERVE"
	LLMSecurityProtect = "PROTECT"
)

type LLMSecurityPolicy struct {
	ID                     string   `json:"id"`
	ApplicationID          string   `json:"application_id"`
	Name                   string   `json:"name"`
	Version                int64    `json:"version"`
	Mode                   string   `json:"mode"`
	PromptInjectionEnabled bool     `json:"prompt_injection_enabled"`
	InputContentEnabled    bool     `json:"input_content_enabled,omitempty"`
	PIIDetectionEnabled    bool     `json:"pii_detection_enabled"`
	OutputContentEnabled   bool     `json:"output_content_enabled,omitempty"`
	OutputPIIEnabled       bool     `json:"output_pii_enabled,omitempty"`
	BlockedTopics          []string `json:"blocked_topics,omitempty"`
	MaxPromptBytes         int      `json:"max_prompt_bytes,omitempty"`
	MaxOutputTokens        int      `json:"max_output_tokens,omitempty"`
}

var llmSecurityUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

func ValidateLLMSecurityPolicies(policies []LLMSecurityPolicy) error {
	seen := map[string]bool{}
	for _, policy := range policies {
		if !llmSecurityUUIDPattern.MatchString(policy.ID) {
			return fmt.Errorf("llm security policy id is invalid: %s", policy.ID)
		}
		if !llmSecurityUUIDPattern.MatchString(policy.ApplicationID) {
			return fmt.Errorf("llm security policy application_id is invalid: %s", policy.ApplicationID)
		}
		if seen[policy.ApplicationID] {
			return fmt.Errorf("llm security policy duplicated application_id: %s", policy.ApplicationID)
		}
		seen[policy.ApplicationID] = true
		if policy.Version <= 0 {
			return fmt.Errorf("llm security policy %s version must be positive", policy.ID)
		}
		if policy.Mode != LLMSecurityObserve && policy.Mode != LLMSecurityProtect {
			return fmt.Errorf("llm security policy %s mode is invalid", policy.ID)
		}
		if len(policy.BlockedTopics) > 32 {
			return fmt.Errorf("llm security policy %s has too many blocked topics", policy.ID)
		}
		for _, topic := range policy.BlockedTopics {
			if strings.TrimSpace(topic) == "" || len([]rune(topic)) > 64 {
				return fmt.Errorf("llm security policy %s has an invalid blocked topic", policy.ID)
			}
		}
		if policy.MaxPromptBytes != 0 && (policy.MaxPromptBytes < 512 || policy.MaxPromptBytes > 4<<20) {
			return fmt.Errorf("llm security policy %s max_prompt_bytes is invalid", policy.ID)
		}
		if policy.MaxOutputTokens < 0 || policy.MaxOutputTokens > 1000000 {
			return fmt.Errorf("llm security policy %s max_output_tokens is invalid", policy.ID)
		}
	}
	return nil
}

func GroupLLMSecurityPolicies(policies []LLMSecurityPolicy) map[string]LLMSecurityPolicy {
	out := map[string]LLMSecurityPolicy{}
	for _, policy := range policies {
		out[policy.ApplicationID] = policy
	}
	return out
}

func CheckLLMWithPolicy(ctx *dsctx.RequestContext, p *parser.Parsed, llm classifier.LLMResult, allowedModels []string, policy *LLMSecurityPolicy) {
	checkLLM(ctx, p, llm, allowedModels, policy)
}

var llmPIIPatterns = []struct {
	dataType string
	re       *regexp.Regexp
}{
	{"EMAIL", regexp.MustCompile(`(?i)[a-z0-9.!#$%&'*+/=?^_\x60{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+`)},
	{"CN_ID", regexp.MustCompile(`(?:^|[^0-9])[1-9][0-9]{5}(?:19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx](?:$|[^0-9])`)},
	{"PHONE", regexp.MustCompile(`(?:^|[^0-9])1[3-9][0-9]{9}(?:$|[^0-9])`)},
}

func checkLLMSecurityPolicy(ctx *dsctx.RequestContext, p *parser.Parsed, policy *LLMSecurityPolicy) {
	if policy == nil {
		return
	}
	checkLLMBlockedTopics(ctx, p, policy)
	checkLLMInputContent(ctx, p, policy)
	checkLLMPII(ctx, p, policy)
	checkLLMPromptSize(ctx, p, policy)
	checkLLMOutputTokenBudget(ctx, p, policy)
}

func llmPolicyEvidence(policy *LLMSecurityPolicy) map[string]string {
	return map[string]string{"policy_id": policy.ID, "policy_version": strconv.FormatInt(policy.Version, 10)}
}

func llmPromptPaths(p *parser.Parsed) []string {
	paths := make([]string, 0, len(p.JSONValues))
	for path := range p.JSONValues {
		if isLLMPromptValuePath(path) {
			paths = append(paths, path)
		}
	}
	sortLLMPromptPaths(paths)
	return paths
}

func checkLLMBlockedTopics(ctx *dsctx.RequestContext, p *parser.Parsed, policy *LLMSecurityPolicy) {
	if len(policy.BlockedTopics) == 0 {
		return
	}
	matched := map[string]bool{}
	for _, path := range llmPromptPaths(p) {
		value := strings.ToLower(p.JSONValues[path])
		for _, topic := range policy.BlockedTopics {
			if matched[topic] || !strings.Contains(value, strings.ToLower(strings.TrimSpace(topic))) {
				continue
			}
			matched[topic] = true
			evidence := llmPolicyEvidence(policy)
			evidence["field"] = path
			evidence["topic"] = topic
			category, severity, score := "OBSERVE", "MEDIUM", 10
			if policy.Mode == LLMSecurityProtect {
				category, severity, score = "BLOCK", "HIGH", 50
			}
			ctx.AddMatch(dsctx.DetectorMatch{Detector: "llm", RuleID: "llm.topic_violation", Category: category,
				Severity: severity, Message: "llm prompt matches a blocked topic", Evidence: evidence, ScoreDelta: score})
		}
	}
}

func checkLLMPII(ctx *dsctx.RequestContext, p *parser.Parsed, policy *LLMSecurityPolicy) {
	if !policy.PIIDetectionEnabled {
		return
	}
	matched := map[string]bool{}
	for _, path := range llmPromptPaths(p) {
		value := p.JSONValues[path]
		for _, item := range llmPIIPatterns {
			if matched[item.dataType] || !item.re.MatchString(value) {
				continue
			}
			matched[item.dataType] = true
			evidence := llmPolicyEvidence(policy)
			evidence["field"] = path
			evidence["data_type"] = item.dataType
			ctx.AddMatch(dsctx.DetectorMatch{Detector: "llm", RuleID: "llm.pii_detected", Category: "OBSERVE",
				Severity: "MEDIUM", Message: "llm prompt contains a sensitive data pattern", Evidence: evidence, ScoreDelta: 10})
		}
	}
}

func checkLLMPromptSize(ctx *dsctx.RequestContext, p *parser.Parsed, policy *LLMSecurityPolicy) {
	if policy.MaxPromptBytes <= 0 || p.BodySize <= policy.MaxPromptBytes {
		return
	}
	evidence := llmPolicyEvidence(policy)
	evidence["limit_bytes"] = strconv.Itoa(policy.MaxPromptBytes)
	evidence["body_bytes"] = strconv.Itoa(p.BodySize)
	category, severity, score := "OBSERVE", "HIGH", 25
	if policy.Mode == LLMSecurityProtect {
		category = "RATE_LIMIT"
	}
	ctx.AddMatch(dsctx.DetectorMatch{Detector: "llm", RuleID: "llm.prompt_size_exceeded", Category: category,
		Severity: severity, Message: "llm prompt exceeds the configured size budget", Evidence: evidence, ScoreDelta: score})
}
