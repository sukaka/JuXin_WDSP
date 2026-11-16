package pipeline

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func TestProcessLLMOutputTokenBudgetProtect(t *testing.T) {
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"生成摘要"}],"max_completion_tokens":4096}`
	r, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	policy := &detectors.LLMSecurityPolicy{
		ID: "11111111-1111-4111-8111-111111111111", ApplicationID: "11111111-1111-4111-8111-111111111111",
		Name: "AI 资源防护", Version: 4, Mode: detectors.LLMSecurityProtect, MaxOutputTokens: 2048,
	}
	res, err := Process(r, Config{Enabled: true, Mode: "PROTECT", LLMSecurityPolicy: policy}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalAction != "RATE_LIMIT" {
		t.Fatalf("final_action=%s matches=%+v", res.FinalAction, res.Context.CopyMatches())
	}
	found := false
	for _, match := range res.Context.CopyMatches() {
		if match.RuleID == "llm.output_token_budget_exceeded" {
			found = true
			if match.Evidence["requested_tokens"] != "4096" || match.Evidence["limit_tokens"] != "2048" {
				t.Fatalf("evidence=%+v", match.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("token budget finding missing: %+v", res.Context.CopyMatches())
	}
}
