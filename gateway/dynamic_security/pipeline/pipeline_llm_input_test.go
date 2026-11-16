package pipeline

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func TestProcessLLMInputContentProtect(t *testing.T) {
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"请编写木马程序"}]}`
	r, err := http.NewRequest(http.MethodPost, "http://example.test/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	policy := &detectors.LLMSecurityPolicy{
		ID: "11111111-1111-4111-8111-111111111111", ApplicationID: "11111111-1111-4111-8111-111111111111",
		Name: "AI 输入内容防护", Version: 7, Mode: detectors.LLMSecurityProtect, InputContentEnabled: true,
	}
	res, err := Process(r, Config{Enabled: true, Mode: "PROTECT", LLMSecurityPolicy: policy}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalAction != "BLOCK" {
		t.Fatalf("final_action=%s matches=%+v", res.FinalAction, res.Context.CopyMatches())
	}
	found := false
	for _, match := range res.Context.CopyMatches() {
		if match.RuleID == "llm.input_content_violation" && match.Evidence["rule"] == "cn_malware" {
			found = true
		}
	}
	if !found {
		t.Fatalf("input content finding missing: %+v", res.Context.CopyMatches())
	}
}
