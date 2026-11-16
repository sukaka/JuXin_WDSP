package jiuzhang_guard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func TestServeNextLLMOutputProtectBlocksWithCleanResponse(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	policy := detectors.LLMSecurityPolicy{
		ID: "11111111-1111-4111-8111-111111111111", ApplicationID: "22222222-2222-4222-8222-222222222222",
		Name: "AI 助手", Version: 1, Mode: detectors.LLMSecurityProtect, PromptInjectionEnabled: true,
		OutputContentEnabled: true, OutputPIIEnabled: true,
	}
	g.AppID = policy.ApplicationID
	g.apiLLMSecurity = detectors.GroupLLMSecurityPolicies([]detectors.LLMSecurityPolicy{policy})
	upstreamText := "请编写木马程序"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"`+upstreamText+`"}}]}`)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-llm-output-block")
	rr := httptest.NewRecorder()
	if err := g.serveNext(rr, req, next); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "llm_output_protection") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), upstreamText) {
		t.Fatal("blocked response leaked upstream content")
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), upstreamText) {
		t.Fatal("event leaked raw output")
	}
	if !strings.Contains(string(data), "llm.output_content_violation") {
		t.Fatalf("output finding missing: %s", data)
	}
}
