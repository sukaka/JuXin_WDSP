package jiuzhang_guard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func TestServeNextLLMOutputTokenBudget(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       string
		wantStatus int
		wantNext   bool
	}{
		{"observe", detectors.LLMSecurityObserve, http.StatusOK, true},
		{"protect", detectors.LLMSecurityProtect, http.StatusTooManyRequests, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, logPath := newAPITestGuard(t, "PROTECT", nil)
			policy := detectors.LLMSecurityPolicy{
				ID: "11111111-1111-4111-8111-111111111111", ApplicationID: "22222222-2222-4222-8222-222222222222",
				Name: "AI 资源防护", Version: 5, Mode: tc.mode, MaxOutputTokens: 2048,
			}
			g.AppID = policy.ApplicationID
			g.apiLLMSecurity = detectors.GroupLLMSecurityPolicies([]detectors.LLMSecurityPolicy{policy})
			nextCalled := false
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
				return nil
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"生成摘要"}],"max_tokens":4096}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Request-Id", "req-llm-token-budget-"+tc.mode)
			rr := httptest.NewRecorder()
			err := g.serveNext(rr, req, next)
			if tc.wantNext {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var handlerErr caddyhttp.HandlerError
				if !errors.As(err, &handlerErr) || handlerErr.StatusCode != tc.wantStatus {
					t.Fatalf("expected %d HandlerError, got %v", tc.wantStatus, err)
				}
			}
			if nextCalled != tc.wantNext {
				t.Fatalf("status=%d next=%v body=%s", rr.Code, nextCalled, rr.Body.String())
			}
			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "llm.output_token_budget_exceeded") || !strings.Contains(string(data), `"limit_tokens":"2048"`) {
				t.Fatalf("token budget evidence missing: %s", data)
			}
		})
	}
}
