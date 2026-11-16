package jiuzhang_guard

import (
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func TestLLMSecurityPolicyForAppIsolation(t *testing.T) {
	policy := detectors.LLMSecurityPolicy{ID: "policy-1", ApplicationID: "app-a", Version: 2, Mode: "PROTECT"}
	g := &Guard{AppID: "app-a", apiLLMSecurity: detectors.GroupLLMSecurityPolicies([]detectors.LLMSecurityPolicy{policy})}
	got := g.llmSecurityPolicyForApp()
	if got == nil || got.ID != "policy-1" || got.Version != 2 {
		t.Fatalf("policy=%+v", got)
	}
	g.AppID = "app-b"
	if got := g.llmSecurityPolicyForApp(); got != nil {
		t.Fatalf("other application must not consume policy: %+v", got)
	}
	g.AppID = ""
	if got := g.llmSecurityPolicyForApp(); got != nil {
		t.Fatalf("unknown application must not consume policy: %+v", got)
	}
}
