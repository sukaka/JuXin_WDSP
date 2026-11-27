package pipeline

import (
	"net/http"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/mcpguard"
)

// TestProcessResponseAppliesAPIExceptions 验证响应相位将 cfg.Exceptions 透传给 decision.Decide，
// 已豁免的响应侧 BLOCK/OBSERVE 规则被打标 Excepted 而不触发误阻断。
func TestProcessResponseAppliesAPIExceptions(t *testing.T) {
	rc := dsctx.New("req-exc-1", dsctx.DefaultParseLimits())
	policy := &detectors.LLMSecurityPolicy{
		ID:                   "11111111-1111-4111-8111-111111111111",
		ApplicationID:        "22222222-2222-4222-8222-222222222222",
		Name:                 "llm-out",
		Version:              1,
		Mode:                 detectors.LLMSecurityProtect,
		OutputContentEnabled: true,
	}
	rc.SetLLMObservation(&dsctx.LLMObservation{Model: "gpt-4o"})
	// 放一条响应侧 BLOCK 命中，并在响应相位传入对应受限例外验证其被豁免
	rc.AddMatch(dsctx.DetectorMatch{
		Detector: "api_response",
		RuleID:   "response.custom_test_block",
		Category: "BLOCK",
		Severity: "HIGH",
		Message:  "test response block",
	})
	act, err := ProcessResponse(rc, ResponseInput{
		Status:      http.StatusOK,
		ContentType: "application/json",
		Body:        []byte(`{"ok":true}`),
		BodySize:    11,
	}, ResponseConfig{
		Mode:              decision.ModeProtect,
		LLMSecurityPolicy: policy,
		Exceptions: []decision.ExceptionRef{{
			ExceptionID: "exc-resp-1",
			Version:     3,
			DetectorID:  "api_response",
			RuleID:      "response.custom_test_block",
		}},
	})
	if err != nil {
		t.Fatalf("ProcessResponse: %v", err)
	}
	if act == dsctx.ActionBlock {
		t.Fatalf("expected excepted response finding not to block, got %s", act)
	}
	foundExcepted := false
	for _, m := range rc.CopyMatches() {
		if m.RuleID == "response.custom_test_block" && m.Excepted && m.ExceptionID == "exc-resp-1" {
			foundExcepted = true
		}
	}
	if !foundExcepted {
		t.Fatalf("expected finding to be marked excepted: %+v", rc.CopyMatches())
	}
}

// TestPipelineMCPGuardNilRequestURLNoPanic 验证启用 MCPGuard 且 r.URL 为 nil 时不 panic。
func TestPipelineMCPGuardNilRequestURLNoPanic(t *testing.T) {
	req := &http.Request{Method: http.MethodPost, Header: http.Header{}}
	res, err := Process(req, Config{
		Enabled:       true,
		Mode:          decision.ModeObserve,
		ApplicationID: "app-1",
		MCPGuard:      &mcpguard.Config{},
	}, nil)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil Result")
	}
}
