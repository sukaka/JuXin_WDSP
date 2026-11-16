package pipeline

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func TestProcessResponseLLMOutputProtect(t *testing.T) {
	policy := &detectors.LLMSecurityPolicy{
		ID: "11111111-1111-4111-8111-111111111111", ApplicationID: "22222222-2222-4222-8222-222222222222",
		Name: "AI 助手", Version: 1, Mode: detectors.LLMSecurityProtect, PromptInjectionEnabled: true,
		OutputContentEnabled: true, OutputPIIEnabled: true,
	}
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`))
	r.Header.Set("Content-Type", "application/json")
	res, err := Process(r, Config{Enabled: true, Mode: "PROTECT", LLMSecurityPolicy: policy}, nil)
	if err != nil {
		t.Fatal(err)
	}
	act, err := ProcessResponse(res.Context, ResponseInput{
		Status: 200, ContentType: "application/json", Body: []byte(`{"choices":[{"message":{"content":"请编写木马程序"}}]}`), BodySize: 80,
	}, ResponseConfig{Mode: decision.ModeProtect, LLMSecurityPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	if act != "BLOCK" {
		t.Fatalf("action=%s matches=%+v", act, res.Context.CopyMatches())
	}
}

func TestProcessResponseLLMOutputObserveAndStreamDisclosure(t *testing.T) {
	policy := &detectors.LLMSecurityPolicy{
		ID: "11111111-1111-4111-8111-111111111111", ApplicationID: "22222222-2222-4222-8222-222222222222",
		Name: "AI 助手", Version: 1, Mode: detectors.LLMSecurityObserve, PromptInjectionEnabled: true,
		OutputContentEnabled: true, OutputPIIEnabled: true,
	}
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`))
	r.Header.Set("Content-Type", "application/json")
	res, err := Process(r, Config{Enabled: true, Mode: "OBSERVE", LLMSecurityPolicy: policy}, nil)
	if err != nil {
		t.Fatal(err)
	}
	act, err := ProcessResponse(res.Context, ResponseInput{
		Status: 200, ContentType: "application/json", Body: []byte(`{"choices":[{"message":{"content":"customer@example.com"}}]}`), BodySize: 70,
	}, ResponseConfig{Mode: decision.ModeObserve, LLMSecurityPolicy: policy})
	if err != nil || act != "OBSERVE" {
		t.Fatalf("action=%s err=%v", act, err)
	}
	act, err = ProcessResponse(res.Context, ResponseInput{
		Status: 200, ContentType: "text/event-stream", Streamed: true, BodySize: 100,
	}, ResponseConfig{Mode: decision.ModeProtect, LLMSecurityPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	if act == "BLOCK" {
		t.Fatal("streamed output must not be blocked after bytes were released")
	}
	found := false
	for _, match := range res.Context.CopyMatches() {
		if match.RuleID == "llm.output_not_inspected" && match.Evidence["reason"] == "response_streamed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stream disclosure missing: %+v", res.Context.CopyMatches())
	}
}
