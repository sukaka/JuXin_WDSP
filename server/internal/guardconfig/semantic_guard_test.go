package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeSemanticGuardLister struct {
	policies map[string]*gatewayconfig.GuardSemanticGuardPolicy
	err      error
}

func (f fakeSemanticGuardLister) ListForGuard(context.Context) (map[string]*gatewayconfig.GuardSemanticGuardPolicy, error) {
	return f.policies, f.err
}

func TestLoadSemanticGuardPolicyAndFailHard(t *testing.T) {
	// 1. nil lister -> no-op
	cfg := &gatewayconfig.GuardConfig{}
	if err := (&Provider{}).loadSemanticGuardPolicy(context.Background(), cfg); err != nil {
		t.Fatalf("nil lister should succeed: %v", err)
	}
	if cfg.SemanticGuardPolicy != nil {
		t.Fatalf("expected nil SemanticGuardPolicy, got %+v", cfg.SemanticGuardPolicy)
	}

	// 2. lister 失败中止发布（fail-hard）
	pErr := &Provider{semanticGuard: fakeSemanticGuardLister{err: errors.New("db down")}}
	if err := pErr.loadSemanticGuardPolicy(context.Background(), &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("lister error must fail-hard")
	}

	// 3. 空策略列表不下发段
	pEmpty := &Provider{semanticGuard: fakeSemanticGuardLister{policies: map[string]*gatewayconfig.GuardSemanticGuardPolicy{}}}
	cfgEmpty := &gatewayconfig.GuardConfig{}
	if err := pEmpty.loadSemanticGuardPolicy(context.Background(), cfgEmpty); err != nil {
		t.Fatalf("empty map should succeed: %v", err)
	}
	if cfgEmpty.SemanticGuardPolicy != nil {
		t.Fatalf("empty map must keep SemanticGuardPolicy nil, got %+v", cfgEmpty.SemanticGuardPolicy)
	}

	// 4. 正常加载填充
	pol := &gatewayconfig.GuardSemanticGuardPolicy{
		SchemaVersion:           1,
		ApplicationID:           "app-1",
		Mode:                    "PROTECT",
		Version:                 2,
		SocketPath:              "/var/run/caddy/sidecars/semantic.sock",
		TimeoutMs:               15,
		MaxConcurrency:          32,
		MaxInputRunes:           4096,
		BlockThreshold:          0.85,
		ObserveThreshold:        0.50,
		FailPolicy:              "FAIL_OPEN",
		InspectLLMPrompts:       true,
		InspectMCPContent:       true,
		InspectWebGrayzone:      true,
		CircuitFailureThreshold: 5,
		CircuitOpenSeconds:      30,
	}
	pOK := &Provider{semanticGuard: fakeSemanticGuardLister{policies: map[string]*gatewayconfig.GuardSemanticGuardPolicy{"llm-app": pol}}}
	cfgOK := &gatewayconfig.GuardConfig{}
	if err := pOK.loadSemanticGuardPolicy(context.Background(), cfgOK); err != nil {
		t.Fatalf("loadSemanticGuardPolicy: %v", err)
	}
	if cfgOK.SemanticGuardPolicy["llm-app"] == nil || cfgOK.SemanticGuardPolicy["llm-app"].Version != 2 {
		t.Fatalf("unexpected cfg.SemanticGuardPolicy: %+v", cfgOK.SemanticGuardPolicy)
	}
}

func TestAPIPolicyVersionIncludesSemanticGuardPolicy(t *testing.T) {
	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{})

	cfg1 := &gatewayconfig.GuardConfig{
		SemanticGuardPolicy: map[string]*gatewayconfig.GuardSemanticGuardPolicy{
			"llm-app": {
				SchemaVersion:           1,
				ApplicationID:           "app-1",
				Mode:                    "OBSERVE",
				Version:                 1,
				SocketPath:              "/var/run/caddy/sidecars/semantic.sock",
				TimeoutMs:               15,
				MaxConcurrency:          32,
				MaxInputRunes:           4096,
				BlockThreshold:          0.85,
				ObserveThreshold:        0.50,
				FailPolicy:              "FAIL_OPEN",
				InspectLLMPrompts:       true,
				InspectMCPContent:       true,
				InspectWebGrayzone:      true,
				CircuitFailureThreshold: 5,
				CircuitOpenSeconds:      30,
			},
		},
	}
	v1 := computeAPIPolicyVersion(cfg1)
	if v1 == base {
		t.Fatal("adding semantic_guard_policy must change api_policy_version")
	}

	cfg2 := &gatewayconfig.GuardConfig{
		SemanticGuardPolicy: map[string]*gatewayconfig.GuardSemanticGuardPolicy{
			"llm-app": {
				SchemaVersion:           1,
				ApplicationID:           "app-1",
				Mode:                    "PROTECT",
				Version:                 2,
				SocketPath:              "/var/run/caddy/sidecars/semantic.sock",
				TimeoutMs:               15,
				MaxConcurrency:          32,
				MaxInputRunes:           4096,
				BlockThreshold:          0.85,
				ObserveThreshold:        0.50,
				FailPolicy:              "FAIL_CLOSED",
				InspectLLMPrompts:       true,
				InspectMCPContent:       true,
				InspectWebGrayzone:      true,
				CircuitFailureThreshold: 5,
				CircuitOpenSeconds:      30,
			},
		},
	}
	v2 := computeAPIPolicyVersion(cfg2)
	if v2 == v1 {
		t.Fatal("changing semantic_guard_policy mode/version/fail_policy must change api_policy_version")
	}
	if v1Again := computeAPIPolicyVersion(cfg1); v1Again != v1 {
		t.Fatalf("hash not deterministic: %s vs %s", v1, v1Again)
	}
}
