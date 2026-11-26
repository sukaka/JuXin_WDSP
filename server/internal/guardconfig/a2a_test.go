package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeA2ALister struct {
	policies map[string]*gatewayconfig.GuardA2APolicy
	err      error
}

func (f fakeA2ALister) ListForGuard(context.Context) (map[string]*gatewayconfig.GuardA2APolicy, error) {
	return f.policies, f.err
}

func TestLoadA2APolicyAndFailHard(t *testing.T) {
	// 1. nil lister -> no-op
	cfg := &gatewayconfig.GuardConfig{}
	if err := (&Provider{}).loadA2APolicy(context.Background(), cfg); err != nil {
		t.Fatalf("nil lister should succeed: %v", err)
	}
	if cfg.APIA2APolicy != nil {
		t.Fatalf("expected nil APIA2APolicy, got %+v", cfg.APIA2APolicy)
	}

	// 2. lister 失败中止发布（fail-hard）
	pErr := &Provider{a2a: fakeA2ALister{err: errors.New("db down")}}
	if err := pErr.loadA2APolicy(context.Background(), &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("lister error must fail-hard")
	}

	// 3. 空策略列表不下发段
	pEmpty := &Provider{a2a: fakeA2ALister{policies: map[string]*gatewayconfig.GuardA2APolicy{}}}
	cfgEmpty := &gatewayconfig.GuardConfig{}
	if err := pEmpty.loadA2APolicy(context.Background(), cfgEmpty); err != nil {
		t.Fatalf("empty map should succeed: %v", err)
	}
	if cfgEmpty.APIA2APolicy != nil {
		t.Fatalf("empty map must keep APIA2APolicy nil, got %+v", cfgEmpty.APIA2APolicy)
	}

	// 4. 正常加载填充
	pol := &gatewayconfig.GuardA2APolicy{
		SchemaVersion:            1,
		ApplicationID:            "app-1",
		Mode:                     "PROTECT",
		Version:                  2,
		CardDiscoveryEnabled:     true,
		A2APathPrefixes:          []string{"/a2a", "/.well-known/agent.json"},
		AllowedCallerAgents:      []string{"planner-agent"},
		MaxDelegationDepth:       3,
		EnforceScopeAttenuation:  true,
		LoopWindowSeconds:        60,
		MaxCallsPerTaskWindow:    20,
		LethalTrifectaEnabled:    true,
		ConfidentialReadPatterns: []string{"/api/v1/secrets"},
		ExternalEgressPatterns:   []string{"send_email"},
	}
	pOK := &Provider{a2a: fakeA2ALister{policies: map[string]*gatewayconfig.GuardA2APolicy{"agent-app": pol}}}
	cfgOK := &gatewayconfig.GuardConfig{}
	if err := pOK.loadA2APolicy(context.Background(), cfgOK); err != nil {
		t.Fatalf("loadA2APolicy: %v", err)
	}
	if cfgOK.APIA2APolicy["agent-app"] == nil || cfgOK.APIA2APolicy["agent-app"].Version != 2 {
		t.Fatalf("unexpected cfg.APIA2APolicy: %+v", cfgOK.APIA2APolicy)
	}
}

func TestAPIPolicyVersionIncludesA2APolicy(t *testing.T) {
	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{})

	cfg1 := &gatewayconfig.GuardConfig{
		APIA2APolicy: map[string]*gatewayconfig.GuardA2APolicy{
			"agent-app": {
				SchemaVersion:         1,
				ApplicationID:         "app-1",
				Mode:                  "OBSERVE",
				Version:               1,
				CardDiscoveryEnabled:  true,
				A2APathPrefixes:       []string{"/a2a"},
				MaxDelegationDepth:    3,
				LoopWindowSeconds:     60,
				MaxCallsPerTaskWindow: 20,
			},
		},
	}
	v1 := computeAPIPolicyVersion(cfg1)
	if v1 == base {
		t.Fatal("adding api_a2a_policy must change api_policy_version")
	}

	cfg2 := &gatewayconfig.GuardConfig{
		APIA2APolicy: map[string]*gatewayconfig.GuardA2APolicy{
			"agent-app": {
				SchemaVersion:         1,
				ApplicationID:         "app-1",
				Mode:                  "PROTECT",
				Version:               2,
				CardDiscoveryEnabled:  true,
				A2APathPrefixes:       []string{"/a2a"},
				MaxDelegationDepth:    3,
				LoopWindowSeconds:     60,
				MaxCallsPerTaskWindow: 20,
			},
		},
	}
	v2 := computeAPIPolicyVersion(cfg2)
	if v2 == v1 {
		t.Fatal("changing api_a2a_policy mode/version must change api_policy_version")
	}
	if v1Again := computeAPIPolicyVersion(cfg1); v1Again != v1 {
		t.Fatalf("hash not deterministic: %s vs %s", v1, v1Again)
	}
}
