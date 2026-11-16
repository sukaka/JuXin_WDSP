package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type riskPolicyOverrideTestLister struct {
	items []gatewayconfig.GuardRiskPolicyOverride
	err   error
}

func (l riskPolicyOverrideTestLister) GetGuardRiskPolicy(context.Context) (*gatewayconfig.GuardRiskPolicy, error) {
	return &gatewayconfig.GuardRiskPolicy{Enabled: true, Mode: "OBSERVE", Version: 3}, nil
}

func (l riskPolicyOverrideTestLister) ListGuardRiskPolicyOverrides(context.Context) ([]gatewayconfig.GuardRiskPolicyOverride, error) {
	return l.items, l.err
}

func TestLoadRiskPolicyOverridesOptional(t *testing.T) {
	provider := &Provider{}
	provider.SetRiskPolicyLister(riskPolicyOverrideTestLister{items: []gatewayconfig.GuardRiskPolicyOverride{{
		ApplicationID: "app-1", Policy: gatewayconfig.GuardRiskPolicy{Enabled: true, Mode: "PROTECT", Version: 4},
	}}})
	cfg := &gatewayconfig.GuardConfig{}
	provider.loadRiskPolicy(t.Context(), cfg)
	if cfg.RiskPolicy == nil || cfg.RiskPolicy.Version != 3 {
		t.Fatalf("global policy=%+v", cfg.RiskPolicy)
	}
	if len(cfg.RiskPolicyOverrides) != 1 || cfg.RiskPolicyOverrides[0].ApplicationID != "app-1" || cfg.RiskPolicyOverrides[0].Policy.Version != 4 {
		t.Fatalf("overrides=%+v", cfg.RiskPolicyOverrides)
	}
}

func TestLoadRiskPolicyOverridesFailureKeepsGlobal(t *testing.T) {
	provider := &Provider{}
	provider.SetRiskPolicyLister(riskPolicyOverrideTestLister{err: errors.New("read failed")})
	cfg := &gatewayconfig.GuardConfig{}
	provider.loadRiskPolicy(t.Context(), cfg)
	if cfg.RiskPolicy == nil || cfg.RiskPolicy.Version != 3 {
		t.Fatalf("global policy=%+v", cfg.RiskPolicy)
	}
	if len(cfg.RiskPolicyOverrides) != 0 {
		t.Fatalf("unexpected overrides: %+v", cfg.RiskPolicyOverrides)
	}
}
