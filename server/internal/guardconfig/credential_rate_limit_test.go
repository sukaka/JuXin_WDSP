package guardconfig

import (
	"context"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestApplyGatewayRuntimeSettingsCredentialRate(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want int
	}{
		{name: "空串", raw: "", want: 0},
		{name: "空白", raw: " \t ", want: 0},
		{name: "零", raw: "0", want: 0},
		{name: "正数", raw: "120", want: 120},
		{name: "带空白正数", raw: " 60 ", want: 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &gatewayconfig.GuardConfig{}
			if err := applyGatewayRuntimeSettings(cfg, map[string]string{"credential_rate_per_minute": tc.raw}); err != nil {
				t.Fatalf("apply credential rate: %v", err)
			}
			if cfg.CredentialRatePerMinute != tc.want {
				t.Fatalf("credential rate = %d, want %d", cfg.CredentialRatePerMinute, tc.want)
			}
		})
	}

	for _, raw := range []string{"-1", "abc", "1.5", "1e2"} {
		err := applyGatewayRuntimeSettings(&gatewayconfig.GuardConfig{}, map[string]string{"credential_rate_per_minute": raw})
		if err == nil || !strings.Contains(err.Error(), "credential_rate_per_minute") {
			t.Errorf("invalid credential rate %q error = %v", raw, err)
		}
	}
}

func TestCredentialRatePolicyVersion(t *testing.T) {
	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{})
	if got := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{CredentialRatePerMinute: 60}); got == base {
		t.Fatal("positive credential rate must change api_policy_version")
	}
	if got := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{}); got != base {
		t.Fatal("zero credential rate must preserve the baseline api_policy_version")
	}
}

func TestReplayRuntimeSecretsCredentialRate(t *testing.T) {
	provider := &Provider{runtimeSettingsLoader: func(context.Context) (map[string]string, error) {
		return map[string]string{"credential_rate_per_minute": "90"}, nil
	}}
	cfg := &gatewayconfig.GuardConfig{CredentialRatePerMinute: 30}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay current credential rate: %v", err)
	}
	if cfg.CredentialRatePerMinute != 90 {
		t.Fatalf("replayed credential rate = %d, want current value 90", cfg.CredentialRatePerMinute)
	}

	provider.runtimeSettingsLoader = func(context.Context) (map[string]string, error) {
		return map[string]string{}, nil
	}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay deleted credential rate: %v", err)
	}
	if cfg.CredentialRatePerMinute != 0 {
		t.Fatalf("deleted credential rate remains %d", cfg.CredentialRatePerMinute)
	}

	provider.runtimeSettingsLoader = func(context.Context) (map[string]string, error) {
		return map[string]string{"credential_rate_per_minute": "-1"}, nil
	}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err == nil {
		t.Fatal("invalid current credential rate must abort rollback replay")
	}
}
