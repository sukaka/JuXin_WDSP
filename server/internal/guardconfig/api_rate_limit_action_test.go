package guardconfig

import (
	"context"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestApplyGatewayRuntimeSettingsAPIRateLimitAction(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{raw: "RATE_LIMIT", want: "RATE_LIMIT"},
		{raw: "BLOCK", want: "BLOCK"},
		{raw: "TEMP_BLOCK", want: "TEMP_BLOCK"},
		{raw: " temp_block ", want: "TEMP_BLOCK"},
	} {
		cfg := &gatewayconfig.GuardConfig{}
		if err := applyGatewayRuntimeSettings(cfg, map[string]string{"api_rate_limit_action": tc.raw}); err != nil {
			t.Fatalf("apply action %q: %v", tc.raw, err)
		}
		if cfg.APIRateLimitAction != tc.want {
			t.Fatalf("action = %q, want %q", cfg.APIRateLimitAction, tc.want)
		}
	}

	for _, tc := range []struct {
		raw  string
		want int
	}{
		{raw: "1", want: 1},
		{raw: "60", want: 60},
		{raw: "86400", want: 86400},
		{raw: " 60 ", want: 60},
	} {
		cfg := &gatewayconfig.GuardConfig{}
		if err := applyGatewayRuntimeSettings(cfg, map[string]string{"api_temp_block_seconds": tc.raw}); err != nil {
			t.Fatalf("apply seconds %q: %v", tc.raw, err)
		}
		if cfg.APITempBlockSeconds != tc.want {
			t.Fatalf("seconds = %d, want %d", cfg.APITempBlockSeconds, tc.want)
		}
	}

	cfg := &gatewayconfig.GuardConfig{}
	if err := applyGatewayRuntimeSettings(cfg, map[string]string{"api_rate_limit_action": "", "api_temp_block_seconds": "  "}); err != nil {
		t.Fatalf("empty values: %v", err)
	}
	if cfg.APIRateLimitAction != "" || cfg.APITempBlockSeconds != 0 {
		t.Fatalf("empty values must preserve gateway defaults: %+v", cfg)
	}

	for _, kv := range []map[string]string{
		{"api_rate_limit_action": "REJECT"},
		{"api_temp_block_seconds": "0"},
		{"api_temp_block_seconds": "86401"},
		{"api_temp_block_seconds": "-1"},
		{"api_temp_block_seconds": "abc"},
		{"api_temp_block_seconds": "1.5"},
	} {
		if err := applyGatewayRuntimeSettings(&gatewayconfig.GuardConfig{}, kv); err == nil {
			t.Errorf("invalid settings must fail: %v", kv)
		}
	}
}

func TestAPIRateLimitActionPolicyVersion(t *testing.T) {
	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{})
	defaultCfg := &gatewayconfig.GuardConfig{APIRateLimitAction: "RATE_LIMIT", APITempBlockSeconds: 60}
	defaultVersion := computeAPIPolicyVersion(defaultCfg)
	if defaultVersion == base {
		t.Fatal("explicit gateway-default action and seconds must be part of api_policy_version")
	}
	if got := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIRateLimitAction: "BLOCK", APITempBlockSeconds: 60}); got == defaultVersion {
		t.Fatal("action change must change api_policy_version")
	}
	if got := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIRateLimitAction: "RATE_LIMIT", APITempBlockSeconds: 61}); got == defaultVersion {
		t.Fatal("seconds change must change api_policy_version")
	}
}

func TestReplayRuntimeSecretsAPIRateLimitAction(t *testing.T) {
	provider := &Provider{runtimeSettingsLoader: func(context.Context) (map[string]string, error) {
		return map[string]string{"api_rate_limit_action": "TEMP_BLOCK", "api_temp_block_seconds": "120"}, nil
	}}
	cfg := &gatewayconfig.GuardConfig{APIRateLimitAction: "BLOCK", APITempBlockSeconds: 30}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay current action settings: %v", err)
	}
	if cfg.APIRateLimitAction != "TEMP_BLOCK" || cfg.APITempBlockSeconds != 120 {
		t.Fatalf("replayed action settings = %+v", cfg)
	}

	provider.runtimeSettingsLoader = func(context.Context) (map[string]string, error) {
		return map[string]string{}, nil
	}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay empty action settings: %v", err)
	}
	if cfg.APIRateLimitAction != "" || cfg.APITempBlockSeconds != 0 {
		t.Fatalf("empty current settings left old values: %+v", cfg)
	}

	for _, kv := range []map[string]string{
		{"api_rate_limit_action": "INVALID"},
		{"api_temp_block_seconds": "0"},
		{"api_temp_block_seconds": "abc"},
	} {
		provider.runtimeSettingsLoader = func(context.Context) (map[string]string, error) { return kv, nil }
		if err := provider.replayRuntimeSecrets(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "gateway_runtime") {
			t.Errorf("invalid current settings must abort replay: %v, error=%v", kv, err)
		}
	}
}
