package guardconfig

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestApplyGatewayRuntimeSettingsResponseSampleRatio(t *testing.T) {
	valid := []struct {
		name string
		raw  string
		want float64
	}{
		{name: "全量", raw: "1", want: 1},
		{name: "显式零", raw: "0", want: 0},
		{name: "小数", raw: "0.25", want: 0.25},
		{name: "两侧空白", raw: " 0.5 ", want: 0.5},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &gatewayconfig.GuardConfig{}
			if err := applyGatewayRuntimeSettings(cfg, map[string]string{"api_response_sample_ratio": tc.raw}); err != nil {
				t.Fatalf("apply ratio %q: %v", tc.raw, err)
			}
			if cfg.APIResponseSampleRatio == nil || *cfg.APIResponseSampleRatio != tc.want {
				t.Fatalf("ratio = %v, want %v", cfg.APIResponseSampleRatio, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name string
		kv   map[string]string
	}{
		{name: "键缺失", kv: map[string]string{}},
		{name: "空串", kv: map[string]string{"api_response_sample_ratio": ""}},
		{name: "全空白", kv: map[string]string{"api_response_sample_ratio": " \t "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &gatewayconfig.GuardConfig{}
			if err := applyGatewayRuntimeSettings(cfg, tc.kv); err != nil {
				t.Fatalf("blank ratio must use gateway default: %v", err)
			}
			if cfg.APIResponseSampleRatio != nil {
				t.Fatalf("blank ratio = %v, want nil", *cfg.APIResponseSampleRatio)
			}
		})
	}

	for _, raw := range []string{"abc", "-0.01", "1.01", "NaN", "nan", "Inf", "+Inf", "-Inf", "Infinity", "1e309"} {
		t.Run("拒绝_"+raw, func(t *testing.T) {
			cfg := &gatewayconfig.GuardConfig{}
			err := applyGatewayRuntimeSettings(cfg, map[string]string{"api_response_sample_ratio": raw})
			if err == nil {
				t.Fatalf("invalid ratio %q must fail", raw)
			}
			if !strings.Contains(err.Error(), "api_response_sample_ratio") {
				t.Fatalf("error %q must identify the setting", err)
			}
			if cfg.APIResponseSampleRatio != nil {
				t.Fatalf("invalid ratio must not be written: %v", *cfg.APIResponseSampleRatio)
			}
		})
	}
}

func TestResponseSampleRatioPolicyVersionAndSnapshot(t *testing.T) {
	baseVersion := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{})
	zero := 0.0
	zeroCfg := &gatewayconfig.GuardConfig{APIResponseSampleRatio: &zero}
	zeroVersion := computeAPIPolicyVersion(zeroCfg)
	if zeroVersion == baseVersion {
		t.Fatal("explicit zero must change api_policy_version")
	}
	if again := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIResponseSampleRatio: &zero}); again != zeroVersion {
		t.Fatal("same ratio must produce a stable api_policy_version")
	}
	one := 1.0
	if computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIResponseSampleRatio: &one}) == zeroVersion {
		t.Fatal("ratio content change must change api_policy_version")
	}

	raw, err := json.Marshal(RedactGuardConfig(zeroCfg))
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if !strings.Contains(string(raw), `"api_response_sample_ratio":0`) {
		t.Fatalf("snapshot lost explicit zero: %s", raw)
	}
	decoded, err := decodeGuardConfigSnapshot(raw)
	if err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if decoded.APIResponseSampleRatio == nil || *decoded.APIResponseSampleRatio != 0 {
		t.Fatalf("snapshot round-trip ratio = %v, want explicit zero", decoded.APIResponseSampleRatio)
	}

	legacy, err := decodeGuardConfigSnapshot([]byte(`{}`))
	if err != nil {
		t.Fatalf("decode legacy snapshot: %v", err)
	}
	if legacy.APIResponseSampleRatio != nil {
		t.Fatal("legacy snapshot without the key must leave the gateway default in effect")
	}
}

func TestReplayRuntimeSecretsResponseSampleRatioZero(t *testing.T) {
	provider := &Provider{runtimeSettingsLoader: func(context.Context) (map[string]string, error) {
		return map[string]string{"api_response_sample_ratio": "0"}, nil
	}}
	one := 1.0
	cfg := &gatewayconfig.GuardConfig{APIResponseSampleRatio: &one}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay current zero: %v", err)
	}
	if cfg.APIResponseSampleRatio == nil || *cfg.APIResponseSampleRatio != 0 {
		t.Fatalf("replayed ratio = %v, want explicit zero", cfg.APIResponseSampleRatio)
	}

	provider.runtimeSettingsLoader = func(context.Context) (map[string]string, error) {
		return map[string]string{}, nil
	}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay deleted setting: %v", err)
	}
	if cfg.APIResponseSampleRatio != nil {
		t.Fatalf("deleted setting must clear stale snapshot ratio: %v", *cfg.APIResponseSampleRatio)
	}
}
