package guardconfig

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeEndpointActionLister struct {
	actions map[string]string
	err     error
	calls   int
}

func (f *fakeEndpointActionLister) ListEndpointActions(context.Context) (map[string]string, error) {
	f.calls++
	return f.actions, f.err
}

func TestApplyGatewayRuntimeSettingsActionRate(t *testing.T) {
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
			if err := applyGatewayRuntimeSettings(cfg, map[string]string{"action_rate_per_minute": tc.raw}); err != nil {
				t.Fatalf("apply action rate: %v", err)
			}
			if cfg.ActionRatePerMinute != tc.want {
				t.Fatalf("action rate = %d, want %d", cfg.ActionRatePerMinute, tc.want)
			}
		})
	}
	for _, raw := range []string{"-1", "abc", "1.5", "1e2"} {
		err := applyGatewayRuntimeSettings(&gatewayconfig.GuardConfig{}, map[string]string{"action_rate_per_minute": raw})
		if err == nil || !strings.Contains(err.Error(), "action_rate_per_minute") {
			t.Errorf("invalid action rate %q error = %v", raw, err)
		}
	}
}

func TestLoadAPIEndpointActionsOnlyWhenEnabled(t *testing.T) {
	lister := &fakeEndpointActionLister{actions: map[string]string{"POST /v1/orders": "CREATE"}}
	provider := &Provider{apiEndpointActions: lister}
	cfg := &gatewayconfig.GuardConfig{APIEndpointActions: map[string]string{"old": "OLD"}}
	if err := provider.loadAPIEndpointActions(context.Background(), cfg); err != nil {
		t.Fatalf("disabled load: %v", err)
	}
	if lister.calls != 0 || cfg.APIEndpointActions != nil {
		t.Fatalf("disabled action rate loaded mappings: calls=%d cfg=%+v", lister.calls, cfg)
	}

	cfg.ActionRatePerMinute = 120
	if err := provider.loadAPIEndpointActions(context.Background(), cfg); err != nil {
		t.Fatalf("enabled load: %v", err)
	}
	if lister.calls != 1 || !reflect.DeepEqual(cfg.APIEndpointActions, lister.actions) {
		t.Fatalf("enabled mappings = %+v, calls=%d", cfg.APIEndpointActions, lister.calls)
	}

	provider.apiEndpointActions = nil
	if err := provider.loadAPIEndpointActions(context.Background(), cfg); err == nil {
		t.Fatal("enabled action rate without lister must fail")
	}
}

func TestLoadAPIEndpointActionsFailure(t *testing.T) {
	provider := &Provider{apiEndpointActions: &fakeEndpointActionLister{err: errors.New("db down")}}
	cfg := &gatewayconfig.GuardConfig{ActionRatePerMinute: 60, APIEndpointActions: map[string]string{"old": "OLD"}}
	if err := provider.loadAPIEndpointActions(context.Background(), cfg); err == nil {
		t.Fatal("mapping read failure must abort publish")
	}
	if cfg.APIEndpointActions != nil {
		t.Fatalf("failed read retained stale mappings: %+v", cfg.APIEndpointActions)
	}
}

func TestActionRatePolicyVersion(t *testing.T) {
	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{})
	withRate := &gatewayconfig.GuardConfig{ActionRatePerMinute: 60, APIEndpointActions: map[string]string{"POST /v1/orders": "CREATE"}}
	if got := computeAPIPolicyVersion(withRate); got == base {
		t.Fatal("enabled action rate must change api_policy_version")
	}
	changed := &gatewayconfig.GuardConfig{ActionRatePerMinute: 60, APIEndpointActions: map[string]string{"POST /v1/orders": "UPDATE"}}
	if computeAPIPolicyVersion(changed) == computeAPIPolicyVersion(withRate) {
		t.Fatal("ACTION mapping change must change api_policy_version")
	}
}

func TestReplayRuntimeSecretsActionRateAndMappings(t *testing.T) {
	lister := &fakeEndpointActionLister{actions: map[string]string{"POST /v1/orders": "CREATE"}}
	provider := &Provider{
		runtimeSettingsLoader: func(context.Context) (map[string]string, error) {
			return map[string]string{"action_rate_per_minute": "90"}, nil
		},
		apiEndpointActions: lister,
	}
	cfg := &gatewayconfig.GuardConfig{ActionRatePerMinute: 30, APIEndpointActions: map[string]string{"old": "OLD"}}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay current action rate: %v", err)
	}
	if cfg.ActionRatePerMinute != 90 || !reflect.DeepEqual(cfg.APIEndpointActions, lister.actions) || lister.calls != 1 {
		t.Fatalf("replayed action config = %+v, calls=%d", cfg, lister.calls)
	}

	provider.runtimeSettingsLoader = func(context.Context) (map[string]string, error) {
		return map[string]string{"action_rate_per_minute": "0"}, nil
	}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay disabled action rate: %v", err)
	}
	if cfg.ActionRatePerMinute != 0 || cfg.APIEndpointActions != nil || lister.calls != 1 {
		t.Fatalf("disabled replay loaded or retained mappings: %+v, calls=%d", cfg, lister.calls)
	}

	provider.runtimeSettingsLoader = func(context.Context) (map[string]string, error) {
		return map[string]string{"action_rate_per_minute": "60"}, nil
	}
	provider.apiEndpointActions = &fakeEndpointActionLister{err: errors.New("db down")}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err == nil {
		t.Fatal("mapping read failure must abort rollback replay")
	}
}
