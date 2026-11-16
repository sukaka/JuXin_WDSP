package guardconfig

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeEndpointGroupLister struct {
	groups map[string]map[string][]string
	err    error
	calls  int
}

func (f *fakeEndpointGroupLister) ListEndpointGroups(context.Context) (map[string]map[string][]string, error) {
	f.calls++
	return f.groups, f.err
}

func TestApplyGatewayRuntimeSettingsGroupRate(t *testing.T) {
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
			if err := applyGatewayRuntimeSettings(cfg, map[string]string{"group_rate_per_minute": tc.raw}); err != nil {
				t.Fatalf("apply group rate: %v", err)
			}
			if cfg.GroupRatePerMinute != tc.want {
				t.Fatalf("group rate = %d, want %d", cfg.GroupRatePerMinute, tc.want)
			}
		})
	}
	for _, raw := range []string{"-1", "abc", "1.5", "1e2"} {
		err := applyGatewayRuntimeSettings(&gatewayconfig.GuardConfig{}, map[string]string{"group_rate_per_minute": raw})
		if err == nil || !strings.Contains(err.Error(), "group_rate_per_minute") {
			t.Errorf("invalid group rate %q error = %v", raw, err)
		}
	}
}

func TestLoadAPIEndpointGroupsOnlyWhenEnabled(t *testing.T) {
	lister := &fakeEndpointGroupLister{groups: map[string]map[string][]string{
		"app-1": {"POST /v1/orders": {"GROUP_A", "GROUP_B"}},
	}}
	provider := &Provider{apiEndpointGroups: lister}
	cfg := &gatewayconfig.GuardConfig{APIEndpointGroups: map[string]map[string][]string{"old": {"old": {"OLD"}}}}
	if err := provider.loadAPIEndpointGroups(context.Background(), cfg); err != nil {
		t.Fatalf("disabled load: %v", err)
	}
	if lister.calls != 0 || cfg.APIEndpointGroups != nil {
		t.Fatalf("disabled group rate loaded mappings: calls=%d cfg=%+v", lister.calls, cfg)
	}

	cfg.GroupRatePerMinute = 120
	if err := provider.loadAPIEndpointGroups(context.Background(), cfg); err != nil {
		t.Fatalf("enabled load: %v", err)
	}
	if lister.calls != 1 || !reflect.DeepEqual(cfg.APIEndpointGroups, lister.groups) {
		t.Fatalf("enabled mappings = %+v, calls=%d", cfg.APIEndpointGroups, lister.calls)
	}

	provider.apiEndpointGroups = nil
	if err := provider.loadAPIEndpointGroups(context.Background(), cfg); err == nil {
		t.Fatal("enabled group rate without lister must fail")
	}
}

func TestLoadAPIEndpointGroupsFailure(t *testing.T) {
	provider := &Provider{apiEndpointGroups: &fakeEndpointGroupLister{err: errors.New("db down")}}
	cfg := &gatewayconfig.GuardConfig{GroupRatePerMinute: 60, APIEndpointGroups: map[string]map[string][]string{"old": {"old": {"OLD"}}}}
	if err := provider.loadAPIEndpointGroups(context.Background(), cfg); err == nil {
		t.Fatal("mapping read failure must abort publish")
	}
	if cfg.APIEndpointGroups != nil {
		t.Fatalf("failed read retained stale mappings: %+v", cfg.APIEndpointGroups)
	}
}

func TestGroupRatePolicyVersion(t *testing.T) {
	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{})
	withRate := &gatewayconfig.GuardConfig{GroupRatePerMinute: 60, APIEndpointGroups: map[string]map[string][]string{
		"app-1": {"POST /v1/orders": {"GROUP_A"}},
	}}
	if got := computeAPIPolicyVersion(withRate); got == base {
		t.Fatal("enabled group rate must change api_policy_version")
	}
	changed := &gatewayconfig.GuardConfig{GroupRatePerMinute: 60, APIEndpointGroups: map[string]map[string][]string{
		"app-1": {"POST /v1/orders": {"GROUP_B"}},
	}}
	if computeAPIPolicyVersion(changed) == computeAPIPolicyVersion(withRate) {
		t.Fatal("group mapping change must change api_policy_version")
	}
}

func TestReplayRuntimeSecretsGroupRateAndMappings(t *testing.T) {
	lister := &fakeEndpointGroupLister{groups: map[string]map[string][]string{
		"app-1": {"POST /v1/orders": {"GROUP_A"}},
	}}
	provider := &Provider{
		runtimeSettingsLoader: func(context.Context) (map[string]string, error) {
			return map[string]string{"group_rate_per_minute": "90"}, nil
		},
		apiEndpointGroups: lister,
	}
	cfg := &gatewayconfig.GuardConfig{GroupRatePerMinute: 30, APIEndpointGroups: map[string]map[string][]string{"old": {"old": {"OLD"}}}}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay current group rate: %v", err)
	}
	if cfg.GroupRatePerMinute != 90 || !reflect.DeepEqual(cfg.APIEndpointGroups, lister.groups) || lister.calls != 1 {
		t.Fatalf("replayed group config = %+v, calls=%d", cfg, lister.calls)
	}

	provider.runtimeSettingsLoader = func(context.Context) (map[string]string, error) {
		return map[string]string{"group_rate_per_minute": "0"}, nil
	}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay disabled group rate: %v", err)
	}
	if cfg.GroupRatePerMinute != 0 || cfg.APIEndpointGroups != nil || lister.calls != 1 {
		t.Fatalf("disabled replay loaded or retained mappings: %+v, calls=%d", cfg, lister.calls)
	}

	provider.runtimeSettingsLoader = func(context.Context) (map[string]string, error) {
		return map[string]string{"group_rate_per_minute": "60"}, nil
	}
	provider.apiEndpointGroups = &fakeEndpointGroupLister{err: errors.New("db down")}
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err == nil {
		t.Fatal("mapping read failure must abort rollback replay")
	}
}
