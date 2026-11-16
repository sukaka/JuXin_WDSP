package pipeline

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func groupRatePipelineConfig(mode, app string) Config {
	return Config{
		Enabled:            true,
		Mode:               decision.Mode(mode),
		ApplicationID:      app,
		GroupRatePerMinute: 1,
		APIEndpointGroups: map[string]map[string][]string{
			app: {"GET /v1/orders/{id}": {"order_query", "audit_query"}},
		},
	}
}

func groupRatePipelineRequest(t *testing.T) *http.Request {
	t.Helper()
	return asmBearerReq(t, http.MethodGet, "http://h/v1/orders/42", "", "")
}

func TestProcessGroupRateMultiGroupAndDecisionModes(t *testing.T) {
	for _, mode := range []string{"OBSERVE", "PROTECT"} {
		t.Run(mode, func(t *testing.T) {
			cfg := groupRatePipelineConfig(mode, "pipeline-group-"+mode)
			first := asmProcess(t, groupRatePipelineRequest(t), cfg)
			if hasRule(first, "ratelimit.group_rate") {
				t.Fatalf("first request must not match: %+v", first.Context.CopyMatches())
			}
			second := asmProcess(t, groupRatePipelineRequest(t), cfg)
			wantAction := "OBSERVE"
			if mode == "PROTECT" {
				wantAction = "RATE_LIMIT"
			}
			if string(second.FinalAction) != wantAction {
				t.Fatalf("final action=%s want=%s", second.FinalAction, wantAction)
			}
			seen := map[string]bool{}
			for _, match := range second.Context.CopyMatches() {
				if match.RuleID != "ratelimit.group_rate" {
					continue
				}
				group := match.Evidence["group_code"]
				wantEvidence := map[string]string{"group_code": group, "window_count": "2", "limit": "1", "window": "1m"}
				if !reflect.DeepEqual(match.Evidence, wantEvidence) {
					t.Fatalf("group evidence boundary: got %+v want %+v", match.Evidence, wantEvidence)
				}
				seen[group] = true
			}
			if !seen["ORDER_QUERY"] || !seen["AUDIT_QUERY"] || len(seen) != 2 {
				t.Fatalf("each classified group must be counted independently: %+v", second.Context.CopyMatches())
			}
		})
	}
}

func TestProcessGroupRateApplicationAndEndpointIsolation(t *testing.T) {
	store := &captureWindowStore{}
	groups := map[string]map[string][]string{
		"app-a": {
			"GET /v1/orders/{id}": {"group_a"},
			"GET /v1/other":       {"group_c"},
		},
		"app-b": {"GET /v1/orders/{id}": {"group_b"}},
	}
	for _, tc := range []struct {
		app     string
		wantKey string
	}{
		{app: "app-a", wantKey: "app-a|GROUP_A"},
		{app: "app-b", wantKey: "app-b|GROUP_B"},
	} {
		cfg := groupRatePipelineConfig("OBSERVE", tc.app)
		cfg.APIEndpointGroups = groups
		cfg.Stores = &detectors.StoreOverrides{GroupRateWindow: store}
		res := asmProcess(t, groupRatePipelineRequest(t), cfg)
		if hasRule(res, "ratelimit.group_rate") {
			t.Fatalf("first hit for %s must not exceed: %+v", tc.app, res.Context.CopyMatches())
		}
		if len(store.calls) != 1 || store.calls[0] != tc.wantKey {
			t.Fatalf("nested lookup must select only current app/endpoint: calls=%v want=%q", store.calls, tc.wantKey)
		}
		store.calls = nil
	}
}

func TestProcessGroupRateSkipsUngroupedMissingAppAndDisabled(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{name: "no table", cfg: Config{Enabled: true, Mode: "PROTECT", ApplicationID: "app-no-groups", GroupRatePerMinute: 1}},
		{name: "different endpoint", cfg: Config{Enabled: true, Mode: "PROTECT", ApplicationID: "app-other-group-endpoint", GroupRatePerMinute: 1, APIEndpointGroups: map[string]map[string][]string{"app-other-group-endpoint": {"POST /v1/other": {"GROUP_A"}}}}},
		{name: "different application", cfg: Config{Enabled: true, Mode: "PROTECT", ApplicationID: "app-current", GroupRatePerMinute: 1, APIEndpointGroups: map[string]map[string][]string{"app-other": {"GET /v1/orders/{id}": {"GROUP_A"}}}}},
		{name: "missing app", cfg: groupRatePipelineConfig("PROTECT", "")},
		{name: "zero disabled", cfg: func() Config {
			cfg := groupRatePipelineConfig("PROTECT", "app-group-disabled")
			cfg.GroupRatePerMinute = 0
			return cfg
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for hit := 0; hit < 2; hit++ {
				res := asmProcess(t, groupRatePipelineRequest(t), tc.cfg)
				if hasRule(res, "ratelimit.group_rate") || res.FinalAction == "RATE_LIMIT" {
					t.Fatalf("ungrouped, missing app or disabled config must skip: %+v", res.Context.CopyMatches())
				}
			}
		})
	}
}

func TestProcessGroupRateStoreBindingAndReloadIsolation(t *testing.T) {
	const app = "pipeline-group-store-reload"
	first := &captureWindowStore{}
	second := &captureWindowStore{}
	process := func(stores *detectors.StoreOverrides) {
		t.Helper()
		cfg := groupRatePipelineConfig("OBSERVE", app)
		cfg.APIEndpointGroups = map[string]map[string][]string{app: {"GET /v1/orders/{id}": {"order_query"}}}
		cfg.Stores = stores
		if _, err := Process(groupRatePipelineRequest(t), cfg, nil); err != nil {
			t.Fatal(err)
		}
	}
	process(&detectors.StoreOverrides{GroupRateWindow: first})
	wantKey := app + "|ORDER_QUERY"
	if len(first.calls) != 1 || first.calls[0] != wantKey || len(second.calls) != 0 {
		t.Fatalf("first group binding=%v second=%v, want %q only on first", first.calls, second.calls, wantKey)
	}
	process(&detectors.StoreOverrides{GroupRateWindow: second})
	if len(first.calls) != 1 || len(second.calls) != 1 || second.calls[0] != wantKey {
		t.Fatalf("reloaded group binding was not isolated: first=%v second=%v", first.calls, second.calls)
	}
	process(&detectors.StoreOverrides{})
	process(nil)
	if len(first.calls) != 1 || len(second.calls) != 1 {
		t.Fatalf("nil or unbound group store reused stale override: first=%v second=%v", first.calls, second.calls)
	}
}
