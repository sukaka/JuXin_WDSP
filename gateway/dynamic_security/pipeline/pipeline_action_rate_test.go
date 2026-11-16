package pipeline

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func actionRatePipelineConfig(mode, app string) Config {
	return Config{
		Enabled:             true,
		Mode:                decision.Mode(mode),
		ApplicationID:       app,
		ActionRatePerMinute: 1,
		APIEndpointActions:  map[string]string{"GET /v1/orders/{id}": "read_detail"},
	}
}

func actionRatePipelineRequest(t *testing.T) *http.Request {
	t.Helper()
	return asmBearerReq(t, http.MethodGet, "http://h/v1/orders/42", "", "")
}

func TestProcessActionRateMountedAndDecisionModes(t *testing.T) {
	for _, mode := range []string{"OBSERVE", "PROTECT"} {
		t.Run(mode, func(t *testing.T) {
			cfg := actionRatePipelineConfig(mode, "pipeline-action-"+mode)
			first := asmProcess(t, actionRatePipelineRequest(t), cfg)
			if hasRule(first, "ratelimit.action_rate") {
				t.Fatalf("first request must not match: %+v", first.Context.CopyMatches())
			}
			second := asmProcess(t, actionRatePipelineRequest(t), cfg)
			if !hasRule(second, "ratelimit.action_rate") {
				t.Fatalf("second request must produce action rate: %+v", second.Context.CopyMatches())
			}
			wantAction := "OBSERVE"
			if mode == "PROTECT" {
				wantAction = "RATE_LIMIT"
			}
			if string(second.FinalAction) != wantAction {
				t.Fatalf("final action=%s want=%s", second.FinalAction, wantAction)
			}
			for _, match := range second.Context.CopyMatches() {
				if match.RuleID != "ratelimit.action_rate" {
					continue
				}
				wantEvidence := map[string]string{"action": "READ_DETAIL", "window_count": "2", "limit": "1", "window": "1m"}
				if !reflect.DeepEqual(match.Evidence, wantEvidence) {
					t.Fatalf("action evidence boundary: got %+v want %+v", match.Evidence, wantEvidence)
				}
			}
		})
	}
}

func TestProcessActionRateSkipsUnclassifiedMissingAppAndDisabled(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{name: "no table", cfg: Config{Enabled: true, Mode: "PROTECT", ApplicationID: "app-no-table", ActionRatePerMinute: 1}},
		{name: "different endpoint", cfg: Config{Enabled: true, Mode: "PROTECT", ApplicationID: "app-other-endpoint", ActionRatePerMinute: 1, APIEndpointActions: map[string]string{"POST /v1/other": "DELETE"}}},
		{name: "missing app", cfg: actionRatePipelineConfig("PROTECT", "")},
		{name: "zero disabled", cfg: func() Config {
			cfg := actionRatePipelineConfig("PROTECT", "app-action-disabled")
			cfg.ActionRatePerMinute = 0
			return cfg
		}()},
		{name: "negative disabled at engine boundary", cfg: func() Config {
			cfg := actionRatePipelineConfig("PROTECT", "app-action-negative")
			cfg.ActionRatePerMinute = -1
			return cfg
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for hit := 0; hit < 2; hit++ {
				res := asmProcess(t, actionRatePipelineRequest(t), tc.cfg)
				if hasRule(res, "ratelimit.action_rate") || res.FinalAction == "RATE_LIMIT" {
					t.Fatalf("unclassified, missing app or disabled config must skip: %+v", res.Context.CopyMatches())
				}
			}
		})
	}
}

func TestProcessActionRateStoreBindingAndReloadIsolation(t *testing.T) {
	const app = "pipeline-action-store-reload"
	first := &captureWindowStore{}
	second := &captureWindowStore{}
	process := func(stores *detectors.StoreOverrides) {
		t.Helper()
		cfg := actionRatePipelineConfig("OBSERVE", app)
		cfg.Stores = stores
		if _, err := Process(actionRatePipelineRequest(t), cfg, nil); err != nil {
			t.Fatal(err)
		}
	}
	process(&detectors.StoreOverrides{ActionRateWindow: first})
	wantKey := app + "|READ_DETAIL"
	if len(first.calls) != 1 || first.calls[0] != wantKey || len(second.calls) != 0 {
		t.Fatalf("first action binding=%v second=%v, want %q only on first", first.calls, second.calls, wantKey)
	}
	process(&detectors.StoreOverrides{ActionRateWindow: second})
	if len(first.calls) != 1 || len(second.calls) != 1 || second.calls[0] != wantKey {
		t.Fatalf("reloaded action binding was not isolated: first=%v second=%v", first.calls, second.calls)
	}
	process(&detectors.StoreOverrides{})
	process(nil)
	if len(first.calls) != 1 || len(second.calls) != 1 {
		t.Fatalf("nil or unbound action store reused stale override: first=%v second=%v", first.calls, second.calls)
	}
}
