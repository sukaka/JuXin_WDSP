package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
)

func TestGuardConfigActionRateJSON(t *testing.T) {
	var g Guard
	if err := json.Unmarshal([]byte(`{
		"app_id":"app-1",
		"events_log":"/tmp/events.log",
		"api_dynamic_protection":true,
		"action_rate_per_minute":2,
		"api_endpoint_actions":{"GET /v1/orders/{id}":"read_detail"}
	}`), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if g.ActionRatePerMinute != 2 || g.APIEndpointActions["GET /v1/orders/{id}"] != "read_detail" {
		t.Fatalf("action config not decoded: rate=%d actions=%v", g.ActionRatePerMinute, g.APIEndpointActions)
	}
	var legacy Guard
	if err := json.Unmarshal([]byte(`{"app_id":"app-1","events_log":"/tmp/events.log"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.ActionRatePerMinute != 0 || legacy.APIEndpointActions != nil {
		t.Fatalf("legacy action config must stay disabled: %+v", legacy.ActionRatePerMinute)
	}
	for _, value := range []string{`"not-a-number"`, `"1"`, `1.5`} {
		var invalid Guard
		if err := json.Unmarshal([]byte(`{"events_log":"/tmp/events.log","action_rate_per_minute":`+value+`}`), &invalid); err == nil {
			t.Fatalf("non-integer action_rate_per_minute %s must be rejected", value)
		}
	}
	var invalidAction Guard
	if err := json.Unmarshal([]byte(`{"events_log":"/tmp/events.log","api_endpoint_actions":{"GET /v1/orders":1}}`), &invalidAction); err == nil {
		t.Fatal("non-string endpoint action must be rejected")
	}
}

func TestGuardRejectsInvalidActionRateConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rate   int
		action map[string]string
		field  string
	}{
		{name: "negative rate", rate: -1, field: "action_rate_per_minute"},
		{name: "blank action", rate: 1, action: map[string]string{"GET /v1/orders": " \t"}, field: "api_endpoint_actions"},
		{name: "leading digit", rate: 1, action: map[string]string{"GET /v1/orders": "1READ_DETAIL"}, field: "api_endpoint_actions"},
		{name: "invalid character", rate: 1, action: map[string]string{"GET /v1/orders": "READ-DETAIL"}, field: "api_endpoint_actions"},
		{name: "non ASCII", rate: 1, action: map[string]string{"GET /v1/orders": "READ_订单"}, field: "api_endpoint_actions"},
		{name: "too long", rate: 1, action: map[string]string{"GET /v1/orders": strings.Repeat("A", maxAPIEndpointActionBytes+1)}, field: "api_endpoint_actions"},
		{name: "blank endpoint", rate: 1, action: map[string]string{" ": "READ_DETAIL"}, field: "api_endpoint_actions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &Guard{EventsLog: filepath.Join(t.TempDir(), "events.log"), ActionRatePerMinute: tc.rate, APIEndpointActions: tc.action}
			if err := g.Validate(); err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("invalid action config must fail Validate with %s, got %v", tc.field, err)
			}
			if err := g.Provision(caddy.Context{Context: context.Background()}); err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("invalid action config must fail Provision with %s, got %v", tc.field, err)
			}
		})
	}
}

func TestGuardActionValidation(t *testing.T) {
	g := &Guard{EventsLog: "x", ActionRatePerMinute: 1, APIEndpointActions: map[string]string{
		"GET /v1/orders/{id}":          " read_detail ",
		"POST /v1/custom":              "custom",
		"POST /v1/inventory/reconcile": " inventory_reconcile_2026 ",
		"POST /v1/max-action":          strings.Repeat("A", maxAPIEndpointActionBytes),
	}}
	if err := g.Validate(); err != nil {
		t.Fatalf("trimmed case-insensitive built-in and custom actions must pass: %v", err)
	}
}

func newActionRateRequest(id string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/orders/42", nil)
	r.Header.Set("Accept", "application/json")
	r.Header.Set("X-Request-Id", id)
	r.RemoteAddr = "203.0.113.93:1001"
	return r
}

func configureActionRateGuard(g *Guard, app string, limit int, actions map[string]string, store detectors.WindowStore) {
	g.AppID = app
	g.ActionRatePerMinute = limit
	g.APIEndpointActions = actions
	if store != nil {
		g.behaviorStores = &detectors.StoreOverrides{ActionRateWindow: store}
	}
}

func actionRateTable() map[string]string {
	return map[string]string{"GET /v1/orders/{id}": "read_detail"}
}

func assertNoActionRateDetail(t *testing.T, rec apievents.Record) {
	t.Helper()
	for _, detail := range rec.Details {
		if detail.RuleID == "ratelimit.action_rate" {
			t.Fatalf("unexpected action rate detail: %+v", detail)
		}
	}
}

func assertActionRateDetail(t *testing.T, rec apievents.Record, action string) {
	t.Helper()
	for _, detail := range rec.Details {
		if detail.RuleID != "ratelimit.action_rate" {
			continue
		}
		if detail.Detector != "api_ratelimit" || detail.Category != "RATE_LIMIT" || detail.Severity != "HIGH" {
			t.Fatalf("bad action rate detail attributes: %+v", detail)
		}
		wantEvidence := map[string]string{"action": action, "window_count": "2", "limit": "1", "window": "1m"}
		if !reflect.DeepEqual(detail.Evidence, wantEvidence) {
			t.Fatalf("action evidence must contain only frozen fields: got %+v want %+v", detail.Evidence, wantEvidence)
		}
		return
	}
	t.Fatalf("ratelimit.action_rate detail missing: %+v", rec.Details)
}

func TestServeNextActionRatePerMinute(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action string
	}{
		{name: "built-in", action: "read_detail"},
		{name: "custom", action: " inventory_reconcile_2026 "},
	} {
		for _, mode := range []string{"OBSERVE", "PROTECT"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				g, logPath := newAPITestGuard(t, mode, nil)
				app := "guard-action-" + tc.name + "-" + mode
				store := newActionRateWindowProbe()
				configureActionRateGuard(g, app, 1, map[string]string{"GET /v1/orders/{id}": tc.action}, store)
				nextCalls := 0
				next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
					nextCalls++
					w.WriteHeader(http.StatusOK)
					return nil
				})
				if err := g.serveNext(httptest.NewRecorder(), newActionRateRequest("action-first"), next); err != nil {
					t.Fatalf("first serveNext: %v", err)
				}
				err := g.serveNext(httptest.NewRecorder(), newActionRateRequest("action-second"), next)
				if mode == "PROTECT" {
					var handlerErr caddyhttp.HandlerError
					if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusTooManyRequests {
						t.Fatalf("second request error=%v, want 429", err)
					}
				} else if err != nil {
					t.Fatalf("OBSERVE second serveNext must pass: %v", err)
				}
				wantNextCalls := 2
				if mode == "PROTECT" {
					wantNextCalls = 1
				}
				if nextCalls != wantNextCalls {
					t.Fatalf("next calls=%d want=%d", nextCalls, wantNextCalls)
				}
				normalizedAction := strings.ToUpper(strings.TrimSpace(tc.action))
				wantKey := app + "|" + normalizedAction
				if len(store.keys) != 2 || store.keys[0] != wantKey || store.keys[1] != wantKey {
					t.Fatalf("action keys=%v want two %q", store.keys, wantKey)
				}
				records := readAPIRecords(t, logPath)
				if len(records) != 2 {
					t.Fatalf("events=%d want 2", len(records))
				}
				assertNoActionRateDetail(t, records[0])
				assertActionRateDetail(t, records[1], normalizedAction)
				wantAction := "OBSERVE"
				if mode == "PROTECT" {
					wantAction = "RATE_LIMIT"
					if records[1].ResponseStatus != http.StatusTooManyRequests {
						t.Fatalf("blocked response status=%d want 429", records[1].ResponseStatus)
					}
				}
				if records[1].FinalAction != wantAction {
					t.Fatalf("final_action=%s want=%s", records[1].FinalAction, wantAction)
				}
			})
		}
	}
}

func TestServeNextActionRateSkipsUnclassifiedMissingAppAndDisabled(t *testing.T) {
	for _, tc := range []struct {
		name    string
		app     string
		limit   int
		actions map[string]string
	}{
		{name: "unclassified", app: "app-action-unclassified", limit: 1},
		{name: "missing app", limit: 1, actions: actionRateTable()},
		{name: "disabled", app: "app-action-disabled", limit: 0, actions: actionRateTable()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, logPath := newAPITestGuard(t, "PROTECT", nil)
			configureActionRateGuard(g, tc.app, tc.limit, tc.actions, nil)
			nextCalls := 0
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextCalls++
				return nil
			})
			for hit := 0; hit < 2; hit++ {
				if err := g.serveNext(httptest.NewRecorder(), newActionRateRequest("action-skip"), next); err != nil {
					t.Fatalf("serveNext %d: %v", hit+1, err)
				}
			}
			if nextCalls != 2 {
				t.Fatalf("next calls=%d want 2", nextCalls)
			}
			for _, record := range readAPIRecords(t, logPath) {
				assertNoActionRateDetail(t, record)
			}
		})
	}
}

type actionRateWindowProbe struct {
	store detectors.WindowStore
	keys  []string
}

func newActionRateWindowProbe() *actionRateWindowProbe {
	return &actionRateWindowProbe{store: detectors.NewMemoryWindowStore(0, nil)}
}

func (p *actionRateWindowProbe) AddAndCount(key string) (int, []int) {
	p.keys = append(p.keys, key)
	return p.store.AddAndCount(key)
}

func TestServeNextActionRateSharedStoreAcrossGuardInstances(t *testing.T) {
	for _, mode := range []string{"OBSERVE", "PROTECT"} {
		t.Run(mode, func(t *testing.T) {
			shared := newActionRateWindowProbe()
			first, firstLog := newAPITestGuard(t, mode, nil)
			second, secondLog := newAPITestGuard(t, mode, nil)
			app := "guard-action-shared-" + mode
			for _, g := range []*Guard{first, second} {
				configureActionRateGuard(g, app, 1, actionRateTable(), shared)
			}
			firstNextCalls := 0
			firstNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				firstNextCalls++
				return nil
			})
			if err := first.serveNext(httptest.NewRecorder(), newActionRateRequest("action-shared-first"), firstNext); err != nil {
				t.Fatalf("first Guard serveNext: %v", err)
			}
			secondNextCalls := 0
			secondNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				secondNextCalls++
				return nil
			})
			err := second.serveNext(httptest.NewRecorder(), newActionRateRequest("action-shared-second"), secondNext)
			if mode == "PROTECT" {
				var handlerErr caddyhttp.HandlerError
				if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusTooManyRequests {
					t.Fatalf("second Guard error=%v, want 429", err)
				}
			} else if err != nil {
				t.Fatalf("OBSERVE second Guard must pass: %v", err)
			}
			if firstNextCalls != 1 {
				t.Fatalf("first Guard next=%d want 1", firstNextCalls)
			}
			wantSecondNext := 1
			if mode == "PROTECT" {
				wantSecondNext = 0
			}
			if secondNextCalls != wantSecondNext {
				t.Fatalf("second Guard next=%d want=%d", secondNextCalls, wantSecondNext)
			}
			wantKey := app + "|READ_DETAIL"
			if len(shared.keys) != 2 || shared.keys[0] != wantKey || shared.keys[1] != wantKey {
				t.Fatalf("shared action keys=%v want two %q", shared.keys, wantKey)
			}
			firstRecords := readAPIRecords(t, firstLog)
			secondRecords := readAPIRecords(t, secondLog)
			if len(firstRecords) != 1 || len(secondRecords) != 1 {
				t.Fatalf("unexpected event counts: first=%d second=%d", len(firstRecords), len(secondRecords))
			}
			assertNoActionRateDetail(t, firstRecords[0])
			assertActionRateDetail(t, secondRecords[0], "READ_DETAIL")
		})
	}
}
