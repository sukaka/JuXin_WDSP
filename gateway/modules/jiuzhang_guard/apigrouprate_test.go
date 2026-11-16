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

func TestGuardConfigGroupRateJSON(t *testing.T) {
	var g Guard
	if err := json.Unmarshal([]byte(`{
		"app_id":"app-1",
		"events_log":"/tmp/events.log",
		"api_dynamic_protection":true,
		"group_rate_per_minute":2,
		"api_endpoint_groups":{"app-1":{"GET /v1/orders/{id}":["order_query","audit_query"]}}
	}`), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got := g.APIEndpointGroups["app-1"]["GET /v1/orders/{id}"]
	if g.GroupRatePerMinute != 2 || !reflect.DeepEqual(got, []string{"order_query", "audit_query"}) {
		t.Fatalf("group config not decoded: rate=%d groups=%v", g.GroupRatePerMinute, g.APIEndpointGroups)
	}
	var legacy Guard
	if err := json.Unmarshal([]byte(`{"app_id":"app-1","events_log":"/tmp/events.log"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.GroupRatePerMinute != 0 || legacy.APIEndpointGroups != nil {
		t.Fatal("legacy group config must stay disabled")
	}
	for _, value := range []string{`"not-a-number"`, `"1"`, `1.5`} {
		var invalid Guard
		if err := json.Unmarshal([]byte(`{"events_log":"/tmp/events.log","group_rate_per_minute":`+value+`}`), &invalid); err == nil {
			t.Fatalf("non-integer group_rate_per_minute %s must be rejected", value)
		}
	}
	var invalidGroups Guard
	if err := json.Unmarshal([]byte(`{"events_log":"/tmp/events.log","api_endpoint_groups":{"app-1":{"GET /v1/orders":[1]}}}`), &invalidGroups); err == nil {
		t.Fatal("non-string group code must be rejected")
	}
}

func TestGuardRejectsInvalidGroupRateConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rate   int
		groups map[string]map[string][]string
		field  string
	}{
		{name: "negative rate", rate: -1, field: "group_rate_per_minute"},
		{name: "empty application", rate: 1, groups: map[string]map[string][]string{" ": {"GET /v1/orders": {"GROUP_A"}}}, field: "api_endpoint_groups"},
		{name: "empty endpoint", rate: 1, groups: map[string]map[string][]string{"app-1": {" ": {"GROUP_A"}}}, field: "api_endpoint_groups"},
		{name: "blank group", rate: 1, groups: map[string]map[string][]string{"app-1": {"GET /v1/orders": {" \t"}}}, field: "api_endpoint_groups"},
		{name: "bad shape", rate: 1, groups: map[string]map[string][]string{"app-1": {"GET /v1/orders": {"ORDER-QUERY"}}}, field: "api_endpoint_groups"},
		{name: "over 64 bytes", rate: 1, groups: map[string]map[string][]string{"app-1": {"GET /v1/orders": {strings.Repeat("A", 65)}}}, field: "api_endpoint_groups"},
		{name: "normalized duplicate", rate: 1, groups: map[string]map[string][]string{"app-1": {"GET /v1/orders": {"order_query", " ORDER_QUERY "}}}, field: "api_endpoint_groups"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &Guard{EventsLog: filepath.Join(t.TempDir(), "events.log"), GroupRatePerMinute: tc.rate, APIEndpointGroups: tc.groups}
			if err := g.Validate(); err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("invalid group config must fail Validate with %s, got %v", tc.field, err)
			}
			if err := g.Provision(caddy.Context{Context: context.Background()}); err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("invalid group config must fail Provision with %s, got %v", tc.field, err)
			}
		})
	}
}

func TestGuardGroupCodeValidationAcceptsNormalizedBounds(t *testing.T) {
	g := &Guard{EventsLog: "x", GroupRatePerMinute: 1, APIEndpointGroups: map[string]map[string][]string{
		"app-1": {
			"GET /v1/orders": {" order_query ", strings.Repeat("a", 64)},
			"GET /v1/other":  {},
		},
	}}
	if err := g.Validate(); err != nil {
		t.Fatalf("trimmed known-shape groups and empty endpoint list must pass: %v", err)
	}
}

func newGroupRateRequest(id string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/orders/42", nil)
	r.Header.Set("Accept", "application/json")
	r.Header.Set("X-Request-Id", id)
	r.RemoteAddr = "203.0.113.94:1001"
	return r
}

func groupRateTable(app string) map[string]map[string][]string {
	return map[string]map[string][]string{app: {"GET /v1/orders/{id}": {"order_query"}}}
}

func configureGroupRateGuard(g *Guard, app string, limit int, groups map[string]map[string][]string, store detectors.WindowStore) {
	g.AppID = app
	g.GroupRatePerMinute = limit
	g.APIEndpointGroups = groups
	if store != nil {
		g.behaviorStores = &detectors.StoreOverrides{GroupRateWindow: store}
	}
}

func assertNoGroupRateDetail(t *testing.T, rec apievents.Record) {
	t.Helper()
	for _, detail := range rec.Details {
		if detail.RuleID == "ratelimit.group_rate" {
			t.Fatalf("unexpected group rate detail: %+v", detail)
		}
	}
}

func assertGroupRateDetail(t *testing.T, rec apievents.Record) {
	t.Helper()
	for _, detail := range rec.Details {
		if detail.RuleID != "ratelimit.group_rate" {
			continue
		}
		if detail.Detector != "api_ratelimit" || detail.Category != "RATE_LIMIT" || detail.Severity != "HIGH" {
			t.Fatalf("bad group rate detail attributes: %+v", detail)
		}
		wantEvidence := map[string]string{"group_code": "ORDER_QUERY", "window_count": "2", "limit": "1", "window": "1m"}
		if !reflect.DeepEqual(detail.Evidence, wantEvidence) {
			t.Fatalf("group evidence must contain only frozen fields: got %+v want %+v", detail.Evidence, wantEvidence)
		}
		return
	}
	t.Fatalf("ratelimit.group_rate detail missing: %+v", rec.Details)
}

func TestServeNextGroupRatePerMinute(t *testing.T) {
	for _, mode := range []string{"OBSERVE", "PROTECT"} {
		t.Run(mode, func(t *testing.T) {
			g, logPath := newAPITestGuard(t, mode, nil)
			app := "guard-group-" + mode
			configureGroupRateGuard(g, app, 1, groupRateTable(app), nil)
			nextCalls := 0
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextCalls++
				w.WriteHeader(http.StatusOK)
				return nil
			})
			if err := g.serveNext(httptest.NewRecorder(), newGroupRateRequest("group-first"), next); err != nil {
				t.Fatalf("first serveNext: %v", err)
			}
			err := g.serveNext(httptest.NewRecorder(), newGroupRateRequest("group-second"), next)
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
			records := readAPIRecords(t, logPath)
			if len(records) != 2 {
				t.Fatalf("events=%d want 2", len(records))
			}
			assertNoGroupRateDetail(t, records[0])
			assertGroupRateDetail(t, records[1])
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

func TestServeNextGroupRateSkipsUngroupedMissingAppAndDisabled(t *testing.T) {
	for _, tc := range []struct {
		name   string
		app    string
		limit  int
		groups map[string]map[string][]string
	}{
		{name: "ungrouped", app: "app-group-ungrouped", limit: 1},
		{name: "missing app", limit: 1, groups: groupRateTable("app-other")},
		{name: "disabled", app: "app-group-disabled", limit: 0, groups: groupRateTable("app-group-disabled")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, logPath := newAPITestGuard(t, "PROTECT", nil)
			configureGroupRateGuard(g, tc.app, tc.limit, tc.groups, nil)
			nextCalls := 0
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextCalls++
				return nil
			})
			for hit := 0; hit < 2; hit++ {
				if err := g.serveNext(httptest.NewRecorder(), newGroupRateRequest("group-skip"), next); err != nil {
					t.Fatalf("serveNext %d: %v", hit+1, err)
				}
			}
			if nextCalls != 2 {
				t.Fatalf("next calls=%d want 2", nextCalls)
			}
			for _, record := range readAPIRecords(t, logPath) {
				assertNoGroupRateDetail(t, record)
			}
		})
	}
}

type groupRateWindowProbe struct {
	store detectors.WindowStore
	keys  []string
}

func newGroupRateWindowProbe() *groupRateWindowProbe {
	return &groupRateWindowProbe{store: detectors.NewMemoryWindowStore(0, nil)}
}

func (p *groupRateWindowProbe) AddAndCount(key string) (int, []int) {
	p.keys = append(p.keys, key)
	return p.store.AddAndCount(key)
}

func TestServeNextGroupRateSharedStoreAcrossGuardInstances(t *testing.T) {
	for _, mode := range []string{"OBSERVE", "PROTECT"} {
		t.Run(mode, func(t *testing.T) {
			shared := newGroupRateWindowProbe()
			first, firstLog := newAPITestGuard(t, mode, nil)
			second, secondLog := newAPITestGuard(t, mode, nil)
			app := "guard-group-shared-" + mode
			for _, g := range []*Guard{first, second} {
				configureGroupRateGuard(g, app, 1, groupRateTable(app), shared)
			}
			firstNextCalls := 0
			firstNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				firstNextCalls++
				return nil
			})
			if err := first.serveNext(httptest.NewRecorder(), newGroupRateRequest("group-shared-first"), firstNext); err != nil {
				t.Fatalf("first Guard serveNext: %v", err)
			}
			secondNextCalls := 0
			secondNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				secondNextCalls++
				return nil
			})
			err := second.serveNext(httptest.NewRecorder(), newGroupRateRequest("group-shared-second"), secondNext)
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
			wantKey := app + "|ORDER_QUERY"
			if len(shared.keys) != 2 || shared.keys[0] != wantKey || shared.keys[1] != wantKey {
				t.Fatalf("shared group keys=%v want two %q", shared.keys, wantKey)
			}
			firstRecords := readAPIRecords(t, firstLog)
			secondRecords := readAPIRecords(t, secondLog)
			if len(firstRecords) != 1 || len(secondRecords) != 1 {
				t.Fatalf("unexpected event counts: first=%d second=%d", len(firstRecords), len(secondRecords))
			}
			assertNoGroupRateDetail(t, firstRecords[0])
			assertGroupRateDetail(t, secondRecords[0])
		})
	}
}
