package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/temporaryblock"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func newRateLimitActionGuard(t *testing.T, app, mode, action string, seconds int) (*Guard, string) {
	t.Helper()
	g := newTestGuard(t, Guard{
		AppID:                app,
		AppCode:              "shop",
		APIDynamicProtection: true,
		APIProtectionMode:    mode,
		ActionRatePerMinute:  1,
		APIEndpointActions:   map[string]string{"GET /v1/orders/{id}": "read_detail"},
		APIRateLimitAction:   action,
		APITempBlockSeconds:  seconds,
	})
	logPath := filepath.Join(t.TempDir(), "api-runtime-events.log")
	logger, err := apievents.NewLogger(logPath, "test-node")
	if err != nil {
		t.Fatal(err)
	}
	g.apiEvents = logger
	t.Cleanup(func() { _ = logger.Close() })
	return g, logPath
}

func rateLimitActionRequest(id, ip string) *http.Request {
	r := newActionRateRequest(id)
	r.RemoteAddr = ip + ":1001"
	return r
}

func requireRateLimitHandlerStatus(t *testing.T, err error, status int) {
	t.Helper()
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) || handlerErr.StatusCode != status {
		t.Fatalf("error=%v, want HandlerError %d", err, status)
	}
}

func TestGuardRateLimitActionConfigDefaultsAndJSON(t *testing.T) {
	var g Guard
	if err := json.Unmarshal([]byte(`{"events_log":"/tmp/e.log","api_rate_limit_action":" temp_block ","api_temp_block_seconds":120}`), &g); err != nil {
		t.Fatal(err)
	}
	if g.APIRateLimitAction != " temp_block " || g.APITempBlockSeconds != 120 {
		t.Fatalf("rate limit disposition not decoded: %q %d", g.APIRateLimitAction, g.APITempBlockSeconds)
	}
	if got := normalizedAPIRateLimitAction(g.APIRateLimitAction); got != "TEMP_BLOCK" {
		t.Fatalf("normalized action=%s", got)
	}
	var legacy Guard
	if legacy.APIRateLimitAction != "" || legacy.APITempBlockSeconds != 0 {
		t.Fatal("zero values must retain legacy defaults")
	}
	if got := normalizedAPIRateLimitAction(legacy.APIRateLimitAction); got != "RATE_LIMIT" {
		t.Fatalf("default action=%s", got)
	}
	if got := normalizedAPITempBlockSeconds(legacy.APITempBlockSeconds); got != 60 {
		t.Fatalf("default temp block seconds=%d want 60", got)
	}
}

func TestGuardRejectsInvalidRateLimitDisposition(t *testing.T) {
	for _, tc := range []struct {
		name    string
		action  string
		seconds int
		field   string
	}{
		{name: "unknown action", action: "BOGUS", field: "api_rate_limit_action"},
		{name: "negative seconds", action: "TEMP_BLOCK", seconds: -1, field: "api_temp_block_seconds"},
		{name: "seconds above maximum", action: "TEMP_BLOCK", seconds: 86401, field: "api_temp_block_seconds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &Guard{EventsLog: filepath.Join(t.TempDir(), "events.log"), APIRateLimitAction: tc.action, APITempBlockSeconds: tc.seconds}
			if err := g.Validate(); err == nil || !contains(err.Error(), tc.field) {
				t.Fatalf("invalid disposition must fail Validate with %s: %v", tc.field, err)
			}
			if err := g.Provision(caddy.Context{Context: context.Background()}); err == nil || !contains(err.Error(), tc.field) {
				t.Fatalf("invalid disposition must fail Provision with %s: %v", tc.field, err)
			}
		})
	}
	for _, tc := range []struct {
		action  string
		seconds int
	}{
		{action: "", seconds: 0},
		{action: "RATE_LIMIT", seconds: 1},
		{action: " temp_block ", seconds: 86400},
	} {
		g := &Guard{EventsLog: "x", APIRateLimitAction: tc.action, APITempBlockSeconds: tc.seconds}
		if err := g.Validate(); err != nil {
			t.Fatalf("valid disposition %q/%d rejected: %v", tc.action, tc.seconds, err)
		}
	}
}

func TestServeHTTPRateLimitActionDefaultAndBlock(t *testing.T) {
	for _, tc := range []struct {
		name       string
		action     string
		wantStatus int
		wantFinal  string
	}{
		{name: "default", wantStatus: http.StatusTooManyRequests, wantFinal: "RATE_LIMIT"},
		{name: "rate limit", action: "RATE_LIMIT", wantStatus: http.StatusTooManyRequests, wantFinal: "RATE_LIMIT"},
		{name: "block", action: "BLOCK", wantStatus: http.StatusForbidden, wantFinal: "BLOCK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, apiLog := newRateLimitActionGuard(t, "app-rate-action-"+tc.name, "PROTECT", tc.action, 0)
			const ip = "203.0.113.201"
			nextCalls := 0
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextCalls++
				return nil
			})
			if err := g.ServeHTTP(httptest.NewRecorder(), rateLimitActionRequest("rate-first", ip), next); err != nil {
				t.Fatalf("first request: %v", err)
			}
			err := g.ServeHTTP(httptest.NewRecorder(), rateLimitActionRequest("rate-second", ip), next)
			requireRateLimitHandlerStatus(t, err, tc.wantStatus)
			if nextCalls != 1 {
				t.Fatalf("next calls=%d want 1", nextCalls)
			}
			if _, blocked := g.engine.blockCache.Blocked(netip.MustParseAddr(ip), g.AppID); blocked {
				t.Fatal("RATE_LIMIT/BLOCK must not create a temporary block")
			}
			for _, event := range g.readEvents(t) {
				if event.EventType == events.CCTempBlockCreated {
					t.Fatalf("unexpected temp block event: %+v", event)
				}
			}
			records := readAPIRecords(t, apiLog)
			if len(records) != 2 || records[1].FinalAction != tc.wantFinal || records[1].ResponseStatus != tc.wantStatus {
				t.Fatalf("unexpected API records: %+v", records)
			}
		})
	}
}

func TestServeHTTPRateLimitActionTempBlockCreatesRealBlock(t *testing.T) {
	g, apiLog := newRateLimitActionGuard(t, "app-rate-temp-real", "PROTECT", "TEMP_BLOCK", 120)
	const ip = "203.0.113.202"
	nextCalls := 0
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalls++
		return nil
	})
	if err := g.ServeHTTP(httptest.NewRecorder(), rateLimitActionRequest("temp-first", ip), next); err != nil {
		t.Fatalf("first request: %v", err)
	}
	before := time.Now().UTC()
	err := g.ServeHTTP(httptest.NewRecorder(), rateLimitActionRequest("temp-second", ip), next)
	after := time.Now().UTC()
	requireRateLimitHandlerStatus(t, err, http.StatusForbidden)
	if nextCalls != 1 {
		t.Fatalf("next calls=%d want 1", nextCalls)
	}
	block, ok := g.engine.blockCache.Blocked(netip.MustParseAddr(ip), g.AppID)
	if !ok {
		t.Fatal("N+1 must create a real temporary block")
	}
	if !block.Auto || block.AppID != g.AppID || block.ClientIP != ip || block.Reason != "api_rate_limit" {
		t.Fatalf("bad temporary block fields: %+v", block)
	}
	wantExpiry := 120 * time.Second
	if block.ExpiresAt.Before(before.Add(wantExpiry)) || block.ExpiresAt.After(after.Add(wantExpiry)) {
		t.Fatalf("expiry=%s not now+120s (before=%s after=%s)", block.ExpiresAt, before, after)
	}

	err = g.ServeHTTP(httptest.NewRecorder(), rateLimitActionRequest("temp-third", ip), next)
	requireRateLimitHandlerStatus(t, err, http.StatusForbidden)
	if nextCalls != 1 {
		t.Fatalf("subsequent blocked request must not reach next: %d", nextCalls)
	}
	created := 0
	rejected := 0
	for _, event := range g.readEvents(t) {
		switch event.EventType {
		case events.CCTempBlockCreated:
			created++
			if event.ApplicationID != g.AppID || event.ClientIP != ip || event.BlockExpiresAt == nil || !event.BlockExpiresAt.Equal(block.ExpiresAt) {
				t.Fatalf("bad temp block created event: %+v", event)
			}
		case events.CCRequestRejected:
			rejected++
		}
	}
	if created != 1 {
		t.Fatalf("created events=%d want 1", created)
	}
	if rejected == 0 {
		t.Fatal("subsequent real block must emit CC_REQUEST_REJECTED")
	}
	records := readAPIRecords(t, apiLog)
	if len(records) != 2 || records[1].FinalAction != "TEMP_BLOCK" || records[1].ResponseStatus != http.StatusForbidden {
		t.Fatalf("unexpected temp block API records: %+v", records)
	}
}

func TestServeHTTPRateLimitActionObserveDoesNotBlock(t *testing.T) {
	g, apiLog := newRateLimitActionGuard(t, "app-rate-temp-observe", "OBSERVE", "TEMP_BLOCK", 120)
	const ip = "203.0.113.203"
	nextCalls := 0
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalls++
		return nil
	})
	for hit := 0; hit < 2; hit++ {
		if err := g.ServeHTTP(httptest.NewRecorder(), rateLimitActionRequest("observe", ip), next); err != nil {
			t.Fatalf("OBSERVE hit %d: %v", hit+1, err)
		}
	}
	if nextCalls != 2 {
		t.Fatalf("next calls=%d want 2", nextCalls)
	}
	if _, blocked := g.engine.blockCache.Blocked(netip.MustParseAddr(ip), g.AppID); blocked {
		t.Fatal("OBSERVE must not create a real block")
	}
	for _, event := range g.readEvents(t) {
		if event.EventType == events.CCTempBlockCreated {
			t.Fatalf("OBSERVE must not emit created event: %+v", event)
		}
	}
	records := readAPIRecords(t, apiLog)
	if len(records) != 2 || records[1].FinalAction != "OBSERVE" {
		t.Fatalf("unexpected OBSERVE records: %+v", records)
	}
}

func TestServeNextRateLimitTempBlockMissingIPWarnsWithoutEvent(t *testing.T) {
	g, _ := newRateLimitActionGuard(t, "app-rate-temp-no-ip", "PROTECT", "TEMP_BLOCK", 120)
	core, logs := observer.New(zap.WarnLevel)
	g.logger = zap.New(core)
	nextCalls := 0
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalls++
		return nil
	})
	if err := g.serveNext(httptest.NewRecorder(), newActionRateRequest("missing-ip-first"), next); err != nil {
		t.Fatalf("first direct serveNext: %v", err)
	}
	err := g.serveNext(httptest.NewRecorder(), newActionRateRequest("missing-ip-second"), next)
	requireRateLimitHandlerStatus(t, err, http.StatusForbidden)
	if logs.FilterMessageSnippet("real client IP unavailable").Len() != 1 {
		t.Fatalf("missing IP must warn: %+v", logs.All())
	}
	for _, event := range g.readEvents(t) {
		if event.EventType == events.CCTempBlockCreated {
			t.Fatalf("missing IP must not fabricate created event: %+v", event)
		}
	}
}

type failingRateLimitValkey struct{}

func (failingRateLimitValkey) Eval(context.Context, string, []string, []string) ([]interface{}, error) {
	return nil, nil
}
func (failingRateLimitValkey) HSet(context.Context, string, string, string) error {
	return errors.New("valkey write failed")
}
func (failingRateLimitValkey) HGetAll(context.Context, string) (map[string]string, error) {
	return map[string]string{}, nil
}
func (failingRateLimitValkey) HDel(context.Context, string, ...string) error { return nil }
func (failingRateLimitValkey) Ping(context.Context) error                    { return nil }
func (failingRateLimitValkey) Close() error                                  { return nil }

func TestServeHTTPRateLimitTempBlockWriteFailureWarnsWithoutCreatedEvent(t *testing.T) {
	g, _ := newRateLimitActionGuard(t, "app-rate-temp-write-failure", "PROTECT", "TEMP_BLOCK", 120)
	g.engine.blockCache = temporaryblock.NewCache(temporaryblock.NewStore(failingRateLimitValkey{}, ""), 0)
	core, logs := observer.New(zap.WarnLevel)
	g.logger = zap.New(core)
	const ip = "203.0.113.204"
	nextCalls := 0
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalls++
		return nil
	})
	if err := g.ServeHTTP(httptest.NewRecorder(), rateLimitActionRequest("failure-first", ip), next); err != nil {
		t.Fatalf("first request: %v", err)
	}
	err := g.ServeHTTP(httptest.NewRecorder(), rateLimitActionRequest("failure-second", ip), next)
	requireRateLimitHandlerStatus(t, err, http.StatusForbidden)
	if logs.FilterMessageSnippet("temporary block write failed").Len() != 1 {
		t.Fatalf("write failure must warn: %+v", logs.All())
	}
	for _, event := range g.readEvents(t) {
		if event.EventType == events.CCTempBlockCreated {
			t.Fatalf("failed write must not emit created event: %+v", event)
		}
	}
}
