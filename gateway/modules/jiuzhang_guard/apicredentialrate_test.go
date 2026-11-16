package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
)

func TestGuardConfigCredentialRatePerMinuteJSON(t *testing.T) {
	var g Guard
	if err := json.Unmarshal([]byte(`{
		"app_id":"app-1",
		"events_log":"/tmp/events.log",
		"api_dynamic_protection":true,
		"credential_rate_per_minute":2
	}`), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if g.CredentialRatePerMinute != 2 {
		t.Fatalf("credential_rate_per_minute = %d, want 2", g.CredentialRatePerMinute)
	}

	var legacy Guard
	if err := json.Unmarshal([]byte(`{"app_id":"app-1","events_log":"/tmp/events.log"}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if legacy.CredentialRatePerMinute != 0 {
		t.Fatalf("legacy credential rate = %d, want disabled zero value", legacy.CredentialRatePerMinute)
	}

	for _, value := range []string{`"not-a-number"`, `"1"`, `1.5`} {
		var invalid Guard
		raw := `{"events_log":"/tmp/events.log","credential_rate_per_minute":` + value + `}`
		if err := json.Unmarshal([]byte(raw), &invalid); err == nil {
			t.Fatalf("non-integer credential_rate_per_minute %s must be rejected", value)
		}
	}
}

func TestGuardRejectsNegativeCredentialRatePerMinute(t *testing.T) {
	g := &Guard{
		EventsLog:               filepath.Join(t.TempDir(), "events.log"),
		CredentialRatePerMinute: -1,
	}
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "credential_rate_per_minute") {
		t.Fatalf("negative credential rate must fail Validate, got %v", err)
	}
	if err := g.Provision(caddy.Context{Context: context.Background()}); err == nil || !strings.Contains(err.Error(), "credential_rate_per_minute") {
		t.Fatalf("negative credential rate must fail Provision, got %v", err)
	}
}

type credentialRateFixture struct {
	name           string
	header         string
	credential     string
	credentialType string
}

func credentialRateFixtures() []credentialRateFixture {
	return []credentialRateFixture{
		{name: "authorization", header: "Authorization", credential: "Bearer credential-rate-authorization-0123456789abcdef", credentialType: "AUTHORIZATION"},
		{name: "api key", header: "X-API-Key", credential: "credential-rate-api-key-0123456789abcdef", credentialType: "API_KEY"},
		{name: "session", header: "Cookie", credential: "session=credential-rate-session-0123456789abcdef", credentialType: "SESSION"},
	}
}

func newCredentialRateRequest(id string, fixture *credentialRateFixture) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/credential-rate", strings.NewReader(`{"id":1}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("X-Request-Id", id)
	r.RemoteAddr = "203.0.113.90:1001"
	if fixture != nil {
		r.Header.Set(fixture.header, fixture.credential)
	}
	return r
}

func assertNoCredentialRateDetail(t *testing.T, rec apievents.Record) {
	t.Helper()
	for _, detail := range rec.Details {
		if detail.RuleID == "ratelimit.credential_rate" {
			t.Fatalf("unexpected credential rate detail: %+v", detail)
		}
	}
}

func assertCredentialRateDetail(t *testing.T, rec apievents.Record, fixture credentialRateFixture) {
	t.Helper()
	for _, detail := range rec.Details {
		if detail.RuleID != "ratelimit.credential_rate" {
			continue
		}
		if detail.Detector != "api_ratelimit" || detail.Category != "RATE_LIMIT" || detail.Severity != "HIGH" {
			t.Fatalf("bad credential rate detail attributes: %+v", detail)
		}
		wantEvidence := map[string]string{
			"credential_type": fixture.credentialType,
			"window_count":    "2",
			"limit":           "1",
			"window":          "1m",
		}
		if len(detail.Evidence) != len(wantEvidence) {
			t.Fatalf("credential rate evidence must contain only frozen fields: %+v", detail.Evidence)
		}
		for key, want := range wantEvidence {
			if got := detail.Evidence[key]; got != want {
				t.Fatalf("evidence[%s] = %q, want %q", key, got, want)
			}
		}
		encoded, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		secret := fixture.credential
		if i := strings.IndexAny(secret, " ="); i >= 0 {
			secret = secret[i+1:]
		}
		if strings.Contains(string(encoded), fixture.credential) || strings.Contains(string(encoded), secret) {
			t.Fatal("raw credential must not appear in api runtime event")
		}
		return
	}
	t.Fatalf("ratelimit.credential_rate detail missing: %+v", rec.Details)
}

func TestServeNextCredentialRatePerMinute(t *testing.T) {
	for _, mode := range []string{"OBSERVE", "PROTECT"} {
		for _, fixture := range credentialRateFixtures() {
			t.Run(mode+"/"+fixture.name, func(t *testing.T) {
				g, logPath := newAPITestGuard(t, mode, nil)
				g.IdentitySalt = "credential-rate-" + mode + "-" + fixture.name
				g.CredentialRatePerMinute = 1
				nextCalls := 0
				next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
					nextCalls++
					w.WriteHeader(http.StatusOK)
					return nil
				})

				if err := g.serveNext(httptest.NewRecorder(), newCredentialRateRequest("first", &fixture), next); err != nil {
					t.Fatalf("first serveNext: %v", err)
				}
				second := newCredentialRateRequest("second", &fixture)
				err := g.serveNext(httptest.NewRecorder(), second, next)
				if mode == "PROTECT" {
					var handlerErr caddyhttp.HandlerError
					if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusTooManyRequests {
						t.Fatalf("second request error = %v, want 429 HandlerError", err)
					}
				} else if err != nil {
					t.Fatalf("OBSERVE second serveNext must pass: %v", err)
				}
				wantNextCalls := 2
				if mode == "PROTECT" {
					wantNextCalls = 1
				}
				if nextCalls != wantNextCalls {
					t.Fatalf("next calls = %d, want %d", nextCalls, wantNextCalls)
				}

				recs := readAPIRecords(t, logPath)
				if len(recs) != 2 {
					t.Fatalf("want 2 api events, got %d: %+v", len(recs), recs)
				}
				assertNoCredentialRateDetail(t, recs[0])
				assertCredentialRateDetail(t, recs[1], fixture)
				wantAction := "OBSERVE"
				if mode == "PROTECT" {
					wantAction = "RATE_LIMIT"
					if recs[1].ResponseStatus != http.StatusTooManyRequests {
						t.Fatalf("blocked event response status = %d, want 429", recs[1].ResponseStatus)
					}
				}
				if recs[1].FinalAction != wantAction {
					t.Fatalf("second final_action = %q, want %q", recs[1].FinalAction, wantAction)
				}
				credKey := detectors.CredentialKey(second, g.IdentitySalt)
				for _, detail := range recs[1].Details {
					if detail.RuleID == "ratelimit.credential_rate" {
						for _, value := range detail.Evidence {
							if value == credKey {
								t.Fatal("credential key must not appear in detector evidence")
							}
						}
					}
				}
			})
		}
	}
}

func TestServeNextCredentialRateSkipsAnonymousAndDisabled(t *testing.T) {
	for _, tc := range []struct {
		name    string
		limit   int
		anon    bool
		fixture credentialRateFixture
	}{
		{name: "anonymous does not fall back to IP", limit: 1, anon: true},
		{name: "zero disables detector", limit: 0, fixture: credentialRateFixtures()[0]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, logPath := newAPITestGuard(t, "PROTECT", nil)
			g.IdentitySalt = "credential-rate-skip-" + tc.name
			g.CredentialRatePerMinute = tc.limit
			nextCalls := 0
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextCalls++
				return nil
			})
			for i := 0; i < 2; i++ {
				var fixture *credentialRateFixture
				if !tc.anon {
					fixture = &tc.fixture
				}
				if err := g.serveNext(httptest.NewRecorder(), newCredentialRateRequest("request", fixture), next); err != nil {
					t.Fatalf("serveNext %d: %v", i+1, err)
				}
			}
			if nextCalls != 2 {
				t.Fatalf("next calls = %d, want 2", nextCalls)
			}
			recs := readAPIRecords(t, logPath)
			if len(recs) != 2 {
				t.Fatalf("want 2 api events, got %d: %+v", len(recs), recs)
			}
			for _, rec := range recs {
				assertNoCredentialRateDetail(t, rec)
			}
		})
	}
}

func TestServeNextCredentialRateIsolatesCredentials(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.IdentitySalt = "credential-rate-isolation"
	g.CredentialRatePerMinute = 1
	nextCalls := 0
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalls++
		return nil
	})
	for _, credential := range []string{
		"Bearer credential-rate-isolation-a-0123456789abcdef",
		"Bearer credential-rate-isolation-b-0123456789abcdef",
	} {
		fixture := credentialRateFixture{header: "Authorization", credential: credential}
		if err := g.serveNext(httptest.NewRecorder(), newCredentialRateRequest("request", &fixture), next); err != nil {
			t.Fatalf("serveNext: %v", err)
		}
	}
	if nextCalls != 2 {
		t.Fatalf("next calls = %d, want 2", nextCalls)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("want 2 api events, got %d: %+v", len(recs), recs)
	}
	for _, rec := range recs {
		assertNoCredentialRateDetail(t, rec)
	}
}

type credentialRateWindowProbe struct {
	store detectors.WindowStore
	keys  []string
}

func newCredentialRateWindowProbe() *credentialRateWindowProbe {
	return &credentialRateWindowProbe{store: detectors.NewMemoryWindowStore(0, nil)}
}

func (p *credentialRateWindowProbe) AddAndCount(key string) (int, []int) {
	p.keys = append(p.keys, key)
	return p.store.AddAndCount(key)
}

func TestServeNextCredentialRateSharedStoreAcrossGuardInstances(t *testing.T) {
	for _, mode := range []string{"OBSERVE", "PROTECT"} {
		t.Run(mode, func(t *testing.T) {
			shared := newCredentialRateWindowProbe()
			first, firstLog := newAPITestGuard(t, mode, nil)
			second, secondLog := newAPITestGuard(t, mode, nil)
			salt := "credential-rate-shared-" + mode
			for _, g := range []*Guard{first, second} {
				g.IdentitySalt = salt
				g.CredentialRatePerMinute = 1
				g.behaviorStores = &detectors.StoreOverrides{CredentialRateWindow: shared}
			}
			fixture := credentialRateFixture{
				header:         "Authorization",
				credential:     "Bearer credential-rate-shared-" + mode + "-0123456789abcdef",
				credentialType: "AUTHORIZATION",
			}
			firstNextCalls := 0
			firstNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				firstNextCalls++
				w.WriteHeader(http.StatusOK)
				return nil
			})
			if err := first.serveNext(httptest.NewRecorder(), newCredentialRateRequest("shared-first", &fixture), firstNext); err != nil {
				t.Fatalf("first Guard serveNext: %v", err)
			}

			secondNextCalls := 0
			secondNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				secondNextCalls++
				w.WriteHeader(http.StatusOK)
				return nil
			})
			secondRequest := newCredentialRateRequest("shared-second", &fixture)
			err := second.serveNext(httptest.NewRecorder(), secondRequest, secondNext)
			if mode == "PROTECT" {
				var handlerErr caddyhttp.HandlerError
				if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusTooManyRequests {
					t.Fatalf("second Guard error = %v, want 429 HandlerError", err)
				}
			} else if err != nil {
				t.Fatalf("OBSERVE second Guard serveNext must pass: %v", err)
			}
			if firstNextCalls != 1 {
				t.Fatalf("first Guard next calls = %d, want 1", firstNextCalls)
			}
			wantSecondNextCalls := 1
			if mode == "PROTECT" {
				wantSecondNextCalls = 0
			}
			if secondNextCalls != wantSecondNextCalls {
				t.Fatalf("second Guard next calls = %d, want %d", secondNextCalls, wantSecondNextCalls)
			}

			wantKey := detectors.CredentialKey(secondRequest, salt)
			if len(shared.keys) != 2 || shared.keys[0] != wantKey || shared.keys[1] != wantKey {
				t.Fatalf("shared store keys = %v, want two calls with salted credential key %q", shared.keys, wantKey)
			}
			firstRecords := readAPIRecords(t, firstLog)
			secondRecords := readAPIRecords(t, secondLog)
			if len(firstRecords) != 1 || len(secondRecords) != 1 {
				t.Fatalf("want one event per Guard, got first=%d second=%d", len(firstRecords), len(secondRecords))
			}
			assertNoCredentialRateDetail(t, firstRecords[0])
			assertCredentialRateDetail(t, secondRecords[0], fixture)
			wantAction := "OBSERVE"
			if mode == "PROTECT" {
				wantAction = "RATE_LIMIT"
				if secondRecords[0].ResponseStatus != http.StatusTooManyRequests {
					t.Fatalf("blocked event response status = %d, want 429", secondRecords[0].ResponseStatus)
				}
			}
			if secondRecords[0].FinalAction != wantAction {
				t.Fatalf("second final_action = %q, want %q", secondRecords[0].FinalAction, wantAction)
			}
		})
	}
}

func TestServeNextCredentialRateMemoryStoresNotSharedAcrossGuardInstances(t *testing.T) {
	const salt = "credential-rate-independent-memory"
	fixture := credentialRateFixture{
		header:         "Authorization",
		credential:     "Bearer credential-rate-independent-memory-0123456789abcdef",
		credentialType: "AUTHORIZATION",
	}
	for i := 0; i < 2; i++ {
		store := newCredentialRateWindowProbe()
		g, logPath := newAPITestGuard(t, "PROTECT", nil)
		g.IdentitySalt = salt
		g.CredentialRatePerMinute = 1
		g.behaviorStores = &detectors.StoreOverrides{CredentialRateWindow: store}
		nextCalls := 0
		next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			nextCalls++
			return nil
		})
		request := newCredentialRateRequest("independent-memory", &fixture)
		if err := g.serveNext(httptest.NewRecorder(), request, next); err != nil {
			t.Fatalf("Guard %d must not inherit the other Guard's count: %v", i+1, err)
		}
		if nextCalls != 1 {
			t.Fatalf("Guard %d next calls = %d, want 1", i+1, nextCalls)
		}
		wantKey := detectors.CredentialKey(request, salt)
		if len(store.keys) != 1 || store.keys[0] != wantKey {
			t.Fatalf("Guard %d store keys = %v, want only %q", i+1, store.keys, wantKey)
		}
		records := readAPIRecords(t, logPath)
		if len(records) != 1 {
			t.Fatalf("Guard %d events = %d, want 1", i+1, len(records))
		}
		assertNoCredentialRateDetail(t, records[0])
	}
}

func TestServeNextCredentialRateAnonymousDoesNotTouchStore(t *testing.T) {
	store := newCredentialRateWindowProbe()
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.IdentitySalt = "credential-rate-anonymous-store"
	g.CredentialRatePerMinute = 1
	g.behaviorStores = &detectors.StoreOverrides{CredentialRateWindow: store}
	nextCalls := 0
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalls++
		return nil
	})
	for i := 0; i < 2; i++ {
		if err := g.serveNext(httptest.NewRecorder(), newCredentialRateRequest("anonymous", nil), next); err != nil {
			t.Fatalf("anonymous serveNext %d: %v", i+1, err)
		}
	}
	if nextCalls != 2 {
		t.Fatalf("anonymous next calls = %d, want 2", nextCalls)
	}
	if len(store.keys) != 0 {
		t.Fatalf("anonymous requests must not enter credential-rate store: %v", store.keys)
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 2 {
		t.Fatalf("anonymous events = %d, want 2", len(records))
	}
	for _, record := range records {
		assertNoCredentialRateDetail(t, record)
	}
}
