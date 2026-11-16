package jiuzhang_guard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
)

type apiQuotaStoreCase struct {
	name      string
	ruleID    string
	window    string
	setLimit  func(*Guard, int)
	bindStore func(*Guard, detectors.QuotaStore)
}

func apiQuotaStoreCases() []apiQuotaStoreCase {
	return []apiQuotaStoreCase{
		{
			name:     "hourly",
			ruleID:   "ratelimit.api_hourly_quota",
			window:   "1h",
			setLimit: func(g *Guard, limit int) { g.APIQuotaPerHour = limit },
			bindStore: func(g *Guard, store detectors.QuotaStore) {
				g.behaviorStores = &detectors.StoreOverrides{HourlyQuota: store}
			},
		},
		{
			name:     "daily",
			ruleID:   "ratelimit.api_daily_quota",
			window:   "1d",
			setLimit: func(g *Guard, limit int) { g.APIQuotaPerDay = limit },
			bindStore: func(g *Guard, store detectors.QuotaStore) {
				g.behaviorStores = &detectors.StoreOverrides{DailyQuota: store}
			},
		},
	}
}

type memoryQuotaStoreProbe struct {
	counts map[string]int
	keys   []string
}

func newMemoryQuotaStoreProbe() *memoryQuotaStoreProbe {
	return &memoryQuotaStoreProbe{counts: map[string]int{}}
}

func (p *memoryQuotaStoreProbe) AddAndCount(key string) int {
	p.keys = append(p.keys, key)
	p.counts[key]++
	return p.counts[key]
}

func newQuotaStoreRequest(id, credential, endpoint string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, endpoint, nil)
	r.Header.Set("Accept", "application/json")
	r.Header.Set("X-Request-Id", id)
	r.RemoteAddr = "203.0.113.92:1001"
	if credential != "" {
		r.Header.Set("Authorization", credential)
	}
	return r
}

func newQuotaStoreTestGuard(t *testing.T, mode string, quota apiQuotaStoreCase, store detectors.QuotaStore, limit int) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, mode, nil)
	g.IdentitySalt = "quota-store-salt"
	quota.setLimit(g, limit)
	quota.bindStore(g, store)
	return g, logPath
}

func assertNoAPIQuotaDetail(t *testing.T, rec apievents.Record, ruleID string) {
	t.Helper()
	for _, detail := range rec.Details {
		if detail.RuleID == ruleID {
			t.Fatalf("unexpected quota detail: %+v", detail)
		}
	}
}

func assertAPIQuotaDetail(t *testing.T, rec apievents.Record, quota apiQuotaStoreCase, count, limit int) {
	t.Helper()
	for _, detail := range rec.Details {
		if detail.RuleID != quota.ruleID {
			continue
		}
		if detail.Detector != "api_ratelimit" || detail.Category != "RATE_LIMIT" || detail.Severity != "HIGH" {
			t.Fatalf("bad quota detail attributes: %+v", detail)
		}
		wantEvidence := map[string]string{
			"window_count": strconv.Itoa(count),
			"limit":        strconv.Itoa(limit),
			"window":       quota.window,
		}
		for key, want := range wantEvidence {
			if got := detail.Evidence[key]; got != want {
				t.Fatalf("evidence[%s] = %q, want %q", key, got, want)
			}
		}
		return
	}
	t.Fatalf("%s detail missing: %+v", quota.ruleID, rec.Details)
}

func TestServeNextQuotaSharedStoreAcrossGuardInstances(t *testing.T) {
	for _, quota := range apiQuotaStoreCases() {
		for _, mode := range []string{"OBSERVE", "PROTECT"} {
			t.Run(quota.name+"/"+mode, func(t *testing.T) {
				shared := newMemoryQuotaStoreProbe()
				first, firstLog := newQuotaStoreTestGuard(t, mode, quota, shared, 2)
				second, secondLog := newQuotaStoreTestGuard(t, mode, quota, shared, 2)
				credential := "Bearer quota-shared-" + quota.name + "-" + mode + "-0123456789abcdef"
				endpoint := "/v1/quota-shared-" + quota.name

				firstNextCalls := 0
				firstNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
					firstNextCalls++
					w.WriteHeader(http.StatusOK)
					return nil
				})
				for i := 0; i < 2; i++ {
					if err := first.serveNext(httptest.NewRecorder(), newQuotaStoreRequest("quota-shared-first", credential, endpoint), firstNext); err != nil {
						t.Fatalf("first Guard request %d at limit must pass: %v", i+1, err)
					}
				}

				secondNextCalls := 0
				secondNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
					secondNextCalls++
					w.WriteHeader(http.StatusOK)
					return nil
				})
				err := second.serveNext(httptest.NewRecorder(), newQuotaStoreRequest("quota-shared-n-plus-one", credential, endpoint), secondNext)
				if mode == "PROTECT" {
					var handlerErr caddyhttp.HandlerError
					if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusTooManyRequests {
						t.Fatalf("N+1 request error = %v, want 429 HandlerError", err)
					}
				} else if err != nil {
					t.Fatalf("OBSERVE N+1 request must pass: %v", err)
				}
				if firstNextCalls != 2 {
					t.Fatalf("first Guard next calls = %d, want 2", firstNextCalls)
				}
				wantSecondNextCalls := 1
				if mode == "PROTECT" {
					wantSecondNextCalls = 0
				}
				if secondNextCalls != wantSecondNextCalls {
					t.Fatalf("second Guard next calls = %d, want %d", secondNextCalls, wantSecondNextCalls)
				}
				if len(shared.keys) != 3 {
					t.Fatalf("shared store calls = %v, want 3", shared.keys)
				}
				for _, key := range shared.keys[1:] {
					if key != shared.keys[0] {
						t.Fatalf("same identity and endpoint must share one key across Guards: %v", shared.keys)
					}
				}

				firstRecords := readAPIRecords(t, firstLog)
				secondRecords := readAPIRecords(t, secondLog)
				if len(firstRecords) != 2 || len(secondRecords) != 1 {
					t.Fatalf("unexpected event counts: first=%d second=%d", len(firstRecords), len(secondRecords))
				}
				for _, record := range firstRecords {
					assertNoAPIQuotaDetail(t, record, quota.ruleID)
				}
				assertAPIQuotaDetail(t, secondRecords[0], quota, 3, 2)
				wantAction := "OBSERVE"
				if mode == "PROTECT" {
					wantAction = "RATE_LIMIT"
					if secondRecords[0].ResponseStatus != http.StatusTooManyRequests {
						t.Fatalf("blocked event response status = %d, want 429", secondRecords[0].ResponseStatus)
					}
				}
				if secondRecords[0].FinalAction != wantAction {
					t.Fatalf("N+1 final_action = %q, want %q", secondRecords[0].FinalAction, wantAction)
				}
			})
		}
	}
}

func TestServeNextQuotaSharedStoreSeparatesEndpointAndIdentity(t *testing.T) {
	for _, quota := range apiQuotaStoreCases() {
		for _, tc := range []struct {
			name             string
			firstCredential  string
			secondCredential string
			firstEndpoint    string
			secondEndpoint   string
		}{
			{
				name:             "different endpoints",
				firstCredential:  "Bearer quota-separate-endpoint-0123456789abcdef",
				secondCredential: "Bearer quota-separate-endpoint-0123456789abcdef",
				firstEndpoint:    "/v1/quota-endpoint-a",
				secondEndpoint:   "/v1/quota-endpoint-b",
			},
			{
				name:             "different identities",
				firstCredential:  "Bearer quota-separate-identity-a-0123456789abcdef",
				secondCredential: "Bearer quota-separate-identity-b-0123456789abcdef",
				firstEndpoint:    "/v1/quota-identity",
				secondEndpoint:   "/v1/quota-identity",
			},
		} {
			t.Run(quota.name+"/"+tc.name, func(t *testing.T) {
				shared := newMemoryQuotaStoreProbe()
				first, firstLog := newQuotaStoreTestGuard(t, "PROTECT", quota, shared, 1)
				second, secondLog := newQuotaStoreTestGuard(t, "PROTECT", quota, shared, 1)
				nextCalls := 0
				next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
					nextCalls++
					return nil
				})
				if err := first.serveNext(httptest.NewRecorder(), newQuotaStoreRequest("quota-separate-first", tc.firstCredential, tc.firstEndpoint), next); err != nil {
					t.Fatalf("first Guard serveNext: %v", err)
				}
				if err := second.serveNext(httptest.NewRecorder(), newQuotaStoreRequest("quota-separate-second", tc.secondCredential, tc.secondEndpoint), next); err != nil {
					t.Fatalf("second Guard must not inherit a different counter: %v", err)
				}
				if nextCalls != 2 {
					t.Fatalf("next calls = %d, want 2", nextCalls)
				}
				if len(shared.keys) != 2 || shared.keys[0] == shared.keys[1] {
					t.Fatalf("different endpoints or identities must use different keys: %v", shared.keys)
				}
				firstRecords := readAPIRecords(t, firstLog)
				secondRecords := readAPIRecords(t, secondLog)
				if len(firstRecords) != 1 || len(secondRecords) != 1 {
					t.Fatalf("unexpected event counts: first=%d second=%d", len(firstRecords), len(secondRecords))
				}
				assertNoAPIQuotaDetail(t, firstRecords[0], quota.ruleID)
				assertNoAPIQuotaDetail(t, secondRecords[0], quota.ruleID)
			})
		}
	}
}

func TestServeNextQuotaMemoryStoresNotSharedAcrossGuardInstances(t *testing.T) {
	for _, quota := range apiQuotaStoreCases() {
		t.Run(quota.name, func(t *testing.T) {
			const credential = "Bearer quota-independent-memory-0123456789abcdef"
			const endpoint = "/v1/quota-independent-memory"
			var firstKey string
			for i := 0; i < 2; i++ {
				store := newMemoryQuotaStoreProbe()
				g, logPath := newQuotaStoreTestGuard(t, "PROTECT", quota, store, 1)
				nextCalls := 0
				next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
					nextCalls++
					return nil
				})
				if err := g.serveNext(httptest.NewRecorder(), newQuotaStoreRequest("quota-independent-memory", credential, endpoint), next); err != nil {
					t.Fatalf("Guard %d must not inherit the other Guard's count: %v", i+1, err)
				}
				if nextCalls != 1 {
					t.Fatalf("Guard %d next calls = %d, want 1", i+1, nextCalls)
				}
				if len(store.keys) != 1 {
					t.Fatalf("Guard %d store keys = %v, want one call", i+1, store.keys)
				}
				if i == 0 {
					firstKey = store.keys[0]
				} else if store.keys[0] != firstKey {
					t.Fatalf("identical requests produced different keys: first=%q second=%q", firstKey, store.keys[0])
				}
				records := readAPIRecords(t, logPath)
				if len(records) != 1 {
					t.Fatalf("Guard %d events = %d, want 1", i+1, len(records))
				}
				assertNoAPIQuotaDetail(t, records[0], quota.ruleID)
			}
		})
	}
}

func TestServeNextQuotaAnonymousKeepsTrackingKey(t *testing.T) {
	for _, quota := range apiQuotaStoreCases() {
		t.Run(quota.name, func(t *testing.T) {
			shared := newMemoryQuotaStoreProbe()
			first, firstLog := newQuotaStoreTestGuard(t, "PROTECT", quota, shared, 1)
			second, secondLog := newQuotaStoreTestGuard(t, "PROTECT", quota, shared, 1)
			const endpoint = "/v1/quota-anonymous"
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
			if err := first.serveNext(httptest.NewRecorder(), newQuotaStoreRequest("quota-anonymous-first", "", endpoint), next); err != nil {
				t.Fatalf("first anonymous request: %v", err)
			}
			err := second.serveNext(httptest.NewRecorder(), newQuotaStoreRequest("quota-anonymous-second", "", endpoint), next)
			var handlerErr caddyhttp.HandlerError
			if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("second anonymous request error = %v, want tracking-based 429", err)
			}
			if len(shared.keys) != 2 || shared.keys[0] != shared.keys[1] ||
				!strings.HasPrefix(shared.keys[0], "ip:203.0.113.92|") {
				t.Fatalf("anonymous requests must retain the original IP tracking key: %v", shared.keys)
			}
			firstRecords := readAPIRecords(t, firstLog)
			secondRecords := readAPIRecords(t, secondLog)
			if len(firstRecords) != 1 || len(secondRecords) != 1 {
				t.Fatalf("unexpected event counts: first=%d second=%d", len(firstRecords), len(secondRecords))
			}
			assertNoAPIQuotaDetail(t, firstRecords[0], quota.ruleID)
			assertAPIQuotaDetail(t, secondRecords[0], quota, 2, 1)
		})
	}
}
