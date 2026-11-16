package jiuzhang_guard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
)

type objectRateWindowProbe struct {
	store detectors.WindowStore
	keys  []string
}

func newObjectRateWindowProbe() *objectRateWindowProbe {
	return &objectRateWindowProbe{store: detectors.NewMemoryWindowStore(0, nil)}
}

func (p *objectRateWindowProbe) AddAndCount(key string) (int, []int) {
	p.keys = append(p.keys, key)
	return p.store.AddAndCount(key)
}

func newObjectRateStoreRequest(id, credential, object string) *http.Request {
	target := "/v1/orders"
	if object != "" {
		target += "/" + object
	}
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Header.Set("Accept", "application/json")
	r.Header.Set("X-Request-Id", id)
	r.RemoteAddr = "203.0.113.91:1001"
	if credential != "" {
		r.Header.Set("Authorization", credential)
	}
	return r
}

func configureObjectRateStoreGuard(g *Guard, salt string, store detectors.WindowStore) {
	g.IdentitySalt = salt
	g.ObjectRatePerMinute = 1
	g.behaviorStores = &detectors.StoreOverrides{ObjectRateWindow: store}
}

func assertNoObjectRateDetail(t *testing.T, rec apievents.Record) {
	t.Helper()
	for _, detail := range rec.Details {
		if detail.RuleID == "ratelimit.object_rate" {
			t.Fatalf("unexpected object rate detail: %+v", detail)
		}
	}
}

func assertObjectRateDetail(t *testing.T, rec apievents.Record) {
	t.Helper()
	for _, detail := range rec.Details {
		if detail.RuleID != "ratelimit.object_rate" {
			continue
		}
		if detail.Detector != "api_ratelimit" || detail.Category != "RATE_LIMIT" || detail.Severity != "HIGH" {
			t.Fatalf("bad object rate detail attributes: %+v", detail)
		}
		wantEvidence := map[string]string{
			"window_count": "2",
			"limit":        "1",
			"window":       "1m",
			"source":       "path",
			"param":        "id",
		}
		for key, want := range wantEvidence {
			if got := detail.Evidence[key]; got != want {
				t.Fatalf("evidence[%s] = %q, want %q", key, got, want)
			}
		}
		return
	}
	t.Fatalf("ratelimit.object_rate detail missing: %+v", rec.Details)
}

func TestServeNextObjectRateSharedStoreAcrossGuardInstances(t *testing.T) {
	for _, mode := range []string{"OBSERVE", "PROTECT"} {
		t.Run(mode, func(t *testing.T) {
			shared := newObjectRateWindowProbe()
			first, firstLog := newAPITestGuard(t, mode, nil)
			second, secondLog := newAPITestGuard(t, mode, nil)
			salt := "object-rate-shared-" + mode
			for _, g := range []*Guard{first, second} {
				configureObjectRateStoreGuard(g, salt, shared)
			}
			credential := "Bearer object-rate-shared-" + mode + "-0123456789abcdef"
			const object = "730101"

			firstNextCalls := 0
			firstNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				firstNextCalls++
				w.WriteHeader(http.StatusOK)
				return nil
			})
			if err := first.serveNext(httptest.NewRecorder(), newObjectRateStoreRequest("object-shared-first", credential, object), firstNext); err != nil {
				t.Fatalf("first Guard serveNext: %v", err)
			}

			secondNextCalls := 0
			secondNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				secondNextCalls++
				w.WriteHeader(http.StatusOK)
				return nil
			})
			err := second.serveNext(httptest.NewRecorder(), newObjectRateStoreRequest("object-shared-second", credential, object), secondNext)
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
			if len(shared.keys) != 2 || shared.keys[0] != shared.keys[1] {
				t.Fatalf("same identity and object must share one key across Guards: %v", shared.keys)
			}

			firstRecords := readAPIRecords(t, firstLog)
			secondRecords := readAPIRecords(t, secondLog)
			if len(firstRecords) != 1 || len(secondRecords) != 1 {
				t.Fatalf("want one event per Guard, got first=%d second=%d", len(firstRecords), len(secondRecords))
			}
			assertNoObjectRateDetail(t, firstRecords[0])
			assertObjectRateDetail(t, secondRecords[0])
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

func TestServeNextObjectRateSharedStoreSeparatesObjectAndIdentity(t *testing.T) {
	for _, tc := range []struct {
		name             string
		firstCredential  string
		secondCredential string
		firstObject      string
		secondObject     string
	}{
		{
			name:             "different objects",
			firstCredential:  "Bearer object-rate-separate-object-0123456789abcdef",
			secondCredential: "Bearer object-rate-separate-object-0123456789abcdef",
			firstObject:      "730201",
			secondObject:     "730202",
		},
		{
			name:             "different identities",
			firstCredential:  "Bearer object-rate-separate-identity-a-0123456789abcdef",
			secondCredential: "Bearer object-rate-separate-identity-b-0123456789abcdef",
			firstObject:      "730203",
			secondObject:     "730203",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shared := newObjectRateWindowProbe()
			first, firstLog := newAPITestGuard(t, "PROTECT", nil)
			second, secondLog := newAPITestGuard(t, "PROTECT", nil)
			const salt = "object-rate-separate"
			configureObjectRateStoreGuard(first, salt, shared)
			configureObjectRateStoreGuard(second, salt, shared)
			nextCalls := 0
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextCalls++
				return nil
			})
			if err := first.serveNext(httptest.NewRecorder(), newObjectRateStoreRequest("object-separate-first", tc.firstCredential, tc.firstObject), next); err != nil {
				t.Fatalf("first Guard serveNext: %v", err)
			}
			if err := second.serveNext(httptest.NewRecorder(), newObjectRateStoreRequest("object-separate-second", tc.secondCredential, tc.secondObject), next); err != nil {
				t.Fatalf("second Guard must not inherit a different counter: %v", err)
			}
			if nextCalls != 2 {
				t.Fatalf("next calls = %d, want 2", nextCalls)
			}
			if len(shared.keys) != 2 || shared.keys[0] == shared.keys[1] {
				t.Fatalf("different objects or identities must use different keys: %v", shared.keys)
			}
			firstRecords := readAPIRecords(t, firstLog)
			secondRecords := readAPIRecords(t, secondLog)
			if len(firstRecords) != 1 || len(secondRecords) != 1 {
				t.Fatalf("want one event per Guard, got first=%d second=%d", len(firstRecords), len(secondRecords))
			}
			assertNoObjectRateDetail(t, firstRecords[0])
			assertNoObjectRateDetail(t, secondRecords[0])
		})
	}
}

func TestServeNextObjectRateMemoryStoresNotSharedAcrossGuardInstances(t *testing.T) {
	const salt = "object-rate-independent-memory"
	const credential = "Bearer object-rate-independent-memory-0123456789abcdef"
	const object = "730301"
	var firstKey string
	for i := 0; i < 2; i++ {
		store := newObjectRateWindowProbe()
		g, logPath := newAPITestGuard(t, "PROTECT", nil)
		configureObjectRateStoreGuard(g, salt, store)
		nextCalls := 0
		next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			nextCalls++
			return nil
		})
		if err := g.serveNext(httptest.NewRecorder(), newObjectRateStoreRequest("object-independent-memory", credential, object), next); err != nil {
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
		assertNoObjectRateDetail(t, records[0])
	}
}

func TestServeNextObjectRateAnonymousAndMissingObjectDoNotTouchStore(t *testing.T) {
	for _, tc := range []struct {
		name       string
		credential string
		object     string
	}{
		{name: "anonymous", object: "730401"},
		{name: "missing object", credential: "Bearer object-rate-missing-object-0123456789abcdef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newObjectRateWindowProbe()
			g, logPath := newAPITestGuard(t, "PROTECT", nil)
			configureObjectRateStoreGuard(g, "object-rate-skip-"+tc.name, store)
			nextCalls := 0
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextCalls++
				return nil
			})
			for i := 0; i < 2; i++ {
				if err := g.serveNext(httptest.NewRecorder(), newObjectRateStoreRequest("object-rate-skip", tc.credential, tc.object), next); err != nil {
					t.Fatalf("serveNext %d: %v", i+1, err)
				}
			}
			if nextCalls != 2 {
				t.Fatalf("next calls = %d, want 2", nextCalls)
			}
			if len(store.keys) != 0 {
				t.Fatalf("requests without identity or object must not enter object-rate store: %v", store.keys)
			}
			records := readAPIRecords(t, logPath)
			if len(records) != 2 {
				t.Fatalf("events = %d, want 2", len(records))
			}
			for _, record := range records {
				assertNoObjectRateDetail(t, record)
			}
		})
	}
}
