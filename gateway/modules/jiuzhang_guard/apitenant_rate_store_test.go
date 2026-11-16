package jiuzhang_guard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

type tenantRateWindowProbe struct {
	store detectors.WindowStore
	keys  []string
}

func newTenantRateWindowProbe() *tenantRateWindowProbe {
	return &tenantRateWindowProbe{store: detectors.NewMemoryWindowStore(0, nil)}
}

func (p *tenantRateWindowProbe) AddAndCount(key string) (int, []int) {
	p.keys = append(p.keys, key)
	return p.store.AddAndCount(key)
}

func configureTenantRateStoreGuard(g *Guard, salt string, limit int, store detectors.WindowStore) {
	g.IdentitySalt = salt
	g.TenantRatePerMinute = limit
	g.behaviorStores = &detectors.StoreOverrides{TenantRateWindow: store}
}

func TestServeNextTenantRateSharedStoreAcrossGuardInstances(t *testing.T) {
	const tenant = "guard-tenant-rate-shared-secret"
	for _, mode := range []string{"OBSERVE", "PROTECT"} {
		t.Run(mode, func(t *testing.T) {
			shared := newTenantRateWindowProbe()
			first, firstLog := newAPITestGuard(t, mode, nil)
			second, secondLog := newAPITestGuard(t, mode, nil)
			salt := "tenant-rate-shared-" + mode
			for _, g := range []*Guard{first, second} {
				configureTenantRateStoreGuard(g, salt, 1, shared)
			}
			jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: tenant}

			firstNextCalls := 0
			firstNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				firstNextCalls++
				w.WriteHeader(http.StatusOK)
				return nil
			})
			if err := first.serveNext(httptest.NewRecorder(), newTenantRateRequest("tenant-shared-first", jwt), firstNext); err != nil {
				t.Fatalf("first Guard serveNext: %v", err)
			}

			secondNextCalls := 0
			secondNext := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				secondNextCalls++
				w.WriteHeader(http.StatusOK)
				return nil
			})
			err := second.serveNext(httptest.NewRecorder(), newTenantRateRequest("tenant-shared-second", jwt), secondNext)
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

			wantKey := detectors.Fingerprint(salt, "jwt-tenant:"+tenant)
			if len(shared.keys) != 2 || shared.keys[0] != wantKey || shared.keys[1] != wantKey {
				t.Fatalf("shared tenant keys = %v, want two calls with salted fingerprint %q", shared.keys, wantKey)
			}
			firstRecords := readAPIRecords(t, firstLog)
			secondRecords := readAPIRecords(t, secondLog)
			if len(firstRecords) != 1 || len(secondRecords) != 1 {
				t.Fatalf("want one event per Guard, got first=%d second=%d", len(firstRecords), len(secondRecords))
			}
			assertNoTenantRateDetail(t, firstRecords[0])
			assertTenantRateDetail(t, secondRecords[0], tenant, salt)
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

func TestServeNextTenantRateMemoryStoresNotSharedAcrossGuardInstances(t *testing.T) {
	const (
		salt   = "tenant-rate-independent-memory"
		tenant = "guard-tenant-rate-independent-secret"
	)
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: tenant}
	wantKey := detectors.Fingerprint(salt, "jwt-tenant:"+tenant)
	for i := 0; i < 2; i++ {
		store := newTenantRateWindowProbe()
		g, logPath := newAPITestGuard(t, "PROTECT", nil)
		configureTenantRateStoreGuard(g, salt, 1, store)
		nextCalls := 0
		next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			nextCalls++
			return nil
		})
		if err := g.serveNext(httptest.NewRecorder(), newTenantRateRequest("tenant-independent-memory", jwt), next); err != nil {
			t.Fatalf("Guard %d must not inherit the other Guard's count: %v", i+1, err)
		}
		if nextCalls != 1 {
			t.Fatalf("Guard %d next calls = %d, want 1", i+1, nextCalls)
		}
		if len(store.keys) != 1 || store.keys[0] != wantKey {
			t.Fatalf("Guard %d store keys = %v, want only salted fingerprint %q", i+1, store.keys, wantKey)
		}
		records := readAPIRecords(t, logPath)
		if len(records) != 1 {
			t.Fatalf("Guard %d events = %d, want 1", i+1, len(records))
		}
		assertNoTenantRateDetail(t, records[0])
	}
}

func TestServeNextTenantRateSkipsDoNotTouchStore(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
		jwt   *jwtverify.VerificationResult
	}{
		{name: "no verification", limit: 1},
		{name: "unverified", limit: 1, jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusUnverified, VerifiedTenantID: "tenant-untrusted-store"}},
		{name: "missing tenant", limit: 1, jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified}},
		{name: "disabled", limit: 0, jwt: &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: "tenant-disabled-store"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newTenantRateWindowProbe()
			g, logPath := newAPITestGuard(t, "PROTECT", nil)
			configureTenantRateStoreGuard(g, "tenant-rate-store-skip-"+tc.name, tc.limit, store)
			nextCalls := 0
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextCalls++
				return nil
			})
			for hit := 0; hit < 2; hit++ {
				if err := g.serveNext(httptest.NewRecorder(), newTenantRateRequest("tenant-store-skip", tc.jwt), next); err != nil {
					t.Fatalf("serveNext %d: %v", hit+1, err)
				}
			}
			if nextCalls != 2 || len(store.keys) != 0 {
				t.Fatalf("skipped tenant requests must pass without store access: next=%d keys=%v", nextCalls, store.keys)
			}
			records := readAPIRecords(t, logPath)
			if len(records) != 2 {
				t.Fatalf("events = %d, want 2", len(records))
			}
			for _, record := range records {
				assertNoTenantRateDetail(t, record)
			}
		})
	}
}
