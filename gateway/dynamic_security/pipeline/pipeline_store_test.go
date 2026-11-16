package pipeline

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

// captureWindowStore 捕获 AddAndCount 调用的 WindowStore 替身。
type captureWindowStore struct{ calls []string }

func (c *captureWindowStore) AddAndCount(key string) (int, []int) {
	c.calls = append(c.calls, key)
	return 1, nil
}

func behaviorRequest(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "http://h/v1/orders/9", strings.NewReader(`{"id":1}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer t")
	return r
}

// Process 将 Stores 绑定到本次 RequestContext；后续无覆盖请求不得复用它。
func TestProcessUsesRequestScopedStores(t *testing.T) {
	cap := &captureWindowStore{}
	res, err := Process(behaviorRequest(t), Config{
		Enabled: true,
		Mode:    "OBSERVE",
		Stores:  &detectors.StoreOverrides{BehaviorWindow: cap},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped || len(cap.calls) == 0 {
		t.Fatalf("request-scoped behavior store was not used: skipped=%v calls=%v", res.Skipped, cap.calls)
	}

	before := len(cap.calls)
	if _, err := Process(behaviorRequest(t), Config{Enabled: true, Mode: "OBSERVE"}, nil); err != nil {
		t.Fatal(err)
	}
	if len(cap.calls) != before {
		t.Fatal("a request without Stores reused another request's override")
	}
}

// 关闭管线时不创建上下文，也不触碰存储。
func TestProcessDisabledDoesNotUseStores(t *testing.T) {
	cap := &captureWindowStore{}
	res, err := Process(behaviorRequest(t), Config{
		Enabled: false,
		Stores:  &detectors.StoreOverrides{BehaviorWindow: cap},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped {
		t.Fatal("expected skip when disabled")
	}
	if len(cap.calls) != 0 {
		t.Fatalf("disabled pipeline must not touch stores: %v", cap.calls)
	}
}

func TestProcessCredentialRateStoreBindingAndReloadIsolation(t *testing.T) {
	const salt = "credential-rate-store-reload"
	first := &captureWindowStore{}
	second := &captureWindowStore{}
	wantKey := detectors.CredentialKey(behaviorRequest(t), salt)
	if wantKey == "" {
		t.Fatal("credential-rate request must have a salted credential key")
	}

	process := func(stores *detectors.StoreOverrides) {
		t.Helper()
		if _, err := Process(behaviorRequest(t), Config{
			Enabled:                 true,
			Mode:                    "OBSERVE",
			IdentitySalt:            salt,
			CredentialRatePerMinute: 1,
			Stores:                  stores,
		}, nil); err != nil {
			t.Fatal(err)
		}
	}

	process(&detectors.StoreOverrides{CredentialRateWindow: first})
	if len(first.calls) != 1 || first.calls[0] != wantKey || len(second.calls) != 0 {
		t.Fatalf("first binding received %v, second received %v; want only %q on first", first.calls, second.calls, wantKey)
	}

	process(&detectors.StoreOverrides{CredentialRateWindow: second})
	if len(first.calls) != 1 || len(second.calls) != 1 || second.calls[0] != wantKey {
		t.Fatalf("reloaded binding was not isolated: first=%v second=%v", first.calls, second.calls)
	}

	process(&detectors.StoreOverrides{})
	process(nil)
	if len(first.calls) != 1 || len(second.calls) != 1 {
		t.Fatalf("nil or unbound credential-rate store reused a stale override: first=%v second=%v", first.calls, second.calls)
	}
}

func TestProcessTenantRateStoreBindingAndReloadIsolation(t *testing.T) {
	const (
		salt   = "tenant-rate-store-reload"
		tenant = "tenant-rate-store-secret"
	)
	first := &captureWindowStore{}
	second := &captureWindowStore{}
	jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedTenantID: tenant}
	wantKey := detectors.Fingerprint(salt, "jwt-tenant:"+tenant)
	process := func(stores *detectors.StoreOverrides) {
		t.Helper()
		if _, err := Process(behaviorRequest(t), Config{
			Enabled:             true,
			Mode:                "OBSERVE",
			IdentitySalt:        salt,
			TenantRatePerMinute: 1,
			JWTVerification:     jwt,
			Stores:              stores,
		}, nil); err != nil {
			t.Fatal(err)
		}
	}

	process(&detectors.StoreOverrides{TenantRateWindow: first})
	if len(first.calls) != 1 || first.calls[0] != wantKey || len(second.calls) != 0 {
		t.Fatalf("first tenant binding received %v, second received %v; want only salted key %q on first", first.calls, second.calls, wantKey)
	}
	process(&detectors.StoreOverrides{TenantRateWindow: second})
	if len(first.calls) != 1 || len(second.calls) != 1 || second.calls[0] != wantKey {
		t.Fatalf("reloaded tenant binding was not isolated: first=%v second=%v", first.calls, second.calls)
	}
	process(&detectors.StoreOverrides{})
	process(nil)
	if len(first.calls) != 1 || len(second.calls) != 1 {
		t.Fatalf("nil or unbound tenant store reused a stale override: first=%v second=%v", first.calls, second.calls)
	}
}

func objectRateStoreRequest(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "http://h/v1/orders/9", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Authorization", "Bearer object-rate-store-token")
	return r
}

func TestProcessObjectRateStoreBindingAndReloadIsolation(t *testing.T) {
	const salt = "object-rate-store-reload"
	first := &captureWindowStore{}
	second := &captureWindowStore{}
	process := func(stores *detectors.StoreOverrides) {
		t.Helper()
		if _, err := Process(objectRateStoreRequest(t), Config{
			Enabled:             true,
			Mode:                "OBSERVE",
			IdentitySalt:        salt,
			ObjectRatePerMinute: 1,
			Stores:              stores,
		}, nil); err != nil {
			t.Fatal(err)
		}
	}

	process(&detectors.StoreOverrides{ObjectRateWindow: first})
	if len(first.calls) != 1 || len(second.calls) != 0 {
		t.Fatalf("first object-rate binding received %v, second received %v", first.calls, second.calls)
	}

	process(&detectors.StoreOverrides{ObjectRateWindow: second})
	if len(first.calls) != 1 || len(second.calls) != 1 || second.calls[0] != first.calls[0] {
		t.Fatalf("reloaded object-rate binding was not isolated: first=%v second=%v", first.calls, second.calls)
	}

	process(&detectors.StoreOverrides{})
	process(nil)
	if len(first.calls) != 1 || len(second.calls) != 1 {
		t.Fatalf("nil or unbound object-rate store reused a stale override: first=%v second=%v", first.calls, second.calls)
	}
}

type captureQuotaStore struct{ calls []string }

func (c *captureQuotaStore) AddAndCount(key string) int {
	c.calls = append(c.calls, key)
	return 1
}

func quotaStoreRequest(t *testing.T) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "http://h/v1/quota-store", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Authorization", "Bearer quota-store-token")
	return r
}

func TestProcessQuotaStoreBindingAndReloadIsolation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		withStore func(detectors.QuotaStore) *detectors.StoreOverrides
		setLimit  func(*Config)
	}{
		{
			name: "hourly",
			withStore: func(store detectors.QuotaStore) *detectors.StoreOverrides {
				return &detectors.StoreOverrides{HourlyQuota: store}
			},
			setLimit: func(cfg *Config) { cfg.APIQuotaPerHour = 1 },
		},
		{
			name: "daily",
			withStore: func(store detectors.QuotaStore) *detectors.StoreOverrides {
				return &detectors.StoreOverrides{DailyQuota: store}
			},
			setLimit: func(cfg *Config) { cfg.APIQuotaPerDay = 1 },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := &captureQuotaStore{}
			second := &captureQuotaStore{}
			process := func(stores *detectors.StoreOverrides) {
				t.Helper()
				cfg := Config{Enabled: true, Mode: "OBSERVE", Stores: stores}
				tc.setLimit(&cfg)
				if _, err := Process(quotaStoreRequest(t), cfg, nil); err != nil {
					t.Fatal(err)
				}
			}

			process(tc.withStore(first))
			if len(first.calls) != 1 || len(second.calls) != 0 {
				t.Fatalf("first binding received %v, second received %v", first.calls, second.calls)
			}

			process(tc.withStore(second))
			if len(first.calls) != 1 || len(second.calls) != 1 || second.calls[0] != first.calls[0] {
				t.Fatalf("reloaded binding was not isolated: first=%v second=%v", first.calls, second.calls)
			}

			process(&detectors.StoreOverrides{})
			process(nil)
			if len(first.calls) != 1 || len(second.calls) != 1 {
				t.Fatalf("nil or unbound quota store reused a stale override: first=%v second=%v", first.calls, second.calls)
			}
		})
	}
}
