package riskpolicy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func validSharedDeviceLimitPolicy() Policy {
	return Policy{
		Scope: ScopeApplication, Enabled: true, Mode: ModeObserve,
		BlockThreshold: 80, RateLimitThreshold: 40, RateLimitRPS: 10, SignalWindowSeconds: 86400,
		Scores: map[string]int{}, RiskLevels: map[string]int{"medium": 20, "high": 40, "critical": 70},
	}
}

func TestSharedDeviceAccountLimitValidation(t *testing.T) {
	for _, limit := range []int{0, 2, 1000} {
		policy := validSharedDeviceLimitPolicy()
		policy.SharedDeviceAccountLimit = limit
		if errs := Validate(&policy); len(errs) != 0 {
			t.Fatalf("valid limit %d rejected: %+v", limit, errs)
		}
	}
	for _, tc := range []struct {
		scope string
		limit int
	}{
		{ScopeApplication, 1}, {ScopeApplication, 1001}, {ScopeApplication, -1}, {ScopeGlobal, 4},
	} {
		policy := validSharedDeviceLimitPolicy()
		policy.Scope = tc.scope
		policy.SharedDeviceAccountLimit = tc.limit
		errs := Validate(&policy)
		found := false
		for _, err := range errs {
			if err.Field == "shared_device_account_limit" {
				found = true
			}
		}
		if !found {
			t.Fatalf("scope=%s limit=%d should fail field validation: %+v", tc.scope, tc.limit, errs)
		}
	}
}

func TestApplicationOverrideSharedDeviceLimitHTTP(t *testing.T) {
	store := newOverrideTestRepository()
	mux := newOverrideTestMux(store, "risk_policy.read", "risk_policy.edit")
	applicationID := uuid.New()
	path := "/api/v1/security/risk-policy/applications/" + applicationID.String()
	body := `{"enabled":true,"mode":"OBSERVE","version":0,"block_threshold":80,"rate_limit_threshold":40,"rate_limit_rps":10,"signal_window_seconds":86400,"shared_device_account_limit":4,"scores":{},"risk_levels":{"medium":20,"high":40,"critical":70}}`
	rr := overrideRequest(t, mux, http.MethodPut, path, body)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"shared_device_account_limit":4`) {
		t.Fatalf("create custom limit status=%d body=%s", rr.Code, rr.Body.String())
	}
	if store.items[applicationID].SharedDeviceAccountLimit != 4 {
		t.Fatalf("stored policy=%+v", store.items[applicationID])
	}
	for _, limit := range []string{"1", "1001"} {
		invalid := strings.Replace(body, `"shared_device_account_limit":4`, `"shared_device_account_limit":`+limit, 1)
		invalid = strings.Replace(invalid, `"version":0`, `"version":1`, 1)
		rr = overrideRequest(t, mux, http.MethodPut, path, invalid)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("limit=%s status=%d body=%s", limit, rr.Code, rr.Body.String())
		}
	}
}
