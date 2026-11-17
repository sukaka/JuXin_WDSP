package riskpolicy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestValidateChallengeThreshold(t *testing.T) {
	for _, threshold := range []int{0, 41, 79} {
		p := validPolicy()
		p.ChallengeThreshold = threshold
		if errs := Validate(p); len(errs) != 0 {
			t.Fatalf("valid challenge threshold %d rejected: %+v", threshold, errs)
		}
	}
	for _, threshold := range []int{-1, 40, 80, 101} {
		p := validPolicy()
		p.ChallengeThreshold = threshold
		assertFieldErr(t, Validate(p), "challenge_threshold")
	}
}

func TestUpdateRequestChallengeThresholdCompatibility(t *testing.T) {
	before := &Policy{ChallengeThreshold: 60}
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{name: "omitted inherits", body: `{}`, want: 60},
		{name: "explicit zero disables", body: `{"challenge_threshold":0}`, want: 0},
		{name: "explicit value", body: `{"challenge_threshold":55}`, want: 55},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var req updateRequest
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatal(err)
			}
			if got := req.challengeThreshold(before); got != tc.want {
				t.Fatalf("challenge threshold = %d, want %d", got, tc.want)
			}
		})
	}
	var req updateRequest
	if got := req.challengeThreshold(nil); got != 0 {
		t.Fatalf("new override omitted challenge threshold = %d, want 0", got)
	}
}

func TestApplicationOverrideChallengeThresholdCompatibility(t *testing.T) {
	store := newOverrideTestRepository()
	mux := newOverrideTestMux(store, "risk_policy.edit")
	applicationID := uuid.New()
	path := "/api/v1/security/risk-policy/applications/" + applicationID.String()
	body := `{"enabled":true,"mode":"OBSERVE","version":0,"block_threshold":80,"rate_limit_threshold":40,"challenge_threshold":60,"rate_limit_rps":10,"signal_window_seconds":86400,"scores":{},"risk_levels":{"medium":20,"high":40,"critical":70}}`
	if rr := overrideRequest(t, mux, http.MethodPut, path, body); rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := store.items[applicationID].ChallengeThreshold; got != 60 {
		t.Fatalf("created challenge threshold=%d, want 60", got)
	}

	legacyBody := strings.Replace(body, `"version":0`, `"version":1`, 1)
	legacyBody = strings.Replace(legacyBody, `,"challenge_threshold":60`, "", 1)
	if rr := overrideRequest(t, mux, http.MethodPut, path, legacyBody); rr.Code != http.StatusOK {
		t.Fatalf("legacy update status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := store.items[applicationID].ChallengeThreshold; got != 60 {
		t.Fatalf("legacy update discarded challenge threshold: %d", got)
	}

	zeroBody := strings.Replace(body, `"version":0`, `"version":2`, 1)
	zeroBody = strings.Replace(zeroBody, `"challenge_threshold":60`, `"challenge_threshold":0`, 1)
	rr := overrideRequest(t, mux, http.MethodPut, path, zeroBody)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"challenge_threshold":0`) {
		t.Fatalf("explicit zero status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := store.items[applicationID].ChallengeThreshold; got != 0 {
		t.Fatalf("explicit zero was not stored: %d", got)
	}
}
