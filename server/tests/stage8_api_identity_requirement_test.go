package tests

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/apiassets"
)

func s8SeedIdentityRuntimeEvent(t *testing.T, env *testEnv, endpointKey, requestID, authType string, status int, occurredAt time.Time) {
	t.Helper()
	s8Exec(t, env, `
INSERT INTO api_runtime_events (request_id, endpoint_key, occurred_at, auth_type, response_status)
VALUES ($1,$2,$3,$4,$5)`, requestID, endpointKey, occurredAt, authType, status)
}

func s8AssertIdentityRequirement(t *testing.T, env *testEnv, store *apiassets.Store, ep *apiassets.Endpoint, wantValue string) {
	t.Helper()
	dims, err := store.AutoClassify(context.Background(), ep.ID)
	if err != nil {
		t.Fatalf("AutoClassify: %v", err)
	}
	var found []apiassets.ClassificationDimension
	for _, d := range dims {
		if d.Dimension == "IDENTITY_REQUIREMENT" {
			found = append(found, d)
		}
	}
	if len(found) != 1 {
		t.Fatalf("IDENTITY_REQUIREMENT dimensions=%v, want exactly one", dims)
	}
	dim := found[0]
	if dim.Value != wantValue || dim.Source != "AUTO" || dim.EndpointID != ep.ID || math.Abs(dim.Confidence-0.7) > 1e-9 {
		t.Fatalf("IDENTITY_REQUIREMENT=%+v, want value=%q source=AUTO confidence=0.7 endpoint=%s", dim, wantValue, ep.ID)
	}
	var value, source string
	var confidence float64
	if err := env.db.QueryRow(context.Background(), `SELECT value, source, confidence FROM api_classification_dimensions
		WHERE endpoint_id=$1 AND dimension='IDENTITY_REQUIREMENT'`, ep.ID).Scan(&value, &source, &confidence); err != nil {
		t.Fatalf("read persisted IDENTITY_REQUIREMENT: %v", err)
	}
	if value != wantValue || source != "AUTO" || math.Abs(confidence-0.7) > 1e-9 {
		t.Fatalf("persisted IDENTITY_REQUIREMENT=(%q,%q,%v), want (%q,AUTO,0.7)", value, source, confidence, wantValue)
	}
}

func s8AssertNoIdentityRequirement(t *testing.T, env *testEnv, store *apiassets.Store, ep *apiassets.Endpoint) {
	t.Helper()
	dims, err := store.AutoClassify(context.Background(), ep.ID)
	if err != nil {
		t.Fatalf("AutoClassify: %v", err)
	}
	for _, d := range dims {
		if d.Dimension == "IDENTITY_REQUIREMENT" {
			t.Fatalf("unexpected IDENTITY_REQUIREMENT: %+v", d)
		}
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
		WHERE endpoint_id=$1 AND dimension='IDENTITY_REQUIREMENT'`, ep.ID); n != 0 {
		t.Fatalf("IDENTITY_REQUIREMENT row count=%d, want 0", n)
	}
}

func TestStage8APIIdentityRequirement(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apiassets.NewStore(env.db)
	now := time.Now().UTC()
	recent := now.Add(-time.Minute)
	old := now.AddDate(0, 0, -31)

	t.Run("anonymous_success_status_boundaries", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-identity/anonymous-success", 0.9)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-anon-200", "", 200, recent)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-anon-399", "", 399, recent)
		s8AssertIdentityRequirement(t, env, store, ep, "ANONYMOUS_ALLOWED")
	})

	t.Run("anonymous_rejected_401", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-identity/anonymous-401", 0.9)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-anon-401", "", 401, recent)
		s8AssertIdentityRequirement(t, env, store, ep, "ANONYMOUS_REJECTED")
	})

	t.Run("anonymous_rejected_403", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-identity/anonymous-403", 0.9)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-anon-403", "", 403, recent)
		s8AssertIdentityRequirement(t, env, store, ep, "ANONYMOUS_REJECTED")
	})

	t.Run("authenticated_only", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-identity/authenticated", 0.9)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-auth-200", "api_key", 200, recent)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-auth-401", "api_key", 401, recent)
		s8AssertIdentityRequirement(t, env, store, ep, "AUTHENTICATED_OBSERVED")
	})

	t.Run("auth_optional_priority", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-identity/optional", 0.9)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-optional-anon", "", 200, recent)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-optional-reject", "", 403, recent)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-optional-auth", "cookie_session", 399, recent)
		s8AssertIdentityRequirement(t, env, store, ep, "AUTH_OPTIONAL")
	})

	t.Run("auth_required", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-identity/required", 0.9)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-required-anon", "", 401, recent)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-required-auth", "bearer_or_basic", 200, recent)
		s8AssertIdentityRequirement(t, env, store, ep, "AUTH_REQUIRED")
	})

	t.Run("anonymous_success_priority", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-identity/anonymous-priority", 0.9)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-priority-success", "", 200, recent)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-priority-reject", "", 403, recent)
		s8AssertIdentityRequirement(t, env, store, ep, "ANONYMOUS_ALLOWED")
	})

	t.Run("old_invalid_and_other_endpoint_events", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-identity/no-effective-events", 0.9)
		other := s8SeedEndpoint(t, env, "GET", "/s8-identity/other", 0.9)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-old-success", "", 200, old)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-status-199", "", 199, recent)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-status-400", "", 400, recent)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-status-404", "", 404, recent)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-auth-403", "api_key", 403, recent)
		s8SeedIdentityRuntimeEvent(t, env, other.EndpointKey, "identity-other-success", "", 200, recent)
		s8AssertNoIdentityRequirement(t, env, store, ep)
	})

	t.Run("classification_locked", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-identity/locked", 0.9)
		s8SeedIdentityRuntimeEvent(t, env, ep.EndpointKey, "identity-locked-success", "", 200, recent)
		if err := store.SetClassificationLocked(ctx, ep.ID, true); err != nil {
			t.Fatalf("lock classification: %v", err)
		}
		if _, err := store.AutoClassify(ctx, ep.ID); !errors.Is(err, apiassets.ErrClassificationLocked) {
			t.Fatalf("AutoClassify locked error=%v, want ErrClassificationLocked", err)
		}
		if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions WHERE endpoint_id=$1`, ep.ID); n != 0 {
			t.Fatalf("locked classification wrote %d rows, want 0", n)
		}
	})
}
