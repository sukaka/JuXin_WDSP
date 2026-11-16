package tests

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/jiuzhang-waf/server/internal/apiassets"
)

func s8SeedRiskFinding(t *testing.T, env *testEnv, ep *apiassets.Endpoint, findingType, severity, status string) {
	t.Helper()
	s8Exec(t, env, `INSERT INTO api_runtime_findings (endpoint_id, finding_type, severity, status)
		VALUES ($1,$2,$3,$4)`, ep.ID, findingType, severity, status)
}

func s8SeedRiskLabel(t *testing.T, env *testEnv, ep *apiassets.Endpoint, value string) {
	t.Helper()
	s8Exec(t, env, `INSERT INTO api_classification_dimensions (endpoint_id, dimension, value, source, confidence)
		VALUES ($1,'RISK_LABEL',$2,'AUTO',0.4)`, ep.ID, value)
}

func s8AssertRiskLabel(t *testing.T, env *testEnv, store *apiassets.Store, ep *apiassets.Endpoint, wantValue string, wantConfidence float64) {
	t.Helper()
	dims, err := store.AutoClassify(context.Background(), ep.ID)
	if err != nil {
		t.Fatalf("AutoClassify: %v", err)
	}
	var found []apiassets.ClassificationDimension
	for _, d := range dims {
		if d.Dimension == "RISK_LABEL" {
			found = append(found, d)
		}
	}
	if len(found) != 1 {
		t.Fatalf("RISK_LABEL dimensions=%v, want exactly one", dims)
	}
	dim := found[0]
	if dim.Value != wantValue || dim.Source != "AUTO" || dim.EndpointID != ep.ID || math.Abs(dim.Confidence-wantConfidence) > 1e-9 {
		t.Fatalf("RISK_LABEL=%+v, want value=%q source=AUTO confidence=%v endpoint=%s", dim, wantValue, wantConfidence, ep.ID)
	}
	var value, source string
	var confidence float64
	if err := env.db.QueryRow(context.Background(), `SELECT value, source, confidence FROM api_classification_dimensions
		WHERE endpoint_id=$1 AND dimension='RISK_LABEL'`, ep.ID).Scan(&value, &source, &confidence); err != nil {
		t.Fatalf("read persisted RISK_LABEL: %v", err)
	}
	if value != wantValue || source != "AUTO" || math.Abs(confidence-wantConfidence) > 1e-9 {
		t.Fatalf("persisted RISK_LABEL=(%q,%q,%v), want (%q,AUTO,%v)", value, source, confidence, wantValue, wantConfidence)
	}
}

func s8AssertNoRiskLabel(t *testing.T, env *testEnv, store *apiassets.Store, ep *apiassets.Endpoint) {
	t.Helper()
	dims, err := store.AutoClassify(context.Background(), ep.ID)
	if err != nil {
		t.Fatalf("AutoClassify: %v", err)
	}
	for _, d := range dims {
		if d.Dimension == "RISK_LABEL" {
			t.Fatalf("unexpected RISK_LABEL: %+v", d)
		}
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
		WHERE endpoint_id=$1 AND dimension='RISK_LABEL'`, ep.ID); n != 0 {
		t.Fatalf("RISK_LABEL row count=%d, want 0", n)
	}
}

func TestStage8APIRiskLabel(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apiassets.NewStore(env.db)

	severityCases := []struct {
		severity, status, findingType, wantValue string
		wantConfidence                           float64
	}{
		{severity: "INFO", status: "NEW", findingType: "  vendor_rule_9  ", wantValue: "VENDOR_RULE_9", wantConfidence: 0.2},
		{severity: "LOW", status: "CONFIRMED", findingType: "LOW_RISK", wantValue: "LOW_RISK", wantConfidence: 0.4},
		{severity: "MEDIUM", status: "IN_PROGRESS", findingType: "MEDIUM_RISK", wantValue: "MEDIUM_RISK", wantConfidence: 0.6},
		{severity: "HIGH", status: "NEW", findingType: "HIGH_RISK", wantValue: "HIGH_RISK", wantConfidence: 0.8},
		{severity: "CRITICAL", status: "CONFIRMED", findingType: "CRITICAL_RISK", wantValue: "CRITICAL_RISK", wantConfidence: 1},
	}
	for _, c := range severityCases {
		t.Run("severity_"+c.severity, func(t *testing.T) {
			ep := s8SeedEndpoint(t, env, "GET", "/s8-risk/severity/"+c.severity, 0.9)
			s8SeedRiskFinding(t, env, ep, c.findingType, c.severity, c.status)
			s8AssertRiskLabel(t, env, store, ep, c.wantValue, c.wantConfidence)
		})
	}

	t.Run("highest_severity_wins", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-risk/priority", 0.9)
		s8SeedRiskFinding(t, env, ep, "LOW_RISK", "LOW", "NEW")
		s8SeedRiskFinding(t, env, ep, "CRITICAL_ONLY", "CRITICAL", "NEW")
		s8SeedRiskFinding(t, env, ep, "HIGH_RISK", "HIGH", "NEW")
		s8AssertRiskLabel(t, env, store, ep, "CRITICAL_ONLY", 1)
	})

	t.Run("multiple_types_at_highest_severity", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-risk/multi", 0.9)
		s8SeedRiskFinding(t, env, ep, "BOLA", "HIGH", "NEW")
		s8SeedRiskFinding(t, env, ep, "LOW_RISK", "LOW", "NEW")
		s8SeedRiskFinding(t, env, ep, "BFLA", "HIGH", "CONFIRMED")
		s8AssertRiskLabel(t, env, store, ep, "MULTI_RISK", 0.8)
	})

	t.Run("normalized_duplicate_type_deduplicated", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-risk/deduplicated", 0.9)
		s8SeedRiskFinding(t, env, ep, " bola ", "HIGH", "NEW")
		s8SeedRiskFinding(t, env, ep, "BOLA", "HIGH", "CONFIRMED")
		s8AssertRiskLabel(t, env, store, ep, "BOLA", 0.8)
	})

	for _, status := range []string{"RESOLVED", "FALSE_POSITIVE", "IGNORED", "ARCHIVED"} {
		t.Run("closed_status_"+status, func(t *testing.T) {
			ep := s8SeedEndpoint(t, env, "GET", "/s8-risk/closed/"+status, 0.9)
			s8SeedRiskLabel(t, env, ep, "STALE_RISK")
			s8SeedRiskFinding(t, env, ep, "CLOSED_RISK", "CRITICAL", status)
			s8AssertNoRiskLabel(t, env, store, ep)
		})
	}

	t.Run("no_findings_clears_stale_label", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-risk/no-findings", 0.9)
		s8SeedRiskLabel(t, env, ep, "STALE_RISK")
		s8AssertNoRiskLabel(t, env, store, ep)
	})

	t.Run("closed_invalid_type_ignored", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-risk/closed-invalid", 0.9)
		s8SeedRiskLabel(t, env, ep, "STALE_RISK")
		s8SeedRiskFinding(t, env, ep, "bad-type", "CRITICAL", "RESOLVED")
		s8AssertNoRiskLabel(t, env, store, ep)
	})

	t.Run("invalid_active_type_rolls_back", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-risk/invalid-active", 0.9)
		s8SeedRiskLabel(t, env, ep, "STALE_RISK")
		s8SeedRiskFinding(t, env, ep, "BOLA", "CRITICAL", "NEW")
		s8SeedRiskFinding(t, env, ep, "bad-type", "INFO", "NEW")
		if _, err := store.AutoClassify(ctx, ep.ID); err == nil {
			t.Fatal("invalid active finding_type should fail")
		}
		if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
			WHERE endpoint_id=$1 AND dimension='RISK_LABEL' AND value='STALE_RISK'`, ep.ID); n != 1 {
			t.Fatalf("stale RISK_LABEL count after rollback=%d, want 1", n)
		}
		if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
			WHERE endpoint_id=$1 AND dimension<>'RISK_LABEL'`, ep.ID); n != 0 {
			t.Fatalf("rollback wrote %d unrelated dimensions, want 0", n)
		}
	})

	t.Run("classification_locked", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-risk/locked", 0.9)
		s8SeedRiskLabel(t, env, ep, "STALE_RISK")
		s8SeedRiskFinding(t, env, ep, "bad-type", "CRITICAL", "NEW")
		if err := store.SetClassificationLocked(ctx, ep.ID, true); err != nil {
			t.Fatalf("lock classification: %v", err)
		}
		if _, err := store.AutoClassify(ctx, ep.ID); !errors.Is(err, apiassets.ErrClassificationLocked) {
			t.Fatalf("AutoClassify locked error=%v, want ErrClassificationLocked", err)
		}
		if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
			WHERE endpoint_id=$1 AND dimension='RISK_LABEL' AND value='STALE_RISK'`, ep.ID); n != 1 {
			t.Fatalf("locked stale RISK_LABEL count=%d, want 1", n)
		}
		if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
			WHERE endpoint_id=$1 AND dimension<>'RISK_LABEL'`, ep.ID); n != 0 {
			t.Fatalf("locked classification wrote %d unrelated dimensions, want 0", n)
		}
	})
}
