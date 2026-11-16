package tests

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apimodels"
)

type stage8SensitivityRow struct {
	level      string
	confidence float64
}

func s8CreateSensitivityVersion(t *testing.T, env *testEnv, models *apimodels.Store, ep *apiassets.Endpoint, rows ...stage8SensitivityRow) uuid.UUID {
	t.Helper()
	version, err := models.CreateCandidateWithReason(context.Background(), ep.ID, ep.EndpointKey, "DATA_SENSITIVITY test",
		apimodels.CreatedReasonManual, map[string]string{}, uuid.Nil)
	if err != nil {
		t.Fatalf("create model version: %v", err)
	}
	for i, row := range rows {
		name := fmt.Sprintf("p%d", i)
		s8Exec(t, env, `
INSERT INTO api_parameter_models (model_version_id, direction, location, structured_path, parameter_name,
  base_type, sensitivity_level, confidence)
VALUES ($1,'REQUEST','BODY',$2,$2,'string',$3,$4)`, version.ID, name, row.level, row.confidence)
	}
	return version.ID
}

func s8UseSensitivityVersion(t *testing.T, env *testEnv, ep *apiassets.Endpoint, versionID uuid.UUID) {
	t.Helper()
	s8Exec(t, env, `UPDATE api_endpoints SET current_model_version_id=$2 WHERE id=$1`, ep.ID, versionID)
}

func s8AssertDataSensitivity(t *testing.T, env *testEnv, store *apiassets.Store, ep *apiassets.Endpoint, wantLevel string, wantConfidence float64) {
	t.Helper()
	dims, err := store.AutoClassify(context.Background(), ep.ID)
	if err != nil {
		t.Fatalf("AutoClassify: %v", err)
	}
	var found []apiassets.ClassificationDimension
	for _, d := range dims {
		if d.Dimension == "DATA_SENSITIVITY" {
			found = append(found, d)
		}
	}
	if len(found) != 1 {
		t.Fatalf("DATA_SENSITIVITY dimensions=%v, want exactly one", dims)
	}
	dim := found[0]
	if dim.Value != wantLevel || dim.Source != "AUTO" || dim.EndpointID != ep.ID || math.Abs(dim.Confidence-wantConfidence) > 1e-9 {
		t.Fatalf("DATA_SENSITIVITY=%+v, want level=%q confidence=%v source=AUTO endpoint=%s", dim, wantLevel, wantConfidence, ep.ID)
	}
	var value, source string
	var confidence float64
	if err := env.db.QueryRow(context.Background(), `SELECT value, source, confidence FROM api_classification_dimensions
		WHERE endpoint_id=$1 AND dimension='DATA_SENSITIVITY'`, ep.ID).Scan(&value, &source, &confidence); err != nil {
		t.Fatalf("read persisted DATA_SENSITIVITY: %v", err)
	}
	if value != wantLevel || source != "AUTO" || math.Abs(confidence-wantConfidence) > 1e-9 {
		t.Fatalf("persisted DATA_SENSITIVITY=(%q,%q,%v), want (%q,AUTO,%v)", value, source, confidence, wantLevel, wantConfidence)
	}
}

func s8AssertNoDataSensitivity(t *testing.T, env *testEnv, store *apiassets.Store, ep *apiassets.Endpoint) {
	t.Helper()
	dims, err := store.AutoClassify(context.Background(), ep.ID)
	if err != nil {
		t.Fatalf("AutoClassify: %v", err)
	}
	for _, d := range dims {
		if d.Dimension == "DATA_SENSITIVITY" {
			t.Fatalf("unexpected DATA_SENSITIVITY: %+v", d)
		}
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
		WHERE endpoint_id=$1 AND dimension='DATA_SENSITIVITY'`, ep.ID); n != 0 {
		t.Fatalf("DATA_SENSITIVITY row count=%d, want 0", n)
	}
}

func TestStage8APIDataSensitivity(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apiassets.NewStore(env.db)
	models := apimodels.NewStore(env.db)

	t.Run("highest_level_and_max_confidence", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-data-sensitivity/priority", 0.9)
		versionID := s8CreateSensitivityVersion(t, env, models, ep,
			stage8SensitivityRow{level: "LOW", confidence: 1},
			stage8SensitivityRow{level: "MEDIUM", confidence: 0.99},
			stage8SensitivityRow{level: "HIGH", confidence: 0.2},
			stage8SensitivityRow{level: "HIGH", confidence: 0.8},
		)
		s8UseSensitivityVersion(t, env, ep, versionID)
		s8AssertDataSensitivity(t, env, store, ep, "HIGH", 0.8)
	})

	t.Run("unknown", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-data-sensitivity/unknown", 0.9)
		versionID := s8CreateSensitivityVersion(t, env, models, ep,
			stage8SensitivityRow{level: "UNKNOWN", confidence: 0.2},
			stage8SensitivityRow{level: "UNKNOWN", confidence: 0.7},
		)
		s8UseSensitivityVersion(t, env, ep, versionID)
		s8AssertDataSensitivity(t, env, store, ep, "UNKNOWN", 0.7)
	})

	t.Run("confidence_normalized", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-data-sensitivity/confidence", 0.9)
		versionID := s8CreateSensitivityVersion(t, env, models, ep,
			stage8SensitivityRow{level: "MEDIUM", confidence: 1.8},
		)
		s8UseSensitivityVersion(t, env, ep, versionID)
		s8AssertDataSensitivity(t, env, store, ep, "MEDIUM", 1)
	})

	t.Run("no_current_model", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/password/token/no-current-model", 0.9)
		s8AssertNoDataSensitivity(t, env, store, ep)
	})

	t.Run("current_model_without_parameters", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-data-sensitivity/no-parameters", 0.9)
		versionID := s8CreateSensitivityVersion(t, env, models, ep)
		s8UseSensitivityVersion(t, env, ep, versionID)
		s8AssertNoDataSensitivity(t, env, store, ep)
	})

	t.Run("old_candidate_excluded", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-data-sensitivity/current-only", 0.9)
		s8CreateSensitivityVersion(t, env, models, ep, stage8SensitivityRow{level: "HIGH", confidence: 1})
		currentID := s8CreateSensitivityVersion(t, env, models, ep, stage8SensitivityRow{level: "LOW", confidence: 0.4})
		s8UseSensitivityVersion(t, env, ep, currentID)
		s8AssertDataSensitivity(t, env, store, ep, "LOW", 0.4)
	})

	t.Run("classification_locked", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-data-sensitivity/locked", 0.9)
		versionID := s8CreateSensitivityVersion(t, env, models, ep, stage8SensitivityRow{level: "HIGH", confidence: 1})
		s8UseSensitivityVersion(t, env, ep, versionID)
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
