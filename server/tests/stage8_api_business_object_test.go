package tests

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/jiuzhang-waf/server/internal/apiassets"
)

func s8SeedBusinessObjectModel(t *testing.T, env *testEnv, ep *apiassets.Endpoint, segment string, publishable bool) {
	t.Helper()
	s8Exec(t, env, `INSERT INTO api_object_models (endpoint_id, object_segment, publishable)
		VALUES ($1,$2,$3)`, ep.ID, segment, publishable)
}

func s8SeedBusinessObjectLabel(t *testing.T, env *testEnv, ep *apiassets.Endpoint, value string) {
	t.Helper()
	s8Exec(t, env, `INSERT INTO api_classification_dimensions (endpoint_id, dimension, value, source, confidence)
		VALUES ($1,'BUSINESS_OBJECT',$2,'AUTO',0.65)`, ep.ID, value)
}

func s8AssertBusinessObject(t *testing.T, env *testEnv, store *apiassets.Store, ep *apiassets.Endpoint, wantValue string, wantConfidence float64) {
	t.Helper()
	dims, err := store.AutoClassify(context.Background(), ep.ID)
	if err != nil {
		t.Fatalf("AutoClassify: %v", err)
	}
	var found []apiassets.ClassificationDimension
	for _, d := range dims {
		if d.Dimension == "BUSINESS_OBJECT" {
			found = append(found, d)
		}
	}
	if len(found) != 1 {
		t.Fatalf("BUSINESS_OBJECT dimensions=%v, want exactly one", dims)
	}
	dim := found[0]
	if dim.Value != wantValue || dim.Source != "AUTO" || dim.EndpointID != ep.ID || math.Abs(dim.Confidence-wantConfidence) > 1e-9 {
		t.Fatalf("BUSINESS_OBJECT=%+v, want value=%q source=AUTO confidence=%v endpoint=%s", dim, wantValue, wantConfidence, ep.ID)
	}
	var value, source string
	var confidence float64
	if err := env.db.QueryRow(context.Background(), `SELECT value, source, confidence FROM api_classification_dimensions
		WHERE endpoint_id=$1 AND dimension='BUSINESS_OBJECT'`, ep.ID).Scan(&value, &source, &confidence); err != nil {
		t.Fatalf("read persisted BUSINESS_OBJECT: %v", err)
	}
	if value != wantValue || source != "AUTO" || math.Abs(confidence-wantConfidence) > 1e-9 {
		t.Fatalf("persisted BUSINESS_OBJECT=(%q,%q,%v), want (%q,AUTO,%v)", value, source, confidence, wantValue, wantConfidence)
	}
}

func s8AssertNoBusinessObject(t *testing.T, env *testEnv, store *apiassets.Store, ep *apiassets.Endpoint) {
	t.Helper()
	dims, err := store.AutoClassify(context.Background(), ep.ID)
	if err != nil {
		t.Fatalf("AutoClassify: %v", err)
	}
	for _, d := range dims {
		if d.Dimension == "BUSINESS_OBJECT" {
			t.Fatalf("unexpected BUSINESS_OBJECT: %+v", d)
		}
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
		WHERE endpoint_id=$1 AND dimension='BUSINESS_OBJECT'`, ep.ID); n != 0 {
		t.Fatalf("BUSINESS_OBJECT row count=%d, want 0", n)
	}
}

func TestStage8APIBusinessObject(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apiassets.NewStore(env.db)

	t.Run("query_without_segments", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-object/query", 0.9)
		s8Exec(t, env, `DELETE FROM api_endpoint_path_segments WHERE endpoint_id=$1`, ep.ID)
		s8SeedBusinessObjectModel(t, env, ep, "query: account_id ", false)
		s8AssertBusinessObject(t, env, store, ep, "ACCOUNT_ID", 0.65)
	})

	t.Run("nearest_previous_static_segment", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/api/orders/{order_id}/items/{item_id}", 0.9)
		s8SeedBusinessObjectModel(t, env, ep, "path:4", false)
		s8AssertBusinessObject(t, env, store, ep, "ITEMS", 0.65)
	})

	t.Run("variable_name_fallback", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/{order_id}", 0.9)
		s8SeedBusinessObjectModel(t, env, ep, "path:0", false)
		s8AssertBusinessObject(t, env, store, ep, "ORDER_ID", 0.65)
	})

	t.Run("multiple_objects_and_publishable_confidence", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/orders/{order_id}", 0.9)
		s8SeedBusinessObjectModel(t, env, ep, "path:1", false)
		s8SeedBusinessObjectModel(t, env, ep, "query:account_id", true)
		s8AssertBusinessObject(t, env, store, ep, "MULTI_OBJECT", 0.9)
	})

	t.Run("same_object_deduplicated", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/{order_id}", 0.9)
		s8SeedBusinessObjectModel(t, env, ep, "path:0", false)
		s8SeedBusinessObjectModel(t, env, ep, "query:order_id", true)
		s8AssertBusinessObject(t, env, store, ep, "ORDER_ID", 0.9)
	})

	t.Run("missing_segment_clears_stale_label", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/orders/{order_id}", 0.9)
		s8SeedBusinessObjectModel(t, env, ep, "path:1", true)
		s8SeedBusinessObjectLabel(t, env, ep, "STALE_OBJECT")
		s8Exec(t, env, `DELETE FROM api_endpoint_path_segments WHERE endpoint_id=$1 AND position=1`, ep.ID)
		s8AssertNoBusinessObject(t, env, store, ep)
	})

	t.Run("no_models_clears_stale_label", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/orders/{order_id}", 0.9)
		s8SeedBusinessObjectLabel(t, env, ep, "STALE_OBJECT")
		s8AssertNoBusinessObject(t, env, store, ep)
	})

	t.Run("control_character_rolls_back", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/orders/{order_id}", 0.9)
		s8SeedBusinessObjectLabel(t, env, ep, "STALE_OBJECT")
		s8SeedBusinessObjectModel(t, env, ep, "query:bad\nname", true)
		if _, err := store.AutoClassify(ctx, ep.ID); err == nil {
			t.Fatal("control character in object value should fail")
		}
		if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
			WHERE endpoint_id=$1 AND dimension='BUSINESS_OBJECT' AND value='STALE_OBJECT'`, ep.ID); n != 1 {
			t.Fatalf("stale BUSINESS_OBJECT count after rollback=%d, want 1", n)
		}
		if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
			WHERE endpoint_id=$1 AND dimension<>'BUSINESS_OBJECT'`, ep.ID); n != 0 {
			t.Fatalf("rollback wrote %d unrelated dimensions, want 0", n)
		}
	})

	t.Run("non_variable_path_target_rolls_back", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/orders/{order_id}", 0.9)
		s8SeedBusinessObjectLabel(t, env, ep, "STALE_OBJECT")
		s8SeedBusinessObjectModel(t, env, ep, "path:0", false)
		if _, err := store.AutoClassify(ctx, ep.ID); err == nil {
			t.Fatal("non-variable path target should fail")
		}
		if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
			WHERE endpoint_id=$1 AND dimension='BUSINESS_OBJECT' AND value='STALE_OBJECT'`, ep.ID); n != 1 {
			t.Fatalf("stale BUSINESS_OBJECT count after rollback=%d, want 1", n)
		}
	})

	t.Run("classification_locked", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/orders/{order_id}", 0.9)
		s8SeedBusinessObjectLabel(t, env, ep, "STALE_OBJECT")
		s8SeedBusinessObjectModel(t, env, ep, "query:bad\nname", true)
		if err := store.SetClassificationLocked(ctx, ep.ID, true); err != nil {
			t.Fatalf("lock classification: %v", err)
		}
		if _, err := store.AutoClassify(ctx, ep.ID); !errors.Is(err, apiassets.ErrClassificationLocked) {
			t.Fatalf("AutoClassify locked error=%v, want ErrClassificationLocked", err)
		}
		if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
			WHERE endpoint_id=$1 AND dimension='BUSINESS_OBJECT' AND value='STALE_OBJECT'`, ep.ID); n != 1 {
			t.Fatalf("locked stale BUSINESS_OBJECT count=%d, want 1", n)
		}
		if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
			WHERE endpoint_id=$1 AND dimension<>'BUSINESS_OBJECT'`, ep.ID); n != 0 {
			t.Fatalf("locked classification wrote %d unrelated dimensions, want 0", n)
		}
	})
}
