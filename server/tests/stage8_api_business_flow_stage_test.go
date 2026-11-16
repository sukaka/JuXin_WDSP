package tests

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

type stage8BusinessFlowStep struct {
	endpoint     *apiassets.Endpoint
	sequence     int
	predecessors []string
	terminal     bool
}

func s8SeedBusinessFlow(t *testing.T, env *testEnv, flowID string, enabled bool, steps ...stage8BusinessFlowStep) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := env.db.QueryRow(context.Background(), `INSERT INTO api_flow_baselines (flow_id, enabled)
		VALUES ($1,$2) RETURNING id`, flowID, enabled).Scan(&id); err != nil {
		t.Fatalf("insert flow baseline: %v", err)
	}
	for i, step := range steps {
		predecessors := step.predecessors
		if predecessors == nil {
			predecessors = []string{}
		}
		s8Exec(t, env, `
INSERT INTO api_flow_baseline_steps (flow_baseline_id, step_id, endpoint_id, sequence, predecessors, terminal)
VALUES ($1,$2,$3,$4,$5,$6)`, id, fmt.Sprintf("step-%d", i), step.endpoint.ID, step.sequence, predecessors, step.terminal)
	}
	return id
}

func s8AssertBusinessFlowStage(t *testing.T, env *testEnv, store *apiassets.Store, ep *apiassets.Endpoint, wantValue string) {
	t.Helper()
	dims, err := store.AutoClassify(context.Background(), ep.ID)
	if err != nil {
		t.Fatalf("AutoClassify: %v", err)
	}
	var found []apiassets.ClassificationDimension
	for _, d := range dims {
		if d.Dimension == "BUSINESS_FLOW_STAGE" {
			found = append(found, d)
		}
	}
	if len(found) != 1 {
		t.Fatalf("BUSINESS_FLOW_STAGE dimensions=%v, want exactly one", dims)
	}
	dim := found[0]
	if dim.Value != wantValue || dim.Source != "AUTO" || dim.EndpointID != ep.ID || dim.Confidence != 1 {
		t.Fatalf("BUSINESS_FLOW_STAGE=%+v, want value=%q source=AUTO confidence=1 endpoint=%s", dim, wantValue, ep.ID)
	}
	var value, source string
	var confidence float64
	if err := env.db.QueryRow(context.Background(), `SELECT value, source, confidence FROM api_classification_dimensions
		WHERE endpoint_id=$1 AND dimension='BUSINESS_FLOW_STAGE'`, ep.ID).Scan(&value, &source, &confidence); err != nil {
		t.Fatalf("read persisted BUSINESS_FLOW_STAGE: %v", err)
	}
	if value != wantValue || source != "AUTO" || confidence != 1 {
		t.Fatalf("persisted BUSINESS_FLOW_STAGE=(%q,%q,%v), want (%q,AUTO,1)", value, source, confidence, wantValue)
	}
}

func s8AssertNoBusinessFlowStage(t *testing.T, env *testEnv, store *apiassets.Store, ep *apiassets.Endpoint) {
	t.Helper()
	dims, err := store.AutoClassify(context.Background(), ep.ID)
	if err != nil {
		t.Fatalf("AutoClassify: %v", err)
	}
	for _, d := range dims {
		if d.Dimension == "BUSINESS_FLOW_STAGE" {
			t.Fatalf("unexpected BUSINESS_FLOW_STAGE: %+v", d)
		}
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
		WHERE endpoint_id=$1 AND dimension='BUSINESS_FLOW_STAGE'`, ep.ID); n != 0 {
		t.Fatalf("BUSINESS_FLOW_STAGE row count=%d, want 0", n)
	}
}

func TestStage8APIBusinessFlowStage(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apiassets.NewStore(env.db)

	t.Run("start_and_terminal", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-flow/start-terminal", 0.9)
		s8SeedBusinessFlow(t, env, "flow-start-terminal", true,
			stage8BusinessFlowStep{endpoint: ep, sequence: 5, terminal: true})
		s8AssertBusinessFlowStage(t, env, store, ep, "START_AND_TERMINAL")
	})

	t.Run("terminal_not_start", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-flow/terminal", 0.9)
		other := s8SeedEndpoint(t, env, "POST", "/s8-flow/terminal-first", 0.9)
		s8SeedBusinessFlow(t, env, "flow-terminal", true,
			stage8BusinessFlowStep{endpoint: other, sequence: 1},
			stage8BusinessFlowStep{endpoint: ep, sequence: 2, terminal: true})
		s8AssertBusinessFlowStage(t, env, store, ep, "TERMINAL")
	})

	t.Run("start", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-flow/start", 0.9)
		other := s8SeedEndpoint(t, env, "POST", "/s8-flow/start-last", 0.9)
		s8SeedBusinessFlow(t, env, "flow-start", true,
			stage8BusinessFlowStep{endpoint: ep, sequence: 1},
			stage8BusinessFlowStep{endpoint: other, sequence: 2, predecessors: []string{"step-0"}, terminal: true})
		s8AssertBusinessFlowStage(t, env, store, ep, "START")
	})

	t.Run("max_sequence_is_not_start_or_terminal", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-flow/intermediate", 0.9)
		other := s8SeedEndpoint(t, env, "POST", "/s8-flow/intermediate-first", 0.9)
		s8SeedBusinessFlow(t, env, "flow-intermediate", true,
			stage8BusinessFlowStep{endpoint: other, sequence: 1},
			stage8BusinessFlowStep{endpoint: ep, sequence: 9})
		s8AssertBusinessFlowStage(t, env, store, ep, "INTERMEDIATE")
	})

	t.Run("multiple_roles_are_multi_stage", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-flow/multi", 0.9)
		other := s8SeedEndpoint(t, env, "POST", "/s8-flow/multi-other", 0.9)
		s8SeedBusinessFlow(t, env, "flow-multi-start", true,
			stage8BusinessFlowStep{endpoint: ep, sequence: 1},
			stage8BusinessFlowStep{endpoint: other, sequence: 2, predecessors: []string{"step-0"}, terminal: true})
		s8SeedBusinessFlow(t, env, "flow-multi-terminal", true,
			stage8BusinessFlowStep{endpoint: other, sequence: 1},
			stage8BusinessFlowStep{endpoint: ep, sequence: 2, terminal: true})
		s8AssertBusinessFlowStage(t, env, store, ep, "MULTI_STAGE")
	})

	t.Run("same_role_across_flows_deduplicated", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-flow/same-role", 0.9)
		s8SeedBusinessFlow(t, env, "flow-same-role-1", true,
			stage8BusinessFlowStep{endpoint: ep, sequence: 1})
		s8SeedBusinessFlow(t, env, "flow-same-role-2", true,
			stage8BusinessFlowStep{endpoint: ep, sequence: 3})
		s8AssertBusinessFlowStage(t, env, store, ep, "START")
	})

	t.Run("disabled_flow_ignored", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-flow/disabled", 0.9)
		s8SeedBusinessFlow(t, env, "flow-disabled", false,
			stage8BusinessFlowStep{endpoint: ep, sequence: 1, terminal: true})
		s8AssertNoBusinessFlowStage(t, env, store, ep)
	})

	t.Run("classification_locked", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "POST", "/s8-flow/locked", 0.9)
		s8SeedBusinessFlow(t, env, "flow-locked", true,
			stage8BusinessFlowStep{endpoint: ep, sequence: 1})
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
