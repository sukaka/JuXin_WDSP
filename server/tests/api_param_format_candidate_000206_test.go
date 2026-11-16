package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

func TestAPIParamFormatCandidateMigration000206Static(t *testing.T) {
	up := readMigration(t, "000206_api_param_format_candidate.up.sql")
	for _, fragment := range []string{
		"api_parameter_value_obs", "format_sample_count", "format_counts",
		"api_parameter_statistics", "format_candidate", "format_candidate_ratio",
		"BIGINT NOT NULL DEFAULT 0", "JSONB NOT NULL DEFAULT '{}'::jsonb",
		"UUID/EMAIL/IPV4/IPV6/DATE/DATETIME", ">=0.9",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("000206 up missing %q: %s", fragment, up)
		}
	}
	down := readMigration(t, "000206_api_param_format_candidate.down.sql")
	for _, fragment := range []string{
		"DROP COLUMN IF EXISTS format_sample_count",
		"DROP COLUMN IF EXISTS format_counts",
		"DROP COLUMN IF EXISTS format_candidate",
		"DROP COLUMN IF EXISTS format_candidate_ratio",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("000206 down missing %q: %s", fragment, down)
		}
	}
}

type formatCandidateState000206 struct {
	samples     int64
	counts      map[string]int64
	candidate   *string
	ratio       *float64
	observed    map[string]any
	recommended map[string]any
	confirmed   map[string]any
}

func TestAPIParamFormatCandidate000206Integration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	up := readMigration(t, "000206_api_param_format_candidate.up.sql")
	down := readMigration(t, "000206_api_param_format_candidate.down.sql")

	assertFormatCandidateColumns000206(t, env, 2, 2)
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, up); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}

	models := apimodels.NewStore(env.db)
	ep := s8SeedEndpoint(t, env, "POST", "/s8-format-"+s5Rand(), 0.9)
	version, err := models.CreateCandidateWithReason(ctx, ep.ID, ep.EndpointKey, "format candidate",
		apimodels.CreatedReasonManual, map[string]string{"value": "string", "legacy": "string"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate: %v", err)
	}
	if _, err := models.Confirm(ctx, version.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	s8Exec(t, env, `UPDATE api_endpoints SET learning_status='LEARNED' WHERE id=$1`, ep.ID)
	s8Exec(t, env, `
INSERT INTO api_learning_samples (api_endpoint_id, request_id, sample_hash, source_fingerprint, response_status, accepted, exclude_reason)
SELECT $1, 'format-'||g, 'format-hash-'||g, 'src', 200, true, '' FROM generate_series(1,100) AS g`, ep.ID)
	s8Exec(t, env, `UPDATE api_parameter_models SET confirmed_constraints='{"max_length":4096}'::jsonb
WHERE model_version_id=$1 AND structured_path='value'`, version.ID)

	observations := make([]apiruntime.ParamObservation, 0, 26)
	for i := 0; i < 18; i++ {
		observations = append(observations, apiruntime.ParamObservation{
			Location: "BODY", Name: "value", Path: "value", BaseType: "string", Length: 36,
			ValueHash: fmt.Sprintf("uuid-%02d", i), FormatSample: true, FormatCandidate: "UUID",
		})
	}
	for i := 0; i < 2; i++ {
		observations = append(observations, apiruntime.ParamObservation{
			Location: "BODY", Name: "value", Path: "value", BaseType: "string", Length: 5,
			ValueHash: fmt.Sprintf("unknown-%02d", i), FormatSample: true,
		})
	}
	observations = append(observations,
		apiruntime.ParamObservation{Location: "BODY", Name: "value", Path: "value", BaseType: "string", Length: 36, FormatSample: true, FormatCandidate: "EMAIL"},
		apiruntime.ParamObservation{Location: "BODY", Name: "value", Path: "value", BaseType: "string", ValueHash: "empty", FormatSample: true},
		apiruntime.ParamObservation{Location: "BODY", Name: "value", Path: "value", BaseType: "number", Length: 3, ValueHash: "number", FormatSample: true, FormatCandidate: "IPV4"},
		apiruntime.ParamObservation{Location: "BODY", Name: "value", Path: "value", BaseType: "bool", Length: 1, ValueHash: "bool", FormatSample: true, FormatCandidate: "DATE"},
		apiruntime.ParamObservation{Location: "BODY", Name: "value", Path: "value", BaseType: "string", Length: 10, ValueHash: "unmarked", FormatCandidate: "DATETIME"},
		apiruntime.ParamObservation{Location: "BODY", Name: "legacy", Path: "legacy", BaseType: "string", Length: 8, ValueHash: "legacy"},
	)
	if err := apiruntime.NewParamObsStore(env.db).RecordParamObservations(ctx, ep.EndpointKey, observations); err != nil {
		t.Fatalf("record observations: %v", err)
	}

	if n, err := models.RefreshParameterStatistics(ctx); err != nil || n != 2 {
		t.Fatalf("refresh: n=%d err=%v, want 2", n, err)
	}
	state := readFormatCandidateState000206(t, env, version.ID, "value")
	if state.samples != 20 || len(state.counts) != 1 || state.counts["UUID"] != 18 {
		t.Fatalf("format observation = samples %d counts %v, want 20 and UUID:18", state.samples, state.counts)
	}
	assertSelectedFormatCandidate000206(t, state, "UUID", 0.9)
	if _, ok := state.recommended["format_candidate"]; ok {
		t.Fatalf("candidate leaked into recommended: %v", state.recommended)
	}
	if _, ok := state.recommended["format_candidate_ratio"]; ok {
		t.Fatalf("ratio leaked into recommended: %v", state.recommended)
	}
	if len(state.confirmed) != 1 || state.confirmed["max_length"] != 4096.0 {
		t.Fatalf("confirmed constraints changed: %v", state.confirmed)
	}
	legacy := readFormatCandidateState000206(t, env, version.ID, "legacy")
	if legacy.samples != 0 || len(legacy.counts) != 0 || legacy.candidate != nil || legacy.ratio != nil {
		t.Fatalf("legacy observation fabricated format state: %+v", legacy)
	}

	if n, err := models.RefreshParameterStatistics(ctx); err != nil || n != 2 {
		t.Fatalf("idempotent refresh: n=%d err=%v", n, err)
	}
	assertSelectedFormatCandidate000206(t, readFormatCandidateState000206(t, env, version.ID, "value"), "UUID", 0.9)

	if err := apiruntime.NewParamObsStore(env.db).RecordParamObservations(ctx, ep.EndpointKey, []apiruntime.ParamObservation{{
		Location: "BODY", Name: "value", Path: "value", BaseType: "string", Length: 4,
		ValueHash: "invalid-label", FormatSample: true, FormatCandidate: "uuid",
	}}); err != nil {
		t.Fatalf("record invalid label: %v", err)
	}
	if _, err := models.RefreshParameterStatistics(ctx); err != nil {
		t.Fatalf("refresh invalid label: %v", err)
	}
	state = readFormatCandidateState000206(t, env, version.ID, "value")
	if state.samples != 21 || len(state.counts) != 1 || state.counts["UUID"] != 18 {
		t.Fatalf("invalid label changed candidate counts: samples=%d counts=%v", state.samples, state.counts)
	}
	if state.candidate != nil || state.ratio != nil {
		t.Fatalf("below-threshold candidate must return to NULL: %+v", state)
	}
	if _, ok := state.observed["format_candidate"]; ok {
		t.Fatalf("stale observed candidate remains after recompute: %v", state.observed)
	}
	if _, ok := state.observed["format_candidate_ratio"]; ok {
		t.Fatalf("stale observed ratio remains after recompute: %v", state.observed)
	}
	if len(state.confirmed) != 1 || state.confirmed["max_length"] != 4096.0 {
		t.Fatalf("confirmed constraints changed after recompute: %v", state.confirmed)
	}

	if _, err := env.db.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	assertFormatCandidateColumns000206(t, env, 0, 0)
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	assertFormatCandidateColumns000206(t, env, 2, 2)
	state = readFormatCandidateState000206(t, env, version.ID, "value")
	if state.samples != 0 || len(state.counts) != 0 || state.candidate != nil || state.ratio != nil {
		t.Fatalf("re-up must restore empty defaults: %+v", state)
	}
}

func assertSelectedFormatCandidate000206(t *testing.T, state formatCandidateState000206, candidate string, ratio float64) {
	t.Helper()
	if state.candidate == nil || *state.candidate != candidate || state.ratio == nil || math.Abs(*state.ratio-ratio) > 1e-12 {
		t.Fatalf("selected format = %v/%v, want %s/%v", state.candidate, state.ratio, candidate, ratio)
	}
	if state.observed["format_candidate"] != candidate {
		t.Fatalf("observed candidate = %v, want %s", state.observed["format_candidate"], candidate)
	}
	gotRatio, ok := state.observed["format_candidate_ratio"].(float64)
	if !ok || math.Abs(gotRatio-ratio) > 1e-12 {
		t.Fatalf("observed ratio = %v, want %v", state.observed["format_candidate_ratio"], ratio)
	}
}

func readFormatCandidateState000206(t *testing.T, env *testEnv, versionID uuid.UUID, path string) formatCandidateState000206 {
	t.Helper()
	var state formatCandidateState000206
	var countsRaw, observedRaw, recommendedRaw, confirmedRaw []byte
	if err := env.db.QueryRow(context.Background(), `
SELECT o.format_sample_count, o.format_counts, st.format_candidate, st.format_candidate_ratio,
       p.observed_constraints, p.recommended_constraints, p.confirmed_constraints
FROM api_parameter_models p
JOIN api_parameter_statistics st ON st.parameter_id=p.id
JOIN api_model_versions v ON v.id=p.model_version_id
JOIN api_parameter_value_obs o ON o.endpoint_key=v.endpoint_key
  AND o.location=p.location AND o.parameter_name=p.parameter_name AND o.structured_path=p.structured_path
WHERE p.model_version_id=$1 AND p.structured_path=$2`, versionID, path).Scan(
		&state.samples, &countsRaw, &state.candidate, &state.ratio,
		&observedRaw, &recommendedRaw, &confirmedRaw); err != nil {
		t.Fatalf("read format state %s: %v", path, err)
	}
	for raw, dst := range map[*[]byte]any{
		&countsRaw: &state.counts, &observedRaw: &state.observed,
		&recommendedRaw: &state.recommended, &confirmedRaw: &state.confirmed,
	} {
		if err := json.Unmarshal(*raw, dst); err != nil {
			t.Fatalf("decode format state %s: %v", path, err)
		}
	}
	return state
}

func assertFormatCandidateColumns000206(t *testing.T, env *testEnv, wantObs, wantStats int) {
	t.Helper()
	if got := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
WHERE table_schema='public' AND table_name='api_parameter_value_obs'
  AND column_name IN ('format_sample_count','format_counts')`); got != wantObs {
		t.Fatalf("observation format columns=%d want %d", got, wantObs)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
WHERE table_schema='public' AND table_name='api_parameter_statistics'
  AND column_name IN ('format_candidate','format_candidate_ratio')`); got != wantStats {
		t.Fatalf("statistics format columns=%d want %d", got, wantStats)
	}
}
