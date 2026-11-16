package tests

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiweakness"
)

func TestStage8SensitiveResponseUnmasked(t *testing.T) {
	db := setupWeaknessDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	sweeper := apiweakness.NewSweeper(db)

	result, err := sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("empty sweep: %v", err)
	}
	if result.Inserted != 0 || result.Updated != 0 || result.Reproduced != 0 || len(result.ByCode) != 0 {
		t.Fatalf("empty sweep result: %+v", result)
	}

	const (
		fieldKey  = "GET /v1/weakness/response-field"
		valueKey  = "POST /v1/weakness/response-value"
		belowKey  = "GET /v1/weakness/below-threshold"
		maskedKey = "GET /v1/weakness/partially-masked"
		oldKey    = "GET /v1/weakness/outside-window"
		secret    = "raw-sensitive-value-must-not-enter-weakness-evidence"
	)
	for _, key := range []string{fieldKey, valueKey, belowKey, maskedKey, oldKey} {
		seedEndpoint(t, db, key)
	}

	fieldDetails := `[{"detector":"sensitive_data","rule_id":"sensitive.response_field","evidence":{"field":"customer.id_card","value":"` + secret + `"}}]`
	valueDetails := `[{"detector":"sensitive_data","rule_id":"sensitive.response_value","evidence":{"field":"customer.phone","value":"` + secret + `"}},{"detector":"api_response","rule_id":"response.mask_failed"}]`
	maskedDetails := `[{"detector":"sensitive_data","rule_id":"sensitive.response_field","evidence":{"field":"customer.id_card"}},{"detector":"api_response","rule_id":"response.mask_applied","evidence":{"applied_fields":"1","skipped_fields":"1"}}]`
	for i := 0; i < 3; i++ {
		occurredAt := now.Add(-time.Duration(i+1) * time.Hour)
		seedEvent(t, db, fieldKey, "bearer_or_basic", fieldDetails, occurredAt)
		seedEvent(t, db, valueKey, "bearer_or_basic", valueDetails, occurredAt)
		seedEvent(t, db, maskedKey, "bearer_or_basic", maskedDetails, occurredAt)
		seedEvent(t, db, oldKey, "bearer_or_basic", fieldDetails, now.Add(-25*time.Hour-time.Duration(i)*time.Minute))
	}
	for i := 0; i < 2; i++ {
		seedEvent(t, db, belowKey, "bearer_or_basic", fieldDetails, now.Add(-time.Duration(i+1)*time.Hour))
	}

	result, err = sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("response-unmasked sweep: %v", err)
	}
	if result.Inserted != 2 || result.Updated != 0 || result.Reproduced != 0 ||
		result.ByCode[apiweakness.CodeSensitiveResponseUnmasked] != 2 {
		t.Fatalf("response-unmasked sweep result: %+v", result)
	}

	for _, endpointKey := range []string{belowKey, maskedKey, oldKey} {
		var count int
		if err := db.QueryRow(ctx, `
SELECT count(*) FROM api_weaknesses w
JOIN api_endpoints e ON e.id = w.endpoint_id
WHERE e.endpoint_key = $1 AND w.weakness_code = $2`, endpointKey, apiweakness.CodeSensitiveResponseUnmasked).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("endpoint %s must not derive response-unmasked weakness", endpointKey)
		}
	}

	allowedEvidenceKeys := map[string]bool{
		"rule": true, "endpoint_key": true, "sample_count": true,
		"window_hours": true, "first_seen": true, "last_seen": true,
	}
	for _, endpointKey := range []string{fieldKey, valueKey} {
		var weaknessID uuid.UUID
		var name, category, severity, status, evidenceJSON string
		var triggerCount int
		if err := db.QueryRow(ctx, `
SELECT w.id, w.weakness_name, w.category, w.severity, w.status, w.evidence_json::text, w.trigger_count
FROM api_weaknesses w
JOIN api_endpoints e ON e.id = w.endpoint_id
WHERE e.endpoint_key = $1 AND w.weakness_code = $2`, endpointKey, apiweakness.CodeSensitiveResponseUnmasked).
			Scan(&weaknessID, &name, &category, &severity, &status, &evidenceJSON, &triggerCount); err != nil {
			t.Fatalf("load weakness for %s: %v", endpointKey, err)
		}
		if name != "响应敏感信息未观察到成功脱敏" || category != apiweakness.CategorySensitive ||
			severity != apiweakness.SeverityMedium || status != apiweakness.StatusNew || triggerCount != 1 {
			t.Fatalf("unexpected weakness for %s: name=%s category=%s severity=%s status=%s count=%d",
				endpointKey, name, category, severity, status, triggerCount)
		}
		var evidence map[string]any
		if err := json.Unmarshal([]byte(evidenceJSON), &evidence); err != nil {
			t.Fatalf("decode evidence for %s: %v", endpointKey, err)
		}
		if len(evidence) != len(allowedEvidenceKeys) {
			t.Fatalf("evidence keys for %s = %v, want exact whitelist", endpointKey, evidence)
		}
		for key := range evidence {
			if !allowedEvidenceKeys[key] {
				t.Fatalf("evidence for %s contains unexpected key %q: %v", endpointKey, key, evidence)
			}
		}
		if evidence["rule"] != apiweakness.CodeSensitiveResponseUnmasked || evidence["endpoint_key"] != endpointKey ||
			evidence["sample_count"] != float64(3) || evidence["window_hours"] != float64(24) {
			t.Fatalf("unexpected evidence for %s: %v", endpointKey, evidence)
		}
		for _, key := range []string{"first_seen", "last_seen"} {
			value, ok := evidence[key].(string)
			if !ok {
				t.Fatalf("evidence %s for %s is not a timestamp string: %v", key, endpointKey, evidence[key])
			}
			if _, err := time.Parse(time.RFC3339, value); err != nil {
				t.Fatalf("evidence %s for %s is not RFC3339: %v", key, endpointKey, err)
			}
		}
		if strings.Contains(evidenceJSON, secret) || strings.Contains(evidenceJSON, "id_card") ||
			strings.Contains(evidenceJSON, "applied_fields") || strings.Contains(evidenceJSON, "skipped_fields") {
			t.Fatalf("sensitive or raw masking data leaked into evidence for %s: %s", endpointKey, evidenceJSON)
		}
	}

	var weaknessID uuid.UUID
	if err := db.QueryRow(ctx, `
SELECT w.id FROM api_weaknesses w
JOIN api_endpoints e ON e.id = w.endpoint_id
WHERE e.endpoint_key = $1 AND w.weakness_code = $2`, fieldKey, apiweakness.CodeSensitiveResponseUnmasked).Scan(&weaknessID); err != nil {
		t.Fatal(err)
	}
	store := apiweakness.NewStore(db)
	for _, action := range []string{apiweakness.ActionConfirm, apiweakness.ActionAssign, apiweakness.ActionMarkFixed} {
		if _, err := store.Transition(ctx, weaknessID, action, apiweakness.TransitionInput{Actor: "tester", Owner: "owner"}); err != nil {
			t.Fatalf("transition %s: %v", action, err)
		}
	}

	result, err = sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("reproduction sweep: %v", err)
	}
	if result.Inserted != 0 || result.Updated != 1 || result.Reproduced != 1 {
		t.Fatalf("reproduction sweep result: %+v", result)
	}
	var status string
	var triggerCount int
	if err := db.QueryRow(ctx, `SELECT status, trigger_count FROM api_weaknesses WHERE id = $1`, weaknessID).
		Scan(&status, &triggerCount); err != nil {
		t.Fatal(err)
	}
	if status != apiweakness.StatusReproduced || triggerCount != 2 {
		t.Fatalf("FIXED weakness was not reproduced through existing logic: status=%s count=%d", status, triggerCount)
	}
	actions, total, err := store.ListActions(ctx, weaknessID, 1, 20)
	if err != nil || total != 5 {
		t.Fatalf("reproduction actions: total=%d actions=%+v err=%v", total, actions, err)
	}
	foundReproduced := false
	for _, action := range actions {
		if action.Action == apiweakness.ActionReproduced && action.Actor == "system" {
			foundReproduced = true
		}
	}
	if !foundReproduced {
		t.Fatalf("system REPRODUCED action missing: %+v", actions)
	}
}
