package guardconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestDecodeGuardConfigSnapshotAcceptsLegacySchemaAndUnknownAuthzShards(t *testing.T) {
	// This fixture represents a snapshot produced before method/publishability
	// metadata was added. The unknown shard models a newer producer field that
	// an older Provider must ignore while retaining the known authorization
	// facts needed for recovery.
	legacy := []byte(`{
		"api_authz_models": [{
			"application_id": "app-legacy",
			"endpoint_key": "GET /orders/{id}",
			"object_type": "order",
			"identifiers": [{"location": "path", "name": "id"}],
			"required_relation": "OWNER"
		}],
		"api_authz_previous_valid": {
			"policy_version": "policy-old",
			"models": [{
				"application_id": "app-legacy",
				"endpoint_key": "GET /orders/{id}",
				"object_type": "order",
				"identifiers": [{"location": "path", "name": "id"}],
				"required_relation": "OWNER"
			}],
			"future_authz_shard": {"version": 2}
		},
		"future_authz_shard": {"version": 2}
	}`)

	cfg, err := decodeGuardConfigSnapshot(legacy)
	if err != nil {
		t.Fatalf("legacy snapshot must decode: %v", err)
	}
	if len(cfg.APIAuthzModels) != 1 || cfg.APIAuthzModels[0].Method != "" {
		t.Fatalf("legacy model was not retained with absent optional method: %+v", cfg.APIAuthzModels)
	}
	if cfg.APIAuthzPreviousValid == nil || len(cfg.APIAuthzPreviousValid.Models) != 1 ||
		cfg.APIAuthzPreviousValid.PolicyVersion != "policy-old" {
		t.Fatalf("legacy PreviousValid snapshot was not retained: %+v", cfg.APIAuthzPreviousValid)
	}

	// Unknown shards are intentionally dropped when the known config is
	// re-encoded; they must never leak into a subsequent publish payload.
	normalized, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal normalized snapshot: %v", err)
	}
	if string(normalized) == "" || string(normalized) == string(legacy) {
		t.Fatal("legacy snapshot was not normalized")
	}
	if bytes.Contains(normalized, []byte("future_authz_shard")) {
		t.Fatal("unknown authorization shard leaked into normalized snapshot")
	}
}

func TestLatestSuccessfulVersionIDFiltersUnsuccessfulVersions(t *testing.T) {
	id := uuid.New()
	for _, result := range []string{accesscontrolversions.PublishPending, accesscontrolversions.PublishFailed} {
		t.Run(result, func(t *testing.T) {
			got, err := latestSuccessfulVersionID(&accesscontrolversions.Version{
				ID:            id,
				PublishResult: result,
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != nil {
				t.Fatalf("unsuccessful version must not become previous: %v", *got)
			}
		})
	}

	got, err := latestSuccessfulVersionID(&accesscontrolversions.Version{
		ID:            id,
		PublishResult: accesscontrolversions.PublishSuccess,
	}, nil)
	if err != nil || got == nil || *got != id {
		t.Fatalf("successful version id = %v, err = %v", got, err)
	}
	got, err = latestSuccessfulVersionID(nil, accesscontrolversions.ErrNotFound)
	if err != nil || got != nil {
		t.Fatalf("empty successful history = %v, err = %v", got, err)
	}
	if _, err = latestSuccessfulVersionID(nil, errors.New("database unavailable")); err == nil {
		t.Fatal("store failures must remain fail-hard")
	}
}

func TestCloneAuthzSnapshotRetainsExpiryAndOmitsHMAC(t *testing.T) {
	modelExpires := time.Date(2026, 9, 1, 2, 3, 4, 0, time.FixedZone("CST", 8*60*60))
	validUntil := modelExpires.Add(-time.Hour)
	cfg := &gatewayconfig.GuardConfig{
		APIPolicyVersion:          "policy-v1",
		APIAuthzObjectHMACKeyHex:  "secret-is-not-copied",
		APIAuthzSnapshotExpiresAt: &modelExpires,
		APIAuthzModels: []gatewayconfig.GuardAuthzObjectModel{{
			ApplicationID:     "app-1",
			EndpointKey:       "GET /v1/orders/{id}",
			Identifiers:       []gatewayconfig.GuardAuthzObjectIdentifier{{Location: "path", Name: "id", Primary: true}},
			SnapshotExpiresAt: &modelExpires,
		}},
		APIAuthzRelations: []gatewayconfig.GuardAuthzObjectRelation{{
			ApplicationID: "app-1", PrincipalID: "user-1", ObjectRef: "order-1", Relation: "OWNER",
			ValidUntil: &validUntil,
		}},
		APIAuthzRoleBaselines: []gatewayconfig.GuardAuthzRoleBaseline{{
			ApplicationID: "app-1", EndpointKey: "GET /v1/orders/{id}", Role: "support", Allowed: true,
		}},
	}

	snapshot := cloneAuthzSnapshot(cfg)
	if snapshot == nil || snapshot.PolicyVersion != cfg.APIPolicyVersion || snapshot.ObjectHMACKeyHex != "" {
		t.Fatalf("snapshot metadata or secret handling is invalid: %+v", snapshot)
	}
	if snapshot.SnapshotExpiresAt == nil || !snapshot.SnapshotExpiresAt.Equal(modelExpires) {
		t.Fatalf("snapshot expiry = %v, want %v", snapshot.SnapshotExpiresAt, modelExpires)
	}
	if snapshot.Models[0].SnapshotExpiresAt == cfg.APIAuthzModels[0].SnapshotExpiresAt ||
		snapshot.Relations[0].ValidUntil == cfg.APIAuthzRelations[0].ValidUntil {
		t.Fatal("snapshot must own its time pointers")
	}

	// The retained facts are a detached snapshot, so later config assembly
	// cannot mutate the historical payload through shared backing arrays.
	snapshot.Models[0].Identifiers[0].Name = "changed"
	if cfg.APIAuthzModels[0].Identifiers[0].Name != "id" {
		t.Fatal("snapshot identifier shares source storage")
	}
	if !snapshot.Models[0].SnapshotExpiresAt.Equal(modelExpires) || !snapshot.Relations[0].ValidUntil.Equal(validUntil) {
		t.Fatal("snapshot expiry facts changed unexpectedly")
	}
}

func TestRedactGuardConfigRedactsPreviousAuthzHMAC(t *testing.T) {
	const secret = "historical-secret-material"
	cfg := &gatewayconfig.GuardConfig{
		APIAuthzPreviousValid: &gatewayconfig.GuardAuthzSnapshot{
			ObjectHMACKeyHex: secret,
			PolicyVersion:    "policy-v0",
		},
	}

	redacted := RedactGuardConfig(cfg)
	if redacted == nil || redacted.APIAuthzPreviousValid == nil || redacted.APIAuthzPreviousValid.ObjectHMACKeyHex != redactPlaceholder {
		t.Fatal("previous authorization snapshot key was not redacted")
	}
	if cfg.APIAuthzPreviousValid.ObjectHMACKeyHex != secret {
		t.Fatal("redaction mutated the source config")
	}
}
