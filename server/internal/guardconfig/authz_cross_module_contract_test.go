package guardconfig

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type authzCrossModuleContract struct {
	AppID            string                       `json:"app_id"`
	GuardConfig      gatewayconfig.GuardConfig    `json:"guard_config"`
	CandidateHandoff authzCandidatePublishHandoff `json:"candidate_handoff"`
	ObjectID         string                       `json:"object_id"`
	AdminPath        string                       `json:"admin_path"`
	EventsLog        string                       `json:"events_log"`
	APIEventsLog     string                       `json:"api_events_log"`
}

type authzCandidatePublishHandoff struct {
	ApplicationID        string                                 `json:"application_id"`
	ObjectID             string                                 `json:"object_id"`
	CandidateID          uuid.UUID                              `json:"candidate_id"`
	CandidateStatus      string                                 `json:"candidate_status"`
	ConfirmedRelation    gatewayconfig.GuardAuthzObjectRelation `json:"confirmed_relation"`
	PublishCallbackCount int                                    `json:"publish_callback_count"`
	PublishRequestID     string                                 `json:"publish_request_id"`
	PublishUserID        uuid.UUID                              `json:"publish_user_id"`
}

// TestWriteAuthzCrossModuleContract is the server half of the two-module
// contract test. The JSON file is handed to a separate gatewayconfig test
// process, which exercises the HTTP client boundary before gateway consumption.
func TestWriteAuthzCrossModuleContract(t *testing.T) {
	out := os.Getenv("AUTHZ_CONTRACT_OUTPUT")
	if out == "" {
		t.Skip("AUTHZ_CONTRACT_OUTPUT is required")
	}
	handoffPath := os.Getenv("AUTHZ_CANDIDATE_INPUT")
	if handoffPath == "" {
		t.Skip("AUTHZ_CANDIDATE_INPUT is required")
	}
	handoffData, err := os.ReadFile(handoffPath)
	if err != nil {
		t.Fatalf("read apiauthz candidate handoff: %v", err)
	}
	var handoff authzCandidatePublishHandoff
	if err := json.Unmarshal(handoffData, &handoff); err != nil {
		t.Fatalf("decode apiauthz candidate handoff: %v", err)
	}
	appID, err := uuid.Parse(handoff.ApplicationID)
	if err != nil {
		t.Fatalf("handoff application id: %v", err)
	}
	if handoff.CandidateID == uuid.Nil || handoff.CandidateStatus != "CONFIRMED" ||
		handoff.ConfirmedRelation.Status != "CONFIRMED" || handoff.ConfirmedRelation.Relation != "OWNER" ||
		handoff.ConfirmedRelation.ApplicationID != handoff.ApplicationID ||
		handoff.ConfirmedRelation.PrincipalID != "user-owner" || handoff.PublishCallbackCount != 1 ||
		handoff.PublishRequestID != "test-rid" || handoff.PublishUserID == uuid.Nil {
		t.Fatalf("apiauthz confirmation handoff is incomplete: %+v", handoff)
	}
	key := []byte("01234567890123456789012345678901")
	objectID := handoff.ObjectID
	if objectID == "" {
		t.Fatal("apiauthz handoff object id is empty")
	}
	now := time.Now().UTC()
	objectRef := detectors.ObjectRefHMAC(key, objectID)
	if handoff.ConfirmedRelation.ObjectRef != objectRef {
		t.Fatalf("apiauthz handoff object ref mismatch: got=%q want=%q", handoff.ConfirmedRelation.ObjectRef, objectRef)
	}
	model := authzSnapshotTestModel()
	model.ApplicationID = appID.String()
	model.PathTemplate = "/v1/orders/{id}"
	model.Identifiers = []gatewayconfig.GuardAuthzObjectIdentifier{{Location: "path", Name: "id", Primary: true}}
	model.UniqueEndpointTemplate = true
	model.SnapshotExpiresAt = ptrTime(now.Add(24 * time.Hour))
	previousExpiry := now.Add(30 * time.Minute)
	previousModel := model
	previousModel.ModelVersion = "previous-model"
	previousModel.PolicyVersion = "previous-policy"
	previousModel.SnapshotExpiresAt = &previousExpiry

	provider := &Provider{}
	provider.SetAuthzSnapshotLister(&fakeAuthzSnapshotLister{
		models: []gatewayconfig.GuardAuthzObjectModel{model},
		relations: []gatewayconfig.GuardAuthzObjectRelation{{
			ApplicationID: handoff.ConfirmedRelation.ApplicationID,
			PrincipalID:   handoff.ConfirmedRelation.PrincipalID,
			ObjectType:    handoff.ConfirmedRelation.ObjectType,
			ObjectRef:     handoff.ConfirmedRelation.ObjectRef,
			Relation:      handoff.ConfirmedRelation.Relation,
			Status:        handoff.ConfirmedRelation.Status,
			ValidFrom:     handoff.ConfirmedRelation.ValidFrom,
			ValidUntil:    handoff.ConfirmedRelation.ValidUntil,
		}},
		roles: []gatewayconfig.GuardAuthzRoleBaseline{{
			ApplicationID: appID.String(), EndpointKey: "GET /v1/admin", Method: "GET",
			Role: "support", Action: "READ", Allowed: true, Confirmed: true,
		}},
	})
	provider.SetAuthzObjectHMACKeyLoader(func(context.Context) (string, error) {
		return hex.EncodeToString(key), nil
	})
	models, relations, roles, keyHex, err := provider.loadAPIAuthzSnapshot(context.Background())
	if err != nil {
		t.Fatalf("load provider snapshot: %v", err)
	}
	if len(models) != 1 || len(relations) != 1 || len(roles) != 1 || keyHex != hex.EncodeToString(key) {
		t.Fatalf("provider snapshot incomplete: models=%d relations=%d roles=%d key=%q", len(models), len(relations), len(roles), keyHex)
	}
	previous := &gatewayconfig.GuardAuthzSnapshot{
		Models:    []gatewayconfig.GuardAuthzObjectModel{previousModel},
		Relations: relations, RoleBaselines: roles,
		PolicyVersion: "previous-policy", SnapshotExpiresAt: &previousExpiry,
	}
	keyHex, err = provider.ensureAuthzSnapshotKey(context.Background(), keyHex, true, previous)
	if err != nil || keyHex != hex.EncodeToString(key) {
		t.Fatalf("reinject previous snapshot key: key=%q err=%v", keyHex, err)
	}
	// Historical versions redact this secret; the gatewayconfig renderer puts
	// the current runtime key back into PreviousValid before JSON hand-off.
	previous.ObjectHMACKeyHex = keyHex
	expired := now.Add(-time.Minute)
	cfg := gatewayconfig.GuardConfig{
		CounterBackend: "memory", FailOpen: true, EventsLog: os.Getenv("AUTHZ_CONTRACT_EVENTS_LOG"),
		GatewayNode: "contract-node", APIDynamicProtection: true, APIProtectionMode: "OBSERVE",
		APIEventsLog: os.Getenv("AUTHZ_CONTRACT_API_EVENTS_LOG"), APIPolicyVersion: "current-policy",
		APIAuthzModels: models, APIAuthzRelations: relations, APIAuthzRoleBaselines: roles,
		APIAuthzObjectHMACKeyHex: keyHex, APIAuthzSnapshotStale: true,
		APIAuthzSnapshotExpiresAt: &expired, APIAuthzPreviousValid: previous,
	}
	if cfg.EventsLog == "" || cfg.APIEventsLog == "" {
		t.Fatal("AUTHZ_CONTRACT_EVENTS_LOG and AUTHZ_CONTRACT_API_EVENTS_LOG are required")
	}
	data, err := json.Marshal(authzCrossModuleContract{
		AppID: appID.String(), GuardConfig: cfg, CandidateHandoff: handoff,
		ObjectID: objectID, AdminPath: "/v1/admin", EventsLog: cfg.EventsLog, APIEventsLog: cfg.APIEventsLog,
	})
	if err != nil {
		t.Fatalf("marshal contract: %v", err)
	}
	// Keep the command-level hand-off honest: the exact JSON written for the
	// gateway must round-trip both the current and PreviousValid key material.
	var wire authzCrossModuleContract
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatalf("unmarshal provider contract: %v", err)
	}
	if wire.CandidateHandoff.CandidateStatus != "CONFIRMED" ||
		wire.CandidateHandoff.ConfirmedRelation.ObjectRef != handoff.ConfirmedRelation.ObjectRef {
		t.Fatalf("provider JSON hand-off lost candidate confirmation: %+v", wire.CandidateHandoff)
	}
	if len(wire.GuardConfig.APIAuthzModels) != 1 || wire.GuardConfig.APIAuthzObjectHMACKeyHex != keyHex ||
		wire.GuardConfig.APIAuthzPreviousValid == nil || wire.GuardConfig.APIAuthzPreviousValid.ObjectHMACKeyHex != keyHex {
		t.Fatalf("provider JSON hand-off lost authz keys or model: current=%q previous=%+v models=%d",
			wire.GuardConfig.APIAuthzObjectHMACKeyHex, wire.GuardConfig.APIAuthzPreviousValid, len(wire.GuardConfig.APIAuthzModels))
	}
	if err := os.WriteFile(out, data, 0600); err != nil {
		t.Fatalf("write contract: %v", err)
	}
}

func ptrTime(v time.Time) *time.Time { return &v }
