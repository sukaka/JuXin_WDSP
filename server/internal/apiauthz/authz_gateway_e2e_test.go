package apiauthz

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// TestRelationCandidateConfirmationGatewayAuthorization exercises the local
// evidence path that can be verified without PostgreSQL or a running gateway:
// an observed candidate is confirmed into an approved relation, then the
// gateway evaluator consumes that relation for an owner and another principal.
func TestRelationCandidateConfirmationGatewayAuthorization(t *testing.T) {
	store := NewMemStore()
	appID := uuid.New()
	principal := "user-owner"
	objectID := "order-78231"
	key := []byte("01234567890123456789012345678901")

	candidate := store.addRelationCandidate(RelationCandidate{
		ApplicationID: appID,
		ObjectType:    "ORDER",
		ObjectRef:     detectors.ObjectRefHMAC(key, objectID),
		PrincipalID:   &principal,
		Source:        CandidateSourceObserved,
		Status:        CandidateStatusPending,
	})
	published := 0
	var publishUserID uuid.UUID
	var publishRequestID string
	h := NewHandler(store, nil)
	h.SetPublishFunc(func(_ context.Context, uid uuid.UUID, requestID string) {
		published++
		publishUserID = uid
		publishRequestID = requestID
	})
	confirmResponse := doJSON(t, newTestMux(h), http.MethodPost,
		"/api/v1/api-security/authz/relations/candidates/"+candidate.ID.String()+"/confirm",
		map[string]any{"relation": "OWNER", "reason": "verified ownership"})
	if confirmResponse.Code != http.StatusOK {
		t.Fatalf("confirm candidate status=%d body=%s", confirmResponse.Code, confirmResponse.Body.String())
	}
	var relation ObjectRelation
	decodeData(t, confirmResponse, &relation)
	if relation.Status != RelationStatusConfirmed || relation.ObjectRef != candidate.ObjectRef {
		t.Fatalf("confirmation did not produce an approved relation: %+v", relation)
	}
	if published != 1 {
		t.Fatalf("confirmed relation must trigger exactly one publish callback: count=%d", published)
	}
	relations, total, err := store.ListObjectRelations(context.Background(), RelationFilter{ApplicationID: &appID, Status: RelationStatusConfirmed})
	if err != nil || total != 1 || len(relations) != 1 {
		t.Fatalf("confirmed relation not available to snapshot consumer: total=%d relations=%+v err=%v", total, relations, err)
	}

	model := detectors.ObjectModel{
		ApplicationID: appID.String(), EndpointKey: "GET /v1/orders/{id}",
		PathTemplate: "/v1/orders/{id}", ObjectType: "ORDER",
		Identifiers:      []detectors.ObjectIdentifier{{Location: "path", Name: "id", Primary: true}},
		RequiredRelation: "OWNER", OwnerExclusive: true, Publishable: true,
		UniqueEndpointTemplate: true, ModelVersion: "local-model-v1",
	}
	cfg := detectors.AuthorizationConfig{
		ApplicationID: appID.String(), EndpointKey: "GET /v1/orders/{id}",
		Models: []detectors.ObjectModel{model}, ObjectRefHMACKey: key,
		PolicyVersion: "local-policy-v1", Relations: []detectors.ObjectRelation{{
			ApplicationID: relation.ApplicationID.String(), PrincipalID: relation.PrincipalID,
			ObjectType: relation.ObjectType, ObjectRef: relation.ObjectRef,
			Relation: relation.Relation, Status: relation.Status,
			ValidFrom: &relation.ValidFrom, ValidUntil: relation.ValidUntil,
		}},
		Now: func() time.Time { return relation.ValidFrom.Add(time.Second) },
	}

	request, err := http.NewRequest(http.MethodGet, "https://example.test/v1/orders/"+objectID, nil)
	if err != nil {
		t.Fatal(err)
	}
	evaluate := func(id string) (*detectors.AuthorizationDecisionGroup, *dsctx.RequestContext) {
		ctx := dsctx.New("req-authz-local-e2e-"+id, dsctx.DefaultParseLimits())
		ctx.ApplicationID = appID.String()
		parsed, parseErr := parser.ParseRequest(request, ctx)
		if parseErr != nil {
			t.Fatalf("parse request: %v", parseErr)
		}
		jwt := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: id}
		return detectors.EvaluateAuthorization(ctx, parsed, cfg, jwt), ctx
	}

	ownerGroup, _ := evaluate(principal)
	if ownerGroup == nil || ownerGroup.Decision != detectors.AuthorizationAllow || len(ownerGroup.Checks) != 1 {
		t.Fatalf("confirmed owner should be allowed: %+v", ownerGroup)
	}
	ownerCheck := ownerGroup.Checks[0]
	if ownerCheck.Type != "BOLA" || ownerCheck.RelationState != "EFFECTIVE_OWNER" || ownerCheck.Decision != detectors.AuthorizationAllow {
		t.Fatalf("unexpected owner decision: %+v", ownerCheck)
	}

	otherGroup, otherCtx := evaluate("user-other")
	if otherGroup == nil || otherGroup.Decision != detectors.AuthorizationObserveViolation || len(otherGroup.Checks) != 1 {
		t.Fatalf("non-owner should produce an OBSERVE violation: %+v", otherGroup)
	}
	otherCheck := otherGroup.Checks[0]
	if otherCheck.ReasonCode != "AUTHZ-BOLA-001" || otherCheck.RelationState != "OTHER_OWNER" {
		t.Fatalf("unexpected BOLA decision: %+v", otherCheck)
	}
	if otherCtx.MatchCount() != 1 {
		t.Fatalf("observe violation should be recorded in request context: %+v", otherCtx.CopyMatches())
	}

	// The shell-level contract test uses this same HTTP confirmation flow as
	// its producer.  It hands only the confirmed relation and publication
	// callback metadata to the next module; candidates never become gateway
	// input directly.
	if out := os.Getenv("AUTHZ_CANDIDATE_OUTPUT"); out != "" {
		handoff := struct {
			ApplicationID        string         `json:"application_id"`
			ObjectID             string         `json:"object_id"`
			CandidateID          uuid.UUID      `json:"candidate_id"`
			CandidateStatus      string         `json:"candidate_status"`
			ConfirmedRelation    ObjectRelation `json:"confirmed_relation"`
			PublishCallbackCount int            `json:"publish_callback_count"`
			PublishRequestID     string         `json:"publish_request_id"`
			PublishUserID        uuid.UUID      `json:"publish_user_id"`
		}{
			ApplicationID:        appID.String(),
			ObjectID:             objectID,
			CandidateID:          candidate.ID,
			CandidateStatus:      store.relationCandidates[candidate.ID].Status,
			ConfirmedRelation:    relation,
			PublishCallbackCount: published,
			PublishRequestID:     publishRequestID,
			PublishUserID:        publishUserID,
		}
		data, err := json.Marshal(handoff)
		if err != nil {
			t.Fatalf("marshal authz publication handoff: %v", err)
		}
		if err := os.WriteFile(out, data, 0600); err != nil {
			t.Fatalf("write authz publication handoff: %v", err)
		}
	}
}
