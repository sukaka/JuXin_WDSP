package apiauthz

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestManualSharedWithRelationUsesExistingLifecycleAndPublish(t *testing.T) {
	store := NewMemStore()
	var published int
	h := NewHandler(store, nil)
	h.SetPublishFunc(func(context.Context, uuid.UUID, string) { published++ })
	mux := newTestMux(h)
	appID := uuid.New()

	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/relations", map[string]any{
		"application_id": appID.String(), "object_type": "invoice", "object_ref": "objref:shared-invoice",
		"principal_id": "recipient-principal", "relation": "shared_with", "source": "MANUAL", "reason": "share ticket",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("create SHARED_WITH status=%d body=%s", rr.Code, rr.Body.String())
	}
	var relation ObjectRelation
	decodeData(t, rr, &relation)
	if relation.Relation != RelationSharedWith || relation.PrincipalID != "recipient-principal" ||
		relation.ObjectRef != "objref:shared-invoice" || relation.Source != RelationSourceManual {
		t.Fatalf("SHARED_WITH direction or source changed: %+v", relation)
	}
	if published != 1 {
		t.Fatalf("create publish calls=%d, want 1", published)
	}

	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/relations/"+relation.ID.String()+"/revoke", map[string]any{"reason": "revoke share"})
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke SHARED_WITH status=%d body=%s", rr.Code, rr.Body.String())
	}
	decodeData(t, rr, &relation)
	if relation.Status != RelationStatusRevoked || relation.Relation != RelationSharedWith {
		t.Fatalf("revoked relation=%+v", relation)
	}

	validFrom := time.Now().UTC().Add(time.Hour)
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/relations/"+relation.ID.String()+"/reauthorize", map[string]any{
		"reason": "renew share", "valid_from": validFrom,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("reauthorize SHARED_WITH status=%d body=%s", rr.Code, rr.Body.String())
	}
	decodeData(t, rr, &relation)
	if relation.Status != RelationStatusConfirmed || relation.Relation != RelationSharedWith || !relation.ValidFrom.Equal(validFrom) {
		t.Fatalf("reauthorized relation=%+v", relation)
	}
	if published != 3 {
		t.Fatalf("lifecycle publish calls=%d, want 3", published)
	}
}

func TestSharedWithIsManualOnlyAndCandidateConfirmationStaysOwner(t *testing.T) {
	store := NewMemStore()
	principal := "verified-principal"
	candidate := store.addRelationCandidate(RelationCandidate{
		ApplicationID: uuid.New(), ObjectType: "invoice", ObjectRef: "objref:candidate-share", PrincipalID: &principal,
	})
	if _, err := store.ConfirmRelationCandidate(context.Background(), candidate.ID, ConfirmCandidateInput{
		Relation: RelationSharedWith, Reason: "must not confirm sharing", ConfirmedBy: "tester",
	}); err == nil {
		t.Fatal("repository accepted SHARED_WITH candidate confirmation")
	}
	if got := store.relationCandidates[candidate.ID].Status; got != CandidateStatusPending {
		t.Fatalf("rejected candidate status=%q, want PENDING", got)
	}

	mux := newTestMux(NewHandler(store, nil))
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/relations/candidates/"+candidate.ID.String()+"/confirm", map[string]any{
		"relation": RelationSharedWith, "reason": "must remain owner-only",
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("candidate SHARED_WITH status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/relations", map[string]any{
		"application_id": uuid.NewString(), "object_type": "invoice", "object_ref": "objref:import-share",
		"principal_id": "recipient", "relation": RelationSharedWith, "source": RelationSourceImport, "reason": "unsupported import",
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("IMPORT SHARED_WITH status=%d body=%s", rr.Code, rr.Body.String())
	}

	rel := &ObjectRelation{
		ApplicationID: uuid.New(), ObjectType: "invoice", ObjectRef: "objref:delegate", PrincipalID: "delegate",
		Relation: "DELEGATED_TO", Source: RelationSourceManual, Reason: "unsupported", ValidFrom: time.Now().UTC(),
	}
	if err := store.CreateObjectRelation(context.Background(), rel); err == nil || errors.Is(err, ErrRelationConflict) {
		t.Fatalf("DELEGATED_TO create error=%v, want validation failure", err)
	}
}
