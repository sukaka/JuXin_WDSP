package apiauthz

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMemStoreCoverageExcludesInactiveRelations(t *testing.T) {
	store := NewMemStore()
	appID := uuid.New()
	now := time.Now().UTC()

	store.relations[uuid.New()] = &ObjectRelation{
		ApplicationID: appID, Status: RelationStatusConfirmed,
		ValidFrom: now.Add(-time.Hour), ValidUntil: nil,
	}
	expired := now.Add(-time.Minute)
	store.relations[uuid.New()] = &ObjectRelation{
		ApplicationID: appID, Status: RelationStatusConfirmed,
		ValidFrom: now.Add(-time.Hour), ValidUntil: &expired,
	}
	future := now.Add(time.Minute)
	store.relations[uuid.New()] = &ObjectRelation{
		ApplicationID: appID, Status: RelationStatusConfirmed,
		ValidFrom: now.Add(time.Minute), ValidUntil: &future,
	}
	store.relations[uuid.New()] = &ObjectRelation{
		ApplicationID: appID, Status: RelationStatusRevoked,
		ValidFrom: now.Add(-time.Hour), ValidUntil: nil,
	}

	coverage, err := store.GetAuthorizationCoverage(context.Background(), &appID)
	if err != nil {
		t.Fatal(err)
	}
	if coverage.ConfirmedRelations != 1 {
		t.Fatalf("confirmed relations=%d, want only the active relation", coverage.ConfirmedRelations)
	}
}

func TestMemStoreCoverageIncludesDecisionMetricsAndApplicationIsolation(t *testing.T) {
	store := NewMemStore()
	appA, appB := uuid.New(), uuid.New()
	store.addRelationCandidate(RelationCandidate{ApplicationID: appA, ObjectType: "invoice", ObjectRef: "objref:a1"})
	store.addRelationCandidate(RelationCandidate{ApplicationID: appA, ObjectType: "invoice", ObjectRef: "objref:a2"})
	store.addRelationCandidate(RelationCandidate{ApplicationID: appB, ObjectType: "invoice", ObjectRef: "objref:b1"})
	now := time.Now().UTC()
	store.relations[uuid.New()] = &ObjectRelation{
		ApplicationID: appA, ObjectType: "invoice", ObjectRef: "objref:a1",
		Status: RelationStatusConfirmed, ValidFrom: now.Add(-time.Minute),
	}
	store.addAuthorizationDecision(AuthorizationDecision{ApplicationID: &appA, Decision: "UNKNOWN"})
	store.addAuthorizationDecision(AuthorizationDecision{ApplicationID: &appA, Decision: "OBSERVE_VIOLATION"})
	store.addAuthorizationDecision(AuthorizationDecision{ApplicationID: &appB, Decision: "UNKNOWN"})

	coverage, err := store.GetAuthorizationCoverage(context.Background(), &appA)
	if err != nil {
		t.Fatal(err)
	}
	if coverage.Decisions != 2 || coverage.UnknownDecisions != 1 || coverage.ObserveViolations != 1 {
		t.Fatalf("decision metrics=%+v, want app A only", coverage)
	}
	if coverage.UnknownRate != 0.5 || coverage.ConfirmedRelationRate != 0.5 {
		t.Fatalf("rates=%+v, want unknown=0.5 and relation=0.5", coverage)
	}

	allCoverage, err := store.GetAuthorizationCoverage(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if allCoverage.Decisions != 3 || allCoverage.UnknownDecisions != 2 {
		t.Fatalf("unfiltered decision metrics=%+v, want all applications", allCoverage)
	}
}
