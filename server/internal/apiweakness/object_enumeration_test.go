package apiweakness

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

type enumerationSignals struct {
	fakeSignals
	signals []EndpointSignal
}

func (s *enumerationSignals) ObjectEnumeration(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	return s.signals, nil
}

func TestSweepObjectEnumerationUsesExistingLifecycle(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	endpointID := uuid.New()
	source := &enumerationSignals{signals: []EndpointSignal{sigFor(endpointID, "GET /v1/cases/{id}", 8, now)}}
	store := NewMemStore()
	store.SetEndpointKey(endpointID, "GET /v1/cases/{id}")
	sweeper := newTestSweeper(source, store, now)
	result, err := sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Inserted != 1 || result.ByCode[CodeObjectEnumerationRisk] != 1 {
		t.Fatalf("unexpected derivation: %+v", result)
	}
	items, total, err := store.List(ctx, ListFilter{Category: CategoryAuthz, Page: 1, PageSize: 20})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("AUTHZ filter: total=%d err=%v", total, err)
	}
	weakness := items[0]
	if weakness.WeaknessCode != CodeObjectEnumerationRisk || weakness.Category != CategoryAuthz || weakness.Severity != SeverityHigh {
		t.Fatalf("unexpected weakness: %+v", weakness)
	}
	var evidence map[string]any
	if err := json.Unmarshal(weakness.Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence["sample_count"] != float64(8) || evidence["rule"] != CodeObjectEnumerationRisk {
		t.Fatalf("unexpected evidence: %+v", evidence)
	}
	for _, key := range []string{"object_id", "object_ref", "principal", "token"} {
		if _, exists := evidence[key]; exists {
			t.Fatalf("weakness evidence must contain aggregate counts only: %+v", evidence)
		}
	}
	for _, action := range []string{ActionConfirm, ActionAssign, ActionMarkFixed, ActionRetestPass} {
		if _, err := store.Transition(ctx, weakness.ID, action, TransitionInput{Actor: "tester", Owner: "owner"}); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	updated, err := store.GetByID(ctx, weakness.ID)
	if err != nil || updated.Status != StatusArchived {
		t.Fatalf("existing retest lifecycle not preserved: %+v err=%v", updated, err)
	}
}

func TestObjectEnumerationCategoryHTTPFilter(t *testing.T) {
	store := NewMemStore()
	seedDerived(t, store, uuid.New(), CodeObjectEnumerationRisk, time.Now().UTC())
	mux := newTestMux(NewHandler(store, nil))
	rr := doJSON(t, mux, "GET", "/api/v1/api-security/weaknesses?category=authz", nil)
	if rr.Code != 200 {
		t.Fatalf("AUTHZ filter status=%d body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	if data["total"] != float64(1) {
		t.Fatalf("AUTHZ filter should return the derived weakness: %+v", data)
	}
}
