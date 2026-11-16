package apiweakness

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

type businessFlowSignals struct {
	fakeSignals
	byRule map[string][]EndpointSignal
}

func (s *businessFlowSignals) FlowSequence(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	return selectFlowSignals(s.byRule, flowSequenceRuleIDs...), nil
}

func (s *businessFlowSignals) FlowReplayBurst(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	return selectFlowSignals(s.byRule, flowReplayBurstRuleIDs...), nil
}

func selectFlowSignals(byRule map[string][]EndpointSignal, rules ...string) []EndpointSignal {
	var out []EndpointSignal
	for _, rule := range rules {
		out = append(out, byRule[rule]...)
	}
	return out
}

func TestSweepBusinessFlowWeaknesses(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	sequenceEndpoint, burstEndpoint, unknownEndpoint := uuid.New(), uuid.New(), uuid.New()
	source := &businessFlowSignals{byRule: map[string][]EndpointSignal{
		"flow.step_skip":      {sigFor(sequenceEndpoint, "POST /v1/orders:submit", 2, now)},
		"flowguard.violation": {sigFor(sequenceEndpoint, "POST /v1/orders:submit", 1, now)},
		"flow.rapid_batch":    {sigFor(burstEndpoint, "POST /v1/orders:approve", 4, now)},
		"flowguard.unknown":   {sigFor(unknownEndpoint, "POST /v1/orders:review", 99, now)},
	}}
	store := NewMemStore()
	store.SetEndpointKey(sequenceEndpoint, "POST /v1/orders:submit")
	store.SetEndpointKey(burstEndpoint, "POST /v1/orders:approve")
	result, err := newTestSweeper(source, store, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Inserted != 2 || result.Updated != 1 || result.ByCode[CodeFlowSequenceDeviation] != 2 || result.ByCode[CodeFlowReplayOrBurst] != 1 {
		t.Fatalf("unexpected business flow derivation: %+v", result)
	}
	items, total, err := store.List(context.Background(), ListFilter{Category: CategoryAuthz, Page: 1, PageSize: 20})
	if err != nil || total != 2 {
		t.Fatalf("weakness list: total=%d err=%v", total, err)
	}
	byCode := map[string]Weakness{}
	for _, item := range items {
		byCode[item.WeaknessCode] = item
	}
	if item := byCode[CodeFlowSequenceDeviation]; item.TriggerCount != 2 || item.Severity != SeverityHigh || item.Category != CategoryAuthz {
		t.Fatalf("sequence weakness must merge evidence into existing lifecycle: %+v", item)
	}
	if item := byCode[CodeFlowReplayOrBurst]; item.TriggerCount != 1 || item.Severity != SeverityMedium {
		t.Fatalf("replay/burst weakness: %+v", item)
	}
	if _, exists := byCode["flowguard.unknown"]; exists {
		t.Fatal("dependency UNKNOWN must not become a business-flow weakness")
	}
	for _, item := range items {
		if item.EndpointID != nil && *item.EndpointID == unknownEndpoint {
			t.Fatalf("UNKNOWN endpoint must not be derived: %+v", item)
		}
	}
}

func TestSweepBusinessFlowNormalFlowProducesNothing(t *testing.T) {
	store := NewMemStore()
	result, err := newTestSweeper(&businessFlowSignals{}, store, time.Now().UTC()).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Inserted != 0 || result.Updated != 0 {
		t.Fatalf("normal flow without findings must not create weaknesses: %+v", result)
	}
	if _, total, err := store.List(context.Background(), ListFilter{Page: 1, PageSize: 20}); err != nil || total != 0 {
		t.Fatalf("normal flow should have no weakness: total=%d err=%v", total, err)
	}
}

func TestBusinessFlowWeaknessHTTP(t *testing.T) {
	store := NewMemStore()
	seedDerived(t, store, uuid.New(), CodeFlowSequenceDeviation, time.Now().UTC())
	mux := newTestMux(NewHandler(store, nil))
	rr := doJSON(t, mux, "GET", "/api/v1/api-security/weaknesses?category=AUTHZ", nil)
	if rr.Code != 200 {
		t.Fatalf("flow weakness HTTP status=%d body=%s", rr.Code, rr.Body.String())
	}
	if data := decodeData(t, rr); data["total"] != float64(1) {
		t.Fatalf("flow weakness should be returned by existing list API: %+v", data)
	}
}
