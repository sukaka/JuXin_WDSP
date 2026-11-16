package apidataflow

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/ingest"
)

type persistentContributionStoreFake struct {
	observations  []agents.APIObservationEnvelope
	contributions []Contribution
	directWrites  int
}

func (f *persistentContributionStoreFake) SaveObservationContributions(_ context.Context, records []agents.APIObservationEnvelope) error {
	f.observations = append(f.observations, records...)
	return nil
}

func (f *persistentContributionStoreFake) SaveContributions(_ context.Context, records []Contribution) error {
	f.directWrites++
	f.contributions = append(f.contributions, records...)
	return nil
}

func TestDataflowWorkerUsesPersistentTraceCorrelation(t *testing.T) {
	envelope := validProjectionEnvelope()
	value, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	store := &persistentContributionStoreFake{}
	worker := NewDataflowWorker(&fakeBus{}, &fakeBus{}, "observations", "dlq", store)
	if err := worker.BuildBatch(context.Background(), []ingest.Record{{
		Key: envelope.AgentID.String(), Value: value, Headers: map[string]string{"event_id": envelope.EventID},
	}}); err != nil {
		t.Fatal(err)
	}
	if len(store.observations) != 1 || store.observations[0].EventID != envelope.EventID || store.directWrites != 0 {
		t.Fatalf("worker bypassed persistent Trace correlation: %+v", store)
	}
}
