package apidataflow

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/ingest"
)

var testAgentID = uuid.New()

type fakeObservationStore struct {
	records []agents.APIObservationEnvelope
}

func (f *fakeObservationStore) SaveBatch(_ context.Context, records []agents.APIObservationEnvelope) error {
	f.records = append(f.records, records...)
	return nil
}

type fakeAssetProjector struct {
	records []agents.APIObservationEnvelope
}

func (f *fakeAssetProjector) Project(_ context.Context, record agents.APIObservationEnvelope) error {
	f.records = append(f.records, record)
	return nil
}

type fakeBus struct {
	produced []ingest.Record
	err      error
}

func (f *fakeBus) PublishBatch(_ context.Context, _ string, records []ingest.Record) error {
	f.produced = append(f.produced, records...)
	return f.err
}
func (f *fakeBus) Health(context.Context) error { return f.err }
func (f *fakeBus) Close() error                 { return nil }
func (f *fakeBus) Run(context.Context, string, []string, ingest.BatchHandler) error {
	return f.err
}

func TestProjectorProjectBatch(t *testing.T) {
	envelope := validProjectionEnvelope()
	value, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	observations := &fakeObservationStore{}
	assets := &fakeAssetProjector{}
	projector := NewProjector(&fakeBus{}, &fakeBus{}, "observations", "dlq", observations, assets)
	err = projector.ProjectBatch(context.Background(), []ingest.Record{{Key: testAgentID.String(), Value: value, Headers: map[string]string{"event_id": envelope.EventID}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(observations.records) != 1 || len(assets.records) != 1 {
		t.Fatalf("projection counts: %d %d", len(observations.records), len(assets.records))
	}
}

func TestProjectorDeadLetter(t *testing.T) {
	bus := &fakeBus{}
	projector := NewProjector(bus, bus, "observations", "dlq", &fakeObservationStore{}, &fakeAssetProjector{})
	raw := ingest.Record{Key: testAgentID.String(), Value: []byte(`{"schema_version":1,"agent_id":"bad"}`), Headers: map[string]string{"event_id": "ev-bad", "agent_id": testAgentID.String()}}
	if err := projector.ProjectBatch(context.Background(), []ingest.Record{raw}); err != nil {
		t.Fatal(err)
	}
	if len(bus.produced) != 1 {
		t.Fatalf("expected one DLQ record: %+v", bus.produced)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(bus.produced[0].Value, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["error_category"] != "INVALID_OBSERVATION" || payload["event_id"] != "ev-bad" {
		t.Fatalf("unexpected DLQ payload: %+v", payload)
	}
}

func TestProjectorRejectsIdentityMismatch(t *testing.T) {
	envelope := validProjectionEnvelope()
	value, _ := json.Marshal(envelope)
	projector := NewProjector(&fakeBus{}, &fakeBus{}, "observations", "dlq", &fakeObservationStore{}, &fakeAssetProjector{})
	_, err := projector.decode(ingest.Record{Key: uuid.NewString(), Value: value})
	if err == nil || !errors.Is(err, err) {
		t.Fatal("expected identity mismatch")
	}
}
