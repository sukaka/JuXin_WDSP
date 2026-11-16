package apidataflow

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/apm"
	"github.com/jiuzhang-waf/server/internal/ingest"
)

type signalingAssetProjector struct {
	envelope agents.APIObservationEnvelope
	done     chan struct{}
}

func (p *signalingAssetProjector) Project(_ context.Context, envelope agents.APIObservationEnvelope) error {
	p.envelope = envelope
	select {
	case <-p.done:
	default:
		close(p.done)
	}
	return nil
}

func TestObservationPipelineIntegration(t *testing.T) {
	address := os.Getenv("WDSP_KAFKA_TEST_ADDR")
	dsn := os.Getenv("WDSP_CLICKHOUSE_TEST_DSN")
	if address == "" || dsn == "" {
		t.Skip("WDSP_KAFKA_TEST_ADDR and WDSP_CLICKHOUSE_TEST_DSN are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	broker := ingest.NewBroker(ingest.Config{Brokers: []string{address}, ClientID: "wdsp-pipeline-integration"})
	defer broker.Close()
	querier, err := apm.OpenClickHouse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	envelope := validProjectionEnvelope()
	envelope.AgentID = uuid.New()
	envelope.EventID = "ev-pipeline-" + uuid.NewString()
	value, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.PublishBatch(ctx, "wdsp.api.observations.v1", []ingest.Record{{
		Key: envelope.AgentID.String(), Value: value, Headers: map[string]string{"event_id": envelope.EventID, "agent_id": envelope.AgentID.String()},
	}}); err != nil {
		t.Fatal(err)
	}
	assets := &signalingAssetProjector{done: make(chan struct{})}
	projector := NewProjector(broker, broker, "wdsp.api.observations.v1", "wdsp.api.observations.dlq.v1",
		NewCHObservationStore(func(context.Context) apm.CHQuerier { return querier }), assets)
	go projector.Run(ctx)
	select {
	case <-assets.done:
	case <-ctx.Done():
		t.Fatalf("projection did not complete: %v", ctx.Err())
	}
	if assets.envelope.EventID != envelope.EventID {
		t.Fatalf("unexpected projected event: %s", assets.envelope.EventID)
	}
	rows, err := querier.Query(ctx, `SELECT count() FROM wdsp.api_observations WHERE agent_id=? AND event_id=?`, envelope.AgentID, envelope.EventID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("missing projected observation")
	}
	var count uint64
	if err := rows.Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("observation count=%d", count)
	}
	cancel()
}
