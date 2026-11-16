package ingest

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBrokerProduceConsumeIntegration(t *testing.T) {
	address := os.Getenv("WDSP_KAFKA_TEST_ADDR")
	if address == "" {
		t.Skip("WDSP_KAFKA_TEST_ADDR is not configured")
	}
	broker := NewBroker(Config{Brokers: []string{address}, ClientID: "wdsp-ingest-integration"})
	defer broker.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := broker.Health(ctx); err != nil {
		t.Fatalf("Kafka health: %v", err)
	}
	id := uuid.NewString()
	value := []byte(fmt.Sprintf(`{"schema_version":1,"event_id":%q}`, id))
	if err := broker.PublishBatch(ctx, "wdsp.api.observations.v1", []Record{{
		Key: "integration-agent", Value: value,
		Headers: map[string]string{"schema_version": "1", "event_id": id},
	}}); err != nil {
		t.Fatalf("produce: %v", err)
	}

	handled := make(chan error, 1)
	runDone := make(chan error, 1)
	go func() {
		runDone <- broker.Run(ctx, "wdsp-ingest-integration-"+id, []string{"wdsp.api.observations.v1"}, func(_ context.Context, records []Record) error {
			for _, rec := range records {
				if string(rec.Value) == string(value) && rec.Headers["event_id"] == id {
					handled <- nil
					return nil
				}
			}
			return nil
		})
	}()
	select {
	case err := <-handled:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for produced record: %v", ctx.Err())
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("consumer stopped with error: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("consumer did not stop")
	}
}
