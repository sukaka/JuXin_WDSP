package ingest

import (
	"context"
	"strings"
	"testing"
)

func TestPublishBatchValidation(t *testing.T) {
	broker := NewBroker(Config{Brokers: []string{"127.0.0.1:9092"}, MaxBatchRecords: 2, MaxBatchBytes: 64})
	ctx := context.Background()
	if err := broker.PublishBatch(ctx, "topic", nil); err != nil {
		t.Fatal(err)
	}
	if err := broker.PublishBatch(ctx, "", []Record{{Key: "a", Value: []byte("x")}}); err == nil {
		t.Fatal("expected empty topic rejection")
	}
	if err := broker.PublishBatch(ctx, "topic", []Record{{Key: "", Value: []byte("x")}}); err == nil {
		t.Fatal("expected empty key rejection")
	}
	if err := broker.PublishBatch(ctx, "topic", []Record{{Key: "a", Value: nil}}); err == nil {
		t.Fatal("expected empty value rejection")
	}
	if err := broker.PublishBatch(ctx, "topic", []Record{{Key: "a", Value: []byte("x")}, {Key: "b", Value: []byte("y")}, {Key: "c", Value: []byte("z")}}); err == nil {
		t.Fatal("expected record count rejection")
	}
	if err := broker.PublishBatch(ctx, "topic", []Record{{Key: "a", Value: []byte(strings.Repeat("x", 65))}}); err == nil {
		t.Fatal("expected byte limit rejection")
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	input := map[string]string{"schema_version": "1", "event_id": "ev-1"}
	got := headerMap(kafkaHeaders(input))
	if len(got) != 2 || got["schema_version"] != "1" || got["event_id"] != "ev-1" {
		t.Fatalf("unexpected headers: %#v", got)
	}
}

func TestSplitKafkaChunks(t *testing.T) {
	records := []Record{
		{Key: "k1", Value: []byte(strings.Repeat("a", 30)), Headers: map[string]string{"id": "1"}},
		{Key: "k2", Value: []byte(strings.Repeat("b", 30)), Headers: map[string]string{"id": "2"}},
		{Key: "k3", Value: []byte(strings.Repeat("c", 30)), Headers: map[string]string{"id": "3"}},
	}
	chunks, err := splitKafkaChunks("wdsp.api.observations.v1", records, 64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks of <=64B, got %d", len(chunks))
	}
	for i, chunk := range chunks {
		if len(chunk) != 1 || string(chunk[0].Key) != records[i].Key {
			t.Fatalf("chunk %d mismatch: %+v", i, chunk)
		}
	}
	// Two records fit in 80 bytes, third goes into second chunk
	chunks, err = splitKafkaChunks("wdsp.api.observations.v1", records, 80)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) != 2 || len(chunks[0]) != 2 || len(chunks[1]) != 1 {
		t.Fatalf("expected [2,1] chunks, got %d chunks (%d, %d)", len(chunks), len(chunks[0]), len(chunks[1]))
	}
	// Single record exceeding maxBatchBytes returns explicit error
	if _, err := splitKafkaChunks("wdsp.api.observations.v1", []Record{{Key: "k", Value: []byte(strings.Repeat("x", 65))}}, 64); err == nil {
		t.Fatal("expected single oversized record error")
	}
}
