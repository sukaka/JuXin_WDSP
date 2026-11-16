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
