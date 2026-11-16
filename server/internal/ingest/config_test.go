package ingest

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	valid := Config{Brokers: []string{"127.0.0.1:9092"}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	tests := []Config{
		{},
		{Brokers: []string{"kafka:9092"}, ProduceTimeout: -time.Second},
		{Brokers: []string{"kafka:9092"}, TLSCertFile: "client.crt"},
		{Brokers: []string{"kafka:9092"}, SASLMechanism: "PLAIN", SASLUsername: "u", SASLPassword: "p"},
		{Brokers: []string{"kafka:9092"}, SASLMechanism: "GSSAPI", SASLUsername: "u", SASLPassword: "p"},
		{Brokers: []string{strings.Repeat("x", 256)}},
	}
	for i, cfg := range tests {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
}

func TestConfigSASLWithTLS(t *testing.T) {
	cfg := Config{Brokers: []string{"kafka:9093"}, TLSEnabled: true, SASLMechanism: "SCRAM-SHA-256", SASLUsername: "writer", SASLPassword: "secret"}
	opts, err := cfg.clientOptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) == 0 {
		t.Fatal("expected Kafka client options")
	}
}
