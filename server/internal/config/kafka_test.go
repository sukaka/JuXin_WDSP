package config

import (
	"testing"
	"time"
)

func TestLoadKafkaDefaultsDisabled(t *testing.T) {
	t.Setenv("POSTGRES_PASSWORD", "test")
	t.Setenv("VALKEY_PASSWORD", "test")
	t.Setenv("KAFKA_ENABLED", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Kafka.Enabled || cfg.Kafka.Topic != "wdsp.api.observations.v1" || cfg.Kafka.MaxBatchRecords != 100 || cfg.Kafka.ProduceTimeout != 10*time.Second {
		t.Fatalf("unexpected Kafka defaults: %+v", cfg.Kafka)
	}
}

func TestLoadKafkaFromEnv(t *testing.T) {
	t.Setenv("POSTGRES_PASSWORD", "test")
	t.Setenv("VALKEY_PASSWORD", "test")
	t.Setenv("KAFKA_ENABLED", "true")
	t.Setenv("KAFKA_BROKERS", "kafka-1:29092, kafka-2:29092")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Kafka.Brokers) != 2 || cfg.Kafka.Brokers[1] != "kafka-2:29092" {
		t.Fatalf("unexpected brokers: %#v", cfg.Kafka.Brokers)
	}
}

func TestLoadKafkaRequiresBrokers(t *testing.T) {
	t.Setenv("POSTGRES_PASSWORD", "test")
	t.Setenv("VALKEY_PASSWORD", "test")
	t.Setenv("KAFKA_ENABLED", "true")
	t.Setenv("KAFKA_BROKERS", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected missing brokers error")
	}
}
