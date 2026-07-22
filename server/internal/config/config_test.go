package config

import "testing"

func TestLoad(t *testing.T) {
	t.Setenv("POSTGRES_PASSWORD", "test-postgres-password")
	t.Setenv("VALKEY_PASSWORD", "test-valkey-password")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Env == "" {
		t.Fatal("expected non-empty env")
	}
}
