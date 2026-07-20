package config

import "testing"

func TestLoad(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Env == "" {
		t.Fatal("expected non-empty env")
	}
}
