package config

import (
	"net/url"
	"reflect"
	"testing"
)

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

func TestGatewayValkeyAddressFallsBackToCache(t *testing.T) {
	cache := CacheConfig{Host: "valkey", Port: 6379}
	if got := (GatewayConfig{}).ValkeyAddress(cache); got != "valkey:6379" {
		t.Fatalf("fallback Valkey address = %q, want valkey:6379", got)
	}
}

func TestGatewayValkeyAddressUsesExplicitOverride(t *testing.T) {
	cache := CacheConfig{Host: "valkey", Port: 6379}
	gw := GatewayConfig{ValkeyAddr: "127.0.0.1:6379"}
	if got := gw.ValkeyAddress(cache); got != "127.0.0.1:6379" {
		t.Fatalf("explicit Valkey address = %q, want 127.0.0.1:6379", got)
	}
}

func TestLoadGatewayValkeyAddrFromEnv(t *testing.T) {
	t.Setenv("POSTGRES_PASSWORD", "test-postgres-password")
	t.Setenv("VALKEY_PASSWORD", "test-valkey-password")
	t.Setenv("GATEWAY_VALKEY_ADDR", "127.0.0.1:6380")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Gateway.ValkeyAddr != "127.0.0.1:6380" {
		t.Fatalf("Gateway.ValkeyAddr = %q, want 127.0.0.1:6380", cfg.Gateway.ValkeyAddr)
	}
}

func TestDBConfigDSNEscapesCredentialsAndIPv6(t *testing.T) {
	cfg := DBConfig{
		Host:     "2001:db8::1",
		Port:     5432,
		Database: "waf/name",
		User:     "user@tenant",
		Password: "p@ss:/?#[]",
		SSLMode:  "verify-full",
	}

	parsed, err := url.Parse(cfg.DSN())
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	password, ok := parsed.User.Password()
	if !ok {
		t.Fatal("DSN password missing")
	}
	if parsed.User.Username() != cfg.User || password != cfg.Password {
		t.Fatalf("credentials = %q/%q, want %q/%q",
			parsed.User.Username(), password, cfg.User, cfg.Password)
	}
	if parsed.Host != "[2001:db8::1]:5432" {
		t.Fatalf("host = %q, want IPv6 host with port", parsed.Host)
	}
	if parsed.Path != "/waf/name" {
		t.Fatalf("database path = %q, want %q", parsed.Path, "/waf/name")
	}
	if parsed.Query().Get("sslmode") != cfg.SSLMode {
		t.Fatalf("sslmode = %q, want %q", parsed.Query().Get("sslmode"), cfg.SSLMode)
	}
}

func TestLoadTrustedProxyCIDRs(t *testing.T) {
	t.Setenv("POSTGRES_PASSWORD", "test-postgres-password")
	t.Setenv("VALKEY_PASSWORD", "test-valkey-password")
	t.Setenv("MANAGEMENT_TRUSTED_PROXY_CIDRS", "172.16.0.0/12, 10.0.0.1/32")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := []string{"172.16.0.0/12", "10.0.0.1/32"}
	if !reflect.DeepEqual(cfg.Security.TrustedProxyCIDRs, want) {
		t.Fatalf("TrustedProxyCIDRs = %#v, want %#v", cfg.Security.TrustedProxyCIDRs, want)
	}
}

func TestLoadRejectsInvalidTrustedProxyCIDR(t *testing.T) {
	t.Setenv("POSTGRES_PASSWORD", "test-postgres-password")
	t.Setenv("VALKEY_PASSWORD", "test-valkey-password")
	t.Setenv("MANAGEMENT_TRUSTED_PROXY_CIDRS", "not-a-cidr")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted invalid MANAGEMENT_TRUSTED_PROXY_CIDRS")
	}
}

func TestLoadAPMSelfTelemetryDefaults(t *testing.T) {
	t.Setenv("POSTGRES_PASSWORD", "test-postgres-password")
	t.Setenv("VALKEY_PASSWORD", "test-valkey-password")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.APM.SelfTelemetryEnabled {
		t.Error("SelfTelemetryEnabled default should be false")
	}
	if cfg.APM.OTLPAddr != "http://127.0.0.1:4318" {
		t.Errorf("OTLPAddr default = %q, want http://127.0.0.1:4318", cfg.APM.OTLPAddr)
	}
	if cfg.Gateway.TracingEnabled {
		t.Error("Gateway.TracingEnabled default should be false")
	}
}

func TestLoadAPMSelfTelemetryFromEnv(t *testing.T) {
	t.Setenv("POSTGRES_PASSWORD", "test-postgres-password")
	t.Setenv("VALKEY_PASSWORD", "test-valkey-password")
	t.Setenv("APM_SELF_TELEMETRY_ENABLED", "true")
	t.Setenv("APM_OTLP_ADDR", "http://10.0.0.8:4318")
	t.Setenv("GATEWAY_TRACING_ENABLED", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.APM.SelfTelemetryEnabled {
		t.Error("SelfTelemetryEnabled should be true")
	}
	if cfg.APM.OTLPAddr != "http://10.0.0.8:4318" {
		t.Errorf("OTLPAddr = %q, want http://10.0.0.8:4318", cfg.APM.OTLPAddr)
	}
	if !cfg.Gateway.TracingEnabled {
		t.Error("Gateway.TracingEnabled should be true")
	}
}
