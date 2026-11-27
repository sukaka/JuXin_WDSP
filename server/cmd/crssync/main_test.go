package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseOptionsUsesFlagsAndEnvWithoutHardcodedPath(t *testing.T) {
	t.Setenv("DB_DIALECT", "postgres")
	t.Setenv("POSTGRES_HOST", "db.internal")
	t.Setenv("POSTGRES_PORT", "5433")
	t.Setenv("POSTGRES_DB", "wdsp_prod")
	t.Setenv("POSTGRES_USER", "wdsp_sync")
	t.Setenv("POSTGRES_PASSWORD", "test-secret")
	t.Setenv("WAF_CRS_DIR", "/opt/crs/rules")
	t.Setenv("WAF_CRS_VERSION", "4.26.0")

	var stderr bytes.Buffer
	opts, err := parseOptions([]string{"--rules-dir", "/custom/crs", "--crs-version", "4.28.1"}, &stderr)
	if err != nil {
		t.Fatalf("parseOptions error: %v", err)
	}
	if opts.rulesDir != "/custom/crs" || opts.crsVersion != "4.28.1" {
		t.Fatalf("unexpected rules opts: %+v", opts)
	}
	if opts.db.Host != "db.internal" || opts.db.Port != 5433 || opts.db.Database != "wdsp_prod" || opts.db.User != "wdsp_sync" {
		t.Fatalf("unexpected db config: %+v", opts.db)
	}
	if opts.db.MaxConns != 2 {
		t.Fatalf("MaxConns = %d, want 2", opts.db.MaxConns)
	}
}

func TestParseOptionsFailsClosedWithoutDBPassword(t *testing.T) {
	t.Setenv("DB_DIALECT", "postgres")
	t.Setenv("DB_PASSWORD", "")
	t.Setenv("POSTGRES_PASSWORD", "")

	var stderr bytes.Buffer
	_, err := parseOptions(nil, &stderr)
	if err == nil || !strings.Contains(err.Error(), "PASSWORD") {
		t.Fatalf("expected missing password error, got %v", err)
	}
}
