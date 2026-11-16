package database

import (
	"context"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/config"
)

func TestConnectDoesNotFallBackToPostgresForVendorDialect(t *testing.T) {
	for _, dialect := range []string{config.DBDialectKingbase, config.DBDialectDameng} {
		t.Run(dialect, func(t *testing.T) {
			cfg := config.DBConfig{
				Dialect:  dialect,
				Host:     "127.0.0.1",
				Port:     1,
				Database: "wdsp",
				User:     "wdsp",
				Password: "test-password",
			}
			_, err := Connect(context.Background(), cfg)
			if err == nil {
				t.Fatal("Connect() unexpectedly used the PostgreSQL driver")
			}
			if !strings.Contains(err.Error(), "vendor driver") {
				t.Fatalf("Connect() error = %q, want vendor driver explanation", err)
			}
		})
	}
}
