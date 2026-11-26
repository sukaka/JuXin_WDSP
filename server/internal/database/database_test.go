package database

import (
	"context"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/config"
)

func TestBuildPoolConfigProfiles(t *testing.T) {
	cfg := config.DBConfig{
		Dialect:              config.DBDialectPostgres,
		Host:                 "127.0.0.1",
		Port:                 5432,
		Database:             "jiuzhang_waf",
		User:                 "jiuzhang",
		Password:             "test-password",
		SSLMode:              "disable",
		MaxConns:             32,
		MinConns:             4,
		BGMaxConns:           16,
		BGMinConns:           2,
		StatementTimeoutMs:   15000,
		BGStatementTimeoutMs: 120000,
		LockTimeoutMs:        5000,
		IdleInTxTimeoutMs:    30000,
	}

	apiCfg, err := buildPoolConfig(cfg, ProfileAPI)
	if err != nil {
		t.Fatalf("ProfileAPI buildPoolConfig: %v", err)
	}
	if apiCfg.MaxConns != 32 || apiCfg.MinConns != 4 {
		t.Fatalf("ProfileAPI conns = %d/%d, want 32/4", apiCfg.MaxConns, apiCfg.MinConns)
	}
	rt := apiCfg.ConnConfig.RuntimeParams
	if rt["application_name"] != "jiuzhang-api" || rt["statement_timeout"] != "15000" ||
		rt["lock_timeout"] != "5000" || rt["idle_in_transaction_session_timeout"] != "30000" {
		t.Fatalf("ProfileAPI runtime params unexpected: %+v", rt)
	}

	bgCfg, err := buildPoolConfig(cfg, ProfileBackground)
	if err != nil {
		t.Fatalf("ProfileBackground buildPoolConfig: %v", err)
	}
	if bgCfg.MaxConns != 16 || bgCfg.MinConns != 2 {
		t.Fatalf("ProfileBackground conns = %d/%d, want 16/2", bgCfg.MaxConns, bgCfg.MinConns)
	}
	bgRT := bgCfg.ConnConfig.RuntimeParams
	if bgRT["application_name"] != "jiuzhang-bg" || bgRT["statement_timeout"] != "120000" ||
		bgRT["lock_timeout"] != "10000" || bgRT["idle_in_transaction_session_timeout"] != "60000" {
		t.Fatalf("ProfileBackground runtime params unexpected: %+v", bgRT)
	}

	migCfg, err := buildPoolConfig(cfg, ProfileMigrate)
	if err != nil {
		t.Fatalf("ProfileMigrate buildPoolConfig: %v", err)
	}
	if migCfg.MaxConns != 4 || migCfg.MinConns != 1 {
		t.Fatalf("ProfileMigrate conns = %d/%d, want 4/1", migCfg.MaxConns, migCfg.MinConns)
	}
	if migCfg.ConnConfig.RuntimeParams["statement_timeout"] != "0" ||
		migCfg.ConnConfig.RuntimeParams["application_name"] != "jiuzhang-migrate" {
		t.Fatalf("ProfileMigrate runtime params unexpected: %+v", migCfg.ConnConfig.RuntimeParams)
	}

	// MinConns > MaxConns 防御钳位
	small := cfg
	small.MaxConns = 2
	small.MinConns = 8
	clamped, err := buildPoolConfig(small, ProfileAPI)
	if err != nil {
		t.Fatalf("clamped buildPoolConfig: %v", err)
	}
	if clamped.MaxConns != 2 || clamped.MinConns != 2 {
		t.Fatalf("expected MinConns clamped to MaxConns=2, got %d/%d", clamped.MaxConns, clamped.MinConns)
	}
}

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

func TestConnectWithProfileSessionTimeoutsPG(t *testing.T) {
	dsn := os.Getenv("DATABASE_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DATABASE_TEST_PG_DSN not set, skipping PG integration test")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 5432
	}
	pw, _ := u.User.Password()
	sslMode := u.Query().Get("sslmode")
	if sslMode == "" {
		sslMode = "disable"
	}
	cfg := config.DBConfig{
		Dialect:              config.DBDialectPostgres,
		Host:                 u.Hostname(),
		Port:                 port,
		Database:             strings.TrimPrefix(u.Path, "/"),
		User:                 u.User.Username(),
		Password:             pw,
		SSLMode:              sslMode,
		MaxConns:             32,
		MinConns:             4,
		BGMaxConns:           16,
		BGMinConns:           2,
		StatementTimeoutMs:   15000,
		BGStatementTimeoutMs: 120000,
		LockTimeoutMs:        5000,
		IdleInTxTimeoutMs:    30000,
	}

	ctx := context.Background()
	for _, tc := range []struct {
		profile    PoolProfile
		wantApp    string
		wantStmt   string
		wantLock   string
		wantIdleTx string
	}{
		{ProfileAPI, "jiuzhang-api", "15s", "5s", "30s"},
		{ProfileBackground, "jiuzhang-bg", "2min", "10s", "1min"},
		{ProfileMigrate, "jiuzhang-migrate", "0", "30s", "1min"},
	} {
		t.Run(string(tc.profile), func(t *testing.T) {
			pool, err := ConnectWithProfile(ctx, cfg, tc.profile)
			if err != nil {
				t.Fatalf("ConnectWithProfile(%s): %v", tc.profile, err)
			}
			defer pool.Close()

			var appName, stmtTimeout, lockTimeout, idleTxTimeout string
			if err := pool.QueryRow(ctx, `SHOW application_name`).Scan(&appName); err != nil {
				t.Fatalf("SHOW application_name: %v", err)
			}
			if err := pool.QueryRow(ctx, `SHOW statement_timeout`).Scan(&stmtTimeout); err != nil {
				t.Fatalf("SHOW statement_timeout: %v", err)
			}
			if err := pool.QueryRow(ctx, `SHOW lock_timeout`).Scan(&lockTimeout); err != nil {
				t.Fatalf("SHOW lock_timeout: %v", err)
			}
			if err := pool.QueryRow(ctx, `SHOW idle_in_transaction_session_timeout`).Scan(&idleTxTimeout); err != nil {
				t.Fatalf("SHOW idle_in_transaction_session_timeout: %v", err)
			}
			if appName != tc.wantApp || stmtTimeout != tc.wantStmt || lockTimeout != tc.wantLock || idleTxTimeout != tc.wantIdleTx {
				t.Fatalf("profile %s settings = (app=%q stmt=%q lock=%q idle_tx=%q), want (app=%q stmt=%q lock=%q idle_tx=%q)",
					tc.profile, appName, stmtTimeout, lockTimeout, idleTxTimeout,
					tc.wantApp, tc.wantStmt, tc.wantLock, tc.wantIdleTx)
			}
		})
	}
}
