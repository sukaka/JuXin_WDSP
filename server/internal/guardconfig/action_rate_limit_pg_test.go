package guardconfig

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/settings"
)

func TestCustomEndpointActionPublishAndRollbackPostgres(t *testing.T) {
	dsn := os.Getenv("ACTION_RATE_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("ACTION_RATE_TEST_PG_DSN not set, skipping custom ACTION publish/rollback PostgreSQL test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PostgreSQL DSN: %v", err)
	}
	config.MaxConns = 1
	config.MinConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	defer pool.Close()

	for _, ddl := range []string{
		`CREATE TEMP TABLE api_endpoints (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			endpoint_key text NOT NULL
		) ON COMMIT PRESERVE ROWS`,
		`CREATE TEMP TABLE api_classification_dimensions (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			endpoint_id uuid NOT NULL REFERENCES api_endpoints(id) ON DELETE CASCADE,
			dimension varchar(64) NOT NULL,
			value varchar(128) NOT NULL,
			source varchar(32) NOT NULL DEFAULT 'AUTO',
			confidence double precision NOT NULL DEFAULT 0,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			UNIQUE (endpoint_id, dimension)
		) ON COMMIT PRESERVE ROWS`,
		`CREATE TEMP TABLE system_settings (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			setting_group varchar(64) NOT NULL,
			setting_key varchar(128) NOT NULL,
			setting_value jsonb NOT NULL,
			value_type varchar(32) NOT NULL DEFAULT 'string',
			is_sensitive boolean NOT NULL DEFAULT false,
			description text NOT NULL DEFAULT '',
			updated_by uuid,
			updated_at timestamptz NOT NULL DEFAULT now(),
			version integer NOT NULL DEFAULT 1,
			UNIQUE (setting_group, setting_key)
		) ON COMMIT PRESERVE ROWS`,
		`CREATE TEMP TABLE access_control_versions (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			version_no integer NOT NULL UNIQUE,
			config jsonb NOT NULL,
			config_hash varchar(64) NOT NULL,
			change_summary varchar(1000) NOT NULL DEFAULT '',
			previous_version_id uuid,
			publish_task_id uuid,
			publish_result varchar(20) NOT NULL DEFAULT 'PENDING',
			created_by uuid,
			created_at timestamptz NOT NULL DEFAULT now()
		) ON COMMIT PRESERVE ROWS`,
	} {
		if _, err := pool.Exec(ctx, ddl); err != nil {
			t.Fatalf("create isolated PostgreSQL table: %v", err)
		}
	}

	settingsService := settings.NewService(pool)
	if err := settingsService.UpsertString(ctx, "gateway_runtime", "action_rate_per_minute", "120", "", uuid.New()); err != nil {
		t.Fatalf("enable action rate setting: %v", err)
	}
	assetStore := apiassets.NewStore(pool)
	seedAction := func(endpointKey, action string) uuid.UUID {
		t.Helper()
		var endpointID uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO api_endpoints(endpoint_key) VALUES ($1) RETURNING id`, endpointKey).Scan(&endpointID); err != nil {
			t.Fatalf("insert endpoint: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO api_classification_dimensions(endpoint_id, dimension, value, source, confidence)
			VALUES ($1, 'ACTION', $2, 'MANUAL', 1)`, endpointID, action); err != nil {
			t.Fatalf("insert ACTION mapping: %v", err)
		}
		return endpointID
	}
	customEndpointID := seedAction("POST /v1/reviews", " manual_review_v2 ")
	seedAction("POST /v1/orders", " create ")

	provider := &Provider{
		versions:           accesscontrolversions.NewStore(pool),
		apiEndpointActions: assetStore,
		runtimeSettingsLoader: func(ctx context.Context) (map[string]string, error) {
			value, found, err := settingsService.GetStringWithSource(ctx, "gateway_runtime", "action_rate_per_minute")
			if err != nil {
				return nil, err
			}
			if !found {
				return map[string]string{}, nil
			}
			return map[string]string{"action_rate_per_minute": value}, nil
		},
	}
	buildActionConfig := func() *gatewayconfig.GuardConfig {
		t.Helper()
		cfg := &gatewayconfig.GuardConfig{APIDynamicProtection: true}
		if err := provider.applyGatewayRuntime(ctx, cfg); err != nil {
			t.Fatalf("apply action rate setting: %v", err)
		}
		if err := provider.loadAPIEndpointActions(ctx, cfg); err != nil {
			t.Fatalf("load ACTION mappings: %v", err)
		}
		cfg.APIPolicyVersion = computeAPIPolicyVersion(cfg)
		return cfg
	}

	published := buildActionConfig()
	if published.ActionRatePerMinute != 120 ||
		published.APIEndpointActions["POST /v1/reviews"] != "MANUAL_REVIEW_V2" ||
		published.APIEndpointActions["POST /v1/orders"] != "CREATE" {
		t.Fatalf("published custom/built-in ACTION config = %+v", published)
	}
	snapshotID, err := provider.SaveVersionSnapshot(ctx, published, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("save publish snapshot: %v", err)
	}

	httpPort := 8080
	apps := []gatewayconfig.AppData{{
		AppID: "app-1", Code: "shop", ProtectionMode: applications.ModeProtect,
		Domains: []applications.Domain{{
			ID: uuid.New(), NormalizedHostname: "www.example.com", DomainType: "EXACT",
			IsPrimary: true, HTTPEnabled: true, HTTPPort: &httpPort, Status: "ACTIVE",
		}},
		Upstreams: []applications.Upstream{{
			ID: uuid.New(), Scheme: "http", Host: "192.0.2.1", NormalizedHost: "192.0.2.1",
			Port: 9001, Weight: 10, Status: "ACTIVE",
		}},
	}}
	generate := func(cfg *gatewayconfig.GuardConfig) string {
		t.Helper()
		generated, err := gatewayconfig.Generate(gatewayconfig.GenerateInput{
			Apps: apps, AdminSocket: "unix//var/run/caddy/admin.sock", Guard: cfg,
		})
		if err != nil {
			t.Fatalf("generate gateway config: %v", err)
		}
		return generated.JSON
	}
	publishedJSON := generate(published)
	for _, want := range []string{
		`"action_rate_per_minute":120`,
		`"POST /v1/reviews":"MANUAL_REVIEW_V2"`,
		`"POST /v1/orders":"CREATE"`,
	} {
		if !strings.Contains(publishedJSON, want) {
			t.Fatalf("published gateway JSON missing %s", want)
		}
	}

	if err := settingsService.UpsertString(ctx, "gateway_runtime", "action_rate_per_minute", "90", "", uuid.New()); err != nil {
		t.Fatalf("change current action rate setting: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE api_classification_dimensions SET value = ' manual_review_v3 ' WHERE endpoint_id = $1`, customEndpointID); err != nil {
		t.Fatalf("change current custom ACTION: %v", err)
	}
	rolledBack, err := provider.GetVersionConfig(ctx, snapshotID)
	if err != nil {
		t.Fatalf("rollback custom ACTION snapshot: %v", err)
	}
	if rolledBack.ActionRatePerMinute != 90 || rolledBack.APIEndpointActions["POST /v1/reviews"] != "MANUAL_REVIEW_V3" {
		t.Fatalf("rollback did not replay current custom ACTION config: %+v", rolledBack)
	}
	rolledBackJSON := generate(rolledBack)
	for _, want := range []string{`"action_rate_per_minute":90`, `"POST /v1/reviews":"MANUAL_REVIEW_V3"`} {
		if !strings.Contains(rolledBackJSON, want) {
			t.Fatalf("rolled-back gateway JSON missing %s", want)
		}
	}

	seedAction("POST /v1/reviews", "second_review")
	if err := provider.loadAPIEndpointActions(ctx, &gatewayconfig.GuardConfig{ActionRatePerMinute: 90}); err == nil || !strings.Contains(err.Error(), "冲突 ACTION") {
		t.Fatalf("publish with conflicting endpoint ACTION must fail, error = %v", err)
	}
	if _, err := provider.GetVersionConfig(ctx, snapshotID); err == nil || !strings.Contains(err.Error(), "冲突 ACTION") {
		t.Fatalf("rollback with conflicting endpoint ACTION must fail, error = %v", err)
	}

	if got := len(published.APIEndpointActions); got != 2 {
		t.Fatalf("published mapping count = %d, want 2", got)
	}
	if published.APIPolicyVersion == computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIDynamicProtection: true}) {
		t.Fatal(fmt.Errorf("custom ACTION mappings must affect api_policy_version"))
	}
}
