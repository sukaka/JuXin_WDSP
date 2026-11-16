package tests

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/riskpolicy"
)

func TestSharedDeviceLimitMigration000202Static(t *testing.T) {
	up := readMigration(t, "000202_shared_device_account_limit.up.sql")
	down := readMigration(t, "000202_shared_device_account_limit.down.sql")
	if !strings.Contains(up, "ADD COLUMN IF NOT EXISTS shared_device_account_limit") ||
		!strings.Contains(up, "pg_constraint") || strings.Contains(up, "ADD CONSTRAINT IF NOT EXISTS") {
		t.Fatalf("000202 up must use idempotent column and constraint guards: %s", up)
	}
	if !strings.Contains(down, "DROP CONSTRAINT IF EXISTS chk_risk_override_shared_device_limit") ||
		!strings.Contains(down, "DROP COLUMN IF EXISTS shared_device_account_limit") {
		t.Fatalf("000202 down incomplete: %s", down)
	}
}

func TestSharedDeviceLimitIntegration000202(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	up, err := os.ReadFile("../migrations/000202_shared_device_account_limit.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(up)); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	applicationID := satInsertApp(t, env, "group-limit-"+s5Rand(), "群控阈值测试应用")
	store := riskpolicy.NewStore(env.db)
	policy := &riskpolicy.Policy{
		Scope: riskpolicy.ScopeApplication, ApplicationID: &applicationID,
		Enabled: true, Mode: riskpolicy.ModeObserve,
		BlockThreshold: 80, RateLimitThreshold: 40, RateLimitRPS: 10, SignalWindowSeconds: 86400,
		SharedDeviceAccountLimit: 4, Scores: map[string]int{},
		RiskLevels: map[string]int{"medium": 20, "high": 40, "critical": 70},
	}
	created, err := store.PutApplicationOverride(ctx, policy, 0, "integration-test")
	if err != nil || created.SharedDeviceAccountLimit != 4 || created.Version != 1 {
		t.Fatalf("create limit policy=%+v err=%v", created, err)
	}
	overrides, err := store.ListGuardRiskPolicyOverrides(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, override := range overrides {
		if override.ApplicationID == applicationID.String() {
			found = true
			if override.SharedDeviceAccountLimit != 4 {
				t.Fatalf("guard override=%+v", override)
			}
		}
	}
	if !found {
		t.Fatal("application override missing from guard publication")
	}
	if _, err := env.db.Exec(ctx, `UPDATE security_risk_policy_overrides
		SET shared_device_account_limit=1 WHERE application_id=$1`, applicationID); err == nil {
		t.Fatal("database accepted invalid one-account threshold")
	}

	down, err := os.ReadFile("../migrations/000202_shared_device_account_limit.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.Exec(ctx, string(down)); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
		WHERE table_name='security_risk_policy_overrides' AND column_name='shared_device_account_limit'`); got != 0 {
		t.Fatalf("column remains after down: %d", got)
	}
	if _, err := env.db.Exec(ctx, string(up)); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	var restored int
	if err := env.db.QueryRow(ctx, `SELECT shared_device_account_limit
		FROM security_risk_policy_overrides WHERE application_id=$1`, applicationID).Scan(&restored); err != nil || restored != 0 {
		t.Fatalf("re-up default limit=%d err=%v", restored, err)
	}
}
