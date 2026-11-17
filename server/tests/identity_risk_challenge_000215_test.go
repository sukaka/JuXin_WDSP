package tests

import (
	"context"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/riskpolicy"
)

func TestIdentityRiskChallengeMigration000215Static(t *testing.T) {
	up := readMigration(t, "000215_identity_risk_challenge.up.sql")
	if got := strings.Count(up, "ADD COLUMN IF NOT EXISTS challenge_threshold INTEGER NOT NULL DEFAULT 0"); got != 2 {
		t.Fatalf("000215 must add a default-zero column to both policy tables, count=%d: %s", got, up)
	}
	for _, fragment := range []string{
		"ALTER TABLE security_risk_policy", "ALTER TABLE security_risk_policy_overrides",
		"chk_risk_policy_challenge_threshold", "chk_risk_override_challenge_threshold",
		"pg_constraint", "challenge_threshold BETWEEN 1 AND 100",
		"rate_limit_threshold < challenge_threshold", "challenge_threshold < block_threshold",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("000215 up missing %q: %s", fragment, up)
		}
	}
	if strings.Contains(up, "ADD CONSTRAINT IF NOT EXISTS") {
		t.Fatalf("000215 must use pg_constraint guards for replay safety: %s", up)
	}
	down := readMigration(t, "000215_identity_risk_challenge.down.sql")
	for _, fragment := range []string{
		"DROP CONSTRAINT IF EXISTS chk_risk_policy_challenge_threshold",
		"DROP CONSTRAINT IF EXISTS chk_risk_override_challenge_threshold",
		"DROP COLUMN IF EXISTS challenge_threshold",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("000215 down missing %q: %s", fragment, down)
		}
	}
}

func TestIdentityRiskChallengeMigration000215Integration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	up := readMigration(t, "000215_identity_risk_challenge.up.sql")
	down := readMigration(t, "000215_identity_risk_challenge.down.sql")
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, up); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}

	store := riskpolicy.NewStore(env.db)
	global, err := store.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if global.ChallengeThreshold != 0 {
		t.Fatalf("global default challenge threshold=%d, want 0", global.ChallengeThreshold)
	}
	global.ChallengeThreshold = 55
	previousVersion := global.Version
	if err := store.Update(ctx, global, "migration-test"); err != nil {
		t.Fatalf("update global challenge threshold: %v", err)
	}
	if global.Version != previousVersion+1 {
		t.Fatalf("global policy version=%d, want %d", global.Version, previousVersion+1)
	}
	guardGlobal, err := store.GetGuardRiskPolicy(ctx)
	if err != nil || guardGlobal.ChallengeThreshold != 55 {
		t.Fatalf("guard global challenge=%+v err=%v", guardGlobal, err)
	}

	applicationID := satInsertApp(t, env, "risk-challenge-"+s5Rand(), "身份挑战迁移测试应用")
	override := &riskpolicy.Policy{
		Scope: riskpolicy.ScopeApplication, ApplicationID: &applicationID,
		Enabled: true, Mode: riskpolicy.ModeObserve,
		BlockThreshold: 80, RateLimitThreshold: 40, ChallengeThreshold: 60,
		RateLimitRPS: 10, SignalWindowSeconds: 86400, Scores: map[string]int{},
		RiskLevels: map[string]int{"medium": 20, "high": 40, "critical": 70},
	}
	created, err := store.PutApplicationOverride(ctx, override, 0, "migration-test")
	if err != nil || created.ChallengeThreshold != 60 || created.Version != 1 {
		t.Fatalf("create challenge override=%+v err=%v", created, err)
	}
	overrides, err := store.ListGuardRiskPolicyOverrides(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range overrides {
		if item.ApplicationID == applicationID.String() {
			found = true
			if item.Policy.ChallengeThreshold != 60 {
				t.Fatalf("guard override challenge=%+v", item.Policy)
			}
		}
	}
	if !found {
		t.Fatal("challenge override missing from guard publication")
	}

	for _, table := range []string{"security_risk_policy", "security_risk_policy_overrides"} {
		for _, threshold := range []int{-1, 1, 40, 80, 101} {
			query := "UPDATE " + table + " SET challenge_threshold=$1"
			args := []any{threshold}
			if table == "security_risk_policy_overrides" {
				query += " WHERE application_id=$2"
				args = append(args, applicationID)
			} else {
				query += " WHERE scope='GLOBAL'"
			}
			if _, err := env.db.Exec(ctx, query, args...); err == nil {
				t.Errorf("%s accepted invalid challenge threshold %d", table, threshold)
			}
		}
	}
	if _, err := env.db.Exec(ctx, `UPDATE security_risk_policy SET challenge_threshold=0 WHERE scope='GLOBAL'`); err != nil {
		t.Fatalf("global explicit zero rejected: %v", err)
	}
	if _, err := env.db.Exec(ctx, `UPDATE security_risk_policy_overrides SET challenge_threshold=0 WHERE application_id=$1`, applicationID); err != nil {
		t.Fatalf("override explicit zero rejected: %v", err)
	}

	if _, err := env.db.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
		WHERE table_name IN ('security_risk_policy','security_risk_policy_overrides') AND column_name='challenge_threshold'`); got != 0 {
		t.Fatalf("challenge columns remain after down: %d", got)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	global, err = store.Get(ctx)
	if err != nil || global.ChallengeThreshold != 0 {
		t.Fatalf("global re-up default=%+v err=%v", global, err)
	}
	created, err = store.GetApplicationOverride(ctx, applicationID)
	if err != nil || created == nil || created.ChallengeThreshold != 0 {
		t.Fatalf("override re-up default=%+v err=%v", created, err)
	}
}
