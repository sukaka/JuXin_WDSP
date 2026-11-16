package tests

import (
	"context"
	"os"
	"testing"
)

func TestRiskPolicyOverrideMigration000200Replay(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	countTable := func() int {
		return s8Count(t, env, `SELECT count(*) FROM information_schema.tables
			WHERE table_schema='public' AND table_name='security_risk_policy_overrides'`)
	}
	if got := countTable(); got != 1 {
		t.Fatalf("override tables=%d want 1", got)
	}
	upRaw, err := os.ReadFile("../migrations/000200_risk_policy_application_overrides.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	downRaw, err := os.ReadFile("../migrations/000200_risk_policy_application_overrides.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.Exec(ctx, string(downRaw)); err != nil {
		t.Fatal(err)
	}
	if got := countTable(); got != 0 {
		t.Fatalf("after down override tables=%d want 0", got)
	}
	if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
		t.Fatal(err)
	}
	if got := countTable(); got != 1 {
		t.Fatalf("after re-up override tables=%d want 1", got)
	}
}
