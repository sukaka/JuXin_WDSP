package tests

import (
	"context"
	"os"
	"testing"
)

func TestLLMSecurityPolicyMigration000195Replay(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	for _, table := range []string{"api_llm_security_policies", "api_llm_security_policy_versions"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables WHERE table_name=$1`, table); n != 1 {
			t.Fatalf("table %s count=%d want 1", table, n)
		}
	}
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code IN ('api_llm_security.read','api_llm_security.manage')`); n != 2 {
		t.Fatalf("permissions=%d want 2", n)
	}
	upRaw, err := os.ReadFile("../migrations/000195_llm_security_policies.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	downRaw, err := os.ReadFile("../migrations/000195_llm_security_policies.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.Exec(ctx, string(downRaw)); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"api_llm_security_policies", "api_llm_security_policy_versions"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables WHERE table_name=$1`, table); n != 0 {
			t.Fatalf("after down table %s count=%d want 0", table, n)
		}
	}
	if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
		t.Fatalf("re-apply up: %v", err)
	}
}
