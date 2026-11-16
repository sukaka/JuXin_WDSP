package tests

import (
	"context"
	"os"
	"testing"
)

func TestLLMTokenBudgetMigration000197Replay(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	countColumns := func() int {
		return s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_llm_security_policies' AND column_name='max_output_tokens'`)
	}
	if got := countColumns(); got != 1 {
		t.Fatalf("token budget columns=%d want 1", got)
	}
	var defaultValue string
	var nullable string
	if err := env.db.QueryRow(ctx, `SELECT column_default, is_nullable FROM information_schema.columns
		WHERE table_name='api_llm_security_policies' AND column_name='max_output_tokens'`).Scan(&defaultValue, &nullable); err != nil {
		t.Fatal(err)
	}
	if defaultValue != "0" || nullable != "NO" {
		t.Fatalf("default=%s nullable=%s", defaultValue, nullable)
	}
	upRaw, err := os.ReadFile("../migrations/000197_llm_token_budget.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	downRaw, err := os.ReadFile("../migrations/000197_llm_token_budget.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.Exec(ctx, string(downRaw)); err != nil {
		t.Fatal(err)
	}
	if got := countColumns(); got != 0 {
		t.Fatalf("after down token budget columns=%d want 0", got)
	}
	if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
		t.Fatal(err)
	}
	if got := countColumns(); got != 1 {
		t.Fatalf("after re-up token budget columns=%d want 1", got)
	}
}
