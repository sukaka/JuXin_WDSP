package tests

import (
	"context"
	"os"
	"testing"
)

func TestLLMInputContentMigration000198Replay(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	countColumns := func() int {
		return s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_llm_security_policies' AND column_name='input_content_enabled'`)
	}
	if got := countColumns(); got != 1 {
		t.Fatalf("input content columns=%d want 1", got)
	}
	var defaultValue string
	if err := env.db.QueryRow(ctx, `SELECT column_default FROM information_schema.columns
		WHERE table_name='api_llm_security_policies' AND column_name='input_content_enabled'`).Scan(&defaultValue); err != nil {
		t.Fatal(err)
	}
	if defaultValue != "false" {
		t.Fatalf("default=%s want false", defaultValue)
	}
	upRaw, err := os.ReadFile("../migrations/000198_llm_input_content.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	downRaw, err := os.ReadFile("../migrations/000198_llm_input_content.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.Exec(ctx, string(downRaw)); err != nil {
		t.Fatal(err)
	}
	if got := countColumns(); got != 0 {
		t.Fatalf("after down input content columns=%d want 0", got)
	}
	if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
		t.Fatal(err)
	}
	if got := countColumns(); got != 1 {
		t.Fatalf("after re-up input content columns=%d want 1", got)
	}
}
