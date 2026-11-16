package tests

import (
	"context"
	"os"
	"testing"
)

func TestLLMOutputProtectionMigration000196Replay(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	countColumns := func() int {
		return s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_llm_security_policies'
			  AND column_name IN ('output_content_enabled','output_pii_enabled')`)
	}
	if got := countColumns(); got != 2 {
		t.Fatalf("output protection columns=%d want 2", got)
	}
	rows, err := env.db.Query(ctx, `SELECT column_name, column_default FROM information_schema.columns
		WHERE table_name='api_llm_security_policies'
		  AND column_name IN ('output_content_enabled','output_pii_enabled') ORDER BY column_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, defaultValue string
		if err := rows.Scan(&name, &defaultValue); err != nil {
			t.Fatal(err)
		}
		if defaultValue != "false" {
			t.Fatalf("%s default=%s want false", name, defaultValue)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	upRaw, err := os.ReadFile("../migrations/000196_llm_output_protection.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	downRaw, err := os.ReadFile("../migrations/000196_llm_output_protection.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.Exec(ctx, string(downRaw)); err != nil {
		t.Fatal(err)
	}
	if got := countColumns(); got != 0 {
		t.Fatalf("after down output columns=%d want 0", got)
	}
	if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
		t.Fatalf("re-apply up: %v", err)
	}
	if got := countColumns(); got != 2 {
		t.Fatalf("after re-up output columns=%d want 2", got)
	}
}
