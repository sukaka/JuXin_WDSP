package tests

import (
	"context"
	"os"
	"testing"
)

func TestAPIScheduleMigration000199Replay(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	countColumns := func() int {
		return s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='report_schedules' AND column_name='api_report_type'`)
	}
	if got := countColumns(); got != 1 {
		t.Fatalf("api report schedule columns=%d want 1", got)
	}
	var defaultValue string
	if err := env.db.QueryRow(ctx, `SELECT column_default FROM information_schema.columns
		WHERE table_name='report_schedules' AND column_name='api_report_type'`).Scan(&defaultValue); err != nil {
		t.Fatal(err)
	}
	if defaultValue != "''::text" {
		t.Fatalf("default=%s want empty string", defaultValue)
	}
	upRaw, err := os.ReadFile("../migrations/000199_report_schedule_api_type.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	downRaw, err := os.ReadFile("../migrations/000199_report_schedule_api_type.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.Exec(ctx, string(downRaw)); err != nil {
		t.Fatal(err)
	}
	if got := countColumns(); got != 0 {
		t.Fatalf("after down api report schedule columns=%d want 0", got)
	}
	if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
		t.Fatal(err)
	}
	if got := countColumns(); got != 1 {
		t.Fatalf("after re-up api report schedule columns=%d want 1", got)
	}
}
