package tests

import (
	"context"
	"os"
	"testing"
)

func TestSoftwareBypassMigration000194Replay(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	count := func() int {
		return s8Count(t, env, `SELECT count(*) FROM system_settings WHERE setting_group='software_bypass'`)
	}
	if got := count(); got != 5 {
		t.Fatalf("software_bypass settings = %d, want 5", got)
	}
	var enabled bool
	if err := env.db.QueryRow(ctx, `SELECT setting_value FROM system_settings
		WHERE setting_group='software_bypass' AND setting_key='enabled'`).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("automatic bypass must be disabled by default")
	}
	upRaw, err := os.ReadFile("../migrations/000194_software_bypass_settings.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	downRaw, err := os.ReadFile("../migrations/000194_software_bypass_settings.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.Exec(ctx, string(downRaw)); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 0 {
		t.Fatalf("after down settings = %d, want 0", got)
	}
	if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
		t.Fatalf("re-apply up: %v", err)
	}
	if got := count(); got != 5 {
		t.Fatalf("after re-up settings = %d, want 5", got)
	}
}
