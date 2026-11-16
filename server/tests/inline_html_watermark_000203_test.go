package tests

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestInlineHTMLWatermarkMigration000203(t *testing.T) {
	up := readMigration(t, "000203_inline_html_watermark.up.sql")
	down := readMigration(t, "000203_inline_html_watermark.down.sql")
	if !containsAllInlineHTML(up, []string{"api_file_watermark_include_inline_html", "'false'", "'boolean'", "ON CONFLICT"}) {
		t.Fatalf("000203 up missing guarded default: %s", up)
	}
	if !containsAllInlineHTML(down, []string{"api_file_watermark_include_inline_html", "DELETE FROM system_settings"}) {
		t.Fatalf("000203 down missing cleanup: %s", down)
	}

	env := setupTestEnv(t)
	ctx := context.Background()
	upRaw, err := os.ReadFile("../migrations/000203_inline_html_watermark.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	var enabled bool
	if err := env.db.QueryRow(ctx, `SELECT setting_value FROM system_settings
		WHERE setting_group='gateway_runtime' AND setting_key='api_file_watermark_include_inline_html'`).Scan(&enabled); err != nil || enabled {
		t.Fatalf("inline HTML default enabled=%v err=%v", enabled, err)
	}
	downRaw, err := os.ReadFile("../migrations/000203_inline_html_watermark.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.db.Exec(ctx, string(downRaw)); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM system_settings
		WHERE setting_group='gateway_runtime' AND setting_key='api_file_watermark_include_inline_html'`); got != 0 {
		t.Fatalf("setting remains after down: %d", got)
	}
	if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
		t.Fatalf("re-up: %v", err)
	}
}

func containsAllInlineHTML(value string, fragments []string) bool {
	for _, fragment := range fragments {
		if !strings.Contains(value, fragment) {
			return false
		}
	}
	return true
}
