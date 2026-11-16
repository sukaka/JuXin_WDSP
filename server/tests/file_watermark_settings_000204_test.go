package tests

import (
	"context"
	"strings"
	"testing"
)

type fileWatermarkSetting000204 struct {
	key       string
	value     string
	valueType string
}

var fileWatermarkDefaults000204 = []fileWatermarkSetting000204{
	{key: "api_file_watermark_enabled", value: "false", valueType: "boolean"},
	{key: "api_file_watermark_template", value: `""`, valueType: "string"},
	{key: "api_file_watermark_content_types", value: `"text/plain,text/csv,application/json,text/markdown"`, valueType: "string"},
	{key: "api_file_watermark_json_key", value: `"_wm"`, valueType: "string"},
}

func TestFileWatermarkSettings000204Static(t *testing.T) {
	up := readMigration(t, "000204_file_watermark_settings.up.sql")
	if !strings.Contains(up, "ON CONFLICT (setting_group, setting_key) DO NOTHING") {
		t.Fatalf("000204 up must preserve existing settings: %s", up)
	}
	for _, setting := range fileWatermarkDefaults000204 {
		for _, fragment := range []string{setting.key, "'" + setting.value + "'", "'" + setting.valueType + "'"} {
			if !strings.Contains(up, fragment) {
				t.Errorf("000204 up missing %q for %s", fragment, setting.key)
			}
		}
	}

	down := readMigration(t, "000204_file_watermark_settings.down.sql")
	if !strings.Contains(down, "DELETE FROM system_settings") ||
		!strings.Contains(down, "setting_group = 'gateway_runtime'") {
		t.Fatalf("000204 down missing scoped settings cleanup: %s", down)
	}
	for _, setting := range fileWatermarkDefaults000204 {
		if !strings.Contains(down, setting.key) {
			t.Errorf("000204 down missing %s", setting.key)
		}
	}
	if strings.Contains(down, "api_file_watermark_include_inline_html") {
		t.Fatal("000204 down must not remove the inline HTML watermark setting")
	}
}

func TestFileWatermarkSettings000204Integration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	up := readMigration(t, "000204_file_watermark_settings.up.sql")
	down := readMigration(t, "000204_file_watermark_settings.down.sql")

	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, up); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	assertFileWatermarkSettings000204(t, env, fileWatermarkDefaults000204)

	custom := []fileWatermarkSetting000204{
		{key: "api_file_watermark_enabled", value: "true", valueType: "boolean"},
		{key: "api_file_watermark_template", value: `"custom {ip}"`, valueType: "string"},
		{key: "api_file_watermark_content_types", value: `"application/json"`, valueType: "string"},
		{key: "api_file_watermark_json_key", value: `"custom_wm"`, valueType: "string"},
	}
	for _, setting := range custom {
		if _, err := env.db.Exec(ctx, `UPDATE system_settings
			SET setting_value=$1::jsonb
			WHERE setting_group='gateway_runtime' AND setting_key=$2`, setting.value, setting.key); err != nil {
			t.Fatalf("customize %s: %v", setting.key, err)
		}
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("replay up with existing values: %v", err)
	}
	assertFileWatermarkSettings000204(t, env, custom)

	if _, err := env.db.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM system_settings
		WHERE setting_group='gateway_runtime' AND setting_key = ANY($1)`, fileWatermarkSettingKeys000204()); got != 0 {
		t.Fatalf("settings remain after down: %d", got)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM system_settings
		WHERE setting_group='gateway_runtime' AND setting_key='api_file_watermark_include_inline_html'`); got != 1 {
		t.Fatalf("down removed unrelated inline HTML setting: count=%d", got)
	}

	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	assertFileWatermarkSettings000204(t, env, fileWatermarkDefaults000204)
}

func fileWatermarkSettingKeys000204() []string {
	keys := make([]string, 0, len(fileWatermarkDefaults000204))
	for _, setting := range fileWatermarkDefaults000204 {
		keys = append(keys, setting.key)
	}
	return keys
}

func assertFileWatermarkSettings000204(t *testing.T, env *testEnv, expected []fileWatermarkSetting000204) {
	t.Helper()
	for _, want := range expected {
		var value, valueType string
		if err := env.db.QueryRow(context.Background(), `SELECT setting_value::text, value_type
			FROM system_settings
			WHERE setting_group='gateway_runtime' AND setting_key=$1`, want.key).Scan(&value, &valueType); err != nil {
			t.Fatalf("read %s: %v", want.key, err)
		}
		if value != want.value || valueType != want.valueType {
			t.Errorf("%s value=%s type=%s, want value=%s type=%s", want.key, value, valueType, want.value, want.valueType)
		}
	}
}
