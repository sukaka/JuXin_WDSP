package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/settings"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
)

const (
	apiRateLimitActionSettingKey  = "api_rate_limit_action"
	apiTempBlockSecondsSettingKey = "api_temp_block_seconds"
)

func TestAPIRateLimitActionMigration000212Static(t *testing.T) {
	up := readMigration(t, "000212_api_rate_limit_action.up.sql")
	for _, fragment := range []string{
		"gateway_runtime", apiRateLimitActionSettingKey, `'"RATE_LIMIT"'`,
		apiTempBlockSecondsSettingKey, `'"60"'`, "ON CONFLICT (setting_group, setting_key) DO NOTHING",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("000212 up missing %q: %s", fragment, up)
		}
	}
	down := readMigration(t, "000212_api_rate_limit_action.down.sql")
	for _, fragment := range []string{
		"DELETE FROM system_settings", "setting_group = 'gateway_runtime'",
		"api_rate_limit_action", "api_temp_block_seconds",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("000212 down missing %q: %s", fragment, down)
		}
	}
}

func TestAPIRateLimitActionMigration000212Integration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	up := readMigration(t, "000212_api_rate_limit_action.up.sql")
	down := readMigration(t, "000212_api_rate_limit_action.down.sql")
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, up); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	assertAPIRateLimitActionSetting000212(t, env, apiRateLimitActionSettingKey, `"RATE_LIMIT"`)
	assertAPIRateLimitActionSetting000212(t, env, apiTempBlockSecondsSettingKey, `"60"`)
	if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value='"BLOCK"'::jsonb
		WHERE setting_group='gateway_runtime' AND setting_key=$1`, apiRateLimitActionSettingKey); err != nil {
		t.Fatalf("customize action: %v", err)
	}
	if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value='"120"'::jsonb
		WHERE setting_group='gateway_runtime' AND setting_key=$1`, apiTempBlockSecondsSettingKey); err != nil {
		t.Fatalf("customize seconds: %v", err)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("replay up with existing values: %v", err)
	}
	assertAPIRateLimitActionSetting000212(t, env, apiRateLimitActionSettingKey, `"BLOCK"`)
	assertAPIRateLimitActionSetting000212(t, env, apiTempBlockSecondsSettingKey, `"120"`)

	if _, err := env.db.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM system_settings
		WHERE setting_group='gateway_runtime' AND setting_key IN ($1,$2)`,
		apiRateLimitActionSettingKey, apiTempBlockSecondsSettingKey); got != 0 {
		t.Fatalf("settings remain after down: %d", got)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	assertAPIRateLimitActionSetting000212(t, env, apiRateLimitActionSettingKey, `"RATE_LIMIT"`)
	assertAPIRateLimitActionSetting000212(t, env, apiTempBlockSecondsSettingKey, `"60"`)
}

func assertAPIRateLimitActionSetting000212(t *testing.T, env *testEnv, key, wantValue string) {
	t.Helper()
	var value, valueType string
	var sensitive bool
	if err := env.db.QueryRow(context.Background(), `SELECT setting_value::text, value_type, is_sensitive
		FROM system_settings WHERE setting_group='gateway_runtime' AND setting_key=$1`, key).
		Scan(&value, &valueType, &sensitive); err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	if value != wantValue || valueType != "string" || sensitive {
		t.Fatalf("%s = value %s, type %s, sensitive %v; want %s, string, false", key, value, valueType, sensitive, wantValue)
	}
}

func apiRateLimitActionProvider(env *testEnv, apiEnabled bool) *guardconfig.Provider {
	provider := guardconfig.NewProvider(
		trustedproxies.NewStore(env.db), protectedaddresses.NewStore(env.db),
		accessrules.NewStore(env.db), ratelimitpolicies.NewStore(env.db),
		accesscontrolversions.NewStore(env.db),
		guardconfig.Config{APIDynamicProtection: apiEnabled, APIProtectionMode: "OBSERVE"},
	)
	settingsSvc := settings.NewService(env.db)
	provider.SetGatewayRuntimeSettingsLoader(func(ctx context.Context) (map[string]string, error) {
		out := map[string]string{}
		for _, key := range []string{apiRateLimitActionSettingKey, apiTempBlockSecondsSettingKey} {
			value, found, err := settingsSvc.GetStringWithSource(ctx, guardconfig.GatewayRuntimeSettingsGroup, key)
			if err != nil {
				return nil, err
			}
			if found {
				out[key] = value
			}
		}
		return out, nil
	})
	return provider
}

func TestAPIRateLimitActionSettingsAndPublishIntegration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	resp := env.get(t, "/api/v1/system-settings?group=gateway_runtime", cookies)
	var list apiRespPage2
	readJSON(t, resp, &list)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list settings status = %d", resp.StatusCode)
	}
	versions := map[string]int{}
	for _, item := range list.Data.Items {
		key, _ := item["setting_key"].(string)
		if key == apiRateLimitActionSettingKey {
			versions[key] = int(item["version"].(float64))
			if item["setting_value"] != "RATE_LIMIT" || item["value_type"] != "string" || item["is_sensitive"] != false {
				t.Fatalf("default action item = %+v", item)
			}
		}
		if key == apiTempBlockSecondsSettingKey {
			versions[key] = int(item["version"].(float64))
			if item["setting_value"] != "60" || item["value_type"] != "string" || item["is_sensitive"] != false {
				t.Fatalf("default seconds item = %+v", item)
			}
		}
	}
	if len(versions) != 2 {
		t.Fatalf("action setting versions = %+v", versions)
	}

	provider := apiRateLimitActionProvider(env, true)
	defaultCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build default config: %v", err)
	}
	if defaultCfg.APIRateLimitAction != "RATE_LIMIT" || defaultCfg.APITempBlockSeconds != 60 {
		t.Fatalf("default action config = %+v", defaultCfg)
	}
	generated := s8GenerateGuardJSON(t, defaultCfg)
	if !strings.Contains(generated, `"api_rate_limit_action":"RATE_LIMIT"`) || !strings.Contains(generated, `"api_temp_block_seconds":60`) {
		t.Fatalf("default compatible action config missing: %s", generated)
	}

	put := func(key string, raw json.RawMessage) int {
		t.Helper()
		body := fmt.Sprintf(`{"setting_group":"gateway_runtime","setting_key":%q,"setting_value":%s,"version":%d}`,
			key, raw, versions[key])
		resp := env.do(t, http.MethodPut, "/api/v1/system-settings", string(body), cookies, csrf)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			versions[key]++
		}
		return resp.StatusCode
	}
	if status := put(apiRateLimitActionSettingKey, json.RawMessage(`""`)); status != http.StatusOK {
		t.Fatalf("clear action status = %d", status)
	}
	if status := put(apiTempBlockSecondsSettingKey, json.RawMessage(`""`)); status != http.StatusOK {
		t.Fatalf("clear seconds status = %d", status)
	}
	emptyCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build empty action config: %v", err)
	}
	if emptyCfg.APIRateLimitAction != "" || emptyCfg.APITempBlockSeconds != 0 {
		t.Fatalf("empty action config = %+v", emptyCfg)
	}
	if generated := s8GenerateGuardJSON(t, emptyCfg); strings.Contains(generated, apiRateLimitActionSettingKey) || strings.Contains(generated, apiTempBlockSecondsSettingKey) {
		t.Fatalf("empty values must use gateway defaults without explicit keys: %s", generated)
	}

	for _, tc := range []struct {
		action  string
		seconds string
	}{
		{action: "RATE_LIMIT", seconds: "1"},
		{action: "BLOCK", seconds: "60"},
		{action: "TEMP_BLOCK", seconds: "86400"},
	} {
		if status := put(apiRateLimitActionSettingKey, json.RawMessage(fmt.Sprintf("%q", tc.action))); status != http.StatusOK {
			t.Fatalf("set action %s status = %d", tc.action, status)
		}
		if status := put(apiTempBlockSecondsSettingKey, json.RawMessage(fmt.Sprintf("%q", tc.seconds))); status != http.StatusOK {
			t.Fatalf("set seconds %s status = %d", tc.seconds, status)
		}
		cfg, err := provider.BuildGuardConfig(ctx)
		if err != nil {
			t.Fatalf("build %s/%s config: %v", tc.action, tc.seconds, err)
		}
		if cfg.APIRateLimitAction != tc.action || cfg.APITempBlockSeconds != mustAtoi000212(t, tc.seconds) {
			t.Fatalf("action config = %+v, want %s/%s", cfg, tc.action, tc.seconds)
		}
		generated := s8GenerateGuardJSON(t, cfg)
		if !strings.Contains(generated, `"api_rate_limit_action":"`+tc.action+`"`) ||
			!strings.Contains(generated, `"api_temp_block_seconds":`+tc.seconds) {
			t.Fatalf("generated %s/%s config mismatch: %s", tc.action, tc.seconds, generated)
		}
	}
	snapshotCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build snapshot config: %v", err)
	}
	versionID, err := provider.SaveVersionSnapshot(ctx, snapshotCfg, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("save action snapshot: %v", err)
	}

	if status := put(apiRateLimitActionSettingKey, json.RawMessage(`"RATE_LIMIT"`)); status != http.StatusOK {
		t.Fatalf("restore action status = %d", status)
	}
	if status := put(apiTempBlockSecondsSettingKey, json.RawMessage(`"60"`)); status != http.StatusOK {
		t.Fatalf("restore seconds status = %d", status)
	}
	back, err := provider.GetVersionConfig(ctx, versionID)
	if err != nil {
		t.Fatalf("replay action snapshot: %v", err)
	}
	if back.APIRateLimitAction != "RATE_LIMIT" || back.APITempBlockSeconds != 60 {
		t.Fatalf("rollback replay did not use current action settings: %+v", back)
	}

	for _, tc := range []struct {
		key string
		raw string
	}{
		{key: apiRateLimitActionSettingKey, raw: `"REJECT"`},
		{key: apiTempBlockSecondsSettingKey, raw: `"0"`},
		{key: apiTempBlockSecondsSettingKey, raw: `"86401"`},
		{key: apiTempBlockSecondsSettingKey, raw: `"abc"`},
		{key: apiTempBlockSecondsSettingKey, raw: `60`},
	} {
		if status := put(tc.key, json.RawMessage(tc.raw)); status != http.StatusBadRequest {
			t.Errorf("invalid %s=%s status = %d, want 400", tc.key, tc.raw, status)
		}
	}
	assertAPIRateLimitActionSetting000212(t, env, apiRateLimitActionSettingKey, `"RATE_LIMIT"`)
	assertAPIRateLimitActionSetting000212(t, env, apiTempBlockSecondsSettingKey, `"60"`)

	for _, tc := range []struct {
		key, bad, good string
	}{
		{key: apiRateLimitActionSettingKey, bad: `"REJECT"`, good: `"RATE_LIMIT"`},
		{key: apiTempBlockSecondsSettingKey, bad: `"0"`, good: `"60"`},
		{key: apiTempBlockSecondsSettingKey, bad: `"86401"`, good: `"60"`},
		{key: apiTempBlockSecondsSettingKey, bad: `"abc"`, good: `"60"`},
	} {
		if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value=$1::jsonb
			WHERE setting_group='gateway_runtime' AND setting_key=$2`, tc.bad, tc.key); err != nil {
			t.Fatalf("inject invalid action setting: %v", err)
		}
		_, buildErr := provider.BuildGuardConfig(ctx)
		if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value=$1::jsonb
			WHERE setting_group='gateway_runtime' AND setting_key=$2`, tc.good, tc.key); err != nil {
			t.Fatalf("restore valid action setting: %v", err)
		}
		if buildErr == nil || !strings.Contains(buildErr.Error(), tc.key) {
			t.Errorf("invalid stored %s=%s must abort publish, error = %v", tc.key, tc.bad, buildErr)
		}
	}

	offCfg, err := apiRateLimitActionProvider(env, false).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build WDSP-off config: %v", err)
	}
	if offCfg.APIRateLimitAction != "" || offCfg.APITempBlockSeconds != 0 {
		t.Fatalf("WDSP-off action config = %+v", offCfg)
	}
	if generated := s8GenerateGuardJSON(t, offCfg); strings.Contains(generated, apiRateLimitActionSettingKey) || strings.Contains(generated, apiTempBlockSecondsSettingKey) {
		t.Fatalf("WDSP-off generated config contains action settings: %s", generated)
	}
}

func mustAtoi000212(t *testing.T, raw string) int {
	t.Helper()
	var value int
	if _, err := fmt.Sscanf(raw, "%d", &value); err != nil {
		t.Fatalf("parse test integer %q: %v", raw, err)
	}
	return value
}
