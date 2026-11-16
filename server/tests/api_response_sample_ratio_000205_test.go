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

const responseSampleRatioSettingKey = "api_response_sample_ratio"

func TestAPIResponseSampleRatioMigration000205Static(t *testing.T) {
	up := readMigration(t, "000205_api_response_sample_ratio.up.sql")
	for _, fragment := range []string{
		"gateway_runtime", responseSampleRatioSettingKey, `'"1"'`, "'string'",
		"ON CONFLICT (setting_group, setting_key) DO NOTHING",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("000205 up missing %q: %s", fragment, up)
		}
	}
	down := readMigration(t, "000205_api_response_sample_ratio.down.sql")
	for _, fragment := range []string{
		"DELETE FROM system_settings", "setting_group = 'gateway_runtime'",
		"setting_key = 'api_response_sample_ratio'",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("000205 down missing %q: %s", fragment, down)
		}
	}
}

func TestAPIResponseSampleRatioMigration000205Integration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	up := readMigration(t, "000205_api_response_sample_ratio.up.sql")
	down := readMigration(t, "000205_api_response_sample_ratio.down.sql")

	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, up); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	assertResponseSampleRatioSetting000205(t, env, `"1"`)
	if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value='"0"'::jsonb
		WHERE setting_group='gateway_runtime' AND setting_key=$1`, responseSampleRatioSettingKey); err != nil {
		t.Fatalf("customize ratio: %v", err)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("replay up with existing value: %v", err)
	}
	assertResponseSampleRatioSetting000205(t, env, `"0"`)

	if _, err := env.db.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM system_settings
		WHERE setting_group='gateway_runtime' AND setting_key=$1`, responseSampleRatioSettingKey); got != 0 {
		t.Fatalf("setting remains after down: %d", got)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	assertResponseSampleRatioSetting000205(t, env, `"1"`)
}

func assertResponseSampleRatioSetting000205(t *testing.T, env *testEnv, wantValue string) {
	t.Helper()
	var value, valueType string
	var sensitive bool
	if err := env.db.QueryRow(context.Background(), `SELECT setting_value::text, value_type, is_sensitive
		FROM system_settings WHERE setting_group='gateway_runtime' AND setting_key=$1`,
		responseSampleRatioSettingKey).Scan(&value, &valueType, &sensitive); err != nil {
		t.Fatalf("read ratio setting: %v", err)
	}
	if value != wantValue || valueType != "string" || sensitive {
		t.Fatalf("ratio setting = value %s, type %s, sensitive %v; want %s, string, false",
			value, valueType, sensitive, wantValue)
	}
}

func responseSampleRatioProvider(env *testEnv, apiEnabled bool) *guardconfig.Provider {
	provider := guardconfig.NewProvider(
		trustedproxies.NewStore(env.db), protectedaddresses.NewStore(env.db),
		accessrules.NewStore(env.db), ratelimitpolicies.NewStore(env.db),
		accesscontrolversions.NewStore(env.db),
		guardconfig.Config{APIDynamicProtection: apiEnabled, APIProtectionMode: "OBSERVE"},
	)
	settingsSvc := settings.NewService(env.db)
	provider.SetGatewayRuntimeSettingsLoader(func(ctx context.Context) (map[string]string, error) {
		value, found, err := settingsSvc.GetStringWithSource(ctx, guardconfig.GatewayRuntimeSettingsGroup, responseSampleRatioSettingKey)
		if err != nil {
			return nil, err
		}
		if !found {
			return map[string]string{}, nil
		}
		return map[string]string{responseSampleRatioSettingKey: value}, nil
	})
	return provider
}

func TestAPIResponseSampleRatioSettingsAndPublishIntegration(t *testing.T) {
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
	version := 0
	for _, item := range list.Data.Items {
		if item["setting_key"] == responseSampleRatioSettingKey {
			version = int(item["version"].(float64))
			if item["setting_value"] != "1" || item["value_type"] != "string" || item["is_sensitive"] != false {
				t.Fatalf("default setting item = %+v", item)
			}
		}
	}
	if version == 0 {
		t.Fatal("response sample ratio setting not found")
	}

	provider := responseSampleRatioProvider(env, true)
	cfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build default config: %v", err)
	}
	if cfg.APIResponseSampleRatio == nil || *cfg.APIResponseSampleRatio != 1 {
		t.Fatalf("default ratio = %v, want 1", cfg.APIResponseSampleRatio)
	}
	if json := s8GenerateGuardJSON(t, cfg); !strings.Contains(json, `"api_response_sample_ratio":1`) {
		t.Fatalf("default ratio missing from generated config: %s", json)
	}
	defaultPolicyVersion := cfg.APIPolicyVersion

	put := func(raw json.RawMessage) int {
		t.Helper()
		body := fmt.Sprintf(`{"setting_group":"gateway_runtime","setting_key":%q,"setting_value":%s,"version":%d}`,
			responseSampleRatioSettingKey, raw, version)
		resp := env.do(t, http.MethodPut, "/api/v1/system-settings", string(body), cookies, csrf)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			version++
		}
		return resp.StatusCode
	}

	if status := put(json.RawMessage(`"0"`)); status != http.StatusOK {
		t.Fatalf("set explicit zero status = %d", status)
	}
	zeroCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build zero config: %v", err)
	}
	if zeroCfg.APIResponseSampleRatio == nil || *zeroCfg.APIResponseSampleRatio != 0 {
		t.Fatalf("zero config ratio = %v", zeroCfg.APIResponseSampleRatio)
	}
	if zeroCfg.APIPolicyVersion == defaultPolicyVersion {
		t.Fatal("explicit zero must change api_policy_version")
	}
	if json := s8GenerateGuardJSON(t, zeroCfg); !strings.Contains(json, `"api_response_sample_ratio":0`) {
		t.Fatalf("explicit zero missing from generated config: %s", json)
	}
	versionID, err := provider.SaveVersionSnapshot(ctx, zeroCfg, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("save zero snapshot: %v", err)
	}
	back, err := provider.GetVersionConfig(ctx, versionID)
	if err != nil {
		t.Fatalf("read zero snapshot: %v", err)
	}
	if back.APIResponseSampleRatio == nil || *back.APIResponseSampleRatio != 0 {
		t.Fatalf("snapshot rollback ratio = %v, want explicit zero", back.APIResponseSampleRatio)
	}

	if status := put(json.RawMessage(`"0.25"`)); status != http.StatusOK {
		t.Fatalf("set fractional ratio status = %d", status)
	}
	fractionCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build fractional config: %v", err)
	}
	if fractionCfg.APIResponseSampleRatio == nil || *fractionCfg.APIResponseSampleRatio != 0.25 {
		t.Fatalf("fractional ratio = %v", fractionCfg.APIResponseSampleRatio)
	}
	if json := s8GenerateGuardJSON(t, fractionCfg); !strings.Contains(json, `"api_response_sample_ratio":0.25`) {
		t.Fatalf("fractional ratio missing from generated config: %s", json)
	}

	if status := put(json.RawMessage(`"  "`)); status != http.StatusOK {
		t.Fatalf("set blank ratio status = %d", status)
	}
	blankCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build blank config: %v", err)
	}
	if blankCfg.APIResponseSampleRatio != nil {
		t.Fatalf("blank ratio = %v, want nil", *blankCfg.APIResponseSampleRatio)
	}
	if json := s8GenerateGuardJSON(t, blankCfg); strings.Contains(json, "api_response_sample_ratio") {
		t.Fatalf("blank ratio must be omitted from generated config: %s", json)
	}

	if status := put(json.RawMessage(`"1"`)); status != http.StatusOK {
		t.Fatalf("restore ratio status = %d", status)
	}
	for _, raw := range []string{"abc", "-0.01", "1.01", "NaN", "Inf", "+Inf", "-Inf"} {
		encoded, _ := json.Marshal(raw)
		if status := put(encoded); status != http.StatusBadRequest {
			t.Errorf("invalid ratio %q status = %d, want 400", raw, status)
		}
	}
	if status := put(json.RawMessage(`0`)); status != http.StatusBadRequest {
		t.Errorf("non-string ratio status = %d, want 400", status)
	}
	assertResponseSampleRatioSetting000205(t, env, `"1"`)

	offCfg, err := responseSampleRatioProvider(env, false).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build WDSP-off config: %v", err)
	}
	if offCfg.APIResponseSampleRatio != nil {
		t.Fatalf("WDSP-off ratio = %v, want nil", *offCfg.APIResponseSampleRatio)
	}
	if json := s8GenerateGuardJSON(t, offCfg); strings.Contains(json, "api_response_sample_ratio") {
		t.Fatalf("WDSP-off generated config contains ratio: %s", json)
	}
}
