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
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/settings"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
)

const actionRateLimitSettingKey = "action_rate_per_minute"

func TestActionRateLimitMigration000209Static(t *testing.T) {
	up := readMigration(t, "000209_action_rate_limit.up.sql")
	for _, fragment := range []string{
		"gateway_runtime", actionRateLimitSettingKey, `'""'`, "'string'", "FALSE",
		"ON CONFLICT (setting_group, setting_key) DO NOTHING",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("000209 up missing %q: %s", fragment, up)
		}
	}
	down := readMigration(t, "000209_action_rate_limit.down.sql")
	for _, fragment := range []string{
		"DELETE FROM system_settings", "setting_group = 'gateway_runtime'",
		"setting_key = 'action_rate_per_minute'",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("000209 down missing %q: %s", fragment, down)
		}
	}
}

func TestActionRateLimitMigration000209Integration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	up := readMigration(t, "000209_action_rate_limit.up.sql")
	down := readMigration(t, "000209_action_rate_limit.down.sql")

	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, up); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	assertActionRateLimitSetting000209(t, env, `""`)
	if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value='"60"'::jsonb
		WHERE setting_group='gateway_runtime' AND setting_key=$1`, actionRateLimitSettingKey); err != nil {
		t.Fatalf("customize action rate: %v", err)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("replay up with existing value: %v", err)
	}
	assertActionRateLimitSetting000209(t, env, `"60"`)

	if _, err := env.db.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM system_settings
		WHERE setting_group='gateway_runtime' AND setting_key=$1`, actionRateLimitSettingKey); got != 0 {
		t.Fatalf("setting remains after down: %d", got)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	assertActionRateLimitSetting000209(t, env, `""`)
}

func assertActionRateLimitSetting000209(t *testing.T, env *testEnv, wantValue string) {
	t.Helper()
	var value, valueType string
	var sensitive bool
	if err := env.db.QueryRow(context.Background(), `SELECT setting_value::text, value_type, is_sensitive
		FROM system_settings WHERE setting_group='gateway_runtime' AND setting_key=$1`,
		actionRateLimitSettingKey).Scan(&value, &valueType, &sensitive); err != nil {
		t.Fatalf("read action rate setting: %v", err)
	}
	if value != wantValue || valueType != "string" || sensitive {
		t.Fatalf("action rate setting = value %s, type %s, sensitive %v; want %s, string, false",
			value, valueType, sensitive, wantValue)
	}
}

func actionRateLimitProvider(env *testEnv, apiEnabled bool) *guardconfig.Provider {
	provider := guardconfig.NewProvider(
		trustedproxies.NewStore(env.db), protectedaddresses.NewStore(env.db),
		accessrules.NewStore(env.db), ratelimitpolicies.NewStore(env.db),
		accesscontrolversions.NewStore(env.db),
		guardconfig.Config{APIDynamicProtection: apiEnabled, APIProtectionMode: "OBSERVE"},
	)
	provider.SetAPIEndpointActionsLister(apiassets.NewStore(env.db))
	settingsSvc := settings.NewService(env.db)
	provider.SetGatewayRuntimeSettingsLoader(func(ctx context.Context) (map[string]string, error) {
		value, found, err := settingsSvc.GetStringWithSource(ctx, guardconfig.GatewayRuntimeSettingsGroup, actionRateLimitSettingKey)
		if err != nil {
			return nil, err
		}
		if !found {
			return map[string]string{}, nil
		}
		return map[string]string{actionRateLimitSettingKey: value}, nil
	})
	return provider
}

func setActionRateDimension(t *testing.T, env *testEnv, endpointID uuid.UUID, value string) {
	t.Helper()
	if _, err := env.db.Exec(context.Background(), `
INSERT INTO api_classification_dimensions (endpoint_id, dimension, value, source, confidence)
VALUES ($1, 'ACTION', $2, 'MANUAL', 1)
ON CONFLICT (endpoint_id, dimension) DO UPDATE SET value=EXCLUDED.value, source='MANUAL', updated_at=now()`,
		endpointID, value); err != nil {
		t.Fatalf("write ACTION dimension: %v", err)
	}
}

func TestActionRateLimitSettingsAndPublishIntegration(t *testing.T) {
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
	found := false
	for _, item := range list.Data.Items {
		if item["setting_key"] != actionRateLimitSettingKey {
			continue
		}
		found = true
		version = int(item["version"].(float64))
		if item["setting_value"] != "" || item["value_type"] != "string" || item["is_sensitive"] != false {
			t.Fatalf("default setting item = %+v", item)
		}
	}
	if !found {
		t.Fatal("action rate setting not found")
	}

	detail := s8SeedEndpoint(t, env, "GET", "/action-rate/widgets/{id}", 0.9)
	setActionRateDimension(t, env, detail.ID, "not-valid")
	provider := actionRateLimitProvider(env, true)
	defaultCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("disabled action rate must not load invalid ACTION rows: %v", err)
	}
	if defaultCfg.ActionRatePerMinute != 0 || defaultCfg.APIEndpointActions != nil {
		t.Fatalf("default action rate config = %+v, want disabled", defaultCfg)
	}
	if json := s8GenerateGuardJSON(t, defaultCfg); strings.Contains(json, actionRateLimitSettingKey) || strings.Contains(json, "api_endpoint_actions") {
		t.Fatalf("default empty action rate must omit both keys: %s", json)
	}
	defaultPolicyVersion := defaultCfg.APIPolicyVersion

	put := func(raw json.RawMessage) int {
		t.Helper()
		body := fmt.Sprintf(`{"setting_group":"gateway_runtime","setting_key":%q,"setting_value":%s,"version":%d}`,
			actionRateLimitSettingKey, raw, version)
		resp := env.do(t, http.MethodPut, "/api/v1/system-settings", string(body), cookies, csrf)
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			version++
		}
		return resp.StatusCode
	}

	if status := put(json.RawMessage(`"0"`)); status != http.StatusOK {
		t.Fatalf("set zero status = %d", status)
	}
	zeroCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("zero action rate must not load invalid ACTION rows: %v", err)
	}
	if zeroCfg.ActionRatePerMinute != 0 || zeroCfg.APIEndpointActions != nil || zeroCfg.APIPolicyVersion != defaultPolicyVersion {
		t.Fatalf("zero config changed action state or policy version: %+v", zeroCfg)
	}

	pathLikeLogin := s8SeedEndpoint(t, env, "POST", "/action-rate/login", 0.9)
	setActionRateDimension(t, env, detail.ID, "read_detail")
	setActionRateDimension(t, env, pathLikeLogin.ID, "export")
	if status := put(json.RawMessage(`"120"`)); status != http.StatusOK {
		t.Fatalf("set positive rate status = %d", status)
	}
	positiveCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build positive config: %v", err)
	}
	if positiveCfg.ActionRatePerMinute != 120 || len(positiveCfg.APIEndpointActions) != 2 ||
		positiveCfg.APIEndpointActions[detail.EndpointKey] != "READ_DETAIL" ||
		positiveCfg.APIEndpointActions[pathLikeLogin.EndpointKey] != "EXPORT" {
		t.Fatalf("positive action config = %+v", positiveCfg)
	}
	if positiveCfg.APIPolicyVersion == defaultPolicyVersion {
		t.Fatal("positive action rate must change api_policy_version")
	}
	generated := s8GenerateGuardJSON(t, positiveCfg)
	for _, want := range []string{
		`"action_rate_per_minute":120`, `"api_endpoint_actions"`,
		`"GET /action-rate/widgets/{id}":"READ_DETAIL"`, `"POST /action-rate/login":"EXPORT"`,
	} {
		if !strings.Contains(generated, want) {
			t.Errorf("generated config missing %s: %s", want, generated)
		}
	}
	versionID, err := provider.SaveVersionSnapshot(ctx, positiveCfg, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("save positive snapshot: %v", err)
	}

	setActionRateDimension(t, env, pathLikeLogin.ID, "restore")
	if status := put(json.RawMessage(`"60"`)); status != http.StatusOK {
		t.Fatalf("change positive rate status = %d", status)
	}
	back, err := provider.GetVersionConfig(ctx, versionID)
	if err != nil {
		t.Fatalf("replay positive snapshot: %v", err)
	}
	if back.ActionRatePerMinute != 60 || back.APIEndpointActions[pathLikeLogin.EndpointKey] != "RESTORE" {
		t.Fatalf("rollback replay did not use current rate and ACTION data: %+v", back)
	}
	if json := s8GenerateGuardJSON(t, back); !strings.Contains(json, `"action_rate_per_minute":60`) ||
		!strings.Contains(json, `"POST /action-rate/login":"RESTORE"`) {
		t.Fatalf("rollback replay missing current action config: %s", json)
	}

	for _, raw := range []string{`"-1"`, `"abc"`, `"1.5"`, `60`} {
		if status := put(json.RawMessage(raw)); status != http.StatusBadRequest {
			t.Errorf("invalid action rate %s status = %d, want 400", raw, status)
		}
	}
	assertActionRateLimitSetting000209(t, env, `"60"`)

	for _, raw := range []string{`"-1"`, `"abc"`} {
		if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value=$1::jsonb
			WHERE setting_group='gateway_runtime' AND setting_key=$2`, raw, actionRateLimitSettingKey); err != nil {
			t.Fatalf("inject invalid publish setting: %v", err)
		}
		_, buildErr := provider.BuildGuardConfig(ctx)
		if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value='"60"'::jsonb
			WHERE setting_group='gateway_runtime' AND setting_key=$1`, actionRateLimitSettingKey); err != nil {
			t.Fatalf("restore valid publish setting: %v", err)
		}
		if buildErr == nil || !strings.Contains(buildErr.Error(), actionRateLimitSettingKey) {
			t.Errorf("invalid stored rate %s must abort publish, error = %v", raw, buildErr)
		}
	}

	setActionRateDimension(t, env, pathLikeLogin.ID, "not_real")
	if _, err := provider.BuildGuardConfig(ctx); err == nil || !strings.Contains(err.Error(), pathLikeLogin.EndpointKey) {
		t.Fatalf("unknown ACTION must abort enabled publish, error = %v", err)
	}
	setActionRateDimension(t, env, pathLikeLogin.ID, "restore")

	offCfg, err := actionRateLimitProvider(env, false).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build WDSP-off config: %v", err)
	}
	if offCfg.ActionRatePerMinute != 0 || offCfg.APIEndpointActions != nil {
		t.Fatalf("WDSP-off action config = %+v, want disabled", offCfg)
	}
	if json := s8GenerateGuardJSON(t, offCfg); strings.Contains(json, actionRateLimitSettingKey) || strings.Contains(json, "api_endpoint_actions") {
		t.Fatalf("WDSP-off generated config contains action rate: %s", json)
	}
}
