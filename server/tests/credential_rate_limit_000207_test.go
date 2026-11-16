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

const credentialRateLimitSettingKey = "credential_rate_per_minute"

func TestCredentialRateLimitMigration000207Static(t *testing.T) {
	up := readMigration(t, "000207_credential_rate_limit.up.sql")
	for _, fragment := range []string{
		"gateway_runtime", credentialRateLimitSettingKey, `'""'`, "'string'", "FALSE",
		"ON CONFLICT (setting_group, setting_key) DO NOTHING",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("000207 up missing %q: %s", fragment, up)
		}
	}
	down := readMigration(t, "000207_credential_rate_limit.down.sql")
	for _, fragment := range []string{
		"DELETE FROM system_settings", "setting_group = 'gateway_runtime'",
		"setting_key = 'credential_rate_per_minute'",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("000207 down missing %q: %s", fragment, down)
		}
	}
}

func TestCredentialRateLimitMigration000207Integration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	up := readMigration(t, "000207_credential_rate_limit.up.sql")
	down := readMigration(t, "000207_credential_rate_limit.down.sql")

	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, up); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	assertCredentialRateLimitSetting000207(t, env, `""`)
	if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value='"60"'::jsonb
		WHERE setting_group='gateway_runtime' AND setting_key=$1`, credentialRateLimitSettingKey); err != nil {
		t.Fatalf("customize credential rate: %v", err)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("replay up with existing value: %v", err)
	}
	assertCredentialRateLimitSetting000207(t, env, `"60"`)

	if _, err := env.db.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM system_settings
		WHERE setting_group='gateway_runtime' AND setting_key=$1`, credentialRateLimitSettingKey); got != 0 {
		t.Fatalf("setting remains after down: %d", got)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	assertCredentialRateLimitSetting000207(t, env, `""`)
}

func assertCredentialRateLimitSetting000207(t *testing.T, env *testEnv, wantValue string) {
	t.Helper()
	var value, valueType string
	var sensitive bool
	if err := env.db.QueryRow(context.Background(), `SELECT setting_value::text, value_type, is_sensitive
		FROM system_settings WHERE setting_group='gateway_runtime' AND setting_key=$1`,
		credentialRateLimitSettingKey).Scan(&value, &valueType, &sensitive); err != nil {
		t.Fatalf("read credential rate setting: %v", err)
	}
	if value != wantValue || valueType != "string" || sensitive {
		t.Fatalf("credential rate setting = value %s, type %s, sensitive %v; want %s, string, false",
			value, valueType, sensitive, wantValue)
	}
}

func credentialRateLimitProvider(env *testEnv, apiEnabled bool) *guardconfig.Provider {
	provider := guardconfig.NewProvider(
		trustedproxies.NewStore(env.db), protectedaddresses.NewStore(env.db),
		accessrules.NewStore(env.db), ratelimitpolicies.NewStore(env.db),
		accesscontrolversions.NewStore(env.db),
		guardconfig.Config{APIDynamicProtection: apiEnabled, APIProtectionMode: "OBSERVE"},
	)
	settingsSvc := settings.NewService(env.db)
	provider.SetGatewayRuntimeSettingsLoader(func(ctx context.Context) (map[string]string, error) {
		value, found, err := settingsSvc.GetStringWithSource(ctx, guardconfig.GatewayRuntimeSettingsGroup, credentialRateLimitSettingKey)
		if err != nil {
			return nil, err
		}
		if !found {
			return map[string]string{}, nil
		}
		return map[string]string{credentialRateLimitSettingKey: value}, nil
	})
	return provider
}

func TestCredentialRateLimitSettingsAndPublishIntegration(t *testing.T) {
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
		if item["setting_key"] != credentialRateLimitSettingKey {
			continue
		}
		found = true
		version = int(item["version"].(float64))
		if item["setting_value"] != "" || item["value_type"] != "string" || item["is_sensitive"] != false {
			t.Fatalf("default setting item = %+v", item)
		}
	}
	if !found {
		t.Fatal("credential rate setting not found")
	}

	provider := credentialRateLimitProvider(env, true)
	defaultCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build default config: %v", err)
	}
	if defaultCfg.CredentialRatePerMinute != 0 {
		t.Fatalf("default credential rate = %d, want disabled", defaultCfg.CredentialRatePerMinute)
	}
	if json := s8GenerateGuardJSON(t, defaultCfg); strings.Contains(json, credentialRateLimitSettingKey) {
		t.Fatalf("default empty credential rate must be omitted: %s", json)
	}
	defaultPolicyVersion := defaultCfg.APIPolicyVersion

	put := func(raw json.RawMessage) int {
		t.Helper()
		body := fmt.Sprintf(`{"setting_group":"gateway_runtime","setting_key":%q,"setting_value":%s,"version":%d}`,
			credentialRateLimitSettingKey, raw, version)
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
		t.Fatalf("build zero config: %v", err)
	}
	if zeroCfg.CredentialRatePerMinute != 0 || zeroCfg.APIPolicyVersion != defaultPolicyVersion {
		t.Fatalf("zero config changed enabled state or policy version: %+v", zeroCfg)
	}
	if json := s8GenerateGuardJSON(t, zeroCfg); strings.Contains(json, credentialRateLimitSettingKey) {
		t.Fatalf("zero credential rate must be omitted: %s", json)
	}

	if status := put(json.RawMessage(`"120"`)); status != http.StatusOK {
		t.Fatalf("set positive rate status = %d", status)
	}
	positiveCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build positive config: %v", err)
	}
	if positiveCfg.CredentialRatePerMinute != 120 {
		t.Fatalf("positive credential rate = %d, want 120", positiveCfg.CredentialRatePerMinute)
	}
	if positiveCfg.APIPolicyVersion == defaultPolicyVersion {
		t.Fatal("positive credential rate must change api_policy_version")
	}
	if json := s8GenerateGuardJSON(t, positiveCfg); !strings.Contains(json, `"credential_rate_per_minute":120`) {
		t.Fatalf("positive credential rate missing from generated config: %s", json)
	}
	versionID, err := provider.SaveVersionSnapshot(ctx, positiveCfg, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("save positive snapshot: %v", err)
	}

	if status := put(json.RawMessage(`"60"`)); status != http.StatusOK {
		t.Fatalf("change positive rate status = %d", status)
	}
	back, err := provider.GetVersionConfig(ctx, versionID)
	if err != nil {
		t.Fatalf("replay positive snapshot: %v", err)
	}
	if back.CredentialRatePerMinute != 60 {
		t.Fatalf("rollback replay rate = %d, want current setting 60", back.CredentialRatePerMinute)
	}
	if json := s8GenerateGuardJSON(t, back); !strings.Contains(json, `"credential_rate_per_minute":60`) {
		t.Fatalf("rollback replay missing current credential rate: %s", json)
	}

	for _, raw := range []string{`"-1"`, `"abc"`, `"1.5"`, `60`} {
		if status := put(json.RawMessage(raw)); status != http.StatusBadRequest {
			t.Errorf("invalid credential rate %s status = %d, want 400", raw, status)
		}
	}
	assertCredentialRateLimitSetting000207(t, env, `"60"`)

	for _, raw := range []string{`"-1"`, `"abc"`} {
		if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value=$1::jsonb
			WHERE setting_group='gateway_runtime' AND setting_key=$2`, raw, credentialRateLimitSettingKey); err != nil {
			t.Fatalf("inject invalid publish setting: %v", err)
		}
		_, buildErr := provider.BuildGuardConfig(ctx)
		if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value='"60"'::jsonb
			WHERE setting_group='gateway_runtime' AND setting_key=$1`, credentialRateLimitSettingKey); err != nil {
			t.Fatalf("restore valid publish setting: %v", err)
		}
		if buildErr == nil || !strings.Contains(buildErr.Error(), credentialRateLimitSettingKey) {
			t.Errorf("invalid stored rate %s must abort publish, error = %v", raw, buildErr)
		}
	}

	offCfg, err := credentialRateLimitProvider(env, false).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build WDSP-off config: %v", err)
	}
	if offCfg.CredentialRatePerMinute != 0 {
		t.Fatalf("WDSP-off credential rate = %d, want disabled", offCfg.CredentialRatePerMinute)
	}
	if json := s8GenerateGuardJSON(t, offCfg); strings.Contains(json, credentialRateLimitSettingKey) {
		t.Fatalf("WDSP-off generated config contains credential rate: %s", json)
	}
}
