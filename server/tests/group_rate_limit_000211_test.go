package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/apigroups"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/settings"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
)

const groupRateLimitSettingKey = "group_rate_per_minute"

func TestGroupRateLimitMigration000211Static(t *testing.T) {
	up := readMigration(t, "000211_group_rate_limit.up.sql")
	for _, fragment := range []string{
		"gateway_runtime", groupRateLimitSettingKey, `'""'`, "'string'", "FALSE",
		"ON CONFLICT (setting_group, setting_key) DO NOTHING",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("000211 up missing %q: %s", fragment, up)
		}
	}
	down := readMigration(t, "000211_group_rate_limit.down.sql")
	for _, fragment := range []string{
		"DELETE FROM system_settings", "setting_group = 'gateway_runtime'",
		"setting_key = 'group_rate_per_minute'",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("000211 down missing %q: %s", fragment, down)
		}
	}
}

func TestGroupRateLimitMigration000211Integration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	up := readMigration(t, "000211_group_rate_limit.up.sql")
	down := readMigration(t, "000211_group_rate_limit.down.sql")

	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, up); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	assertGroupRateLimitSetting000211(t, env, `""`)
	if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value='"60"'::jsonb
		WHERE setting_group='gateway_runtime' AND setting_key=$1`, groupRateLimitSettingKey); err != nil {
		t.Fatalf("customize group rate: %v", err)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("replay up with existing value: %v", err)
	}
	assertGroupRateLimitSetting000211(t, env, `"60"`)

	if _, err := env.db.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM system_settings
		WHERE setting_group='gateway_runtime' AND setting_key=$1`, groupRateLimitSettingKey); got != 0 {
		t.Fatalf("setting remains after down: %d", got)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	assertGroupRateLimitSetting000211(t, env, `""`)
}

func assertGroupRateLimitSetting000211(t *testing.T, env *testEnv, wantValue string) {
	t.Helper()
	var value, valueType string
	var sensitive bool
	if err := env.db.QueryRow(context.Background(), `SELECT setting_value::text, value_type, is_sensitive
		FROM system_settings WHERE setting_group='gateway_runtime' AND setting_key=$1`,
		groupRateLimitSettingKey).Scan(&value, &valueType, &sensitive); err != nil {
		t.Fatalf("read group rate setting: %v", err)
	}
	if value != wantValue || valueType != "string" || sensitive {
		t.Fatalf("group rate setting = value %s, type %s, sensitive %v; want %s, string, false",
			value, valueType, sensitive, wantValue)
	}
}

func groupRateLimitProvider(env *testEnv, apiEnabled bool) *guardconfig.Provider {
	provider := guardconfig.NewProvider(
		trustedproxies.NewStore(env.db), protectedaddresses.NewStore(env.db),
		accessrules.NewStore(env.db), ratelimitpolicies.NewStore(env.db),
		accesscontrolversions.NewStore(env.db),
		guardconfig.Config{APIDynamicProtection: apiEnabled, APIProtectionMode: "OBSERVE"},
	)
	provider.SetAPIEndpointGroupsLister(apigroups.NewStore(env.db))
	settingsSvc := settings.NewService(env.db)
	provider.SetGatewayRuntimeSettingsLoader(func(ctx context.Context) (map[string]string, error) {
		value, found, err := settingsSvc.GetStringWithSource(ctx, guardconfig.GatewayRuntimeSettingsGroup, groupRateLimitSettingKey)
		if err != nil {
			return nil, err
		}
		if !found {
			return map[string]string{}, nil
		}
		return map[string]string{groupRateLimitSettingKey: value}, nil
	})
	return provider
}

func TestGroupRateLimitSettingsPublishAndMappingIntegration(t *testing.T) {
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
		if item["setting_key"] != groupRateLimitSettingKey {
			continue
		}
		found = true
		version = int(item["version"].(float64))
		if item["setting_value"] != "" || item["value_type"] != "string" || item["is_sensitive"] != false {
			t.Fatalf("default setting item = %+v", item)
		}
	}
	if !found {
		t.Fatal("group rate setting not found")
	}

	app1 := seedEndpointGroupApp(t, env, "gr-orders", "分组订单应用")
	app2 := seedEndpointGroupApp(t, env, "gr-inventory", "分组库存应用")
	endpoint1 := seedEndpointGroupEndpoint(t, env, app1, "GET", "/group-rate/shared")
	otherEndpoint := seedEndpointGroupEndpoint(t, env, app1, "POST", "/group-rate/other")
	endpoint2 := seedEndpointGroupEndpoint(t, env, app2, "GET", "/group-rate/shared")
	groupStore := apigroups.NewStore(env.db)
	createGroup := func(appID uuid.UUID, code string, enabled bool) *apigroups.Group {
		t.Helper()
		group, err := groupStore.Create(ctx, apigroups.CreateInput{ApplicationID: appID, Code: code, Name: code, Enabled: enabled})
		if err != nil {
			t.Fatalf("create group %s: %v", code, err)
		}
		return group
	}
	addMember := func(groupID, endpointID uuid.UUID) {
		t.Helper()
		if _, err := groupStore.AddEndpoint(ctx, groupID, endpointID); err != nil {
			t.Fatalf("add group member: %v", err)
		}
	}
	zeta := createGroup(app1, "zeta", true)
	alpha := createGroup(app1, "alpha", true)
	disabled := createGroup(app1, "disabled", false)
	beta := createGroup(app2, "beta", true)
	addMember(zeta.ID, endpoint1)
	addMember(alpha.ID, endpoint1)
	addMember(zeta.ID, otherEndpoint)
	addMember(disabled.ID, endpoint1)
	addMember(beta.ID, endpoint2)

	if _, err := env.db.Exec(ctx, `INSERT INTO api_endpoint_group_members(group_id,endpoint_id) VALUES ($1,$2)`, zeta.ID, endpoint2); err != nil {
		t.Fatalf("seed cross-application conflict: %v", err)
	}
	provider := groupRateLimitProvider(env, true)
	defaultCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("disabled group rate must not load conflicting members: %v", err)
	}
	if defaultCfg.GroupRatePerMinute != 0 || defaultCfg.APIEndpointGroups != nil {
		t.Fatalf("default group rate config = %+v, want disabled", defaultCfg)
	}
	if json := s8GenerateGuardJSON(t, defaultCfg); strings.Contains(json, groupRateLimitSettingKey) || strings.Contains(json, "api_endpoint_groups") {
		t.Fatalf("default empty group rate must omit both keys: %s", json)
	}
	defaultPolicyVersion := defaultCfg.APIPolicyVersion

	put := func(raw json.RawMessage) int {
		t.Helper()
		body := fmt.Sprintf(`{"setting_group":"gateway_runtime","setting_key":%q,"setting_value":%s,"version":%d}`,
			groupRateLimitSettingKey, raw, version)
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
		t.Fatalf("zero group rate must not load conflicting members: %v", err)
	}
	if zeroCfg.GroupRatePerMinute != 0 || zeroCfg.APIEndpointGroups != nil || zeroCfg.APIPolicyVersion != defaultPolicyVersion {
		t.Fatalf("zero config changed group state or policy version: %+v", zeroCfg)
	}

	if _, err := env.db.Exec(ctx, `DELETE FROM api_endpoint_group_members WHERE group_id=$1 AND endpoint_id=$2`, zeta.ID, endpoint2); err != nil {
		t.Fatalf("remove cross-application conflict: %v", err)
	}
	if status := put(json.RawMessage(`"120"`)); status != http.StatusOK {
		t.Fatalf("set positive rate status = %d", status)
	}
	positiveCfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build positive config: %v", err)
	}
	app1ID, app2ID := app1.String(), app2.String()
	if positiveCfg.GroupRatePerMinute != 120 || len(positiveCfg.APIEndpointGroups) != 2 ||
		!reflect.DeepEqual(positiveCfg.APIEndpointGroups[app1ID]["GET /group-rate/shared"], []string{"ALPHA", "ZETA"}) ||
		!reflect.DeepEqual(positiveCfg.APIEndpointGroups[app1ID]["POST /group-rate/other"], []string{"ZETA"}) ||
		!reflect.DeepEqual(positiveCfg.APIEndpointGroups[app2ID]["GET /group-rate/shared"], []string{"BETA"}) {
		t.Fatalf("positive group config = %+v", positiveCfg.APIEndpointGroups)
	}
	for _, endpointGroups := range positiveCfg.APIEndpointGroups {
		for _, codes := range endpointGroups {
			for _, code := range codes {
				if code == "DISABLED" {
					t.Fatal("disabled group must not enter publish mapping")
				}
			}
		}
	}
	if positiveCfg.APIPolicyVersion == defaultPolicyVersion {
		t.Fatal("positive group rate must change api_policy_version")
	}
	generated := s8GenerateGuardJSON(t, positiveCfg)
	for _, want := range []string{`"group_rate_per_minute":120`, `"api_endpoint_groups"`, `["ALPHA","ZETA"]`, `["BETA"]`} {
		if !strings.Contains(generated, want) {
			t.Errorf("generated config missing %s: %s", want, generated)
		}
	}
	versionID, err := provider.SaveVersionSnapshot(ctx, positiveCfg, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("save positive snapshot: %v", err)
	}

	current := createGroup(app1, "current", true)
	addMember(current.ID, endpoint1)
	if status := put(json.RawMessage(`"60"`)); status != http.StatusOK {
		t.Fatalf("change positive rate status = %d", status)
	}
	back, err := provider.GetVersionConfig(ctx, versionID)
	if err != nil {
		t.Fatalf("replay positive snapshot: %v", err)
	}
	if back.GroupRatePerMinute != 60 || !reflect.DeepEqual(back.APIEndpointGroups[app1ID]["GET /group-rate/shared"], []string{"ALPHA", "CURRENT", "ZETA"}) {
		t.Fatalf("rollback replay did not use current rate and groups: %+v", back.APIEndpointGroups)
	}
	if json := s8GenerateGuardJSON(t, back); !strings.Contains(json, `"group_rate_per_minute":60`) || !strings.Contains(json, `["ALPHA","CURRENT","ZETA"]`) {
		t.Fatalf("rollback replay missing current group config: %s", json)
	}

	for _, raw := range []string{`"-1"`, `"abc"`, `"1.5"`, `60`} {
		if status := put(json.RawMessage(raw)); status != http.StatusBadRequest {
			t.Errorf("invalid group rate %s status = %d, want 400", raw, status)
		}
	}
	assertGroupRateLimitSetting000211(t, env, `"60"`)

	for _, raw := range []string{`"-1"`, `"abc"`} {
		if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value=$1::jsonb
			WHERE setting_group='gateway_runtime' AND setting_key=$2`, raw, groupRateLimitSettingKey); err != nil {
			t.Fatalf("inject invalid publish setting: %v", err)
		}
		_, buildErr := provider.BuildGuardConfig(ctx)
		if _, err := env.db.Exec(ctx, `UPDATE system_settings SET setting_value='"60"'::jsonb
			WHERE setting_group='gateway_runtime' AND setting_key=$1`, groupRateLimitSettingKey); err != nil {
			t.Fatalf("restore valid publish setting: %v", err)
		}
		if buildErr == nil || !strings.Contains(buildErr.Error(), groupRateLimitSettingKey) {
			t.Errorf("invalid stored rate %s must abort publish, error = %v", raw, buildErr)
		}
	}

	if _, err := env.db.Exec(ctx, `INSERT INTO api_endpoint_group_members(group_id,endpoint_id) VALUES ($1,$2)`, zeta.ID, endpoint2); err != nil {
		t.Fatalf("restore cross-application conflict: %v", err)
	}
	if _, err := provider.BuildGuardConfig(ctx); err == nil || !strings.Contains(err.Error(), "冲突") {
		t.Fatalf("cross-application conflict must abort publish, error = %v", err)
	}
	if _, err := provider.GetVersionConfig(ctx, versionID); err == nil || !strings.Contains(err.Error(), "冲突") {
		t.Fatalf("cross-application conflict must abort rollback, error = %v", err)
	}
	if _, err := env.db.Exec(ctx, `DELETE FROM api_endpoint_group_members WHERE group_id=$1 AND endpoint_id=$2`, zeta.ID, endpoint2); err != nil {
		t.Fatalf("clean cross-application conflict: %v", err)
	}

	offCfg, err := groupRateLimitProvider(env, false).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build WDSP-off config: %v", err)
	}
	if offCfg.GroupRatePerMinute != 0 || offCfg.APIEndpointGroups != nil {
		t.Fatalf("WDSP-off group config = %+v, want disabled", offCfg)
	}
	if json := s8GenerateGuardJSON(t, offCfg); strings.Contains(json, groupRateLimitSettingKey) || strings.Contains(json, "api_endpoint_groups") {
		t.Fatalf("WDSP-off generated config contains group rate: %s", json)
	}
}
