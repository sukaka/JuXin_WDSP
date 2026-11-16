package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestSoftwareBypassSettingsAPIAndPublishLoad(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	ctx := context.Background()
	type settingItem struct {
		Key     string          `json:"setting_key"`
		Value   json.RawMessage `json:"setting_value"`
		Version int             `json:"version"`
	}
	list := func() map[string]settingItem {
		resp := env.get(t, "/api/v1/system-settings?group=software_bypass", cookies)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list software bypass settings: %d", resp.StatusCode)
		}
		var result struct {
			Data struct {
				Items []settingItem `json:"items"`
			} `json:"data"`
		}
		readJSON(t, resp, &result)
		items := make(map[string]settingItem, len(result.Data.Items))
		for _, item := range result.Data.Items {
			items[item.Key] = item
		}
		if len(items) != 5 {
			t.Fatalf("software bypass setting count = %d, want 5", len(items))
		}
		return items
	}
	put := func(key string, value json.RawMessage, version int) *http.Response {
		body := fmt.Sprintf(`{"setting_group":"software_bypass","setting_key":%q,"setting_value":%s,"version":%d}`, key, value, version)
		return env.do(t, http.MethodPut, "/api/v1/system-settings", body, cookies, csrf)
	}

	items := list()
	if string(items["enabled"].Value) != "false" || string(items["cpu_threshold_percent"].Value) != "80" {
		t.Fatalf("unexpected defaults: %+v", items)
	}
	resp := put("cpu_threshold_percent", json.RawMessage(`85`), items["cpu_threshold_percent"].Version)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update CPU threshold: %d", resp.StatusCode)
	}
	resp = put("enabled", json.RawMessage(`true`), items["enabled"].Version)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable software bypass: %d", resp.StatusCode)
	}
	cfg, err := gatewayconfig.LoadSoftwareBypass(ctx, env.db)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || cfg.CPUThresholdPercent != 85 || cfg.MemoryThresholdPercent != 80 {
		t.Fatalf("published config = %+v", cfg)
	}
	items = list()
	resp = put("memory_threshold_percent", json.RawMessage(`0`), items["memory_threshold_percent"].Version)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("zero memory threshold status = %d, want 400", resp.StatusCode)
	}
	resp = put("cpu_threshold_percent", json.RawMessage(`90`), 999999)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale version status = %d, want 409", resp.StatusCode)
	}
	var audits int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM operation_audits
		WHERE module='system_settings' AND object_id='software_bypass:cpu_threshold_percent'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits == 0 {
		t.Fatal("software bypass setting update did not produce an operation audit")
	}

	env.createUserDirect(t, "software_bypass_no_perm", "NoPerm@2026!xy", "SECURITY_ADMIN")
	otherCookies, _ := env.login(t, "software_bypass_no_perm", "NoPerm@2026!xy")
	resp = env.get(t, "/api/v1/system-settings?group=software_bypass", otherCookies)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("security admin read status = %d, want 403", resp.StatusCode)
	}

	items = list()
	for key, value := range map[string]json.RawMessage{
		"enabled": json.RawMessage(`false`), "cpu_threshold_percent": json.RawMessage(`80`),
	} {
		resp = put(key, value, items[key].Version)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("restore %s: %d", key, resp.StatusCode)
		}
		items = list()
	}
}
