package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// TestStage5BlockResponseSettings 阶段5 §5.1 自定义 429/阻断响应页面实库集成：
// 迁移 000151 种子四键（空串=内置默认）→ 设置接口更新（白名单+长度上限+乐观锁）
// → gatewayconfig.LoadBlockResponse 组装下发配置（发布侧校验同口径）。
func TestStage5BlockResponseSettings(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	ctx := context.Background()

	// 1) 种子行存在且默认全空（网关内置默认模板）
	type settingItem struct {
		Group   string `json:"setting_group"`
		Key     string `json:"setting_key"`
		Value   string `json:"setting_value"`
		Version int    `json:"version"`
	}
	listSettings := func() []settingItem {
		resp := env.get(t, "/api/v1/system-settings?group=block_response", cookies)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list block_response settings: status %d", resp.StatusCode)
		}
		var result struct {
			Data struct {
				Items []settingItem `json:"items"`
			} `json:"data"`
		}
		readJSON(t, resp, &result)
		return result.Data.Items
	}
	items := listSettings()
	if len(items) != 4 {
		t.Fatalf("expected 4 seeded block_response settings, got %d", len(items))
	}
	versions := map[string]int{}
	for _, it := range items {
		if it.Group != "block_response" {
			t.Fatalf("unexpected group: %s", it.Group)
		}
		if it.Value != "" {
			t.Fatalf("seeded value should be empty (内置默认): %s=%q", it.Key, it.Value)
		}
		versions[it.Key] = it.Version
	}

	// 2) 缺省（全空）时发布侧组装为 nil（不下发，网关与历史版本逐字节一致）
	br, err := gatewayconfig.LoadBlockResponse(ctx, env.db)
	if err != nil || br != nil {
		t.Fatalf("default settings should assemble to nil: %v %+v", err, br)
	}

	// 3) 设置接口更新（白名单+审计跟随现有配置管理），发布侧读回组装
	putSetting := func(key, value string, version int) *http.Response {
		body := fmt.Sprintf(`{"setting_group":"block_response","setting_key":%q,"setting_value":%q,"version":%d}`,
			key, value, version)
		return env.do(t, http.MethodPut, "/api/v1/system-settings", body, cookies, csrf)
	}
	resp := putSetting("html_body", "<p>系统繁忙</p><script>alert(1)</script>", versions["html_body"])
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update html_body: status %d", resp.StatusCode)
	}
	resp = putSetting("json_code", "rate_limited", versions["json_code"])
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update json_code: status %d", resp.StatusCode)
	}

	br, err = gatewayconfig.LoadBlockResponse(ctx, env.db)
	if err != nil {
		t.Fatalf("LoadBlockResponse: %v", err)
	}
	if br == nil || br.HTMLBody != "<p>系统繁忙</p><script>alert(1)</script>" || br.JSONCode != "rate_limited" {
		t.Fatalf("assembled block response: %+v", br)
	}
	// 未设置项回落空串（网关侧用内置默认）
	if br.HTMLTitle != "" || br.JSONMessage != "" {
		t.Fatalf("unset fields should stay empty: %+v", br)
	}

	// 4) 保存期长度上限：超上限 400（发布侧与网关装配期另有同口径校验）
	items = listSettings()
	versions = map[string]int{}
	for _, it := range items {
		versions[it.Key] = it.Version
	}
	resp = putSetting("html_body", strings.Repeat("p", 4097), versions["html_body"])
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversize html_body should be 400, got %d", resp.StatusCode)
	}
	// 非白名单键 400
	resp = env.do(t, http.MethodPut, "/api/v1/system-settings",
		`{"setting_group":"block_response","setting_key":"evil_key","setting_value":"x","version":1}`, cookies, csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-whitelisted key should be 400, got %d", resp.StatusCode)
	}

	// 5) 清空恢复缺省 → 组装回 nil
	items = listSettings()
	versions = map[string]int{}
	for _, it := range items {
		versions[it.Key] = it.Version
	}
	for _, key := range []string{"html_body", "json_code"} {
		resp = putSetting(key, "", versions[key])
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("clear %s: status %d", key, resp.StatusCode)
		}
	}
	br, err = gatewayconfig.LoadBlockResponse(ctx, env.db)
	if err != nil || br != nil {
		t.Fatalf("cleared settings should assemble to nil: %v %+v", err, br)
	}
}
