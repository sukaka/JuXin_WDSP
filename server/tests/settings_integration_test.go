package tests

import (
	"fmt"
	"net/http"
	"testing"
)

// TestSystemSettingsRead 系统管理员读取设置。
func TestSystemSettingsRead(t *testing.T) {
	env := setupTestEnv(t)
	cookies, _ := env.login(t, "test_sysadmin", env.adminPwd)
	resp := env.get(t, "/api/v1/system-settings", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("settings list status = %d", resp.StatusCode)
	}
	var result apiRespPage2
	readJSON(t, resp, &result)
	if len(result.Data.Items) == 0 {
		t.Error("no settings returned")
	}
}

// TestSystemSettingsUpdate 系统管理员修改密码策略并生效。
func TestSystemSettingsUpdate(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	// 读取当前 min_length 版本
	resp := env.get(t, "/api/v1/system-settings?group=password", cookies)
	var list apiRespPage2
	readJSON(t, resp, &list)
	resp.Body.Close()
	var minLen map[string]interface{}
	for _, item := range list.Data.Items {
		if item["setting_key"] == "min_length" {
			minLen = item
			break
		}
	}
	if minLen == nil {
		t.Fatal("min_length setting not found")
	}
	version := int(minLen["version"].(float64))

	// 修改为 16
	body := fmt.Sprintf(`{"setting_group":"password","setting_key":"min_length","setting_value":16,"version":%d}`, version)
	resp2 := env.do(t, http.MethodPut, "/api/v1/system-settings", body, cookies, csrf)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("update setting status = %d, body: %s", resp2.StatusCode, readBodyString(t, resp2))
	}

	// 验证已生效：用长度14的密码改密应失败（新密码需≥16）
	env.createUserDirect(t, "policy_target", "Old@Pass2026!xy", "SECURITY_ADMIN")
	c2, csrf2 := env.login(t, "policy_target", "Old@Pass2026!xy")
	resp3 := env.post(t, "/api/v1/auth/change-password",
		`{"old_password":"Old@Pass2026!xy","new_password":"Sh0rt!Pass"}`, c2, csrf2)
	defer resp3.Body.Close()
	var result apiResp
	readJSON(t, resp3, &result)
	if result.Code != "INVALID_ARGUMENT" {
		t.Errorf("short password after policy change code = %q, want INVALID_ARGUMENT", result.Code)
	}
}

// TestSystemSettingsVersionConflict 设置乐观锁冲突。
func TestSystemSettingsVersionConflict(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	resp := env.get(t, "/api/v1/system-settings?group=password", cookies)
	resp.Body.Close()
	// 用过期版本号更新
	body := fmt.Sprintf(`{"setting_group":"password","setting_key":"min_length","setting_value":14,"version":%d}`, 999)
	resp2 := env.do(t, http.MethodPut, "/api/v1/system-settings", body, cookies, csrf)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("stale version status = %d, want 409", resp2.StatusCode)
	}
}

// TestSystemSettingsForbiddenForOthers 非系统管理员无法访问设置。
func TestSystemSettingsForbiddenForOthers(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "no_perm_user", "NoPerm@2026!xy", "SECURITY_ADMIN")
	cookies, _ := env.login(t, "no_perm_user", "NoPerm@2026!xy")
	resp := env.get(t, "/api/v1/system-settings", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("security admin settings status = %d, want 403", resp.StatusCode)
	}
}

// TestRateLimitLogin 登录接口限速生效。
func TestRateLimitLogin(t *testing.T) {
	env := setupTestEnv(t)
	// 默认限速 10 次/分钟（登录接口），快速请求应触发 RATE_LIMITED。
	// 注意：验证码接口与登录共用同额度配置，循环中验证码可能先被 429；
	// 此时用占位验证码继续打登录接口，登录桶同样会耗尽并返回 RATE_LIMITED。
	var lastCode string
	for i := 0; i < 12; i++ {
		capID, capCode := env.captchaTolerant(t)
		body := fmt.Sprintf(`{"username":"rl_user","password":"x","captcha_id":%q,"captcha_code":%q}`, capID, capCode)
		resp := env.post(t, "/api/v1/auth/login", body, nil, "")
		var result apiResp
		readJSON(t, resp, &result)
		resp.Body.Close()
		lastCode = result.Code
	}
	if lastCode != "RATE_LIMITED" {
		t.Errorf("after rapid requests code = %q, want RATE_LIMITED", lastCode)
	}
}

// apiRespPage2 是含 items 数组的响应（非分页的 list）。
type apiRespPage2 struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Items []map[string]interface{} `json:"items"`
		Total int64                    `json:"total"`
	} `json:"data"`
}
