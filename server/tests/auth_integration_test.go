package tests

import (
	"fmt"
	"net/http"
	"testing"
)

// TestHealthCheck 健康检查。
func TestHealthCheck(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.get(t, "/api/v1/health", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}
	body := readBodyString(t, resp)
	if !contains(body, `"postgres":true`) || !contains(body, `"valkey":true`) {
		t.Errorf("health body = %s", body)
	}
}

// TestLoginSuccess 正确账号密码登录成功。
func TestLoginSuccess(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	if len(cookies) == 0 {
		t.Fatal("no session cookie after login")
	}
	if csrf == "" {
		t.Fatal("no csrf token after login")
	}
	// 访问 me
	resp := env.get(t, "/api/v1/auth/me", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me status = %d", resp.StatusCode)
	}
}

// TestLoginWrongPassword 错误密码登录失败（统一提示）。
func TestLoginWrongPassword(t *testing.T) {
	env := setupTestEnv(t)
	capID, capCode := env.captcha(t)
	body := fmt.Sprintf(`{"username":"test_sysadmin","password":"wrong","captcha_id":%q,"captcha_code":%q}`, capID, capCode)
	resp := env.post(t, "/api/v1/auth/login", body, nil, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want 401", resp.StatusCode)
	}
	var result apiResp
	readJSON(t, resp, &result)
	if result.Message != "用户名或密码错误" {
		t.Errorf("message = %q, want unified hint", result.Message)
	}
}

// TestLoginNonexistentUser 不存在账号返回相同提示（防枚举）。
func TestLoginNonexistentUser(t *testing.T) {
	env := setupTestEnv(t)
	capID, capCode := env.captcha(t)
	body := fmt.Sprintf(`{"username":"no_such_user","password":"x","captcha_id":%q,"captcha_code":%q}`, capID, capCode)
	resp := env.post(t, "/api/v1/auth/login", body, nil, "")
	defer resp.Body.Close()
	var result apiResp
	readJSON(t, resp, &result)
	if result.Message != "用户名或密码错误" {
		t.Errorf("nonexistent user message = %q, want unified hint", result.Message)
	}
}

// TestLoginBadCaptcha 验证码错误拒绝登录。
func TestLoginBadCaptcha(t *testing.T) {
	env := setupTestEnv(t)
	capID, _ := env.captcha(t)
	body := fmt.Sprintf(`{"username":"test_sysadmin","password":%q,"captcha_id":%q,"captcha_code":"WRONG"}`, env.adminPwd, capID)
	resp := env.post(t, "/api/v1/auth/login", body, nil, "")
	defer resp.Body.Close()
	var result apiResp
	readJSON(t, resp, &result)
	if result.Code != "CAPTCHA_INVALID" {
		t.Errorf("code = %q, want CAPTCHA_INVALID", result.Code)
	}
}

// TestLoginLockout 连续失败锁定账号。
func TestLoginLockout(t *testing.T) {
	env := setupTestEnv(t)
	// 默认阈值 5 次
	for i := 0; i < 5; i++ {
		capID, capCode := env.captcha(t)
		body := fmt.Sprintf(`{"username":"test_sysadmin","password":"wrong%d","captcha_id":%q,"captcha_code":%q}`, i, capID, capCode)
		resp := env.post(t, "/api/v1/auth/login", body, nil, "")
		resp.Body.Close()
	}
	// 第 6 次即使密码正确也应锁定
	capID, capCode := env.captcha(t)
	body := fmt.Sprintf(`{"username":"test_sysadmin","password":%q,"captcha_id":%q,"captcha_code":%q}`, env.adminPwd, capID, capCode)
	resp := env.post(t, "/api/v1/auth/login", body, nil, "")
	defer resp.Body.Close()
	var result apiResp
	readJSON(t, resp, &result)
	if result.Code != "ACCOUNT_LOCKED" && result.Code != "UNAUTHENTICATED" {
		t.Errorf("after lockout code = %q", result.Code)
	}
}

// TestUnauthenticatedAccess 未登录访问受保护接口返回 401。
func TestUnauthenticatedAccess(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.get(t, "/api/v1/users", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", resp.StatusCode)
	}
}

// TestLogout 退出后会话失效。
func TestLogout(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	resp := env.post(t, "/api/v1/auth/logout", "", cookies, csrf)
	resp.Body.Close()
	// 再用旧 cookie 访问 me 应 401
	resp2 := env.get(t, "/api/v1/auth/me", cookies)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout status = %d, want 401", resp2.StatusCode)
	}
}

// TestCSRFRequired 写操作缺少 CSRF Token 被拒绝。
func TestCSRFRequired(t *testing.T) {
	env := setupTestEnv(t)
	cookies, _ := env.login(t, "test_sysadmin", env.adminPwd)
	resp := env.post(t, "/api/v1/users", `{"username":"newuser1","display_name":"x","role_code":"SECURITY_ADMIN"}`, cookies, "")
	defer resp.Body.Close()
	var result apiResp
	readJSON(t, resp, &result)
	if result.Code != "CSRF_INVALID" {
		t.Errorf("no csrf code = %q, want CSRF_INVALID", result.Code)
	}
}

// TestRequestIDHeader 响应包含 Request ID。
func TestRequestIDHeader(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.get(t, "/api/v1/health", nil)
	defer resp.Body.Close()
	rid := resp.Header.Get("X-Jiuzhang-Request-ID")
	if rid == "" {
		t.Error("missing X-Jiuzhang-Request-ID header")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
