package tests

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/security"
)

// loginRaw 执行登录并返回原始响应（不假定成功，供 TOTP 分支断言）。
func (e *testEnv) loginRaw(t *testing.T, username, password string) *http.Response {
	t.Helper()
	capID, capCode := e.captcha(t)
	body := fmt.Sprintf(`{"username":%q,"password":%q,"captcha_id":%q,"captcha_code":%q}`,
		username, password, capID, capCode)
	return e.post(t, "/api/v1/auth/login", body, nil, "")
}

// totpVerifyRaw 提交登录第二步验证。
func (e *testEnv) totpVerifyRaw(t *testing.T, challengeToken, code string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"challenge_token":%q,"code":%q}`, challengeToken, code)
	return e.post(t, "/api/v1/auth/totp-verify", body, nil, "")
}

// hasSessionCookie 判断响应是否下发会话 Cookie。
func hasSessionCookie(resp *http.Response) bool {
	for _, c := range resp.Cookies() {
		if c.Name == "jiuzhang_session" && c.Value != "" {
			return true
		}
	}
	return false
}

// wrongTOTP 返回一个与当前有效窗口（±1 时间步）均不匹配的 6 位错误令牌。
func wrongTOTP(t *testing.T, secret string) string {
	t.Helper()
	valid := map[string]bool{}
	for _, at := range []time.Time{time.Now().Add(-30 * time.Second), time.Now(), time.Now().Add(30 * time.Second)} {
		c, err := security.TOTPCode(secret, at)
		if err != nil {
			t.Fatalf("totp code: %v", err)
		}
		valid[c] = true
	}
	for i := 0; i < 1000000; i++ {
		c := fmt.Sprintf("%06d", i)
		if !valid[c] {
			return c
		}
	}
	t.Fatal("unreachable")
	return ""
}

// TestTOTPIntegration 双因子认证全流程集成测试：
// setup → enable → 登录挑战 → 第二步验证 → 恢复码一次性 → 自助关闭 → 管理员重置 → 权限校验。
func TestTOTPIntegration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	// 全流程登录/验证请求超过默认限流阈值（10 次/分钟），测试库直接调大
	if _, err := env.db.Exec(ctx, `
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('login', 'rate_limit_per_minute', '1000', 'int', '集成测试调大登录限流')
ON CONFLICT (setting_group, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value`); err != nil {
		t.Fatalf("raise login rate limit: %v", err)
	}

	userID := env.createUserDirect(t, "totp_user", "TotpUser@2026!", "SECURITY_ADMIN")

	// ---- 1. 自助开启：setup → enable ----
	cookies, csrf := env.login(t, "totp_user", "TotpUser@2026!")
	resp := env.post(t, "/api/v1/auth/totp/setup", "", cookies, csrf)
	var setupResp apiResp
	readJSON(t, resp, &setupResp)
	resp.Body.Close()
	if setupResp.Code != "SUCCESS" {
		t.Fatalf("setup code = %s", setupResp.Code)
	}
	secret, _ := setupResp.Data["secret"].(string)
	otpauthURL, _ := setupResp.Data["otpauth_url"].(string)
	rawCodes, _ := setupResp.Data["recovery_codes"].([]interface{})
	if secret == "" || otpauthURL == "" || len(rawCodes) != 10 {
		t.Fatalf("bad setup data: %v", setupResp.Data)
	}
	recoveryCodes := make([]string, 0, len(rawCodes))
	for _, c := range rawCodes {
		recoveryCodes = append(recoveryCodes, c.(string))
	}

	// 未 enable 前登录仍不需要双因子（pending 状态不影响登录）
	resp = env.loginRaw(t, "totp_user", "TotpUser@2026!")
	var loginResp apiResp
	readJSON(t, resp, &loginResp)
	if resp.StatusCode != http.StatusOK || loginResp.Code != "SUCCESS" {
		t.Fatalf("login with pending totp status=%d code=%s, want 200 SUCCESS", resp.StatusCode, loginResp.Code)
	}
	pendingCookies := resp.Cookies()
	resp.Body.Close()

	code, err := security.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	resp = env.post(t, "/api/v1/auth/totp/enable", fmt.Sprintf(`{"code":%q}`, code), cookies, csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable status = %d", resp.StatusCode)
	}

	// 会话内可见 totp_enabled=true
	resp = env.get(t, "/api/v1/auth/me", pendingCookies)
	readJSON(t, resp, &loginResp)
	resp.Body.Close()
	userMap, _ := loginResp.Data["user"].(map[string]interface{})
	if enabled, _ := userMap["totp_enabled"].(bool); !enabled {
		t.Fatal("me.totp_enabled should be true after enable")
	}

	// ---- 2. 登录挑战与第二步验证 ----
	// 已开启用户登录：返回 TOTP_REQUIRED + challenge_token，不下发会话
	resp = env.loginRaw(t, "totp_user", "TotpUser@2026!")
	readJSON(t, resp, &loginResp)
	if resp.StatusCode != http.StatusOK || loginResp.Code != "TOTP_REQUIRED" {
		t.Fatalf("login status=%d code=%s, want 200 TOTP_REQUIRED", resp.StatusCode, loginResp.Code)
	}
	if hasSessionCookie(resp) {
		t.Fatal("session cookie must not be issued before TOTP verify")
	}
	resp.Body.Close()
	challenge, _ := loginResp.Data["challenge_token"].(string)
	if challenge == "" {
		t.Fatal("missing challenge_token")
	}

	// 错误动态令牌 → 401 TOTP_INVALID（挑战保留可重试）
	resp = env.totpVerifyRaw(t, challenge, wrongTOTP(t, secret))
	readJSON(t, resp, &loginResp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || loginResp.Code != "TOTP_INVALID" {
		t.Fatalf("wrong totp status=%d code=%s, want 401 TOTP_INVALID", resp.StatusCode, loginResp.Code)
	}

	// 正确动态令牌 → 200，会话与 CSRF 下发
	code, _ = security.TOTPCode(secret, time.Now())
	resp = env.totpVerifyRaw(t, challenge, code)
	readJSON(t, resp, &loginResp)
	if resp.StatusCode != http.StatusOK || loginResp.Code != "SUCCESS" {
		t.Fatalf("verify status=%d code=%s", resp.StatusCode, loginResp.Code)
	}
	if !hasSessionCookie(resp) {
		t.Fatal("missing session cookie after verify")
	}
	resp.Body.Close()

	// 挑战令牌一次性：二次使用 → 401
	resp = env.totpVerifyRaw(t, challenge, code)
	readJSON(t, resp, &loginResp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || loginResp.Code != "UNAUTHENTICATED" {
		t.Fatalf("reused challenge status=%d code=%s, want 401 UNAUTHENTICATED", resp.StatusCode, loginResp.Code)
	}

	// 无效挑战 → 401 UNAUTHENTICATED
	resp = env.totpVerifyRaw(t, "deadbeef", "123456")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid challenge status = %d, want 401", resp.StatusCode)
	}

	// ---- 3. 恢复码一次性 ----
	resp = env.loginRaw(t, "totp_user", "TotpUser@2026!")
	readJSON(t, resp, &loginResp)
	resp.Body.Close()
	challenge2, _ := loginResp.Data["challenge_token"].(string)
	resp = env.totpVerifyRaw(t, challenge2, recoveryCodes[0])
	readJSON(t, resp, &loginResp)
	recoveryCookies := resp.Cookies()
	recoveryCSRF, _ := loginResp.Data["csrf_token"].(string)
	resp.Body.Close()
	if loginResp.Code != "SUCCESS" {
		t.Fatalf("recovery verify code = %s", loginResp.Code)
	}

	resp = env.loginRaw(t, "totp_user", "TotpUser@2026!")
	readJSON(t, resp, &loginResp)
	resp.Body.Close()
	challenge3, _ := loginResp.Data["challenge_token"].(string)
	resp = env.totpVerifyRaw(t, challenge3, recoveryCodes[0])
	readJSON(t, resp, &loginResp)
	resp.Body.Close()
	if loginResp.Code != "TOTP_INVALID" {
		t.Fatalf("reused recovery code = %s, want TOTP_INVALID", loginResp.Code)
	}

	// ---- 4. 自助关闭（恢复码会话仍有效）----
	resp = env.post(t, "/api/v1/auth/totp/disable", fmt.Sprintf(`{"code":%q}`, wrongTOTP(t, secret)), recoveryCookies, recoveryCSRF)
	readJSON(t, resp, &loginResp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || loginResp.Code != "TOTP_INVALID" {
		t.Fatalf("disable wrong code status=%d code=%s, want 400 TOTP_INVALID", resp.StatusCode, loginResp.Code)
	}
	code, _ = security.TOTPCode(secret, time.Now())
	resp = env.post(t, "/api/v1/auth/totp/disable", fmt.Sprintf(`{"code":%q}`, code), recoveryCookies, recoveryCSRF)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable status = %d", resp.StatusCode)
	}

	// 关闭后登录不再需要双因子
	resp = env.loginRaw(t, "totp_user", "TotpUser@2026!")
	readJSON(t, resp, &loginResp)
	resp.Body.Close()
	if loginResp.Code != "SUCCESS" {
		t.Fatalf("login after disable code = %s, want SUCCESS", loginResp.Code)
	}

	// ---- 5. 管理员重置 ----
	// 重新开启
	cookies2, csrf2 := env.login(t, "totp_user", "TotpUser@2026!")
	resp = env.post(t, "/api/v1/auth/totp/setup", "", cookies2, csrf2)
	readJSON(t, resp, &setupResp)
	resp.Body.Close()
	secret2, _ := setupResp.Data["secret"].(string)
	code, _ = security.TOTPCode(secret2, time.Now())
	resp = env.post(t, "/api/v1/auth/totp/enable", fmt.Sprintf(`{"code":%q}`, code), cookies2, csrf2)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-enable status = %d", resp.StatusCode)
	}

	adminCookies, adminCSRF := env.login(t, "test_sysadmin", env.adminPwd)
	resp = env.post(t, fmt.Sprintf("/api/v1/users/%s/totp/reset", userID), "", adminCookies, adminCSRF)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin reset status = %d", resp.StatusCode)
	}

	// 重置后登录不再需要双因子，me 显示未开启
	resp = env.loginRaw(t, "totp_user", "TotpUser@2026!")
	readJSON(t, resp, &loginResp)
	resetCookies := resp.Cookies()
	resp.Body.Close()
	if loginResp.Code != "SUCCESS" {
		t.Fatalf("login after admin reset code = %s, want SUCCESS", loginResp.Code)
	}
	resp = env.get(t, "/api/v1/auth/me", resetCookies)
	readJSON(t, resp, &loginResp)
	resp.Body.Close()
	userMap, _ = loginResp.Data["user"].(map[string]interface{})
	if enabled, _ := userMap["totp_enabled"].(bool); enabled {
		t.Fatal("totp_enabled should be false after admin reset")
	}

	// 重复重置 → 409
	resp = env.post(t, fmt.Sprintf("/api/v1/users/%s/totp/reset", userID), "", adminCookies, adminCSRF)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("re-reset status = %d, want 409", resp.StatusCode)
	}

	// ---- 6. 权限：SECURITY_ADMIN 无 users.reset_password，调重置接口 → 403 ----
	resp = env.post(t, fmt.Sprintf("/api/v1/users/%s/totp/reset", userID), "", resetCookies, "")
	readJSON(t, resp, &loginResp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("reset without permission status = %d, want 403", resp.StatusCode)
	}
}
