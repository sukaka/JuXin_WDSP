package tests

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

// createUserAsAdmin 以系统管理员创建用户并返回用户ID与临时密码。
func (e *testEnv) createUserAsAdmin(t *testing.T, adminCookies []*http.Cookie, csrf, username, roleCode string) (string, string) {
	t.Helper()
	body := fmt.Sprintf(`{"username":%q,"display_name":%q,"role_code":%q}`, username, username+"_name", roleCode)
	resp := e.post2(t, "/api/v1/users", body, adminCookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create user %s status = %d, body: %s", username, resp.StatusCode, readBodyString(t, resp))
	}
	var result apiResp
	readJSON(t, resp, &result)
	tempPwd, _ := result.Data["temporary_password"].(string)
	userMap, _ := result.Data["user"].(map[string]interface{})
	userID, _ := userMap["id"].(string)
	return userID, tempPwd
}

// createUserDirect 直接在数据库创建用户（绕过API，用于快速准备测试账号）。
func (e *testEnv) createUserDirect(t *testing.T, username, password, roleCode string) uuid.UUID {
	t.Helper()
	hash, _ := security.HashPassword(password)
	store := users.NewStore(e.db)
	u := &users.User{
		Username:     username,
		DisplayName:  username,
		PasswordHash: hash,
		Status:       users.StatusActive,
	}
	if err := store.Create(context.Background(), u); err != nil {
		t.Fatalf("createUserDirect: %v", err)
	}
	roleID, _ := store.GetRoleIDByCode(context.Background(), roleCode)
	if err := store.AssignRole(context.Background(), u.ID, roleID, u.ID); err != nil {
		t.Fatalf("assignRole: %v", err)
	}
	return u.ID
}

func (e *testEnv) post2(t *testing.T, path, body string, cookies []*http.Cookie, csrf string) *http.Response {
	t.Helper()
	return e.request(t, http.MethodPost, path, body, cookies, csrf)
}

// TestSecurityAdminCannotManageUsers 安全管理员访问用户管理被拒绝。
func TestSecurityAdminCannotManageUsers(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_admin1", "SecAdmin@2026!", "SECURITY_ADMIN")
	cookies, _ := env.login(t, "sec_admin1", "SecAdmin@2026!")

	resp := env.get(t, "/api/v1/users", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("security admin GET /users status = %d, want 403", resp.StatusCode)
	}
}

// TestAuditAdminCannotModifyUsers 审计管理员修改用户被拒绝。
func TestAuditAdminCannotModifyUsers(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "audit_admin1", "AuditAdmin@2026!", "AUDIT_ADMIN")
	cookies, csrf := env.login(t, "audit_admin1", "AuditAdmin@2026!")

	resp := env.post(t, "/api/v1/users", `{"username":"hacker1","display_name":"x","role_code":"SYSTEM_ADMIN"}`, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("audit admin POST /users status = %d, want 403", resp.StatusCode)
	}
}

// TestAuditAdminCanReadAudits 审计管理员可以查看审计与登录日志。
func TestAuditAdminCanReadAudits(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "audit_admin2", "AuditAdmin@2026!", "AUDIT_ADMIN")
	cookies, _ := env.login(t, "audit_admin2", "AuditAdmin@2026!")

	for _, path := range []string{"/api/v1/audits", "/api/v1/login-logs"} {
		resp := env.get(t, path, cookies)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("audit admin GET %s status = %d, want 200", path, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

// TestSysAdminCannotReadAudits 系统管理员不能查看完整审计。
func TestSysAdminCannotReadAudits(t *testing.T) {
	env := setupTestEnv(t)
	cookies, _ := env.login(t, "test_sysadmin", env.adminPwd)
	resp := env.get(t, "/api/v1/audits", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("sysadmin GET /audits status = %d, want 403", resp.StatusCode)
	}
}

// TestCreateUserDuplicateUsername 重复用户名返回冲突。
func TestCreateUserDuplicateUsername(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	env.createUserAsAdmin(t, cookies, csrf, "dup_user", "SECURITY_ADMIN")

	resp := env.post(t, "/api/v1/users", `{"username":"dup_user","display_name":"x","role_code":"SECURITY_ADMIN"}`, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate username status = %d, want 409", resp.StatusCode)
	}
}

// TestCannotDisableLastSysAdmin 不能停用最后一个系统管理员。
func TestCannotDisableLastSysAdmin(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	// 查询当前管理员ID
	resp := env.get(t, "/api/v1/users?username=test_sysadmin", cookies)
	var list apiRespPage
	readJSON(t, resp, &list)
	resp.Body.Close()
	adminID := list.Data.Items[0]["id"].(string)

	// 停用自己（最后一个系统管理员）应被拒绝
	resp2 := env.post(t, "/api/v1/users/"+adminID+"/disable", "", cookies, csrf)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("disable last sysadmin status = %d, want 409", resp2.StatusCode)
	}
}

// TestCannotDeleteSelf 不能删除当前登录账号。
func TestCannotDeleteSelf(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	resp := env.get(t, "/api/v1/users?username=test_sysadmin", cookies)
	var list apiRespPage
	readJSON(t, resp, &list)
	resp.Body.Close()
	adminID := list.Data.Items[0]["id"].(string)

	req, _ := http.NewRequest(http.MethodDelete, env.server.URL+"/api/v1/users/"+adminID, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", csrf)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete self: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("delete self status = %d, want 409", resp2.StatusCode)
	}
}

// TestResetPassword 重置密码生成临时密码且旧会话失效。
func TestResetPassword(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	userID, _ := env.createUserAsAdmin(t, cookies, csrf, "reset_target", "SECURITY_ADMIN")

	resp := env.post(t, "/api/v1/users/"+userID+"/reset-password", "", cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset password status = %d", resp.StatusCode)
	}
	var result apiResp
	readJSON(t, resp, &result)
	tempPwd, _ := result.Data["temporary_password"].(string)
	if tempPwd == "" {
		t.Fatal("no temporary_password returned")
	}
	// 临时密码可登录且必须改密
	cookies2, _ := env.login(t, "reset_target", tempPwd)
	resp2 := env.get(t, "/api/v1/auth/me", cookies2)
	defer resp2.Body.Close()
	var me apiResp
	readJSON(t, resp2, &me)
	user, _ := me.Data["user"].(map[string]interface{})
	if user["must_change_password"] != true {
		t.Errorf("must_change_password = %v, want true", user["must_change_password"])
	}
}

// TestAuditRecorded 操作审计被记录且脱敏。
func TestAuditRecorded(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	env.createUserAsAdmin(t, cookies, csrf, "audit_target", "AUDIT_ADMIN")

	// 查询审计记录（需要审计管理员）
	env.createUserDirect(t, "audit_reader", "AuditAdmin@2026!", "AUDIT_ADMIN")
	auditCookies, _ := env.login(t, "audit_reader", "AuditAdmin@2026!")
	resp := env.get(t, "/api/v1/audits?module=users&action=create", auditCookies)
	defer resp.Body.Close()
	var list apiRespPage
	readJSON(t, resp, &list)
	if list.Data.Total == 0 {
		t.Fatal("no audit recorded for user creation")
	}
	// 验证审计不含密码
	body := readBodyString(t, resp)
	if contains(body, "temporary_password\":\"") && !contains(body, "********") {
		t.Errorf("audit may leak password")
	}
}

// TestAuditHashChain 审计哈希链完整。
func TestAuditHashChain(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	env.createUserAsAdmin(t, cookies, csrf, "chain_user", "SECURITY_ADMIN")

	env.createUserDirect(t, "audit_reader2", "AuditAdmin@2026!", "AUDIT_ADMIN")
	auditCookies, auditCsrf := env.login(t, "audit_reader2", "AuditAdmin@2026!")
	resp := env.post(t, "/api/v1/audits/verify-chain", "", auditCookies, auditCsrf)
	defer resp.Body.Close()
	var result apiResp
	readJSON(t, resp, &result)
	if result.Data["valid"] != true {
		t.Errorf("audit hash chain invalid: %v", result.Data)
	}
}

// TestForceLogout 强制下线后用户会话失效。
func TestForceLogout(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "kick_target", "Kick@2026!Pass", "SECURITY_ADMIN")
	targetCookies, _ := env.login(t, "kick_target", "Kick@2026!Pass")

	// 管理员强制下线
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	resp := env.get(t, "/api/v1/users?username=kick_target", cookies)
	var list apiRespPage
	readJSON(t, resp, &list)
	resp.Body.Close()
	targetID := list.Data.Items[0]["id"].(string)

	req, _ := http.NewRequest(http.MethodDelete, env.server.URL+"/api/v1/users/"+targetID+"/sessions", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", csrf)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("force logout: %v", err)
	}
	resp2.Body.Close()

	// 目标用户会话已失效
	resp3 := env.get(t, "/api/v1/auth/me", targetCookies)
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Errorf("after force logout status = %d, want 401", resp3.StatusCode)
	}
}

// TestChangePasswordInvalidatesOtherSessions 修改密码后其他会话失效。
func TestChangePasswordInvalidatesOtherSessions(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "pwd_changer", "Old@Pass2026!", "SECURITY_ADMIN")
	// 两个会话
	cookies1, csrf1 := env.login(t, "pwd_changer", "Old@Pass2026!")
	cookies2, _ := env.login(t, "pwd_changer", "Old@Pass2026!")

	// 会话1改密
	body := `{"old_password":"Old@Pass2026!","new_password":"New@Pass2026!"}`
	resp := env.post(t, "/api/v1/auth/change-password", body, cookies1, csrf1)
	resp.Body.Close()

	// 会话2应失效
	resp2 := env.get(t, "/api/v1/auth/me", cookies2)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("other session after pwd change status = %d, want 401", resp2.StatusCode)
	}
}

// TestWeakPasswordRejected 弱密码被拒绝。
func TestWeakPasswordRejected(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "weak_pwd_user", "Old@Pass2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "weak_pwd_user", "Old@Pass2026!")
	body := `{"old_password":"Old@Pass2026!","new_password":"admin123"}`
	resp := env.post(t, "/api/v1/auth/change-password", body, cookies, csrf)
	defer resp.Body.Close()
	var result apiResp
	readJSON(t, resp, &result)
	if result.Code != "INVALID_ARGUMENT" {
		t.Errorf("weak password code = %q, want INVALID_ARGUMENT", result.Code)
	}
}

// apiRespPage 是分页响应。
type apiRespPage struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Items    []map[string]interface{} `json:"items"`
		Page     int                      `json:"page"`
		PageSize int                      `json:"page_size"`
		Total    int64                    `json:"total"`
	} `json:"data"`
}
