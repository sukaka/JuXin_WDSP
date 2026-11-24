package tests

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

// TestMigration000232Static 验证 000232 迁移 up/down 静态契约（无需外部 DB）。
func TestMigration000232Static(t *testing.T) {
	up := readMigration(t, "000232_role_rename_and_perm_rebalance.up.sql")
	for _, frag := range []string{
		"name = '运维管理员'",
		"WHERE code = 'SECURITY_ADMIN'",
		"big_screen.runtime.read",
		"'system_alerts.read'",
		"'system_alerts.acknowledge'",
		"'vuln_intel.manage'",
		"'gateway_runtime.read'",
		"'jwt_trust.read'",
		"'bot_policy.read'",
		"'security_regression.read'",
		"'risk_policy.read'",
		"'attack_sessions.read'",
		"'security_identities.block'",
		"'traffic.agents.view'",
		"'traffic.agents.manage'",
	} {
		if !strings.Contains(up, frag) {
			t.Errorf("000232 up missing %q", frag)
		}
	}

	down := readMigration(t, "000232_role_rename_and_perm_rebalance.down.sql")
	for _, frag := range []string{
		"name = '安全管理员'",
		"WHERE code = 'SECURITY_ADMIN'",
		"DELETE FROM permissions WHERE code = 'big_screen.runtime.read'",
		"'system_alerts.read'",
		"'vuln_intel.manage'",
	} {
		if !strings.Contains(down, frag) {
			t.Errorf("000232 down missing %q", frag)
		}
	}
}

// TestMigration000232ReplayAndMatrix 验证 000232 角色更名、权限再平衡、重放幂等与 down/up 回滚闭环。
func TestMigration000232ReplayAndMatrix(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	assertPost000232State := func(phase string) {
		t.Helper()
		var secName string
		if err := env.db.QueryRow(ctx, `SELECT name FROM roles WHERE code='SECURITY_ADMIN'`).Scan(&secName); err != nil {
			t.Fatalf("%s: query SECURITY_ADMIN name: %v", phase, err)
		}
		if secName != "运维管理员" {
			t.Fatalf("%s: SECURITY_ADMIN name = %q, want 运维管理员", phase, secName)
		}

		// big_screen.runtime.read 仅授予 SECURITY_ADMIN
		if got := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
			JOIN roles r ON r.id=rp.role_id JOIN permissions p ON p.id=rp.permission_id
			WHERE p.code='big_screen.runtime.read' AND r.code='SECURITY_ADMIN'`); got != 1 {
			t.Fatalf("%s: big_screen.runtime.read SECURITY_ADMIN grant = %d, want 1", phase, got)
		}
		if got := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
			JOIN roles r ON r.id=rp.role_id JOIN permissions p ON p.id=rp.permission_id
			WHERE p.code='big_screen.runtime.read' AND r.code <> 'SECURITY_ADMIN'`); got != 0 {
			t.Fatalf("%s: big_screen.runtime.read leaked to other roles = %d", phase, got)
		}

		// 移交给运维管理员的 4 个原 SYSTEM_ADMIN 独有权限均已授予 SECURITY_ADMIN
		if got := s8Count(t, env, `SELECT count(DISTINCT p.code) FROM role_permissions rp
			JOIN roles r ON r.id=rp.role_id JOIN permissions p ON p.id=rp.permission_id
			WHERE r.code='SECURITY_ADMIN' AND p.code IN (
				'system_alerts.read','system_alerts.acknowledge','vuln_intel.manage','gateway_runtime.read'
			)`); got != 4 {
			t.Fatalf("%s: SECURITY_ADMIN handed-over grants = %d, want 4", phase, got)
		}

		// SYSTEM_ADMIN 不再持有 7 大菜单对应的全部 17 个权限点及大屏权限
		if got := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
			JOIN roles r ON r.id=rp.role_id JOIN permissions p ON p.id=rp.permission_id
			WHERE r.code='SYSTEM_ADMIN' AND p.code IN (
				'big_screen.runtime.read',
				'gateway_runtime.read',
				'jwt_trust.read','jwt_trust.manage',
				'bot_policy.read','bot_policy.edit',
				'security_regression.read','security_regression.import','security_regression.policy',
				'risk_policy.read',
				'attack_sessions.read','security_identities.block',
				'traffic.agents.view','traffic.agents.manage',
				'system_alerts.read','system_alerts.acknowledge',
				'vuln_intel.read','vuln_intel.manage'
			)`); got != 0 {
			t.Fatalf("%s: SYSTEM_ADMIN still holds %d revoked permissions, want 0", phase, got)
		}

		// SYSTEM_ADMIN 仍保留系统运维与账号管理核心权限
		if got := s8Count(t, env, `SELECT count(DISTINCT p.code) FROM role_permissions rp
			JOIN roles r ON r.id=rp.role_id JOIN permissions p ON p.id=rp.permission_id
			WHERE r.code='SYSTEM_ADMIN' AND p.code IN (
				'users.read','roles.read','system_settings.read','system_health.read',
				'dashboard.runtime.read','backups.read','upgrades.read','license.read',
				'ha.read','notification.read','request_pcap.capture_control','ai.models.read'
			)`); got != 12 {
			t.Fatalf("%s: SYSTEM_ADMIN core retained perms = %d, want 12", phase, got)
		}
	}

	assertPost000232State("initial")

	// 重放 up 幂等
	up := readMigration(t, "000232_role_rename_and_perm_rebalance.up.sql")
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("replay 000232 up: %v", err)
	}
	assertPost000232State("replayed-up")

	// 执行 down 回滚验证
	down := readMigration(t, "000232_role_rename_and_perm_rebalance.down.sql")
	if _, err := env.db.Exec(ctx, down); err != nil {
		t.Fatalf("apply 000232 down: %v", err)
	}
	var secNameAfterDown string
	if err := env.db.QueryRow(ctx, `SELECT name FROM roles WHERE code='SECURITY_ADMIN'`).Scan(&secNameAfterDown); err != nil {
		t.Fatal(err)
	}
	if secNameAfterDown != "安全管理员" {
		t.Fatalf("after down SECURITY_ADMIN name = %q, want 安全管理员", secNameAfterDown)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code='big_screen.runtime.read'`); got != 0 {
		t.Fatalf("after down big_screen.runtime.read still exists: %d", got)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id=rp.role_id JOIN permissions p ON p.id=rp.permission_id
		WHERE r.code='SYSTEM_ADMIN' AND p.code IN ('system_alerts.read','vuln_intel.manage','traffic.agents.view')`); got != 3 {
		t.Fatalf("after down SYSTEM_ADMIN restored perms = %d, want 3", got)
	}

	// 重新 up 恢复闭环
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("re-apply 000232 up: %v", err)
	}
	assertPost000232State("re-up")
}

// TestMigration000232BigScreenAndSevenMenusRBAC 端到端 HTTP 权限隔离验证：
//   - 运维管理员（SECURITY_ADMIN）：可访问 4 个运行监控大屏只读接口、7 大菜单接口；不可访问系统运维专属接口；
//   - 系统管理员（SYSTEM_ADMIN）：可访问系统运维与角色接口（角色名为「运维管理员」）；对 7 大菜单接口全部 403；
//   - 审计管理员（AUDIT_ADMIN）：对运行监控大屏接口全部 403。
func TestMigration000232BigScreenAndSevenMenusRBAC(t *testing.T) {
	env := setupStage8Env(t)
	sysCookies, sysCSRF := env.s5Login(t, "rb232_sys", authz.RoleSystemAdmin)
	operCookies, _ := env.s5Login(t, "rb232_oper", authz.RoleSecurityAdmin)
	audCookies, _ := env.s5Login(t, "rb232_aud", authz.RoleAuditAdmin)

	// 1. /api/v1/roles 返回的 SECURITY_ADMIN 中文名为「运维管理员」
	rolesResp := s5OK(t, env.get(t, "/api/v1/roles", sysCookies), "list roles")
	items, _ := rolesResp.Data["items"].([]interface{})
	foundOper := false
	for _, it := range items {
		m, _ := it.(map[string]interface{})
		if m["code"] == authz.RoleSecurityAdmin {
			if m["name"] != "运维管理员" {
				t.Fatalf("GET /roles SECURITY_ADMIN name = %v, want 运维管理员", m["name"])
			}
			foundOper = true
		}
	}
	if !foundOper {
		t.Fatalf("GET /roles missing SECURITY_ADMIN: %+v", items)
	}

	// 2. 运行监控大屏 4 个只读接口：运维管理员 200，系统管理员 200，审计管理员 403
	for _, path := range []string{
		"/api/v1/system-health",
		"/api/v1/system-health/storage",
		"/api/v1/system-health/gateway-trend",
		"/api/v1/dashboard/runtime-overview",
	} {
		s5Expect(t, env.get(t, path, operCookies), http.StatusOK, "operadmin "+path)
		s5Expect(t, env.get(t, path, sysCookies), http.StatusOK, "sysadmin "+path)
		s5Expect(t, env.get(t, path, audCookies), http.StatusForbidden, "auditor "+path)
	}

	// 3. 系统运维专属只读接口：系统管理员 200，运维管理员 403（big_screen.runtime.read 不越权泄漏）
	for _, path := range []string{
		"/api/v1/system-health/components",
		"/api/v1/metrics",
		"/api/v1/gateway/interfaces",
		"/api/v1/gateway/network-config",
	} {
		s5Expect(t, env.get(t, path, sysCookies), http.StatusOK, "sysadmin ops "+path)
		s5Expect(t, env.get(t, path, operCookies), http.StatusForbidden, "operadmin forbidden ops "+path)
	}

	// 4. 7 大菜单后端接口：运维管理员 200，系统管理员全部 403
	for _, path := range []string{
		"/api/v1/system-alerts",
		"/api/v1/system-alerts/export",
		"/api/v1/vuln-intel/overview",
		"/api/v1/vuln-intel/settings",
		"/api/v1/traffic/agents",
		"/api/v1/security/risk-policy",
		"/api/v1/security/attack-sessions",
		"/api/v1/security/regressions",
		"/api/v1/security/regression-policy",
		"/api/v1/api-security/machine-identities",
	} {
		s5Expect(t, env.get(t, path, operCookies), http.StatusOK, "operadmin 7-menu "+path)
		s5Expect(t, env.get(t, path, sysCookies), http.StatusForbidden, "sysadmin forbidden 7-menu "+path)
	}
	s5Expect(t, env.post(t, "/api/v1/vuln-intel/import", `{"advisories":[]}`, sysCookies, sysCSRF),
		http.StatusForbidden, "sysadmin forbidden vuln-intel import")
}

// TestEnsureInitialRoleUserIntegration 验证 users.Store.HasRoleUsers 与 EnsureInitialRoleUser 在真实 PG 下的幂等性与冲突保护。
func TestEnsureInitialRoleUserIntegration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	store := users.NewStore(env.db)

	// setupTestEnv 已创建 1 名 SYSTEM_ADMIN（test_sysadmin），尚未创建 SECURITY_ADMIN / AUDIT_ADMIN
	hasSys, err := store.HasRoleUsers(ctx, authz.RoleSystemAdmin)
	if err != nil || !hasSys {
		t.Fatalf("HasRoleUsers(SYSTEM_ADMIN) = (%v, %v), want (true, nil)", hasSys, err)
	}
	hasOper, err := store.HasRoleUsers(ctx, authz.RoleSecurityAdmin)
	if err != nil || hasOper {
		t.Fatalf("HasRoleUsers(SECURITY_ADMIN) = (%v, %v), want (false, nil)", hasOper, err)
	}
	hasAud, err := store.HasRoleUsers(ctx, authz.RoleAuditAdmin)
	if err != nil || hasAud {
		t.Fatalf("HasRoleUsers(AUDIT_ADMIN) = (%v, %v), want (false, nil)", hasAud, err)
	}

	hash, err := security.HashPassword("Init@Strong2026!A")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// 1. 已有 SYSTEM_ADMIN 时幂等跳过，不创建 admin
	created, err := store.EnsureInitialRoleUser(ctx, authz.RoleSystemAdmin, &users.User{
		Username: "admin", DisplayName: "系统管理员", PasswordHash: hash,
		Status: users.StatusActive, MustChangePassword: true, PasswordChangedAt: &now,
	})
	if err != nil || created {
		t.Fatalf("EnsureInitialRoleUser(SYSTEM_ADMIN) = (%v, %v), want (false, nil)", created, err)
	}

	// 2. 缺失的 SECURITY_ADMIN 与 AUDIT_ADMIN 自动补齐 operadmin / auditor
	created, err = store.EnsureInitialRoleUser(ctx, authz.RoleSecurityAdmin, &users.User{
		Username: "operadmin", DisplayName: "运维管理员", PasswordHash: hash,
		Status: users.StatusActive, MustChangePassword: true, PasswordChangedAt: &now,
	})
	if err != nil || !created {
		t.Fatalf("EnsureInitialRoleUser(SECURITY_ADMIN) = (%v, %v), want (true, nil)", created, err)
	}
	// 再次调用完全幂等
	created, err = store.EnsureInitialRoleUser(ctx, authz.RoleSecurityAdmin, &users.User{
		Username: "operadmin2", DisplayName: "运维管理员", PasswordHash: hash,
		Status: users.StatusActive, MustChangePassword: true, PasswordChangedAt: &now,
	})
	if err != nil || created {
		t.Fatalf("second EnsureInitialRoleUser(SECURITY_ADMIN) = (%v, %v), want (false, nil)", created, err)
	}

	// 3. 用户名冲突（忽略大小写）返回 ErrUsernameExists 且不破坏现有账号
	created, err = store.EnsureInitialRoleUser(ctx, authz.RoleAuditAdmin, &users.User{
		Username: "OPERADMIN", DisplayName: "审计管理员", PasswordHash: hash,
		Status: users.StatusActive, MustChangePassword: true, PasswordChangedAt: &now,
	})
	if err != users.ErrUsernameExists || created {
		t.Fatalf("collision EnsureInitialRoleUser(AUDIT_ADMIN) = (%v, %v), want (false, ErrUsernameExists)", created, err)
	}

	// 4. 正常用户名 auditor 创建成功
	created, err = store.EnsureInitialRoleUser(ctx, authz.RoleAuditAdmin, &users.User{
		Username: "auditor", DisplayName: "审计管理员", PasswordHash: hash,
		Status: users.StatusActive, MustChangePassword: true, PasswordChangedAt: &now,
	})
	if err != nil || !created {
		t.Fatalf("EnsureInitialRoleUser(AUDIT_ADMIN) = (%v, %v), want (true, nil)", created, err)
	}

	// 核验新账号角色名已为「运维管理员」
	operUser, err := store.GetByUsername(ctx, "operadmin")
	if err != nil {
		t.Fatalf("GetByUsername(operadmin): %v", err)
	}
	if !operUser.MustChangePassword {
		t.Errorf("operadmin MustChangePassword = false, want true")
	}
	roles, err := store.GetRoles(ctx, operUser.ID)
	if err != nil || len(roles) != 1 || roles[0].Code != authz.RoleSecurityAdmin || roles[0].Name != "运维管理员" {
		t.Fatalf("operadmin roles = %+v (err=%v), want SECURITY_ADMIN/运维管理员", roles, err)
	}
}
