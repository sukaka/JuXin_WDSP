package tests

import (
	"context"
	"os"
	"testing"
)

// TestVulnIntelMigration000189Replay 验证漏洞情报迁移（000189）：
// 全量迁移后四表与权限种子就位（vuln_intel.read 授予 SYSTEM_ADMIN+SECURITY_ADMIN，
// vuln_intel.manage 仅授予 SYSTEM_ADMIN）；up 重放幂等；down 只清除本功能权限与四表
// （不影响其他迁移的表与权限）；down 后可重新 up。
func TestVulnIntelMigration000189Replay(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	// 表就位
	for _, table := range []string{"vuln_advisories", "application_technologies", "vuln_alerted", "vuln_intel_sync_state"} {
		var exists bool
		if err := env.db.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("table %s 不存在", table)
		}
	}
	// 权限点与授权就位（000232 后读写均归运维管理员 SECURITY_ADMIN，SYSTEM_ADMIN 不再持有）
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code IN ('vuln_intel.read','vuln_intel.manage')`); n != 2 {
		t.Fatalf("vuln_intel permission rows=%d want 2", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
		WHERE r.code = 'SECURITY_ADMIN' AND p.code = 'vuln_intel.read'`); n != 1 {
		t.Fatalf("vuln_intel.read SECURITY_ADMIN grant=%d want 1", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
		WHERE r.code = 'SECURITY_ADMIN' AND p.code = 'vuln_intel.manage'`); n != 1 {
		t.Fatalf("vuln_intel.manage SECURITY_ADMIN grant=%d want 1", n)
	}
	// 读写均不泄漏到其他内置角色
	if n := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
		WHERE r.code <> 'SECURITY_ADMIN' AND p.code IN ('vuln_intel.read','vuln_intel.manage')`); n != 0 {
		t.Fatalf("vuln_intel.* 泄漏到其他角色: %d", n)
	}

	upRaw, err := os.ReadFile("../migrations/000189_vuln_intel.up.sql")
	if err != nil {
		t.Fatalf("read 000189 up migration: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
			t.Fatalf("replay 000189 up #%d: %v", i+1, err)
		}
	}
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code LIKE 'vuln_intel.%'`); n != 2 {
		t.Fatalf("after up replay permission rows=%d want 2", n)
	}

	downRaw, err := os.ReadFile("../migrations/000189_vuln_intel.down.sql")
	if err != nil {
		t.Fatalf("read 000189 down migration: %v", err)
	}
	if _, err := env.db.Exec(ctx, string(downRaw)); err != nil {
		t.Fatalf("apply 000189 down: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code LIKE 'vuln_intel.%'`); n != 0 {
		t.Fatalf("after down permission rows=%d want 0", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
		JOIN permissions p ON p.id = rp.permission_id WHERE p.code LIKE 'vuln_intel.%'`); n != 0 {
		t.Fatalf("after down grant rows=%d want 0", n)
	}
	for _, table := range []string{"vuln_advisories", "application_technologies", "vuln_alerted", "vuln_intel_sync_state"} {
		var exists bool
		if err := env.db.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatalf("after down table %s 仍存在", table)
		}
	}
	// down 不影响其他迁移的表与权限（抽查 000188 的权限点仍在）
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code = 'api_asset.export'`); n != 1 {
		t.Fatalf("down 误伤其他迁移权限（api_asset.export=%d）", n)
	}
	// down 后重新 up 可恢复（迁移链回滚-重放闭环）
	if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
		t.Fatalf("re-apply 000189 up after down: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code LIKE 'vuln_intel.%'`); n != 2 {
		t.Fatalf("after re-up permission rows=%d want 2", n)
	}
}
