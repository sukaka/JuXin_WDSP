package tests

import (
	"context"
	"os"
	"testing"
)

// TestContainerOpsMigration000186Replay 验证容器运维权限种子迁移（000186）：
// 全量迁移已播种 4 个权限点且仅授予 SYSTEM_ADMIN；up 重放幂等；down 清除后可重新 up。
func TestContainerOpsMigration000186Replay(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	permCodes := []string{"containers.read", "containers.logs", "containers.control", "containers.update"}

	// 全量迁移（newTestEnv 已执行）后权限点与授权就位
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code IN ($1,$2,$3,$4)`, permCodes[0], permCodes[1], permCodes[2], permCodes[3]); n != 4 {
		t.Fatalf("container ops permission rows=%d want 4", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
		WHERE r.code = 'SYSTEM_ADMIN' AND p.code IN ($1,$2,$3,$4)`, permCodes[0], permCodes[1], permCodes[2], permCodes[3]); n != 4 {
		t.Fatalf("SYSTEM_ADMIN container ops grants=%d want 4", n)
	}
	// 不授予其他内置角色（SECURITY_ADMIN/AUDITOR）
	if n := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
		WHERE r.code <> 'SYSTEM_ADMIN' AND p.code LIKE 'containers.%'`); n != 0 {
		t.Fatalf("container ops perms leaked to non-SYSTEM_ADMIN roles=%d want 0", n)
	}

	upRaw, err := os.ReadFile("../migrations/000186_container_ops_perms.up.sql")
	if err != nil {
		t.Fatalf("read 000186 up migration: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
			t.Fatalf("replay 000186 up #%d: %v", i+1, err)
		}
	}
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code LIKE 'containers.%'`); n != 4 {
		t.Fatalf("after up replay permission rows=%d want 4", n)
	}

	downRaw, err := os.ReadFile("../migrations/000186_container_ops_perms.down.sql")
	if err != nil {
		t.Fatalf("read 000186 down migration: %v", err)
	}
	if _, err := env.db.Exec(ctx, string(downRaw)); err != nil {
		t.Fatalf("apply 000186 down: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code LIKE 'containers.%'`); n != 0 {
		t.Fatalf("after down permission rows=%d want 0", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
		JOIN permissions p ON p.id = rp.permission_id WHERE p.code LIKE 'containers.%'`); n != 0 {
		t.Fatalf("after down grant rows=%d want 0", n)
	}
	// down 后重新 up 可恢复（迁移链回滚-重放闭环）
	if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
		t.Fatalf("re-apply 000186 up after down: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code LIKE 'containers.%'`); n != 4 {
		t.Fatalf("after re-up permission rows=%d want 4", n)
	}
}
