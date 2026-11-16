package tests

import (
	"context"
	"os"
	"testing"
)

// TestAPIAssetExportMigration000188Replay 验证 API 资产导出权限与来源分类证据迁移（000188）：
// 权限只授予 SECURITY_ADMIN；分类列存在；up 重放幂等；down 清理后可重新 up。
func TestAPIAssetExportMigration000188Replay(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code='api_asset.export'`); n != 1 {
		t.Fatalf("api_asset.export permission rows=%d want 1", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
		WHERE r.code='SECURITY_ADMIN' AND p.code='api_asset.export'`); n != 1 {
		t.Fatalf("SECURITY_ADMIN api_asset.export grants=%d want 1", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
		WHERE r.code <> 'SECURITY_ADMIN' AND p.code='api_asset.export'`); n != 0 {
		t.Fatalf("api_asset.export leaked to non-SECURITY_ADMIN roles=%d want 0", n)
	}

	classificationColumns := []string{
		"classification_is_api", "classification_confidence", "classification_level",
		"classification_signals", "classified_at",
	}
	for _, column := range classificationColumns {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='agent_http_asset_sources' AND column_name=$1`, column); n != 1 {
			t.Fatalf("classification column %s count=%d want 1", column, n)
		}
	}

	upRaw, err := os.ReadFile("../migrations/000188_api_asset_export.up.sql")
	if err != nil {
		t.Fatalf("read 000188 up migration: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
			t.Fatalf("replay 000188 up #%d: %v", i+1, err)
		}
	}
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code='api_asset.export'`); n != 1 {
		t.Fatalf("after up replay permission rows=%d want 1", n)
	}

	downRaw, err := os.ReadFile("../migrations/000188_api_asset_export.down.sql")
	if err != nil {
		t.Fatalf("read 000188 down migration: %v", err)
	}
	if _, err := env.db.Exec(ctx, string(downRaw)); err != nil {
		t.Fatalf("apply 000188 down: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code='api_asset.export'`); n != 0 {
		t.Fatalf("after down permission rows=%d want 0", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
		WHERE table_name='agent_http_asset_sources' AND column_name LIKE 'classification%'`); n != 0 {
		t.Fatalf("after down classification columns=%d want 0", n)
	}
	if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
		t.Fatalf("re-apply 000188 up after down: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM permissions WHERE code='api_asset.export'`); n != 1 {
		t.Fatalf("after re-up permission rows=%d want 1", n)
	}
}
