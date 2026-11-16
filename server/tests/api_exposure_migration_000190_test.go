package tests

import (
	"context"
	"os"
	"testing"
)

// TestAPIExposureMigration000190Replay 验证暴露面判定引擎迁移（000190）：
// 三张表存在且枚举词表无数据库 CHECK（应用层校验纪律）；up 重放幂等；
// down 清理后可重新 up。
func TestAPIExposureMigration000190Replay(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	tables := []string{
		"api_endpoint_source_buckets",
		"api_endpoint_source_seen",
		"api_exposure_assessments",
	}
	for _, table := range tables {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables
			WHERE table_name=$1`, table); n != 1 {
			t.Fatalf("table %s count=%d want 1", table, n)
		}
	}
	// seen 表只存盐化指纹：必须不含明文 client_ip 列
	if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
		WHERE table_name='api_endpoint_source_seen' AND column_name LIKE '%ip%'`); n != 0 {
		t.Fatalf("api_endpoint_source_seen must not store plain IP columns, got %d", n)
	}
	// 枚举词表不落 CHECK（应用层校验纪律）：三表不得有 CHECK 约束
	if n := s8Count(t, env, `SELECT count(*) FROM information_schema.table_constraints
		WHERE table_name IN ('api_endpoint_source_buckets','api_endpoint_source_seen','api_exposure_assessments')
		  AND constraint_type='CHECK'`); n != 0 {
		t.Fatalf("exposure tables must not carry CHECK constraints, got %d", n)
	}
	// exposure_engine 设置种子 5 键
	if n := s8Count(t, env, `SELECT count(*) FROM system_settings WHERE setting_group='exposure_engine'`); n != 5 {
		t.Fatalf("exposure_engine settings rows=%d want 5", n)
	}

	upRaw, err := os.ReadFile("../migrations/000190_api_exposure.up.sql")
	if err != nil {
		t.Fatalf("read 000190 up migration: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
			t.Fatalf("replay 000190 up #%d: %v", i+1, err)
		}
	}

	downRaw, err := os.ReadFile("../migrations/000190_api_exposure.down.sql")
	if err != nil {
		t.Fatalf("read 000190 down migration: %v", err)
	}
	if _, err := env.db.Exec(ctx, string(downRaw)); err != nil {
		t.Fatalf("apply 000190 down: %v", err)
	}
	for _, table := range tables {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables
			WHERE table_name=$1`, table); n != 0 {
			t.Fatalf("after down table %s count=%d want 0", table, n)
		}
	}
	if n := s8Count(t, env, `SELECT count(*) FROM system_settings WHERE setting_group='exposure_engine'`); n != 0 {
		t.Fatalf("after down exposure_engine settings rows=%d want 0", n)
	}
	if _, err := env.db.Exec(ctx, string(upRaw)); err != nil {
		t.Fatalf("re-apply 000190 up after down: %v", err)
	}
	for _, table := range tables {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables
			WHERE table_name=$1`, table); n != 1 {
			t.Fatalf("after re-up table %s count=%d want 1", table, n)
		}
	}
}
