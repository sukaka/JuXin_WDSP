// stage8_api_classifications_backfill_test.go 启发式分类值内置目录回填迁移集成测试（000096）。
package tests

import (
	"context"
	"os"
	"testing"
)

var builtinHeuristicClassifications = [][2]string{
	{"AUTH", "认证鉴权"},
	{"TRADE", "交易支付"},
	{"FILE", "文件传输"},
	{"ADMIN", "管理运维"},
	{"USER_MGMT", "用户管理"},
	{"QUERY", "查询检索"},
	{"GENERAL", "通用业务"},
	{"INTERNAL", "内部使用"},
	{"PARTNER", "合作方开放"},
	{"PUBLIC", "公网开放"},
}

func TestStage8APIClassificationBackfillMigration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	assertBuiltinHeuristicClassifications(t, env)

	// 回填迁移允许安全重放，且不覆盖已修订的说明。
	raw, err := os.ReadFile("../migrations/000096_api_classifications_builtin_backfill.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := env.db.Exec(ctx, string(raw)); err != nil {
		t.Fatalf("replay migration 000096: %v", err)
	}
	assertBuiltinHeuristicClassifications(t, env)

	// 人工修订说明后重放：非空说明不被覆盖。
	if _, err := env.db.Exec(ctx,
		`UPDATE api_classifications SET description='人工修订说明' WHERE code='AUTH'`); err != nil {
		t.Fatalf("revise description: %v", err)
	}
	if _, err := env.db.Exec(ctx, string(raw)); err != nil {
		t.Fatalf("replay migration 000096 after revise: %v", err)
	}
	if n := s8Count(t, env,
		`SELECT count(*) FROM api_classifications WHERE code='AUTH' AND description='人工修订说明'`); n != 1 {
		t.Fatalf("revised description overwritten by replay")
	}
}

func assertBuiltinHeuristicClassifications(t *testing.T, env *testEnv) {
	t.Helper()
	for _, want := range builtinHeuristicClassifications {
		if n := s8Count(t, env, `SELECT count(*) FROM api_classifications
			WHERE code=$1 AND name=$2 AND description <> '' AND is_builtin`, want[0], want[1]); n != 1 {
			t.Fatalf("builtin heuristic classification %v count=%d want 1", want, n)
		}
	}
}
