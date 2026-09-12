// stage8_api_classifications_expansion_test.go 用途分类扩展迁移集成测试。
package tests

import (
	"context"
	"os"
	"testing"
)

var expandedPurposeClassifications = [][2]string{
	{"PRODUCT_CATALOG", "商品目录"},
	{"INVENTORY_LOGISTICS", "库存物流"},
	{"CUSTOMER_SERVICE", "客户服务"},
	{"MARKETING_GROWTH", "营销增长"},
	{"CONTENT_COMMUNITY", "内容社区"},
	{"MEDIA_STREAMING", "音视频媒体"},
	{"LOCATION_SERVICE", "位置服务"},
	{"DEVELOPER_PLATFORM", "开发者平台"},
}

func TestStage8APIClassificationExpansionMigration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	assertExpandedPurposeClassifications(t, env)

	// 种子迁移允许安全重放，且不会产生重复编码。
	raw, err := os.ReadFile("../migrations/000087_api_classifications_expansion.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := env.db.Exec(ctx, string(raw)); err != nil {
		t.Fatalf("replay migration 000087: %v", err)
	}
	assertExpandedPurposeClassifications(t, env)
}

func assertExpandedPurposeClassifications(t *testing.T, env *testEnv) {
	t.Helper()
	for _, want := range expandedPurposeClassifications {
		if n := s8Count(t, env, `SELECT count(*) FROM api_classifications
			WHERE code=$1 AND name=$2 AND description <> '' AND is_builtin`, want[0], want[1]); n != 1 {
			t.Fatalf("expanded purpose classification %v count=%d want 1", want, n)
		}
	}
}
