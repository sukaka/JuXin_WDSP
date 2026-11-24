// stage8_api_taxonomy_catalog_test.go 分类维度值目录种子迁移集成测试（000095）。
package tests

import (
	"context"
	"os"
	"testing"
)

var taxonomyCatalogSeeds = [][2]string{
	// 数据类型
	{"DATA_TYPE", "身份信息"},
	{"DATA_TYPE", "联系方式"},
	{"DATA_TYPE", "认证凭证"},
	{"DATA_TYPE", "财务数据"},
	{"DATA_TYPE", "位置数据"},
	{"DATA_TYPE", "设备数据"},
	{"DATA_TYPE", "交易数据"},
	// 操作类型
	{"OPERATION", "查询"},
	{"OPERATION", "新增"},
	{"OPERATION", "修改"},
	{"OPERATION", "删除"},
	{"OPERATION", "上传"},
	{"OPERATION", "下载"},
	{"OPERATION", "导入"},
	{"OPERATION", "导出"},
	{"OPERATION", "批处理"},
	// 生命周期
	{"LIFECYCLE", "活跃"},
	{"LIFECYCLE", "废弃"},
	{"LIFECYCLE", "影子接口"},
	{"LIFECYCLE", "僵尸接口"},
	{"LIFECYCLE", "测试接口"},
	// 调用方向
	{"DIRECTION", "入站"},
	{"DIRECTION", "出站"},
	{"DIRECTION", "东西向"},
	{"DIRECTION", "第三方回调"},
	// 认证方式
	{"AUTH_TYPE", "无需认证"},
	{"AUTH_TYPE", "Session"},
	{"AUTH_TYPE", "API Key"},
	{"AUTH_TYPE", "OAuth2"},
	{"AUTH_TYPE", "JWT"},
	{"AUTH_TYPE", "签名"},
	{"AUTH_TYPE", "mTLS"},
	// 环境
	{"ENV", "生产"},
	{"ENV", "预发布"},
	{"ENV", "测试"},
	{"ENV", "开发"},
	// 合规范围
	{"COMPLIANCE_SCOPE", "网络安全法"},
	{"COMPLIANCE_SCOPE", "数据安全法"},
	{"COMPLIANCE_SCOPE", "等保"},
	{"COMPLIANCE_SCOPE", "GDPR"},
	// 数据跨境
	{"DATA_CROSS_BORDER", "不涉及"},
	{"DATA_CROSS_BORDER", "境内"},
	{"DATA_CROSS_BORDER", "跨境"},
	{"DATA_CROSS_BORDER", "待确认"},
}

func TestStage8APITaxonomyCatalogMigration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	assertTaxonomyCatalogSeeds(t, env)

	// 种子迁移允许安全重放，且不会产生重复条目。
	raw, err := os.ReadFile("../migrations/000095_api_taxonomy_catalog_seed.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := env.db.Exec(ctx, string(raw)); err != nil {
		t.Fatalf("replay migration 000095: %v", err)
	}
	assertTaxonomyCatalogSeeds(t, env)
}

func assertTaxonomyCatalogSeeds(t *testing.T, env *testEnv) {
	t.Helper()
	for _, want := range taxonomyCatalogSeeds {
		if n := s8Count(t, env, `SELECT count(*) FROM api_custom_taxonomies
			WHERE dimension=$1 AND value=$2 AND description <> '' AND description !~ '[A-Za-z]'`, want[0], want[1]); n != 1 {
			t.Fatalf("taxonomy catalog seed %v count=%d want 1", want, n)
		}
	}
}
