// apimcp_pg_test.go MCP 工具目录 PG 契约（NG-MCP G1 批次 B1，Opt-in
// AUTHZ_TEST_PG_DSN——单元运行不需要活动数据库）：
// 迁移 000181/000182 up/up/down×5/up 幂等与词表 CHECK（status/mode/review_status/
// risk_level/data_classification/tool_hash 形态/endpoint_path/max_calls_per_minute）
// （down 先回滚 000185（升级任务 executor_deadline 列，NG-REL-02 F7）与其上的
// 000184/000183（NG-ID 机器身份四表）再回滚 182/181——五步）；
// 唯一键（目录 name、(catalog_id,tool_name)、(application_id,endpoint_path)）拒收；
// FK 拒收与级联（删目录级联工具行与绑定、删应用级联绑定）；store 真事务语义
// （审核状态机、tool_hash 变更重算+旧审批不继承、语义相等幂等不重置、catalog_hash
// 审核后更新）；发布段读取只含 APPROVED 且 DISABLED 目录不出现。
package apimcp

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func openMCPPG(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping mcp catalog PG test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("create pg pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping pg: %v", err)
	}
	return pool, ctx
}

func mkApp(t *testing.T, pool *pgxpool.Pool, ctx context.Context, prefix string) string {
	t.Helper()
	code := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestMCPCatalogMigrationPostgresContract(t *testing.T) {
	pool, ctx := openMCPPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}
	for _, v := range []int{181, 182} {
		var applied int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=$1`, v).Scan(&applied); err != nil {
			t.Fatal(err)
		}
		if applied != 1 {
			t.Fatalf("migration %d records=%d, want 1", v, applied)
		}
	}
	appID := mkApp(t, pool, ctx, "mcp181")
	catName := fmt.Sprintf("mcp181-cat-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM mcp_tool_catalogs WHERE name LIKE 'mcp181-%'`)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})
	var catID, toolID string
	if err := pool.QueryRow(ctx, `INSERT INTO mcp_tool_catalogs(name,service_identity) VALUES ($1,'mcp://pay.example.com') RETURNING id`, catName).Scan(&catID); err != nil {
		t.Fatal(err)
	}
	// 目录词表 CHECK：status 词表外拒收
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_tool_catalogs(name,service_identity,status) VALUES ('mcp181-x','mcp://x','BOGUS')`); err == nil {
		t.Fatal("status=BOGUS 应被 CHECK 拒收")
	}
	// 目录 name 唯一
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_tool_catalogs(name,service_identity) VALUES ($1,'mcp://y')`, catName); err == nil {
		t.Fatal("同名目录应被唯一索引拒收")
	}
	goodHash := "mcp-tool-sha256:v1:" + strings.Repeat("a", 64)
	goodDigest := strings.Repeat("b", 64)
	if err := pool.QueryRow(ctx, `INSERT INTO mcp_catalog_tools(catalog_id,tool_name,description_digest,tool_hash) VALUES ($1,'refund',$2,$3) RETURNING id`, catID, goodDigest, goodHash).Scan(&toolID); err != nil {
		t.Fatalf("合法工具行应通过: %v", err)
	}
	// 工具词表 CHECK 矩阵
	for name, sql := range map[string]string{
		"review_status 词表":     `INSERT INTO mcp_catalog_tools(catalog_id,tool_name,description_digest,tool_hash,review_status) VALUES ($1,'t1','` + goodDigest + `','` + goodHash + `','BOGUS')`,
		"risk_level 词表":        `INSERT INTO mcp_catalog_tools(catalog_id,tool_name,description_digest,tool_hash,risk_level) VALUES ($1,'t2','` + goodDigest + `','` + goodHash + `','CRITICAL')`,
		"classification 词表":    `INSERT INTO mcp_catalog_tools(catalog_id,tool_name,description_digest,tool_hash,data_classification) VALUES ($1,'t3','` + goodDigest + `','` + goodHash + `','SECRET')`,
		"tool_hash 形态":         `INSERT INTO mcp_catalog_tools(catalog_id,tool_name,description_digest,tool_hash) VALUES ($1,'t4','` + goodDigest + `','sha256:abc')`,
		"max_calls_per_minute": `INSERT INTO mcp_catalog_tools(catalog_id,tool_name,description_digest,tool_hash,max_calls_per_minute) VALUES ($1,'t5','` + goodDigest + `','` + goodHash + `',-1)`,
	} {
		if _, err := pool.Exec(ctx, sql, catID); err == nil {
			t.Fatalf("%s 应被 CHECK 拒收", name)
		}
	}
	// (catalog_id, tool_name) 唯一
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_catalog_tools(catalog_id,tool_name,description_digest,tool_hash) VALUES ($1,'refund',$2,$3)`, catID, goodDigest, goodHash); err == nil {
		t.Fatal("同（目录,工具名）应被唯一索引拒收")
	}
	// 工具 FK：目录不存在拒收
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_catalog_tools(catalog_id,tool_name,description_digest,tool_hash) VALUES ($1,'ghost',$2,$3)`, uuid.New(), goodDigest, goodHash); err == nil {
		t.Fatal("引用不存在目录应被 FK 拒收")
	}
	// 绑定词表 CHECK：mode 词表外 / endpoint_path 形态
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_catalog_bindings(application_id,endpoint_path,catalog_id,mode) VALUES ($1,'/mcp',$2,'BLOCK')`, appID, catID); err == nil {
		t.Fatal("mode=BLOCK 应被 CHECK 拒收")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_catalog_bindings(application_id,endpoint_path,catalog_id) VALUES ($1,'mcp',$2)`, appID, catID); err == nil {
		t.Fatal("endpoint_path 非 / 开头应被 CHECK 拒收")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_catalog_bindings(application_id,endpoint_path,catalog_id) VALUES ($1,'/mcp/pay',$2)`, appID, catID); err != nil {
		t.Fatalf("合法绑定应通过: %v", err)
	}
	// (application_id, endpoint_path) 唯一
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_catalog_bindings(application_id,endpoint_path,catalog_id) VALUES ($1,'/mcp/pay',$2)`, appID, catID); err == nil {
		t.Fatal("同（应用,endpoint_path）应被唯一索引拒收")
	}
	// 绑定 FK：应用/目录不存在拒收
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_catalog_bindings(application_id,endpoint_path,catalog_id) VALUES ($1,'/mcp/x',$2)`, uuid.New(), catID); err == nil {
		t.Fatal("引用不存在应用应被 FK 拒收")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_catalog_bindings(application_id,endpoint_path,catalog_id) VALUES ($1,'/mcp/y',$2)`, appID, uuid.New()); err == nil {
		t.Fatal("引用不存在目录应被 FK 拒收")
	}
	// 级联：删目录 → 工具行与绑定级联删除
	if _, err := pool.Exec(ctx, `DELETE FROM mcp_tool_catalogs WHERE id=$1`, catID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"mcp_catalog_tools", "mcp_catalog_bindings"} {
		var remain int
		if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s WHERE catalog_id=$1`, table), catID).Scan(&remain); err != nil {
			t.Fatal(err)
		}
		if remain != 0 {
			t.Fatalf("目录删除应级联清空 %s: %d", table, remain)
		}
	}
	// 级联：删应用 → 绑定级联删除
	if err := pool.QueryRow(ctx, `INSERT INTO mcp_tool_catalogs(name,service_identity) VALUES ($1,'mcp://z') RETURNING id`, catName+"2").Scan(&catID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO mcp_catalog_bindings(application_id,endpoint_path,catalog_id) VALUES ($1,'/mcp/z',$2)`, appID, catID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM applications WHERE id=$1`, appID); err != nil {
		t.Fatal(err)
	}
	var remain int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM mcp_catalog_bindings WHERE application_id=$1`, appID).Scan(&remain); err != nil {
		t.Fatal(err)
	}
	if remain != 0 {
		t.Fatalf("应用删除应级联删绑定: %d", remain)
	}
	// down 五步（185 → 184 → 183 → 182 → 181）：先回滚 000185（升级任务
	// executor_deadline 列，NG-REL-02 F7）与 000184/000183（NG-ID 机器身份
	// 四表），再回滚 182/181——本测试锚定三表消失；复 up 恢复
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 185: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 184: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 183: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 182: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("migrate down 181: %v", err)
	}
	for _, table := range []string{"mcp_catalog_bindings", "mcp_tool_catalogs", "mcp_catalog_tools"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatalf("down 后 %s 应被移除", table)
		}
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
}

func TestMCPCatalogStorePostgresContract(t *testing.T) {
	pool, ctx := openMCPPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	appID := mkApp(t, pool, ctx, "mcpcrud")
	name := fmt.Sprintf("pay-mcp-%d", time.Now().UnixNano())
	store := NewStore(pool)
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM mcp_tool_catalogs WHERE name=$1`, name)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})

	schema := map[string]any{"type": "object", "properties": map[string]any{"order_id": map[string]any{"type": "string"}}}
	mkTools := func(desc string) []ToolInput {
		return []ToolInput{
			{ToolName: "refund", ToolVersion: "1.0.0", Description: desc, InputSchema: &schema},
			{ToolName: "query_order", Description: "查询订单"},
		}
	}
	// ① Create：导入恒落 PENDING_REVIEW、tool_hash 前缀、缺省定级 HIGH/UNKNOWN、
	//    catalog_hash=空 APPROVED 集摘要
	c, tools, err := store.CreateCatalog(ctx, CatalogInput{Name: name, ServiceIdentity: "mcp://pay.example.com", Tools: mkTools("发起退款")}, "tester")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.ProtocolVersion != ProtocolVersionDefault || c.Status != StatusEnabled || c.Source != "MANUAL_IMPORT" {
		t.Fatalf("目录归一: %+v", c)
	}
	if c.CatalogHash != ComputeCatalogHash(nil) {
		t.Fatalf("空 APPROVED 集摘要: %s", c.CatalogHash)
	}
	if len(tools) != 2 {
		t.Fatalf("工具行数: %d", len(tools))
	}
	var refundID uuid.UUID
	for _, tool := range tools {
		if tool.ReviewStatus != ReviewPending || tool.ReviewedBy != "" || tool.ReviewedAt != nil {
			t.Fatalf("导入恒落 PENDING_REVIEW: %+v", tool)
		}
		if !strings.HasPrefix(tool.ToolHash, ToolHashPrefix) || len(tool.ToolHash) != len(ToolHashPrefix)+64 {
			t.Fatalf("tool_hash 形态: %s", tool.ToolHash)
		}
		if tool.RiskLevel != RiskHigh || tool.DataClassification != ClassUnknown {
			t.Fatalf("缺省定级: %s/%s", tool.RiskLevel, tool.DataClassification)
		}
		if tool.ToolName == "refund" {
			refundID = tool.ID
		}
	}
	// 同名 → ErrDuplicateName
	if _, _, err := store.CreateCatalog(ctx, CatalogInput{Name: name, ServiceIdentity: "mcp://dup"}, "tester"); err != ErrDuplicateName {
		t.Fatalf("同名应 ErrDuplicateName: %v", err)
	}
	// ② Review APPROVED+定级 → reviewed_* 落账 + DB catalog_hash 更新为 APPROVED 集摘要
	rt, err := store.ReviewTool(ctx, c.ID, refundID, ReviewInput{Action: "APPROVED", RiskLevel: "MEDIUM", DataClassification: "INTERNAL"}, "secadmin")
	if err != nil {
		t.Fatalf("review: %v", err)
	}
	if rt.ReviewStatus != ReviewApproved || rt.ReviewedBy != "secadmin" || rt.ReviewedAt == nil {
		t.Fatalf("审核落账: %+v", rt)
	}
	if rt.RiskLevel != RiskMedium || rt.DataClassification != ClassInternal {
		t.Fatalf("审核定级: %+v", rt)
	}
	var dbHash string
	if err := pool.QueryRow(ctx, `SELECT catalog_hash FROM mcp_tool_catalogs WHERE id=$1`, c.ID).Scan(&dbHash); err != nil {
		t.Fatal(err)
	}
	if want := ComputeCatalogHash([]string{rt.ToolHash}); dbHash != want {
		t.Fatalf("审核后 catalog_hash: %s, want %s", dbHash, want)
	}
	// ③ 发布段 APPROVED-only/DISABLED 排除/catalog_hash 现算断言在
	//    guardconfig/mcp_catalogs_pg_test.go（import 环：guardconfig 已导入本包
	//    的 ComputeCatalogHash，发布段 PG 断言随加载器侧覆盖）。
	// ④ Update 整体再导入：乐观锁冲突 → ErrVersionConflict；
	//    语义相等行（refund 原样）保留 tool_hash+APPROVED 审核态（M02 幂等）；
	//    变更行（query_order 描述变更）重算 tool_hash+重置 PENDING_REVIEW+reviewed_* 清空
	if _, _, err := store.UpdateCatalog(ctx, c.ID, CatalogInput{Name: name, ServiceIdentity: "mcp://pay.example.com", Tools: mkTools("发起退款"), Version: 9}); err != ErrVersionConflict {
		t.Fatalf("乐观锁冲突应 ErrVersionConflict: %v", err)
	}
	// 先审核 query_order 再改描述——旧审批不得继承
	var queryID uuid.UUID
	_, tools, _ = store.GetCatalog(ctx, c.ID)
	for _, tool := range tools {
		if tool.ToolName == "query_order" {
			queryID = tool.ID
		}
	}
	if _, err := store.ReviewTool(ctx, c.ID, queryID, ReviewInput{Action: "APPROVED"}, "secadmin"); err != nil {
		t.Fatal(err)
	}
	c2, tools2, err := store.UpdateCatalog(ctx, c.ID, CatalogInput{
		Name: name, ServiceIdentity: "mcp://pay.example.com", Version: 1,
		Tools: []ToolInput{
			{ToolName: "refund", ToolVersion: "1.0.0", Description: "发起退款", InputSchema: &schema}, // 语义相等
			{ToolName: "query_order", Description: "查询订单v2"},                                      // 描述变更
			{ToolName: "close_order", Description: "关闭订单"},                                        // 新增
		},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if c2.Version != 2 {
		t.Fatalf("版本递增: %d", c2.Version)
	}
	byName := map[string]Tool{}
	for _, tool := range tools2 {
		byName[tool.ToolName] = tool
	}
	if len(tools2) != 3 {
		t.Fatalf("再导入工具行数: %d", len(tools2))
	}
	if byName["refund"].ReviewStatus != ReviewApproved || byName["refund"].ToolHash != rt.ToolHash ||
		byName["refund"].ReviewedBy != "secadmin" {
		t.Fatalf("语义相等行应保留 tool_hash+审核态: %+v", byName["refund"])
	}
	if byName["query_order"].ReviewStatus != ReviewPending || byName["query_order"].ReviewedBy != "" ||
		byName["query_order"].ReviewedAt != nil {
		t.Fatalf("变更行应重置 PENDING_REVIEW: %+v", byName["query_order"])
	}
	newHash, _ := ComputeToolHash("query_order", "", "查询订单v2", nil, nil)
	if byName["query_order"].ToolHash != newHash {
		t.Fatalf("变更行应重算 tool_hash: %s, want %s", byName["query_order"].ToolHash, newHash)
	}
	if byName["close_order"].ReviewStatus != ReviewPending {
		t.Fatalf("新增行应 PENDING_REVIEW: %+v", byName["close_order"])
	}
	// 消失行删除（tools2 无原 3 行之外行——query_order 描述变更非删除；再导入去掉 close_order 验证删除路径）
	_, tools3, err := store.UpdateCatalog(ctx, c.ID, CatalogInput{
		Name: name, ServiceIdentity: "mcp://pay.example.com", Version: 2,
		Tools: []ToolInput{{ToolName: "refund", ToolVersion: "1.0.0", Description: "发起退款", InputSchema: &schema}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(tools3) != 1 || tools3[0].ToolName != "refund" || tools3[0].ReviewStatus != ReviewApproved {
		t.Fatalf("消失行删除+相等行保留: %+v", tools3)
	}
	// ⑤ 绑定 CRUD + 发布段绑定读取
	b, err := store.CreateBinding(ctx, BindingInput{ApplicationID: appID, EndpointPath: "/mcp/pay", CatalogID: c.ID.String()}, "tester")
	if err != nil {
		t.Fatalf("binding create: %v", err)
	}
	if b.Mode != ModeObserve || b.CatalogName != name || b.Version != 1 {
		t.Fatalf("绑定归一（缺省 OBSERVE+catalog_name 回读）: %+v", b)
	}
	if _, err := store.CreateBinding(ctx, BindingInput{ApplicationID: appID, EndpointPath: "/mcp/pay", CatalogID: c.ID.String()}, "tester"); err != ErrBindingDuplicate {
		t.Fatalf("同键应 ErrBindingDuplicate: %v", err)
	}
	if _, err := store.CreateBinding(ctx, BindingInput{ApplicationID: appID, EndpointPath: "/mcp/ghost", CatalogID: uuid.NewString()}, "tester"); err != ErrCatalogNotFound {
		t.Fatalf("目录缺失应 ErrCatalogNotFound: %v", err)
	}
	if _, err := store.CreateBinding(ctx, BindingInput{ApplicationID: uuid.NewString(), EndpointPath: "/mcp/ghost2", CatalogID: c.ID.String()}, "tester"); err != ErrAppNotFound {
		t.Fatalf("应用缺失应 ErrAppNotFound: %v", err)
	}
	if _, err := store.UpdateBinding(ctx, b.ID, BindingInput{CatalogID: c.ID.String(), Mode: "PROTECT", Version: 9}); err != ErrVersionConflict {
		t.Fatalf("绑定乐观锁冲突应 ErrVersionConflict: %v", err)
	}
	b2, err := store.UpdateBinding(ctx, b.ID, BindingInput{CatalogID: c.ID.String(), Mode: "PROTECT", Version: 1})
	if err != nil {
		t.Fatalf("binding update: %v", err)
	}
	if b2.Mode != ModeProtect || b2.Version != 2 {
		t.Fatalf("绑定更新: %+v", b2)
	}
	// 发布段绑定读取（catalog_name JOIN）断言在 guardconfig/mcp_catalogs_pg_test.go。
	// ⑥ 目录删除：引用中 409；解绑后删除；工具行 FK 级联清空
	if err := store.DeleteCatalog(ctx, c.ID); err != ErrCatalogInUse {
		t.Fatalf("引用中删除应 ErrCatalogInUse: %v", err)
	}
	if err := store.DeleteBinding(ctx, b.ID); err != nil {
		t.Fatalf("binding delete: %v", err)
	}
	if err := store.DeleteBinding(ctx, b.ID); err != ErrBindingNotFound {
		t.Fatalf("重复 delete 应 ErrBindingNotFound: %v", err)
	}
	if err := store.DeleteCatalog(ctx, c.ID); err != nil {
		t.Fatalf("catalog delete: %v", err)
	}
	if err := store.DeleteCatalog(ctx, c.ID); err != ErrNotFound {
		t.Fatalf("重复 delete 应 ErrNotFound: %v", err)
	}
	var toolRemain int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM mcp_catalog_tools WHERE catalog_id=$1`, c.ID).Scan(&toolRemain); err != nil {
		t.Fatal(err)
	}
	if toolRemain != 0 {
		t.Fatalf("目录删除应 FK 级联清空工具行: %d", toolRemain)
	}
}
