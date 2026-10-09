// mcp_catalogs_pg_test.go MCP 工具目录发布段 PG 契约（NG-MCP G1 批次 B1，Opt-in
// AUTHZ_TEST_PG_DSN——单元运行不需要活动数据库）：
// ListEnabledMCPCatalogs 只含 ENABLED 目录且工具行只含 APPROVED（PENDING_REVIEW/
// REJECTED 不出现——发布面安全语义锚定）、catalog_hash 发布侧现算与 APPROVED 集一致、
// 全字段下发形状；ListAllMCPBindings 全行稳定序+catalog_name JOIN 带出。
// 数据经 apimcp.Store 真事务构造（审核状态机语义由 apimcp_pg_test.go 覆盖）。
package guardconfig

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/apimcp"
	"github.com/jiuzhang-waf/server/internal/database"
)

func openMCPPublishPG(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping mcp publish segment PG test")
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

func TestMCPCatalogPublishSegmentPostgresContract(t *testing.T) {
	pool, ctx := openMCPPublishPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	code := fmt.Sprintf("mcppub-%d", time.Now().UnixNano())
	var appID string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("pay-mcp-pub-%d", time.Now().UnixNano())
	store := apimcp.NewStore(pool)
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM mcp_tool_catalogs WHERE name=$1`, name)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})

	schema := map[string]any{"type": "object"}
	c, tools, err := store.CreateCatalog(ctx, apimcp.CatalogInput{
		Name: name, ServiceIdentity: "mcp://pay.example.com",
		Tools: []apimcp.ToolInput{
			{ToolName: "refund", ToolVersion: "1.0.0", Description: "发起退款", InputSchema: &schema,
				CapabilityTags: []string{"payment.write"}, AllowedRoles: []string{"finance"}},
			{ToolName: "query_order", Description: "查询订单"},
			{ToolName: "close_order", Description: "关闭订单"},
		},
	}, "tester")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// 审核矩阵：refund APPROVED / close_order REJECTED / query_order 保持 PENDING_REVIEW
	idByName := map[string]uuid.UUID{}
	for _, tool := range tools {
		idByName[tool.ToolName] = tool.ID
	}
	var approvedHash string
	for _, tool := range tools {
		if tool.ToolName == "refund" {
			approvedHash = tool.ToolHash
		}
	}
	if _, err := store.ReviewTool(ctx, c.ID, idByName["refund"], apimcp.ReviewInput{Action: "APPROVED"}, "secadmin"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReviewTool(ctx, c.ID, idByName["close_order"], apimcp.ReviewInput{Action: "REJECTED"}, "secadmin"); err != nil {
		t.Fatal(err)
	}
	b, err := store.CreateBinding(ctx, apimcp.BindingInput{ApplicationID: appID, EndpointPath: "/mcp/pay", CatalogID: c.ID.String(), Mode: "PROTECT"}, "tester")
	if err != nil {
		t.Fatalf("binding create: %v", err)
	}

	// ① 发布段目录：只含 APPROVED 工具行（PENDING/REJECTED 不出现）；catalog_hash
	//    发布侧现算=APPROVED 集摘要；全字段下发形状
	pubStore := NewMCPCatalogStore(pool)
	cats, err := pubStore.ListEnabledMCPCatalogs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := range cats {
		if cats[i].Name != name {
			continue
		}
		found = true
		if len(cats[i].Tools) != 1 || cats[i].Tools[0].ToolName != "refund" {
			names := []string{}
			for _, tool := range cats[i].Tools {
				names = append(names, tool.ToolName+"("+tool.RiskLevel+")")
			}
			t.Fatalf("发布段只应含 APPROVED 工具: %v", names)
		}
		gt := cats[i].Tools[0]
		if gt.ToolHash != approvedHash || gt.ToolVersion != "1.0.0" ||
			gt.RiskLevel != "HIGH" || gt.DataClassification != "UNKNOWN" {
			t.Fatalf("发布段工具行形状: %+v", gt)
		}
		if gt.InputSchema["type"] != "object" || gt.OutputSchema != nil {
			t.Fatalf("schema 下发形状（无 omitempty nil→null 由序列化层保证）: %+v", gt)
		}
		if len(gt.CapabilityTags) != 1 || gt.CapabilityTags[0] != "payment.write" ||
			len(gt.AllowedRoles) != 1 || gt.AllowedRoles[0] != "finance" {
			t.Fatalf("标签/允许集下发: %+v", gt)
		}
		if cats[i].CatalogHash != apimcp.ComputeCatalogHash([]string{approvedHash}) {
			t.Fatalf("发布段 catalog_hash 现算: %s", cats[i].CatalogHash)
		}
		if cats[i].ProtocolVersion != "2025-11-25" || cats[i].ServiceIdentity != "mcp://pay.example.com" {
			t.Fatalf("目录头形状: %+v", cats[i])
		}
	}
	if !found {
		t.Fatal("发布段应含 ENABLED 目录")
	}
	// ② DISABLED 目录不出现
	if _, err := pool.Exec(ctx, `UPDATE mcp_tool_catalogs SET status='DISABLED' WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	cats, err = pubStore.ListEnabledMCPCatalogs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range cats {
		if cats[i].Name == name {
			t.Fatal("DISABLED 目录不得出现在发布段")
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE mcp_tool_catalogs SET status='ENABLED' WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	// ③ 发布段绑定：全行（含 PROTECT 行）+catalog_name JOIN 带出+稳定序
	bindings, err := pubStore.ListAllMCPBindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundB := false
	for _, x := range bindings {
		if x.ApplicationID == appID && x.EndpointPath == "/mcp/pay" {
			foundB = true
			if x.CatalogName != name || x.Mode != "PROTECT" {
				t.Fatalf("发布段绑定行: %+v", x)
			}
		}
	}
	if !foundB {
		t.Fatalf("发布段应含绑定: %+v", bindings)
	}
	// 清理绑定（目录删除 FK 级联同样覆盖，显式解绑保持 t.Cleanup 目录删除路径干净）
	if err := store.DeleteBinding(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
}
