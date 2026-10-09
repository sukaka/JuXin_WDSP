package customrules

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

// openTestDB 在 CNNVD_TEST_PG_DSN 指向的 PostgreSQL 上建一次性库并应用全量迁移；
// 未配置 DSN 时跳过（本地单测不依赖数据库）。
func openTestDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("CNNVD_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("CNNVD_TEST_PG_DSN not set, skipping customrules integration test")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect admin db: %v", err)
	}
	dbName := fmt.Sprintf("cnnvd_it_customrules_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+dbName); err != nil {
		admin.Close()
		t.Fatalf("create test db: %v", err)
	}
	admin.Close()

	cfg.ConnConfig.Database = dbName
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		if admin, err := pgxpool.New(ctx, dsn); err == nil {
			_, _ = admin.Exec(ctx, `DROP DATABASE IF EXISTS `+dbName+` WITH (FORCE)`)
			admin.Close()
		}
	})
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return pool, ctx
}

// TestStoreVulnIDsReadWrite CNNVD 兼容性 P1：编号字段随创建/更新落库，读回 [] 非 null。
func TestStoreVulnIDsReadWrite(t *testing.T) {
	pool, ctx := openTestDB(t)
	s := NewStore(pool)
	creator := uuid.New()

	r := validRule()
	r.RuleID = 7100801
	r.CNNVDIDs = []string{"cnnvd-202401-2345", "CNNVD-202401-2345"} // 小写+重复：落库须归一去重
	r.CVEIDs = []string{"cve-2024-0001"}
	if err := s.Create(ctx, r, creator); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetByID(ctx, r.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.CNNVDIDs) != 1 || got.CNNVDIDs[0] != "CNNVD-202401-2345" {
		t.Errorf("cnnvd_ids round trip wrong: %v", got.CNNVDIDs)
	}
	if len(got.CVEIDs) != 1 || got.CVEIDs[0] != "CVE-2024-0001" {
		t.Errorf("cve_ids round trip wrong: %v", got.CVEIDs)
	}

	// 未标注规则读回空数组（契约：[] 非 null）
	r2 := validRule()
	r2.RuleID = 7100802
	if err := s.Create(ctx, r2, creator); err != nil {
		t.Fatalf("create plain: %v", err)
	}
	got2, err := s.GetByID(ctx, r2.ID)
	if err != nil {
		t.Fatalf("get plain: %v", err)
	}
	if got2.CNNVDIDs == nil || got2.CVEIDs == nil || len(got2.CNNVDIDs) != 0 || len(got2.CVEIDs) != 0 {
		t.Errorf("plain rule ids must be empty slices: %+v", got2)
	}

	// 更新改写编号
	got.CNNVDIDs = []string{"CNNVD-202402-0007"}
	got.CVEIDs = []string{}
	if err := s.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	got3, err := s.GetByID(ctx, r.ID)
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if len(got3.CNNVDIDs) != 1 || got3.CNNVDIDs[0] != "CNNVD-202402-0007" || len(got3.CVEIDs) != 0 {
		t.Errorf("update ids wrong: %+v", got3)
	}

	// 非法编号拒绝落库
	bad := validRule()
	bad.RuleID = 7100803
	bad.CNNVDIDs = []string{"CNNVD-2024-1"}
	if err := s.Create(ctx, bad, creator); err == nil {
		t.Error("invalid cnnvd id should be rejected at create")
	}
}

// TestStoreListVulnIDFilter 列表按编号精确反查（JSONB 包含匹配）；空参数不过滤。
func TestStoreListVulnIDFilter(t *testing.T) {
	pool, ctx := openTestDB(t)
	s := NewStore(pool)
	creator := uuid.New()

	seed := func(ruleID int, cnnvd, cve []string) {
		r := validRule()
		r.RuleID = ruleID
		r.CNNVDIDs = cnnvd
		r.CVEIDs = cve
		if err := s.Create(ctx, r, creator); err != nil {
			t.Fatalf("seed %d: %v", ruleID, err)
		}
	}
	seed(7100811, []string{"CNNVD-202401-2345"}, []string{"CVE-2024-0001"})
	seed(7100812, []string{"CNNVD-202401-2345"}, nil)
	seed(7100813, nil, []string{"CVE-2024-0001"})

	// cnnvd_id 精确反查：命中 811/812
	list, total, err := s.List(ctx, "", "", "CNNVD-202401-2345", "", 1, 20)
	if err != nil || total != 2 {
		t.Fatalf("cnnvd filter: total=%d err=%v, want 2", total, err)
	}
	for _, r := range list {
		if r.RuleID == 7100813 {
			t.Errorf("rule 7100813 must not match cnnvd filter: %+v", r)
		}
	}
	// cve_id 精确反查：命中 811/813
	_, total, err = s.List(ctx, "", "", "", "CVE-2024-0001", 1, 20)
	if err != nil || total != 2 {
		t.Errorf("cve filter: total=%d err=%v, want 2", total, err)
	}
	// 双条件叠加：仅 811
	list, total, err = s.List(ctx, "", "", "CNNVD-202401-2345", "CVE-2024-0001", 1, 20)
	if err != nil || total != 1 || list[0].RuleID != 7100811 {
		t.Errorf("combined filter: total=%d err=%v, want 1 (7100811)", total, err)
	}
	// 无命中编号
	_, total, err = s.List(ctx, "", "", "CNNVD-209901-999", "", 1, 20)
	if err != nil || total != 0 {
		t.Errorf("no-match filter: total=%d err=%v, want 0", total, err)
	}
	// 空编号不过滤
	_, total, err = s.List(ctx, "", "", "", "", 1, 20)
	if err != nil || total != 3 {
		t.Errorf("no filter: total=%d err=%v, want 3", total, err)
	}
}
