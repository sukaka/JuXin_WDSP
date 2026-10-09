package securityevents

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

// openVulnTestDB 在 CNNVD_TEST_PG_DSN 指向的 PostgreSQL 上建一次性库并应用全量迁移；
// 未配置 DSN 时跳过。
func openVulnTestDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("CNNVD_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("CNNVD_TEST_PG_DSN not set, skipping securityevents integration test")
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
	dbName := fmt.Sprintf("cnnvd_it_secevents_%d", time.Now().UnixNano())
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

// seedVulnEvent 落一条带匹配记录的事件。
func seedVulnEvent(t *testing.T, ctx context.Context, s *Store, requestID string, matches []MatchInfo) {
	t.Helper()
	evt := &NormalizedEvent{
		RequestID:  requestID,
		OccurredAt: time.Now(),
		ClientIP:   "198.51.100.7",
		Method:     "GET",
		URI:        "/x?a=1",
		Path:       "/x",
		AttackType: "SQL_INJECTION",
		Severity:   "HIGH",
		Action:     "BLOCK",
		Matches:    matches,
	}
	if _, _, err := s.InsertEvent(ctx, evt); err != nil {
		t.Fatalf("insert event: %v", err)
	}
}

// TestAttachVulnIDs 事件详情 matches 编号联查：自定义规则与 CRS 目录两种来源取现值；
// 规则删除/未知规则静默降级为空数组。
func TestAttachVulnIDs(t *testing.T) {
	pool, ctx := openVulnTestDB(t)
	s := NewStore(pool)

	// 规则面：自定义规则 7100901 带编号；CRS 目录 942991 两个版本行（取最新）；
	// 942992 无编号（空数组）
	if _, err := pool.Exec(ctx, `
INSERT INTO custom_rules (rule_id, name, status, cnnvd_ids, cve_ids)
VALUES (7100901, '带编号自定义规则', 'ENABLED', '["CNNVD-202401-2345"]', '["CVE-2024-0001"]')`); err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO waf_rules (rule_id, rule_source, name, crs_version, cnnvd_ids, cve_ids) VALUES
(942991, 'OWASP_CRS', '旧版本', '4.0.0', '[]', '[]'),
(942991, 'OWASP_CRS', '新版本', '4.1.0', '["CNNVD-202402-0007"]', '[]'),
(942992, 'OWASP_CRS', '无编号', '4.1.0', '[]', '[]')`); err != nil {
		t.Fatalf("seed waf_rules: %v", err)
	}

	seedVulnEvent(t, ctx, s, "req-vuln-1", []MatchInfo{
		{RuleID: 7100901, RuleName: "带编号自定义规则", RuleSource: "USER_CUSTOM"},
		{RuleID: 942991, RuleName: "CRS 规则", RuleSource: "OWASP_CRS"},
		{RuleID: 942992, RuleName: "无编号 CRS 规则", RuleSource: "OWASP_CRS"},
		{RuleID: 999999, RuleName: "未知规则", RuleSource: "OWASP_CRS"},
	})

	var eventID string
	if err := pool.QueryRow(ctx, `SELECT id FROM security_events WHERE request_id = 'req-vuln-1'`).Scan(&eventID); err != nil {
		t.Fatalf("find event: %v", err)
	}
	_, matches, err := s.GetByID(ctx, mustUUID(t, eventID))
	if err != nil {
		t.Fatalf("get event: %v", err)
	}
	if len(matches) != 4 {
		t.Fatalf("matches len = %d, want 4", len(matches))
	}
	if err := s.AttachVulnIDs(ctx, matches); err != nil {
		t.Fatalf("attach: %v", err)
	}

	assertIDs := func(ruleID int, wantCNNVD, wantCVE []string) {
		t.Helper()
		var m *MatchInfo
		for i := range matches {
			if matches[i].RuleID == ruleID {
				m = &matches[i]
			}
		}
		if m == nil {
			t.Fatalf("match %d missing", ruleID)
		}
		if fmt.Sprint(m.CNNVDIDs) != fmt.Sprint(wantCNNVD) || fmt.Sprint(m.CVEIDs) != fmt.Sprint(wantCVE) {
			t.Errorf("rule %d: got cnnvd=%v cve=%v, want %v/%v", ruleID, m.CNNVDIDs, m.CVEIDs, wantCNNVD, wantCVE)
		}
	}
	assertIDs(7100901, []string{"CNNVD-202401-2345"}, []string{"CVE-2024-0001"})
	assertIDs(942991, []string{"CNNVD-202402-0007"}, []string{}) // 最新 crs_version 行现值
	assertIDs(942992, []string{}, []string{})
	assertIDs(999999, []string{}, []string{}) // 未知规则降级空数组

	// 规则删除后联查降级为空数组（取现值口径，不阻塞详情）
	if _, err := pool.Exec(ctx, `DELETE FROM custom_rules WHERE rule_id = 7100901`); err != nil {
		t.Fatalf("delete custom rule: %v", err)
	}
	if err := s.AttachVulnIDs(ctx, matches); err != nil {
		t.Fatalf("attach after delete: %v", err)
	}
	for _, m := range matches {
		if m.RuleID == 7100901 && (len(m.CNNVDIDs) != 0 || len(m.CVEIDs) != 0) {
			t.Errorf("deleted rule should degrade to empty ids: %+v", m)
		}
	}
}

// TestGetByIDMatchIDsDefault 联查未执行时编号字段缺省为空数组（JSON 契约 [] 非 null）。
func TestGetByIDMatchIDsDefault(t *testing.T) {
	pool, ctx := openVulnTestDB(t)
	s := NewStore(pool)
	seedVulnEvent(t, ctx, s, "req-vuln-2", []MatchInfo{
		{RuleID: 942100, RuleName: "CRS 规则", RuleSource: "OWASP_CRS"},
	})
	var eventID string
	if err := pool.QueryRow(ctx, `SELECT id FROM security_events WHERE request_id = 'req-vuln-2'`).Scan(&eventID); err != nil {
		t.Fatalf("find event: %v", err)
	}
	_, matches, err := s.GetByID(ctx, mustUUID(t, eventID))
	if err != nil {
		t.Fatalf("get event: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches len = %d, want 1", len(matches))
	}
	if matches[0].CNNVDIDs == nil || matches[0].CVEIDs == nil {
		t.Error("cnnvd_ids/cve_ids must default to empty slices")
	}
}

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parse uuid %q: %v", s, err)
	}
	return id
}
