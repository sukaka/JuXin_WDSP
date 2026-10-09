package vulnrefs

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

// openTestDB 在 CNNVD_TEST_PG_DSN 指向的 PostgreSQL 上建一次性库并应用全量迁移
// （同时验证迁移 000167 可应用、可重复执行）。未配置 DSN 时跳过。
func openTestDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("CNNVD_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("CNNVD_TEST_PG_DSN not set, skipping vulnrefs integration test")
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
	dbName := fmt.Sprintf("cnnvd_it_vulnrefs_%d", time.Now().UnixNano())
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
		admin, err := pgxpool.NewWithConfig(ctx, dropCfg(dsn))
		if err == nil {
			_, _ = admin.Exec(ctx, `DROP DATABASE IF EXISTS `+dbName+` WITH (FORCE)`)
			admin.Close()
		}
	})

	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("rerun migrations (idempotency): %v", err)
	}
	return pool, ctx
}

func dropCfg(dsn string) *pgxpool.Config {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil
	}
	return cfg
}

// strPtr 返回字符串指针。
func strPtr(s string) *string { return &s }

// TestMigrationDownRollback 000167 down 完整回滚：权限种子、vuln_refs 表、
// 索引与四列全部移除；回滚后重新 up 可再应用（部署重试口径）。
func TestMigrationDownRollback(t *testing.T) {
	pool, ctx := openTestDB(t)

	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("rollback 000167: %v", err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('vuln_refs') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatalf("check table: %v", err)
	}
	if exists {
		t.Error("vuln_refs should be dropped after rollback")
	}
	for _, col := range []string{"cnnvd_ids", "cve_ids"} {
		for _, table := range []string{"custom_rules", "waf_rules"} {
			if err := pool.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2
			)`, table, col).Scan(&exists); err != nil {
				t.Fatalf("check column: %v", err)
			}
			if exists {
				t.Errorf("%s.%s should be dropped after rollback", table, col)
			}
		}
	}
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM permissions WHERE code = 'waf_rule.vuln_ref.edit')`).Scan(&exists); err != nil {
		t.Fatalf("check permission: %v", err)
	}
	if exists {
		t.Error("permission seed should be removed after rollback")
	}

	// 重新应用后可正常写入
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("re-apply after rollback: %v", err)
	}
	s := NewStore(pool)
	if err := s.Create(ctx, &Ref{CNNVDID: "CNNVD-202401-2345", Title: "回滚后再应用"}); err != nil {
		t.Fatalf("create after re-apply: %v", err)
	}
	// 权限种子就位且授予 SECURITY_ADMIN
	var granted bool
	if err := pool.QueryRow(ctx, `
SELECT EXISTS (
  SELECT 1 FROM role_permissions rp
  JOIN roles r ON r.id = rp.role_id
  JOIN permissions p ON p.id = rp.permission_id
  WHERE r.code = 'SECURITY_ADMIN' AND p.code = 'waf_rule.vuln_ref.edit'
)`).Scan(&granted); err != nil {
		t.Fatalf("check grant: %v", err)
	}
	if !granted {
		t.Error("SECURITY_ADMIN should hold waf_rule.vuln_ref.edit")
	}
	// AUDIT_ADMIN / SYSTEM_ADMIN 不授予写权限点
	var others int
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id
JOIN permissions p ON p.id = rp.permission_id
WHERE p.code = 'waf_rule.vuln_ref.edit' AND r.code <> 'SECURITY_ADMIN'`).Scan(&others); err != nil {
		t.Fatalf("check other grants: %v", err)
	}
	if others != 0 {
		t.Errorf("non-SECURITY_ADMIN grants = %d, want 0", others)
	}
}

// TestStoreCRUD 档案 CRUD：创建/详情/更新/删除 + 重复编号 409 语义 + 缺失 404 语义。
func TestStoreCRUD(t *testing.T) {
	pool, ctx := openTestDB(t)
	s := NewStore(pool)

	ref := &Ref{
		CNNVDID:     "CNNVD-202401-2345",
		CVEID:       "CVE-2024-0001",
		Title:       "Apache Struts2 远程代码执行漏洞",
		Severity:    "高危",
		PublishedAt: strPtr("2024-01-15"),
		URL:         "https://www.cnnvd.org.cn/home/loophole",
	}
	if err := s.Create(ctx, ref); err != nil {
		t.Fatalf("create: %v", err)
	}
	if ref.ID == uuid.Nil {
		t.Fatal("create should assign id")
	}

	got, err := s.GetByCNNVD(ctx, "CNNVD-202401-2345")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.CVEID != "CVE-2024-0001" || got.Title != ref.Title || got.Severity != "高危" {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if got.PublishedAt == nil || *got.PublishedAt != "2024-01-15" {
		t.Errorf("published_at = %v, want 2024-01-15", got.PublishedAt)
	}

	// 重复编号 → ErrConflict（409 语义）
	dup := &Ref{CNNVDID: "CNNVD-202401-2345", Title: "重复"}
	if err := s.Create(ctx, dup); err != ErrConflict {
		t.Errorf("duplicate create err = %v, want ErrConflict", err)
	}

	// 更新（编号不变，其余字段改写；published_at 清空为 NULL）
	got.CVEID = "CVE-2024-0002"
	got.Title = "更新后的规范名称"
	got.PublishedAt = nil
	if err := s.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	got2, err := s.GetByCNNVD(ctx, "CNNVD-202401-2345")
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if got2.CVEID != "CVE-2024-0002" || got2.Title != "更新后的规范名称" || got2.PublishedAt != nil {
		t.Errorf("update not applied: %+v", got2)
	}
	if !got2.UpdatedAt.After(got2.CreatedAt) && !got2.UpdatedAt.Equal(got2.CreatedAt) {
		t.Errorf("updated_at not maintained: %+v", got2)
	}

	// 更新不存在的编号 → ErrNotFound
	if err := s.Update(ctx, &Ref{CNNVDID: "CNNVD-209901-999"}); err != ErrNotFound {
		t.Errorf("update missing err = %v, want ErrNotFound", err)
	}

	// 删除 → 再查 404；重复删除 → ErrNotFound
	if err := s.Delete(ctx, "CNNVD-202401-2345"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetByCNNVD(ctx, "CNNVD-202401-2345"); err != ErrNotFound {
		t.Errorf("get deleted err = %v, want ErrNotFound", err)
	}
	if err := s.Delete(ctx, "CNNVD-202401-2345"); err != ErrNotFound {
		t.Errorf("delete again err = %v, want ErrNotFound", err)
	}
}

// TestListKeywordAndPagination 列表：keyword 模糊匹配编号/名称，分页计数正确。
func TestListKeywordAndPagination(t *testing.T) {
	pool, ctx := openTestDB(t)
	s := NewStore(pool)
	for i, id := range []string{"CNNVD-202401-0001", "CNNVD-202401-0002", "CNNVD-202402-0003"} {
		ref := &Ref{CNNVDID: id, Title: fmt.Sprintf("测试漏洞%d", i), Severity: "中危"}
		if i == 2 {
			ref.CVEID = "CVE-2024-7777"
		}
		if err := s.Create(ctx, ref); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	items, total, err := s.List(ctx, "", 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("list total=%d len=%d, want 3/3", total, len(items))
	}
	if !strings.HasPrefix(items[0].CNNVDID, "CNNVD-202401") {
		t.Errorf("order should be cnnvd_id asc: %v", items[0].CNNVDID)
	}
	// 无任何规则/事件时计数为零
	for _, it := range items {
		if it.RuleCount != 0 || it.EventCount30d != 0 {
			t.Errorf("empty cross counts should be 0: %+v", it)
		}
	}

	items, total, err = s.List(ctx, "CVE-2024-7777", 1, 20)
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("keyword by cve_id: total=%d err=%v", total, err)
	}
	if items[0].CNNVDID != "CNNVD-202402-0003" {
		t.Errorf("keyword hit wrong item: %+v", items[0])
	}

	items, total, err = s.List(ctx, "测试漏洞", 1, 2)
	if err != nil || total != 3 || len(items) != 2 {
		t.Errorf("pagination: total=%d len=%d err=%v, want 3/2", total, len(items), err)
	}
}

// TestCrossCountsAndDetail 交叉口径：rule_count=携带编号规则数（自定义 + 目录去重）；
// event_count_30d=近 30 天去重事件数；sample_events 为最近 ≤5 条。
func TestCrossCountsAndDetail(t *testing.T) {
	pool, ctx := openTestDB(t)
	s := NewStore(pool)

	ref := &Ref{CNNVDID: "CNNVD-202401-2345", CVEID: "CVE-2024-0001", Title: "交叉查询测试漏洞"}
	if err := s.Create(ctx, ref); err != nil {
		t.Fatalf("create ref: %v", err)
	}

	// 规则面：1 条自定义规则标注 CNNVD；1 条 CRS 目录规则（两个 crs_version 行，应去重）标注 CVE
	if _, err := pool.Exec(ctx, `
INSERT INTO custom_rules (rule_id, name, description, status, cnnvd_ids, cve_ids)
VALUES (7100991, '虚拟补丁-Struts2', '拦截 CVE-2024-0001 利用', 'ENABLED', '["CNNVD-202401-2345"]', '["CVE-2024-0001"]')`); err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}
	for _, ver := range []string{"4.0.0", "4.1.0"} {
		if _, err := pool.Exec(ctx, `
INSERT INTO waf_rules (rule_id, rule_source, name, message, default_state, crs_version, cnnvd_ids, cve_ids)
VALUES (942990, 'OWASP_CRS', 'CRS 规则', '目录消息', 'ENABLED', $1, '[]', '["CVE-2024-0001"]')`, ver); err != nil {
			t.Fatalf("seed waf_rules %s: %v", ver, err)
		}
	}

	now := time.Now()
	// 事件面：e1 近 30 天命中自定义规则；e2 近 30 天命中目录规则；e3 40 天前（不计入）
	seedEvent := func(requestID string, occurredAt time.Time, ruleID int, ruleSource string) uuid.UUID {
		var eventID uuid.UUID
		err := pool.QueryRow(ctx, `
INSERT INTO security_events (request_id, occurred_at, client_ip, request_method, request_uri, request_path,
  attack_type, severity, action)
VALUES ($1, $2, '203.0.113.9', 'GET', '/struts2/xxe', '/struts2/xxe', 'RCE', 'HIGH', 'BLOCK')
RETURNING id`, requestID, occurredAt).Scan(&eventID)
		if err != nil {
			t.Fatalf("seed event %s: %v", requestID, err)
		}
		if _, err := pool.Exec(ctx, `
INSERT INTO security_event_matches (event_id, event_occurred_at, rule_id, rule_name, rule_source)
VALUES ($1, $2, $3, '命中规则', $4)`, eventID, occurredAt, ruleID, ruleSource); err != nil {
			t.Fatalf("seed match %s: %v", requestID, err)
		}
		return eventID
	}
	e1 := seedEvent("req-1", now.Add(-24*time.Hour), 7100991, "USER_CUSTOM")
	seedEvent("req-2", now.Add(-48*time.Hour), 942990, "OWASP_CRS")
	seedEvent("req-3", now.Add(-40*24*time.Hour), 7100991, "USER_CUSTOM")

	// 列表交叉计数
	items, total, err := s.List(ctx, "CNNVD-202401-2345", 1, 20)
	if err != nil || total != 1 {
		t.Fatalf("list: total=%d err=%v", total, err)
	}
	if items[0].RuleCount != 2 {
		t.Errorf("rule_count = %d, want 2（自定义1 + 目录按 rule_id 去重1）", items[0].RuleCount)
	}
	if items[0].EventCount30d != 2 {
		t.Errorf("event_count_30d = %d, want 2（40 天前事件不计入）", items[0].EventCount30d)
	}

	// 详情交叉查询
	d, err := s.Detail(ctx, "CNNVD-202401-2345")
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if d.Item.RuleCount != 2 || d.EventCount30d != 2 {
		t.Errorf("detail counts: rule=%d event=%d, want 2/2", d.Item.RuleCount, d.EventCount30d)
	}
	if len(d.Rules) != 2 {
		t.Fatalf("rules len = %d, want 2", len(d.Rules))
	}
	var custom, catalog *RuleRef
	for i := range d.Rules {
		switch d.Rules[i].RuleSource {
		case "USER_CUSTOM":
			custom = &d.Rules[i]
		case "OWASP_CRS":
			catalog = &d.Rules[i]
		}
	}
	if custom == nil || catalog == nil {
		t.Fatalf("rules missing sources: %+v", d.Rules)
	}
	if custom.RuleID != 7100991 || !custom.Enabled || custom.RuleName != "虚拟补丁-Struts2" {
		t.Errorf("custom rule projection wrong: %+v", custom)
	}
	if catalog.RuleID != 942990 || catalog.Description != "目录消息" {
		t.Errorf("catalog rule projection wrong: %+v", catalog)
	}

	if len(d.SampleEvents) != 2 {
		t.Fatalf("sample_events len = %d, want 2", len(d.SampleEvents))
	}
	if d.SampleEvents[0].ID != e1 {
		t.Errorf("sample events should order by occurred_at desc (latest first): %+v", d.SampleEvents[0])
	}
	se := d.SampleEvents[0]
	if se.AttackType != "RCE" || se.ClientIP != "203.0.113.9" || se.Path != "/struts2/xxe" || se.Action != "BLOCK" {
		t.Errorf("sample event projection wrong: %+v", se)
	}

	// 未标注任何规则的档案：计数为零、样例为空数组
	ref2 := &Ref{CNNVDID: "CNNVD-202403-0009", Title: "无关联档案"}
	if err := s.Create(ctx, ref2); err != nil {
		t.Fatalf("create ref2: %v", err)
	}
	d2, err := s.Detail(ctx, "CNNVD-202403-0009")
	if err != nil {
		t.Fatalf("detail ref2: %v", err)
	}
	if d2.EventCount30d != 0 || len(d2.Rules) != 0 || len(d2.SampleEvents) != 0 {
		t.Errorf("unrelated ref should have zero counts: %+v", d2)
	}
	if d2.Rules == nil || d2.SampleEvents == nil {
		t.Error("empty collections must be [] not nil（JSON 契约）")
	}
}
