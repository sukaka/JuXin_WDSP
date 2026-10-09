package threatintel

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/database"
)

// openTestDB 在 THREATINTEL_TEST_PG_DSN 指向的 PostgreSQL 上建一次性库并应用
// 全量迁移（与服务层真实依赖同构）。未配置 DSN 时跳过。
func openTestDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("THREATINTEL_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("THREATINTEL_TEST_PG_DSN not set, skipping threatintel service integration test")
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
	dbName := fmt.Sprintf("threatintel_it_%d", time.Now().UnixNano())
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
		admin, err := pgxpool.NewWithConfig(ctx, mustDropCfg(t, dsn))
		if err == nil {
			_, _ = admin.Exec(ctx, `DROP DATABASE IF EXISTS `+dbName+` WITH (FORCE)`)
			admin.Close()
		}
	})

	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return pool, ctx
}

func mustDropCfg(t *testing.T, dsn string) *pgxpool.Config {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn for drop: %v", err)
	}
	return cfg
}

// ruleRow 是断言用的规则行投影。
type ruleRow struct {
	Status       string
	ValidityType string
	Until        *time.Time
	Reason       string
	SourceType   string
	ScopeType    string
	RuleType     string
}

func getRule(t *testing.T, ctx context.Context, db *pgxpool.Pool, address string) *ruleRow {
	t.Helper()
	var r ruleRow
	err := db.QueryRow(ctx, `
SELECT status, validity_type, effective_until, reason, source_type, scope_type, rule_type
FROM ip_access_rules WHERE deleted_at IS NULL AND address = $1 AND scope_type = 'GLOBAL' AND rule_type = 'DENY'`,
		address).Scan(&r.Status, &r.ValidityType, &r.Until, &r.Reason, &r.SourceType, &r.ScopeType, &r.RuleType)
	if err != nil {
		return nil
	}
	return &r
}

func insertManualDeny(t *testing.T, ctx context.Context, db *pgxpool.Pool, address, sourceType, reason string) {
	t.Helper()
	_, err := db.Exec(ctx, `
INSERT INTO ip_access_rules (name, rule_type, scope_type, application_id, address, ip_version,
  priority, status, validity_type, reason, source_type, created_by, updated_by)
VALUES ($1,'DENY','GLOBAL',NULL,$1,'IPV4',100,'ACTIVE','PERMANENT',$2,$3,$4,$4)`,
		address, reason, sourceType, uuid.New())
	if err != nil {
		t.Fatalf("insert manual deny %s: %v", address, err)
	}
}

func entries(ips ...string) []Entry {
	out := make([]Entry, 0, len(ips))
	for i, ip := range ips {
		out = append(out, Entry{IP: ip, Line: i + 1})
	}
	return out
}

func TestThreatIntelImport_FirstBatch(t *testing.T) {
	db, ctx := openTestDB(t)
	svc := NewService(db, nil)
	op := uuid.New()

	res, err := svc.Import(ctx, ImportInput{
		Feed: "feodo", TTLDays: 30, Operator: op,
		Entries: []Entry{
			{IP: "192.0.2.10", Family: "Emotet", Line: 1},
			{IP: "198.51.100.20", Family: "QakBot", Line: 2},
			{IP: "203.0.113.30", Line: 3},
		},
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.Added != 3 || res.Refreshed != 0 || res.Expired != 0 || res.SkippedConflict != 0 {
		t.Fatalf("counters wrong: %+v", res)
	}
	if res.BatchID == "" {
		t.Fatal("batch id empty")
	}
	before := time.Now().Add(-time.Minute)
	for _, tc := range []struct{ ip, fam string }{
		{"192.0.2.10", "Emotet"}, {"198.51.100.20", "QakBot"}, {"203.0.113.30", "c2"},
	} {
		r := getRule(t, ctx, db, tc.ip)
		if r == nil {
			t.Fatalf("rule %s not found", tc.ip)
		}
		if r.Status != "ACTIVE" || r.ValidityType != "TEMPORARY" || r.SourceType != "IMPORT" ||
			r.ScopeType != "GLOBAL" || r.RuleType != "DENY" {
			t.Errorf("rule %s shape wrong: %+v", tc.ip, r)
		}
		if r.Until == nil || r.Until.Before(before.Add(29*24*time.Hour)) || r.Until.After(time.Now().Add(31*24*time.Hour)) {
			t.Errorf("rule %s effective_until out of ~30d window: %v", tc.ip, r.Until)
		}
		if !strings.HasPrefix(r.Reason, "威胁情报 feodo 批次"+res.BatchID) {
			t.Errorf("rule %s reason prefix wrong: %q", tc.ip, r.Reason)
		}
		if !strings.Contains(r.Reason, "（"+tc.fam+"）") {
			t.Errorf("rule %s reason family wrong: %q", tc.ip, r.Reason)
		}
	}
}

func TestThreatIntelImport_Reconcile(t *testing.T) {
	db, ctx := openTestDB(t)
	svc := NewService(db, nil)
	op := uuid.New()

	first, err := svc.Import(ctx, ImportInput{
		Feed: "feodo", TTLDays: 30, Operator: op,
		Entries: []Entry{
			{IP: "192.0.2.10", Family: "Emotet"},
			{IP: "192.0.2.11", Family: "Emotet"},
		},
	})
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	if first.Added != 2 {
		t.Fatalf("first added=%d, want 2", first.Added)
	}

	// 二次导入：.10 仍在册（refreshed）、.11 消失（expired）、.12 新增（added）
	second, err := svc.Import(ctx, ImportInput{
		Feed: "feodo", TTLDays: 30, Operator: op,
		Entries: []Entry{
			{IP: "192.0.2.10", Family: "Emotet"},
			{IP: "192.0.2.12", Family: "QakBot"},
		},
	})
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if second.Added != 1 || second.Refreshed != 1 || second.Expired != 1 || second.SkippedConflict != 0 {
		t.Fatalf("second counters wrong: %+v", second)
	}

	r10 := getRule(t, ctx, db, "192.0.2.10")
	if r10 == nil || r10.Status != "ACTIVE" {
		t.Fatalf(".10 should stay ACTIVE: %+v", r10)
	}
	if !strings.Contains(r10.Reason, second.BatchID) {
		t.Errorf(".10 reason not updated to new batch: %q", r10.Reason)
	}
	r11 := getRule(t, ctx, db, "192.0.2.11")
	if r11 == nil || r11.Status != "EXPIRED" {
		t.Fatalf(".11 should be EXPIRED (保留历史): %+v", r11)
	}
	r12 := getRule(t, ctx, db, "192.0.2.12")
	if r12 == nil || r12.Status != "ACTIVE" || !strings.Contains(r12.Reason, "QakBot") {
		t.Fatalf(".12 should be added ACTIVE: %+v", r12)
	}

	// 三次导入：.11 复活（EXPIRED → ACTIVE）
	third, err := svc.Import(ctx, ImportInput{
		Feed: "feodo", TTLDays: 30, Operator: op,
		Entries: entries("192.0.2.10", "192.0.2.11", "192.0.2.12"),
	})
	if err != nil {
		t.Fatalf("third import: %v", err)
	}
	if third.Refreshed != 3 || third.Added != 0 || third.Expired != 0 {
		t.Fatalf("third counters wrong (复活走 refreshed): %+v", third)
	}
	if r := getRule(t, ctx, db, "192.0.2.11"); r == nil || r.Status != "ACTIVE" {
		t.Fatalf(".11 should be re-activated: %+v", r)
	}

	// 空集对账清空：全部 EXPIRED，规则行保留
	fourth, err := svc.Import(ctx, ImportInput{Feed: "feodo", TTLDays: 30, Operator: op, Entries: nil})
	if err != nil {
		t.Fatalf("fourth import: %v", err)
	}
	if fourth.Expired != 3 || fourth.Added != 0 || fourth.Refreshed != 0 {
		t.Fatalf("fourth counters wrong: %+v", fourth)
	}
	for _, ip := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} {
		if r := getRule(t, ctx, db, ip); r == nil || r.Status != "EXPIRED" {
			t.Errorf("%s should be EXPIRED after empty reconcile: %+v", ip, r)
		}
	}
}

func TestThreatIntelImport_ConflictManualDeny(t *testing.T) {
	db, ctx := openTestDB(t)
	svc := NewService(db, nil)
	op := uuid.New()

	// 预置：MANUAL GLOBAL DENY ACTIVE 同址
	insertManualDeny(t, ctx, db, "192.0.2.66", "MANUAL", "人工封禁")

	res, err := svc.Import(ctx, ImportInput{
		Feed: "feodo", TTLDays: 30, Operator: op,
		Entries: entries("192.0.2.66", "192.0.2.67"),
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.Added != 1 || res.SkippedConflict != 1 {
		t.Fatalf("counters wrong: %+v", res)
	}
	if len(res.Conflicts) != 1 || res.Conflicts[0].Address != "192.0.2.66" {
		t.Fatalf("conflict detail wrong: %+v", res.Conflicts)
	}
	// MANUAL 行不被触碰
	r := getRule(t, ctx, db, "192.0.2.66")
	if r == nil || r.SourceType != "MANUAL" || r.Reason != "人工封禁" || r.ValidityType != "PERMANENT" {
		t.Fatalf("manual rule must stay untouched: %+v", r)
	}
}

func TestThreatIntelImport_NeverTouchOtherSources(t *testing.T) {
	db, ctx := openTestDB(t)
	svc := NewService(db, nil)
	op := uuid.New()

	// 预置各类非本功能行（同 feed 批次外）：都不在对账集合内，绝不能被 EXPIRED/刷新
	insertManualDeny(t, ctx, db, "192.0.2.1", "MANUAL", "人工封禁")
	insertManualDeny(t, ctx, db, "192.0.2.2", "SECURITY_EVENT", "安全事件联动封禁")
	insertManualDeny(t, ctx, db, "192.0.2.3", "AUTO_BLOCK", "CC 自动封禁")
	insertManualDeny(t, ctx, db, "192.0.2.4", "IMPORT", "批量导入")               // 其他前缀 IMPORT
	insertManualDeny(t, ctx, db, "192.0.2.5", "IMPORT", "威胁情报 otherfeed 批次x") // 其他 feed

	res, err := svc.Import(ctx, ImportInput{
		Feed: "feodo", TTLDays: 30, Operator: op, Entries: entries("192.0.2.10"),
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.Expired != 0 {
		t.Fatalf("must not expire foreign rows: %+v", res)
	}
	for ip, want := range map[string]string{
		"192.0.2.1": "人工封禁", "192.0.2.2": "安全事件联动封禁", "192.0.2.3": "CC 自动封禁",
		"192.0.2.4": "批量导入", "192.0.2.5": "威胁情报 otherfeed 批次x",
	} {
		r := getRule(t, ctx, db, ip)
		if r == nil || r.Status != "ACTIVE" || r.Reason != want {
			t.Errorf("foreign rule %s touched: %+v", ip, r)
		}
	}
}

func TestThreatIntelImport_PermanentTTL(t *testing.T) {
	db, ctx := openTestDB(t)
	svc := NewService(db, nil)
	op := uuid.New()

	res, err := svc.Import(ctx, ImportInput{
		Feed: "feodo", TTLDays: 0, Operator: op, Entries: entries("192.0.2.10"),
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.Added != 1 {
		t.Fatalf("added=%d, want 1", res.Added)
	}
	r := getRule(t, ctx, db, "192.0.2.10")
	if r == nil || r.ValidityType != "PERMANENT" || r.Until != nil {
		t.Fatalf("TTL=0 should create PERMANENT rule: %+v", r)
	}

	// TTL=0 批次重导带 TTL>0：有效期按新 TTL 重算为 TEMPORARY
	res2, err := svc.Import(ctx, ImportInput{
		Feed: "feodo", TTLDays: 7, Operator: op, Entries: entries("192.0.2.10"),
	})
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if res2.Refreshed != 1 {
		t.Fatalf("refreshed=%d, want 1", res2.Refreshed)
	}
	r = getRule(t, ctx, db, "192.0.2.10")
	if r == nil || r.ValidityType != "TEMPORARY" || r.Until == nil {
		t.Fatalf("TTL 切换应按本批重算: %+v", r)
	}
}

func TestThreatIntelImport_DisabledRulePreserved(t *testing.T) {
	db, ctx := openTestDB(t)
	svc := NewService(db, nil)
	op := uuid.New()

	if _, err := svc.Import(ctx, ImportInput{
		Feed: "feodo", TTLDays: 30, Operator: op, Entries: entries("192.0.2.10", "192.0.2.11"),
	}); err != nil {
		t.Fatalf("first import: %v", err)
	}
	// 人工停用 .10（模拟管理员处置）
	if _, err := db.Exec(ctx,
		`UPDATE ip_access_rules SET status='DISABLED' WHERE address='192.0.2.10'`); err != nil {
		t.Fatalf("disable: %v", err)
	}
	// 二次导入：.10 在批（人工停用→跳过）、.11 消失但非 ACTIVE（DISABLED 不动？.11 是 ACTIVE→EXPIRED）
	res, err := svc.Import(ctx, ImportInput{
		Feed: "feodo", TTLDays: 30, Operator: op, Entries: entries("192.0.2.10"),
	})
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if res.SkippedConflict != 1 || res.Refreshed != 0 {
		t.Fatalf("disabled in-batch must be skipped not refreshed: %+v", res)
	}
	if r := getRule(t, ctx, db, "192.0.2.10"); r == nil || r.Status != "DISABLED" {
		t.Fatalf("人工停用行不得复活: %+v", r)
	}
	if r := getRule(t, ctx, db, "192.0.2.11"); r == nil || r.Status != "EXPIRED" {
		t.Fatalf("消失的 ACTIVE 行应 EXPIRED: %+v", r)
	}
}

func TestThreatIntelImport_Validation(t *testing.T) {
	db, ctx := openTestDB(t)
	svc := NewService(db, nil)

	if _, err := svc.Import(ctx, ImportInput{Feed: "bad feed!", Entries: nil}); err == nil {
		t.Fatal("want feed validation error")
	}
	if _, err := svc.Import(ctx, ImportInput{Feed: "feodo", TTLDays: -1}); err == nil {
		t.Fatal("want ttl validation error")
	}
	if _, err := svc.Import(ctx, ImportInput{Feed: "feodo", TTLDays: MaxTTLDays + 1}); err == nil {
		t.Fatal("want ttl cap error")
	}
	// feed 缺省归一
	in := ImportInput{Feed: " FEODO ", TTLDays: 30, Operator: uuid.New()}
	if err := ValidateInput(&in); err != nil {
		t.Fatalf("ValidateInput: %v", err)
	}
	if in.Feed != "feodo" {
		t.Fatalf("feed normalize wrong: %q", in.Feed)
	}
}

func TestThreatIntelImport_ReasonPrefixIsolation(t *testing.T) {
	db, ctx := openTestDB(t)
	svc := NewService(db, nil)
	op := uuid.New()

	// feed 含下划线：LIKE 转义必须生效（"feodo_x" 不应匹配 "feodoAx" 之类）
	if _, err := svc.Import(ctx, ImportInput{
		Feed: "feodo_eu", TTLDays: 30, Operator: op, Entries: entries("192.0.2.10"),
	}); err != nil {
		t.Fatalf("import feodo_eu: %v", err)
	}
	// 另一 feed 的对账不得触碰 feodo_eu 的行
	res, err := svc.Import(ctx, ImportInput{
		Feed: "feodo", TTLDays: 30, Operator: op, Entries: nil,
	})
	if err != nil {
		t.Fatalf("import feodo empty: %v", err)
	}
	if res.Expired != 0 {
		t.Fatalf("feed 隔离失败: %+v", res)
	}
	if r := getRule(t, ctx, db, "192.0.2.10"); r == nil || r.Status != "ACTIVE" {
		t.Fatalf("feodo_eu 行被误触: %+v", r)
	}
}

// 编译期接口一致性：accessrules 常量复用（防漂移）。
var _ = accessrules.RuleTypeDeny
