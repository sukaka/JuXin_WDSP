package vulnintel

// store_pg_test.go 漏洞情报 PG 契约（VULN_INTEL MVP，Opt-in AUTHZ_TEST_PG_DSN——
// 单元运行不需要活动数据库）：迁移 000189 up 后 upsert 幂等/isNew 判定、分页过滤、
// overview、应用技术栈整组替换与级联、vuln_alerted 唯一键去重、sync_state 覆盖写、
// tech_name CHECK（大写/超长拒收）、FK 级联（删应用级联映射、删情报级联提醒记录）。

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

func openVulnIntelPG(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping vuln intel PG test")
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

func mkVulnApp(t *testing.T, pool *pgxpool.Pool, ctx context.Context, prefix string) uuid.UUID {
	t.Helper()
	code := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func pgAdvisory(cve string, sev string, published time.Time) *Advisory {
	score := 7.5
	return &Advisory{
		CVEID:          cve,
		Title:          cve + " title",
		Summary:        "PHP remote code execution in test fixture",
		Severity:       sev,
		CVSSScore:      &score,
		PublishedAt:    &published,
		LastModifiedAt: &published,
		TechTags:       []string{"php"},
		References:     []string{"https://example.com/" + cve},
		Source:         SourceNVD,
	}
}

func TestVulnIntelStorePostgresContract(t *testing.T) {
	pool, ctx := openVulnIntelPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	store := NewStore(pool)

	pub1 := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	pub2 := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)

	// upsert 新建/更新 isNew 判定
	a1 := pgAdvisory("CVE-2099-9001", SeverityHigh, pub1)
	isNew, err := store.UpsertAdvisory(ctx, a1, []byte(`{"id":"CVE-2099-9001"}`))
	if err != nil {
		t.Fatalf("upsert 新建: %v", err)
	}
	if !isNew {
		t.Error("首次 upsert 应判新建")
	}
	a1.Severity = SeverityCritical
	isNew, err = store.UpsertAdvisory(ctx, a1, nil)
	if err != nil {
		t.Fatalf("upsert 更新: %v", err)
	}
	if isNew {
		t.Error("同 cve_id 二次 upsert 应判更新")
	}

	// 详情
	got, err := store.GetByCVE(ctx, "CVE-2099-9001")
	if err != nil {
		t.Fatal(err)
	}
	if got.Severity != SeverityCritical || len(got.TechTags) != 1 || got.TechTags[0] != "php" {
		t.Errorf("详情 = %+v", got)
	}
	if _, err := store.GetByCVE(ctx, "CVE-2099-0000"); err == nil {
		t.Error("不存在 CVE 应返回错误")
	}

	// 列表过滤
	if _, err := store.UpsertAdvisory(ctx, pgAdvisory("CVE-2099-9002", SeverityLow, pub2), nil); err != nil {
		t.Fatal(err)
	}
	list, total, err := store.ListAdvisories(ctx, ListFilter{Keyword: "2099-900", Severity: SeverityCritical})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(list) != 1 || list[0].CVEID != "CVE-2099-9001" {
		t.Errorf("keyword+severity 过滤 = %d/%v", total, list)
	}
	// keyword 通配符注入防护（% 应被转义，匹配不到任何行）
	if _, total, err := store.ListAdvisories(ctx, ListFilter{Keyword: "%"}); err != nil || total != 0 {
		t.Errorf("通配符注入应被转义: total=%d err=%v", total, err)
	}
	list, total, err = store.ListAdvisories(ctx, ListFilter{Tech: "php", PublishedStart: &pub2})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || list[0].CVEID != "CVE-2099-9002" {
		t.Errorf("tech+published_start 过滤 = %d/%v", total, list)
	}
	if _, total, err := store.ListAdvisories(ctx, ListFilter{Source: SourceManual}); err != nil || total != 0 {
		t.Errorf("source=MANUAL 过滤 = %d, want 0", total)
	}

	// overview（总量口径含其他用例可能写入的行，只断言 >=）
	ov, err := store.GetOverview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ov.Total < 2 || ov.CriticalCount < 1 || ov.HighCount < 0 {
		t.Errorf("overview = %+v", ov)
	}

	// 应用技术栈：整组替换 + 受影响应用 + 非法应用拒收
	app1 := mkVulnApp(t, pool, ctx, "vi-app1")
	app2 := mkVulnApp(t, pool, ctx, "vi-app2")
	if err := store.ReplaceAllTechAssets(ctx, []TechAssetInput{
		{ApplicationID: app1, TechTags: []string{"php"}},
		{ApplicationID: app2, TechTags: []string{"php", "nodejs"}},
	}); err != nil {
		t.Fatalf("replace tech assets: %v", err)
	}
	apps, err := store.AffectedApps(ctx, "php")
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) < 2 {
		t.Errorf("affected php apps = %v", apps)
	}
	assets, err := store.ListTechAssets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := map[uuid.UUID][]string{}
	for _, ta := range assets {
		found[ta.ApplicationID] = ta.TechTags
	}
	if len(found[app1]) != 1 || found[app1][0] != "php" {
		t.Errorf("app1 tags = %v", found[app1])
	}
	if len(found[app2]) != 2 {
		t.Errorf("app2 tags = %v", found[app2])
	}
	// 全量替换语义：未列出的应用清空
	if err := store.ReplaceAllTechAssets(ctx, []TechAssetInput{
		{ApplicationID: app1, TechTags: []string{"php"}},
	}); err != nil {
		t.Fatal(err)
	}
	apps, _ = store.AffectedApps(ctx, "nodejs")
	if len(apps) != 0 {
		t.Errorf("替换后 nodejs 应用应清空: %v", apps)
	}
	if err := store.ReplaceAllTechAssets(ctx, []TechAssetInput{
		{ApplicationID: uuid.New(), TechTags: []string{"php"}},
	}); err == nil {
		t.Error("不存在应用应拒收")
	}

	// tech_name CHECK：大写/超长拒收（数据库层兜底）
	if _, err := pool.Exec(ctx, `INSERT INTO application_technologies(application_id, tech_name) VALUES ($1,'PHP')`, app1); err == nil {
		t.Error("大写 tech_name 应被 CHECK 拒收")
	}
	// 唯一键 (application_id, tech_name) 拒收重复
	if _, err := pool.Exec(ctx, `INSERT INTO application_technologies(application_id, tech_name) VALUES ($1,'php'),($1,'php')`, app1); err == nil {
		t.Error("重复 (application_id, tech_name) 应被唯一键拒收")
	}

	// vuln_alerted：唯一键 + RecordAlerted 幂等 + FilterAlerted
	a2 := pgAdvisory("CVE-2099-9003", SeverityMedium, pub2)
	if _, err := store.UpsertAdvisory(ctx, a2, nil); err != nil {
		t.Fatal(err)
	}
	alertID := uuid.New()
	if err := store.RecordAlerted(ctx, []uuid.UUID{a2.ID}, "php", &alertID); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAlerted(ctx, []uuid.UUID{a2.ID}, "php", &alertID); err != nil {
		t.Errorf("RecordAlerted 应幂等: %v", err)
	}
	hit, err := store.FilterAlerted(ctx, []uuid.UUID{a2.ID, a1.ID}, "php")
	if err != nil {
		t.Fatal(err)
	}
	if !hit[a2.ID] || hit[a1.ID] {
		t.Errorf("FilterAlerted = %v", hit)
	}

	// FK 级联：删情报级联提醒记录；删应用级联技术映射
	if _, err := pool.Exec(ctx, `DELETE FROM vuln_advisories WHERE id = $1`, a2.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM vuln_alerted WHERE advisory_id = $1`, a2.ID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("删情报应级联提醒记录, 剩 %d", n)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM applications WHERE id = $1`, app1); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM application_technologies WHERE application_id = $1`, app1).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("删应用应级联技术映射, 剩 %d", n)
	}

	// sync_state：覆盖写与失败现场
	now := time.Now().UTC()
	if err := store.SaveSyncState(ctx, &SyncState{
		Source: SyncSourceNVD, LastSyncAt: &now, LastWindowStart: &now, LastWindowEnd: &now,
		RecordsUpserted: 5, Status: SyncStatusSuccess,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSyncState(ctx, &SyncState{
		Source: SyncSourceNVD, Status: SyncStatusFailed, FailureMessage: "NVD 返回 HTTP 503",
	}); err != nil {
		t.Fatal(err)
	}
	st, err := store.GetSyncState(ctx, SyncSourceNVD)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != SyncStatusFailed || st.FailureMessage != "NVD 返回 HTTP 503" {
		t.Errorf("sync_state = %+v", st)
	}
}
