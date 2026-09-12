// stage8_api_ai_ops_test.go AI 定时运营任务（W8-AIOPS / P1-02 续）集成测试：
// 真实 PostgreSQL 验证迁移 000062/000063 建表与权限种子 + apiops.Store 全生命周期
// （计划 CRUD/启停游标/执行记录/级联删除/CHECK 约束）+ SQLSource 五种任务原料查询 +
// Sweeper 端到端（造数 → SweepOnce → runs 产物断言）+ 迁移 down/up 往返
// （直读 SQL 文件执行，不经 migrate 机制避免影响其他分片迁移）。
// 说明：HTTP 层（权限矩阵/参数校验/CRUD/启停/立即执行）由 apiops 包内单测经
// RegisterRoutes + MemStore 覆盖；经 app 装配的端到端 HTTP 验收待集成方装配后进行。
package tests

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiops"
	"github.com/jiuzhang-waf/server/internal/settings"
)

// enableAIOpsSwitch 打开全局开关（api_ai_ops.schedules_enabled=true）。
func enableAIOpsSwitch(t *testing.T, env *testEnv) {
	t.Helper()
	_, err := env.db.Exec(context.Background(), `
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('api_ai_ops', 'schedules_enabled', 'true'::jsonb, 'boolean', 'AI 运营定时任务总开关（测试）')
ON CONFLICT (setting_group, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value`)
	if err != nil {
		t.Fatalf("enable ai ops switch: %v", err)
	}
}

// seedAIOpsEndpoint 造端点并返回 ID。
func seedAIOpsEndpoint(t *testing.T, env *testEnv, method, path, status string, firstSeen time.Time, confirmed bool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var confirmedAt *time.Time
	if confirmed {
		confirmedAt = &firstSeen
	}
	err := env.db.QueryRow(context.Background(), `
INSERT INTO api_endpoints (http_method, normalized_path, endpoint_key, asset_status, first_seen_at, last_seen_at, confirmed_at)
VALUES ($1, $2, $3, $4, $5, $5, $6) RETURNING id`,
		method, path, method+" "+path, status, firstSeen, confirmedAt).Scan(&id)
	if err != nil {
		t.Fatalf("seed endpoint %s %s: %v", method, path, err)
	}
	return id
}

// TestAIOpsStoreIntegration 仓储全生命周期（真实 PG，含 CHECK/FK/级联）。
func TestAIOpsStoreIntegration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	store := apiops.NewStore(env.db)

	// ---- 计划 CRUD ----
	next := time.Now().Add(time.Hour)
	sc := &apiops.Schedule{
		TaskType: apiops.TaskRiskDigest, Name: "每日高危摘要", CronExpr: "0 9 * * *",
		Enabled: true, Config: json.RawMessage(`{"window_hours":48,"limit":10}`), NextRunAt: &next,
	}
	if err := store.CreateSchedule(ctx, sc); err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	got, err := store.GetSchedule(ctx, sc.ID)
	if err != nil || got.TaskType != apiops.TaskRiskDigest || !got.Enabled || got.NextRunAt == nil {
		t.Fatalf("get schedule: %+v err=%v", got, err)
	}
	var cfg map[string]int
	if err := json.Unmarshal(got.Config, &cfg); err != nil || cfg["window_hours"] != 48 {
		t.Fatalf("config roundtrip: %s err=%v", got.Config, err)
	}
	// 词表 CHECK：非法 task_type 被数据库拒绝
	bad := &apiops.Schedule{TaskType: "HACK", Name: "x", CronExpr: "0 9 * * *"}
	if err := store.CreateSchedule(ctx, bad); err == nil {
		t.Fatal("invalid task_type should be rejected by CHECK")
	}
	// 列表过滤
	enabled := true
	list, total, err := store.ListSchedules(ctx, apiops.ScheduleFilter{TaskType: apiops.TaskRiskDigest, Enabled: &enabled, Page: 1, PageSize: 20})
	if err != nil || total != 1 || list[0].ID != sc.ID {
		t.Fatalf("list schedules: total=%d err=%v", total, err)
	}
	// 更新（cron 变更 + 游标重算由调用方写入）
	got.Name = "每日高危摘要v2"
	got.CronExpr = "30 8 * * 1-5"
	got.Config = json.RawMessage(`{}`)
	if err := store.UpdateSchedule(ctx, got); err != nil {
		t.Fatalf("update schedule: %v", err)
	}
	got2, _ := store.GetSchedule(ctx, sc.ID)
	if got2.Name != "每日高危摘要v2" || got2.CronExpr != "30 8 * * 1-5" || string(got2.Config) != "{}" {
		t.Fatalf("updated: %+v", got2)
	}
	// 启停
	disabled, err := store.SetScheduleEnabled(ctx, sc.ID, false, nil)
	if err != nil || disabled.Enabled || disabled.NextRunAt != nil {
		t.Fatalf("disable: %+v err=%v", disabled, err)
	}
	enabledAgain, err := store.SetScheduleEnabled(ctx, sc.ID, true, &next)
	if err != nil || !enabledAgain.Enabled || enabledAgain.NextRunAt == nil {
		t.Fatalf("enable: %+v err=%v", enabledAgain, err)
	}
	// 不存在：GetSchedule → ErrScheduleNotFound
	if _, err := store.GetSchedule(ctx, uuid.New()); err == nil {
		t.Fatal("missing schedule should return error")
	}

	// ---- 到期游标 ----
	past := time.Now().Add(-time.Minute)
	dueSc := &apiops.Schedule{TaskType: apiops.TaskShadowReview, Name: "到期计划", CronExpr: "*/5 * * * *", Enabled: true, NextRunAt: &past}
	if err := store.CreateSchedule(ctx, dueSc); err != nil {
		t.Fatalf("create due schedule: %v", err)
	}
	due, err := store.ListDueSchedules(ctx, time.Now(), 20)
	if err != nil || len(due) != 1 || due[0].ID != dueSc.ID {
		t.Fatalf("due schedules: %+v err=%v", due, err)
	}
	later := time.Now().Add(2 * time.Hour)
	if err := store.UpdateNextRunAt(ctx, dueSc.ID, &later); err != nil {
		t.Fatalf("update next_run_at: %v", err)
	}
	due, _ = store.ListDueSchedules(ctx, time.Now(), 20)
	if len(due) != 0 {
		t.Fatalf("after claim due should be empty: %+v", due)
	}

	// ---- 执行记录 ----
	run := &apiops.Run{ScheduleID: sc.ID, StartedAt: time.Now()}
	if err := store.CreateRun(ctx, run); err != nil {
		t.Fatalf("create run: %v", err)
	}
	if run.Status != apiops.RunStatusRunning {
		t.Fatalf("run default status=%s", run.Status)
	}
	running, err := store.HasRunningRun(ctx, sc.ID)
	if err != nil || !running {
		t.Fatalf("has running: %v err=%v", running, err)
	}
	if err := store.FinishRun(ctx, run.ID, apiops.RunStatusSuccess, "完成", json.RawMessage(`{"open_high_total":8}`), time.Now()); err != nil {
		t.Fatalf("finish run: %v", err)
	}
	gotRun, err := store.GetRun(ctx, run.ID)
	if err != nil || gotRun.Status != apiops.RunStatusSuccess || gotRun.Summary != "完成" || gotRun.FinishedAt == nil {
		t.Fatalf("get run: %+v err=%v", gotRun, err)
	}
	var report map[string]int
	if err := json.Unmarshal(gotRun.Report, &report); err != nil || report["open_high_total"] != 8 {
		t.Fatalf("report roundtrip: %s err=%v", gotRun.Report, err)
	}
	running, _ = store.HasRunningRun(ctx, sc.ID)
	if running {
		t.Fatal("finished run should not count as running")
	}
	runs, runsTotal, err := store.ListRuns(ctx, sc.ID, 1, 20)
	if err != nil || runsTotal != 1 || runs[0].ID != run.ID {
		t.Fatalf("list runs: total=%d err=%v", runsTotal, err)
	}
	// 状态 CHECK：词表外状态被拒绝
	if _, err := env.db.Exec(ctx,
		`INSERT INTO api_ai_schedule_runs (schedule_id, status) VALUES ($1, 'BOGUS')`, sc.ID); err == nil {
		t.Fatal("invalid run status should be rejected by CHECK")
	}
	// FK：未知计划 → 23503
	if _, err := env.db.Exec(ctx,
		`INSERT INTO api_ai_schedule_runs (schedule_id) VALUES ($1)`, uuid.New()); err == nil {
		t.Fatal("run with unknown schedule should fail (FK)")
	}
	// 执行轨迹回填
	if err := store.UpdateScheduleRunState(ctx, sc.ID, time.Now(), apiops.RunStatusFailed, "db down"); err != nil {
		t.Fatalf("update run state: %v", err)
	}
	got3, _ := store.GetSchedule(ctx, sc.ID)
	if got3.LastStatus != apiops.RunStatusFailed || got3.LastError != "db down" || got3.LastRunAt == nil {
		t.Fatalf("run state: %+v", got3)
	}
	// last_status CHECK
	if _, err := env.db.Exec(ctx,
		`UPDATE api_ai_schedules SET last_status='BOGUS' WHERE id=$1`, sc.ID); err == nil {
		t.Fatal("invalid last_status should be rejected by CHECK")
	}

	// ---- 删除级联 ----
	if err := store.DeleteSchedule(ctx, sc.ID); err != nil {
		t.Fatalf("delete schedule: %v", err)
	}
	if _, err := store.GetRun(ctx, run.ID); err == nil {
		t.Fatal("run should be cascade-deleted with schedule")
	}
	if err := store.DeleteSchedule(ctx, sc.ID); err == nil {
		t.Fatal("delete missing schedule should return error")
	}
}

// TestAIOpsSweepIntegration 五种内置任务端到端：造数 → SweepOnce → 产物断言。
func TestAIOpsSweepIntegration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	enableAIOpsSwitch(t, env)
	now := time.Now()

	// ---- 造数 ----
	epNew := seedAIOpsEndpoint(t, env, "GET", "/v1/aiops-users", "DISCOVERED", now.Add(-time.Hour), false)
	epConfirmed := seedAIOpsEndpoint(t, env, "POST", "/v1/aiops-orders", "CONFIRMED", now.Add(-2*time.Hour), true)
	epOld := seedAIOpsEndpoint(t, env, "GET", "/v1/aiops-old", "CONFIRMED", now.Add(-72*time.Hour), true)

	// findings：SHADOW NEW ×2（一新一旧）、ZOMBIE NEW、BOLA CRITICAL NEW、BOLA HIGH CONFIRMED、
	// 排除项：RESOLVED HIGH、LOW NEW（RISK_DIGEST 不收）
	seedFinding := func(endpointID uuid.UUID, ftype, severity, status string, firstSeen time.Time) {
		t.Helper()
		if _, err := env.db.Exec(ctx, `
INSERT INTO api_runtime_findings (endpoint_id, finding_type, severity, status, title, first_seen_at, last_seen_at)
VALUES ($1,$2,$3,$4,$5,$6,$6)`,
			endpointID, ftype, severity, status, ftype+"-"+severity, firstSeen); err != nil {
			t.Fatalf("seed finding %s/%s/%s: %v", ftype, severity, status, err)
		}
	}
	seedFinding(epNew, "SHADOW", "MEDIUM", "NEW", now.Add(-time.Hour))
	seedFinding(epOld, "SHADOW", "LOW", "CONFIRMED", now.Add(-48*time.Hour))
	seedFinding(epOld, "ZOMBIE", "LOW", "NEW", now.Add(-24*time.Hour))
	seedFinding(epConfirmed, "BOLA", "CRITICAL", "NEW", now.Add(-3*time.Hour))
	seedFinding(epConfirmed, "BOLA", "HIGH", "CONFIRMED", now.Add(-5*time.Hour))
	seedFinding(epConfirmed, "BOLA", "HIGH", "RESOLVED", now.Add(-time.Hour))       // 已闭环，不计
	seedFinding(epConfirmed, "SCHEMA_DEVIATION", "LOW", "NEW", now.Add(-time.Hour)) // 低危，不计

	// weaknesses：超期 1、临期 1、未设期限 1、已修复（排除）1
	seedWeakness := func(endpointID uuid.UUID, code, name, severity, status string, due *time.Time) {
		t.Helper()
		if _, err := env.db.Exec(ctx, `
INSERT INTO api_weaknesses (endpoint_id, weakness_code, weakness_name, category, severity, status, due_date)
VALUES ($1,$2,$3,'AUTHN',$4,$5,$6)`,
			endpointID, code, name, severity, status, due); err != nil {
			t.Fatalf("seed weakness %s/%s: %v", code, status, err)
		}
	}
	overdueDue := now.Add(-24 * time.Hour)
	soonDue := now.Add(48 * time.Hour)
	fixedDue := now.Add(-24 * time.Hour)
	seedWeakness(epConfirmed, "UNAUTHENTICATED_SENSITIVE_API", "未认证敏感API", "HIGH", "TO_FIX", &overdueDue)
	seedWeakness(epNew, "SENSITIVE_IN_QUERY", "查询串敏感参数", "MEDIUM", "NEW", &soonDue)
	seedWeakness(epOld, "SCHEMA_DRIFT_PERSISTENT", "Schema持续漂移", "LOW", "CONFIRMED", nil)
	seedWeakness(epOld, "DEPRECATED_STILL_CALLED", "下线仍被调用", "MEDIUM", "FIXED", &fixedDue) // 已收口，不计

	// sensitive fields：phone ×2（不同端点）、id_card ×1；一条旧数据（不计入窗口新增）
	seedField := func(endpointID uuid.UUID, direction, path, dataType string, firstSeen time.Time) {
		t.Helper()
		if _, err := env.db.Exec(ctx, `
INSERT INTO api_sensitive_fields (endpoint_id, direction, structured_path, data_type, first_seen, last_seen)
VALUES ($1,$2,$3,$4,$5,$5)`,
			endpointID, direction, path, dataType, firstSeen); err != nil {
			t.Fatalf("seed sensitive field %s: %v", path, err)
		}
	}
	seedField(epConfirmed, "RESPONSE", "user.phone", "phone", now.Add(-time.Hour))
	seedField(epNew, "RESPONSE", "phone", "phone", now.Add(-2*time.Hour))
	seedField(epConfirmed, "REQUEST", "id_card", "id_card", now.Add(-72*time.Hour))

	// ---- 计划（五种任务全部到期）----
	store := apiops.NewStore(env.db)
	past := now.Add(-time.Minute)
	ids := map[string]uuid.UUID{}
	for _, tt := range apiops.TaskTypes() {
		sc := &apiops.Schedule{
			TaskType: tt, Name: "集成测试-" + tt, CronExpr: "0 9 * * *", Enabled: true,
			Config:    json.RawMessage(`{"window_hours":24,"limit":20,"due_within_days":3}`),
			NextRunAt: &past,
		}
		if err := store.CreateSchedule(ctx, sc); err != nil {
			t.Fatalf("create schedule %s: %v", tt, err)
		}
		ids[tt] = sc.ID
	}

	// ---- 调度执行 ----
	sweeper := apiops.NewSweeper(store, apiops.NewSQLSource(env.db)).SetSettings(settings.NewService(env.db))
	stats, err := sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if stats.Due != 5 || stats.Succeeded != 5 || stats.Failed != 0 || stats.Skipped != 0 {
		t.Fatalf("stats=%+v", stats)
	}

	// 产物断言辅助
	getRun := func(tt string) *apiops.Run {
		t.Helper()
		runs, total, err := store.ListRuns(ctx, ids[tt], 1, 20)
		if err != nil || total != 1 {
			t.Fatalf("%s runs total=%d err=%v", tt, total, err)
		}
		if runs[0].Status != apiops.RunStatusSuccess || runs[0].FinishedAt == nil || runs[0].Summary == "" {
			t.Fatalf("%s run: %+v", tt, runs[0])
		}
		got, err := store.GetRun(ctx, runs[0].ID)
		if err != nil {
			t.Fatalf("%s get run: %v", tt, err)
		}
		return got
	}

	// 资产摘要：总 3 端点；窗口内新增 2（72h 前的 epOld 不计）；确认 1；Shadow 未闭环 2；Zombie 1
	assetRun := getRun(apiops.TaskAssetDigest)
	var asset apiops.AssetDigestData
	if err := json.Unmarshal(assetRun.Report, &asset); err != nil {
		t.Fatalf("asset report: %v", err)
	}
	if asset.TotalEndpoints != 3 || asset.NewInWindow != 2 || asset.ConfirmedInWindow != 1 ||
		asset.ShadowOpen != 2 || asset.ZombieOpen != 1 || len(asset.NewEndpoints) != 2 {
		t.Fatalf("asset report: %+v", asset)
	}
	if !strings.Contains(assetRun.Summary, "新发现端点 2 个") || !strings.Contains(assetRun.Summary, "Shadow 未闭环 2 项") {
		t.Fatalf("asset summary: %s", assetRun.Summary)
	}

	// Shadow 运营：未闭环 2（NEW+CONFIRMED）、窗口内新增 1
	shadowRun := getRun(apiops.TaskShadowReview)
	var shadow apiops.ShadowReviewData
	if err := json.Unmarshal(shadowRun.Report, &shadow); err != nil {
		t.Fatalf("shadow report: %v", err)
	}
	if shadow.OpenTotal != 2 || shadow.NewInWindow != 1 || len(shadow.Items) != 2 {
		t.Fatalf("shadow report: %+v", shadow)
	}
	if shadow.Items[0].EndpointKey == "" {
		t.Fatalf("shadow item endpoint_key should be resolved via join: %+v", shadow.Items[0])
	}

	// 弱点跟进：待整改 3、超期 1、临期 1（FIXED 不计）
	weakRun := getRun(apiops.TaskWeaknessFollow)
	var weak apiops.WeaknessFollowData
	if err := json.Unmarshal(weakRun.Report, &weak); err != nil {
		t.Fatalf("weakness report: %v", err)
	}
	if weak.OpenTotal != 3 || len(weak.Overdue) != 1 || len(weak.DueSoon) != 1 || weak.NoDueDate != 1 {
		t.Fatalf("weakness report: %+v", weak)
	}
	if weak.Overdue[0].WeaknessCode != "UNAUTHENTICATED_SENSITIVE_API" || weak.DueSoon[0].WeaknessCode != "SENSITIVE_IN_QUERY" {
		t.Fatalf("weakness lists: overdue=%+v dueSoon=%+v", weak.Overdue, weak.DueSoon)
	}
	if !strings.Contains(weakRun.Summary, "已超期 1 项") {
		t.Fatalf("weakness summary: %s", weakRun.Summary)
	}

	// 风险摘要：HIGH+CRITICAL 未闭环 2（CRITICAL 1；RESOLVED/LOW 不计）
	riskRun := getRun(apiops.TaskRiskDigest)
	var risk apiops.RiskDigestData
	if err := json.Unmarshal(riskRun.Report, &risk); err != nil {
		t.Fatalf("risk report: %v", err)
	}
	if risk.OpenHighTotal != 2 || risk.OpenCritical != 1 || risk.NewInWindow != 2 || len(risk.Items) != 2 {
		t.Fatalf("risk report: %+v", risk)
	}
	if risk.Items[0].Severity != "CRITICAL" { // CRITICAL 优先排序
		t.Fatalf("risk items order: %+v", risk.Items)
	}

	// 涉敏概览：涉敏端点 2（去重）、字段 3、窗口新增 2（72h 前 id_card 不计）
	sensRun := getRun(apiops.TaskSensitiveDigest)
	var sens apiops.SensitiveDigestData
	if err := json.Unmarshal(sensRun.Report, &sens); err != nil {
		t.Fatalf("sensitive report: %v", err)
	}
	if sens.SensitiveEndpointCount != 2 || sens.SensitiveFieldCount != 3 || sens.NewFieldsInWindow != 2 || len(sens.NewFields) != 2 {
		t.Fatalf("sensitive report: %+v", sens)
	}

	// 计划轨迹：全部 SUCCESS 且游标推进到未来
	for _, tt := range apiops.TaskTypes() {
		got, err := store.GetSchedule(ctx, ids[tt])
		if err != nil || got.LastStatus != apiops.RunStatusSuccess || got.LastError != "" {
			t.Fatalf("%s last state: %+v err=%v", tt, got, err)
		}
		if got.NextRunAt == nil || !got.NextRunAt.After(now) {
			t.Fatalf("%s next_run_at should advance: %v", tt, got.NextRunAt)
		}
	}
	// 第二轮（游标已推进）不再触发
	stats, err = sweeper.SweepOnce(ctx)
	if err != nil || stats.Due != 0 {
		t.Fatalf("second sweep: %+v err=%v", stats, err)
	}

	// 开关关闭后 SweepOnce 空转、RunNow 拒绝
	if _, err := env.db.Exec(ctx, `
UPDATE system_settings SET setting_value='false'::jsonb
WHERE setting_group='api_ai_ops' AND setting_key='schedules_enabled'`); err != nil {
		t.Fatalf("disable switch: %v", err)
	}
	stats, err = sweeper.SweepOnce(ctx)
	if err != nil || stats.Due != 0 {
		t.Fatalf("switch-off sweep: %+v err=%v", stats, err)
	}
	if _, err := sweeper.RunNow(ctx, ids[apiops.TaskRiskDigest]); err == nil {
		t.Fatal("RunNow should be rejected when global switch off")
	}
}

// TestAIOpsPermissionSeeds 迁移 000063 权限种子三权口径（SECURITY_ADMIN 全量、
// SYSTEM_ADMIN 无），叠加 000100 后 AUDIT_ADMIN 纯审计化（api_ai.* 全移除）。
func TestAIOpsPermissionSeeds(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	permExists := func(code string) bool {
		var exists bool
		if err := env.db.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM permissions WHERE code=$1)`, code).Scan(&exists); err != nil {
			t.Fatalf("check permission %s: %v", code, err)
		}
		return exists
	}
	if !permExists("api_ai.read") || !permExists("api_ai.execute") {
		t.Fatal("api_ai.read / api_ai.execute permission seeds missing")
	}
	roleHas := func(role, perm string) bool {
		var has bool
		if err := env.db.QueryRow(ctx, `
SELECT EXISTS(
  SELECT 1 FROM role_permissions rp
  JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
  WHERE r.code=$1 AND p.code=$2)`, role, perm).Scan(&has); err != nil {
			t.Fatalf("check role perm %s/%s: %v", role, perm, err)
		}
		return has
	}
	if !roleHas("SECURITY_ADMIN", "api_ai.read") || !roleHas("SECURITY_ADMIN", "api_ai.execute") {
		t.Fatal("SECURITY_ADMIN should hold both api_ai permissions")
	}
	if roleHas("AUDIT_ADMIN", "api_ai.read") || roleHas("AUDIT_ADMIN", "api_ai.execute") {
		t.Fatal("AUDIT_ADMIN should hold no api_ai permissions after 000100")
	}
	if roleHas("SYSTEM_ADMIN", "api_ai.read") || roleHas("SYSTEM_ADMIN", "api_ai.execute") {
		t.Fatal("SYSTEM_ADMIN should hold no api_ai permissions")
	}
}

// TestAIOpsMigrationDownUp 迁移 000062/000063 down/up 往返（直接执行 SQL 文件）。
func TestAIOpsMigrationDownUp(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	tableExists := func(name string) bool {
		var exists bool
		if err := env.db.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`, name).Scan(&exists); err != nil {
			t.Fatalf("check table %s: %v", name, err)
		}
		return exists
	}
	for _, tbl := range []string{"api_ai_schedules", "api_ai_schedule_runs"} {
		if !tableExists(tbl) {
			t.Fatalf("table %s missing after migrate up", tbl)
		}
	}
	execFile := func(path string) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if _, err := env.db.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("exec %s: %v", path, err)
		}
	}
	// down（依赖逆序：权限种子 → 两表）
	execFile("../migrations/000063_api_ai_schedule_perms.down.sql")
	execFile("../migrations/000062_api_ai_schedules.down.sql")
	for _, tbl := range []string{"api_ai_schedules", "api_ai_schedule_runs"} {
		if tableExists(tbl) {
			t.Fatalf("table %s still exists after down", tbl)
		}
	}
	var permCount int
	if err := env.db.QueryRow(ctx,
		`SELECT count(*) FROM permissions WHERE code IN ('api_ai.read','api_ai.execute')`).Scan(&permCount); err != nil {
		t.Fatalf("count perms after down: %v", err)
	}
	if permCount != 0 {
		t.Fatalf("perms should be removed after down: %d", permCount)
	}
	// up 恢复
	execFile("../migrations/000062_api_ai_schedules.up.sql")
	execFile("../migrations/000063_api_ai_schedule_perms.up.sql")
	for _, tbl := range []string{"api_ai_schedules", "api_ai_schedule_runs"} {
		if !tableExists(tbl) {
			t.Fatalf("table %s missing after re-up", tbl)
		}
	}
	if err := env.db.QueryRow(ctx,
		`SELECT count(*) FROM permissions WHERE code IN ('api_ai.read','api_ai.execute')`).Scan(&permCount); err != nil {
		t.Fatalf("count perms after re-up: %v", err)
	}
	if permCount != 2 {
		t.Fatalf("perms should be restored after re-up: %d", permCount)
	}
}
