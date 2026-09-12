package tests

// stage8_api_security_alerts_test.go W6-B（P1-08）API 安全告警接线集成测试。
//
// 覆盖范围（真实 PostgreSQL，迁移含 000055_api_security_alerts）：
//   - Store 层：findings 统计 SQL（窗口/状态/类型口径）、Silence/Resume 状态机、
//     HasActiveSilence 指纹静默判定、List 三态视图过滤；
//   - Handler 层（手工 mux + authz.WithPrincipal）：silence/resume 参数校验与状态冲突、
//     view/status 互斥校验、操作审计落库。
//
// 注：silence/resume 的路由注册与权限中间件（alertWrite =
// system_alerts.acknowledge/acknowledge_security）在 app.go 装配层完成（本分片
// 不改动 app 包），故 403 全链路用例不在本文件；权限点本身为既有机制复用。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

// insertAlert 直插一条系统告警，返回 ID。
func insertAlert(t *testing.T, env *testEnv, alertType, status string, silencedUntil *time.Time) string {
	t.Helper()
	var id string
	err := env.db.QueryRow(context.Background(), `
INSERT INTO system_alerts (alert_type, severity, component, title, message, status, silenced_until)
VALUES ($1,'HIGH','API_SECURITY','集成测试告警','msg',$2,$3) RETURNING id`,
		alertType, status, silencedUntil).Scan(&id)
	if err != nil {
		t.Fatalf("insert alert: %v", err)
	}
	return id
}

// insertFinding 直插一条 API 运行时风险发现（dedup_fingerprint 留 NULL，行互不冲突）。
// ageSeconds 为相对当前时刻的距今秒数（窗口内外控制用）。
func insertFinding(t *testing.T, env *testEnv, findingType, severity, status string, ageSeconds int) {
	t.Helper()
	_, err := env.db.Exec(context.Background(), `
INSERT INTO api_runtime_findings (finding_type, severity, status, title, first_seen_at, last_seen_at)
VALUES ($1,$2,$3,'集成测试发现', now() - make_interval(secs => $4), now() - make_interval(secs => $4))`,
		findingType, severity, status, ageSeconds)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
}

// TestStage8APIAlertFindingsStats findings 统计 SQL：窗口、状态、类型口径。
func TestStage8APIAlertFindingsStats(t *testing.T) {
	env := setupTestEnv(t)
	store := systemalerts.NewStore(env.db)
	ctx := context.Background()

	// 窗口内新增未处置 CRITICAL ×2；窗口外 ×1；已处置（非 NEW）×1 不计
	insertFinding(t, env, "BOLA_UNAUTHENTICATED_OBJECT_ACCESS", "CRITICAL", "NEW", 120)
	insertFinding(t, env, "SENSITIVE_LEAK", "CRITICAL", "NEW", 300)
	insertFinding(t, env, "ZOMBIE", "CRITICAL", "NEW", 7200)
	insertFinding(t, env, "BOLA_UNAUTHENTICATED_OBJECT_ACCESS", "CRITICAL", "CONFIRMED", 120)
	// HIGH 不计入 CRITICAL 统计
	insertFinding(t, env, "SCHEMA_DEVIATION", "HIGH", "NEW", 60)
	// MASK 失败信号（response.mask_failed 机械映射类型）
	insertFinding(t, env, "RESPONSE_MASK_FAILED", "HIGH", "NEW", 180)

	total, samples, err := store.CountNewCritical(ctx, 10*time.Minute, 3)
	if err != nil {
		t.Fatalf("CountNewCritical: %v", err)
	}
	if total != 2 {
		t.Errorf("窗口内 NEW+CRITICAL 总数 = %d, want 2（窗口外/已处置/非CRITICAL 不计）", total)
	}
	if len(samples) != 2 {
		t.Errorf("样本条数 = %d, want 2", len(samples))
	}

	// 窄窗口排除 5 分钟前那条
	total, _, err = store.CountNewCritical(ctx, 3*time.Minute, 3)
	if err != nil {
		t.Fatalf("CountNewCritical 窄窗口: %v", err)
	}
	if total != 1 {
		t.Errorf("3 分钟窗口 NEW+CRITICAL = %d, want 1", total)
	}

	counts, err := store.CountNewByType(ctx, 10*time.Minute)
	if err != nil {
		t.Fatalf("CountNewByType: %v", err)
	}
	byType := map[string]int64{}
	for _, c := range counts {
		byType[c.FindingType] = c.Count
	}
	if byType["BOLA_UNAUTHENTICATED_OBJECT_ACCESS"] != 1 {
		t.Errorf("BOLA 窗口内 NEW 计数 = %d, want 1（CONFIRMED 不计）", byType["BOLA_UNAUTHENTICATED_OBJECT_ACCESS"])
	}
	if byType["ZOMBIE"] != 0 {
		t.Errorf("窗口外 ZOMBIE 不应计入, got %d", byType["ZOMBIE"])
	}

	n, err := store.CountNewMaskFailures(ctx, 10*time.Minute)
	if err != nil {
		t.Fatalf("CountNewMaskFailures: %v", err)
	}
	if n != 1 {
		t.Errorf("MASK 失败计数 = %d, want 1", n)
	}
}

// TestStage8APIAlertSilenceStore 静默 Store 状态机与指纹静默判定。
func TestStage8APIAlertSilenceStore(t *testing.T) {
	env := setupTestEnv(t)
	store := systemalerts.NewStore(env.db)
	ctx := context.Background()

	openID := insertAlert(t, env, systemalerts.TypeAPIFindingSpike, "OPEN", nil)

	// 静默前：无同指纹静默
	silenced, err := store.HasActiveSilence(ctx, systemalerts.TypeAPIFindingSpike, "API_SECURITY")
	if err != nil {
		t.Fatalf("HasActiveSilence: %v", err)
	}
	if silenced {
		t.Fatalf("静默前 HasActiveSilence 应为 false")
	}

	// 静默（未关闭告警）
	until := time.Now().UTC().Add(time.Hour)
	if err := store.Silence(ctx, uuid.MustParse(openID), until); err != nil {
		t.Fatalf("Silence: %v", err)
	}
	a, err := store.GetByID(ctx, uuid.MustParse(openID))
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if a.SilencedUntil == nil || !a.SilencedUntil.Equal(until) {
		t.Errorf("silenced_until 读回错误: %v, want %v", a.SilencedUntil, until)
	}
	if a.Status != systemalerts.StatusOpen {
		t.Errorf("静默不改变状态, got %s", a.Status)
	}
	silenced, err = store.HasActiveSilence(ctx, systemalerts.TypeAPIFindingSpike, "API_SECURITY")
	if err != nil {
		t.Fatalf("HasActiveSilence: %v", err)
	}
	if !silenced {
		t.Errorf("静默后 HasActiveSilence 应为 true")
	}
	// 不同指纹不受影响
	other, err := store.HasActiveSilence(ctx, systemalerts.TypeAPIMaskFailure, "API_SECURITY")
	if err != nil {
		t.Fatalf("HasActiveSilence 异类型: %v", err)
	}
	if other {
		t.Errorf("不同 alert_type 不应命中静默")
	}

	// 已关闭告警不可静默
	resolvedID := insertAlert(t, env, systemalerts.TypeAPIMaskFailure, "RESOLVED", nil)
	if err := store.Silence(ctx, uuid.MustParse(resolvedID), until); err == nil {
		t.Errorf("RESOLVED 告警静默应返回 ErrInvalidTransition")
	}

	// 解除静默；重复解除报错
	if err := store.Resume(ctx, uuid.MustParse(openID)); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	a, _ = store.GetByID(ctx, uuid.MustParse(openID))
	if a.SilencedUntil != nil {
		t.Errorf("Resume 后 silenced_until 应为 NULL, got %v", a.SilencedUntil)
	}
	if err := store.Resume(ctx, uuid.MustParse(openID)); err == nil {
		t.Errorf("未静默告警重复 Resume 应返回 ErrInvalidTransition")
	}
	silenced, _ = store.HasActiveSilence(ctx, systemalerts.TypeAPIFindingSpike, "API_SECURITY")
	if silenced {
		t.Errorf("Resume 后 HasActiveSilence 应为 false")
	}
}

// TestStage8APIAlertListView 列表三态视图过滤。
func TestStage8APIAlertListView(t *testing.T) {
	env := setupTestEnv(t)
	store := systemalerts.NewStore(env.db)
	ctx := context.Background()

	future := time.Now().UTC().Add(time.Hour)
	activeID := insertAlert(t, env, systemalerts.TypeAPICriticalFinding, "OPEN", nil)
	silencedID := insertAlert(t, env, systemalerts.TypeAPIFindingSpike, "OPEN", &future)
	historyID := insertAlert(t, env, systemalerts.TypeAPIMaskFailure, "RESOLVED", nil)

	contains := func(view string, id string) bool {
		list, _, err := store.List(ctx, systemalerts.ListFilter{View: view, Page: 1, PageSize: 100})
		if err != nil {
			t.Fatalf("List view=%s: %v", view, err)
		}
		for _, a := range list {
			if a.ID.String() == id {
				return true
			}
		}
		return false
	}

	if !contains(systemalerts.ViewActive, activeID) || contains(systemalerts.ViewActive, silencedID) || contains(systemalerts.ViewActive, historyID) {
		t.Errorf("ACTIVE 视图口径错误（应仅含未静默未关闭告警）")
	}
	if contains(systemalerts.ViewSilenced, activeID) || !contains(systemalerts.ViewSilenced, silencedID) || contains(systemalerts.ViewSilenced, historyID) {
		t.Errorf("SILENCED 视图口径错误（应仅含静默期内的未关闭告警）")
	}
	if contains(systemalerts.ViewHistory, activeID) || contains(systemalerts.ViewHistory, silencedID) || !contains(systemalerts.ViewHistory, historyID) {
		t.Errorf("HISTORY 视图口径错误（应仅含已关闭告警）")
	}
}

// newAlertTestMux 手工装配 silence/resume/list 路由（无权限中间件；Principal 直接注入），
// 复刻 app.go 生产路径的 Handler 调用形态。
func newAlertTestMux(env *testEnv, principal *authz.Principal) *http.ServeMux {
	store := systemalerts.NewStore(env.db)
	h := systemalerts.NewHandler(store, audits.NewService(env.db))
	wrap := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			next(w, r.WithContext(authz.WithPrincipal(r.Context(), principal)))
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/system-alerts", wrap(h.List))
	mux.HandleFunc("POST /api/v1/system-alerts/{id}/silence", wrap(h.Silence))
	mux.HandleFunc("POST /api/v1/system-alerts/{id}/resume", wrap(h.Resume))
	return mux
}

func serveAlert(mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// TestStage8APIAlertSilenceHTTP silence/resume 接口语义：正常流转、参数校验、状态冲突、审计。
func TestStage8APIAlertSilenceHTTP(t *testing.T) {
	env := setupTestEnv(t)
	principal := &authz.Principal{UserID: uuid.New(), Username: "w6b_tester"}
	mux := newAlertTestMux(env, principal)
	ctx := context.Background()

	openID := insertAlert(t, env, systemalerts.TypeAPIFindingSpike, "OPEN", nil)

	// 正常静默 60 分钟
	rec := serveAlert(mux, http.MethodPost, "/api/v1/system-alerts/"+openID+"/silence", `{"duration_minutes":60}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("silence status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"silenced_until"`) || strings.Contains(rec.Body.String(), `"silenced_until":null`) {
		t.Errorf("静默后响应应携带非空 silenced_until: %s", rec.Body.String())
	}
	// 审计落库（silence）
	var auditCount int
	if err := env.db.QueryRow(ctx, `
SELECT count(*) FROM operation_audits
WHERE module='system_alerts' AND action='silence' AND object_id=$1 AND username='w6b_tester'`,
		openID).Scan(&auditCount); err != nil {
		t.Fatalf("query audits: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("silence 审计记录 = %d, want 1", auditCount)
	}

	// 参数校验：时长缺失/超界/非法 ID/不存在
	for _, tc := range []struct {
		name string
		path string
		body string
		want int
	}{
		{"时长为0", "/api/v1/system-alerts/" + openID + "/silence", `{"duration_minutes":0}`, http.StatusBadRequest},
		{"时长超上限", "/api/v1/system-alerts/" + openID + "/silence", `{"duration_minutes":43201}`, http.StatusBadRequest},
		{"负数时长", "/api/v1/system-alerts/" + openID + "/silence", `{"duration_minutes":-5}`, http.StatusBadRequest},
		{"非法ID", "/api/v1/system-alerts/not-a-uuid/silence", `{"duration_minutes":60}`, http.StatusBadRequest},
		{"不存在", "/api/v1/system-alerts/00000000-0000-0000-0000-000000000000/silence", `{"duration_minutes":60}`, http.StatusNotFound},
	} {
		rec := serveAlert(mux, http.MethodPost, tc.path, tc.body)
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d, body: %s", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}

	// 已关闭告警不可静默（409）
	resolvedID := insertAlert(t, env, systemalerts.TypeAPIMaskFailure, "RESOLVED", nil)
	rec = serveAlert(mux, http.MethodPost, "/api/v1/system-alerts/"+resolvedID+"/silence", `{"duration_minutes":60}`)
	if rec.Code != http.StatusConflict {
		t.Errorf("RESOLVED 静默 status = %d, want 409", rec.Code)
	}

	// 解除静默
	rec = serveAlert(mux, http.MethodPost, "/api/v1/system-alerts/"+openID+"/resume", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("resume status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"silenced_until":null`) {
		t.Errorf("resume 后响应 silenced_until 应为 null: %s", rec.Body.String())
	}
	// 审计落库（resume）
	if err := env.db.QueryRow(ctx, `
SELECT count(*) FROM operation_audits
WHERE module='system_alerts' AND action='resume' AND object_id=$1`,
		openID).Scan(&auditCount); err != nil {
		t.Fatalf("query audits: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("resume 审计记录 = %d, want 1", auditCount)
	}

	// 未静默告警重复解除（409）
	rec = serveAlert(mux, http.MethodPost, "/api/v1/system-alerts/"+openID+"/resume", `{}`)
	if rec.Code != http.StatusConflict {
		t.Errorf("重复 resume status = %d, want 409", rec.Code)
	}

	// view 与 status 互斥；非法 view 400
	rec = serveAlert(mux, http.MethodGet, "/api/v1/system-alerts?view=ACTIVE&status=OPEN", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("view+status 互斥校验 status = %d, want 400", rec.Code)
	}
	rec = serveAlert(mux, http.MethodGet, "/api/v1/system-alerts?view=BOGUS", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("非法 view status = %d, want 400", rec.Code)
	}
	rec = serveAlert(mux, http.MethodGet, "/api/v1/system-alerts?view=SILENCED", "")
	if rec.Code != http.StatusOK {
		t.Errorf("合法 view 查询 status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
}

// TestStage8APIAlertEvaluateAgainstDB 引擎评估全链路（真实 DB 统计源 + 内存配置）。
func TestStage8APIAlertEvaluateAgainstDB(t *testing.T) {
	env := setupTestEnv(t)
	store := systemalerts.NewStore(env.db)
	ctx := context.Background()

	// 窗口内新增 CRITICAL finding → 评估应产生 API_CRITICAL_FINDING 告警
	insertFinding(t, env, "BOLA_UNAUTHENTICATED_OBJECT_ACCESS", "CRITICAL", "NEW", 60)

	engine := systemalerts.NewEngine(store, systemalerts.EngineOptions{
		APIFindings: store,
		// Settings 缺省 → 全默认（开关开、阈值 20、窗口 60/10 分钟）
	})
	if err := engine.EvaluateAPIFindings(ctx); err != nil {
		t.Fatalf("EvaluateAPIFindings: %v", err)
	}
	list, total, err := store.List(ctx, systemalerts.ListFilter{
		AlertType: systemalerts.TypeAPICriticalFinding, Page: 1, PageSize: 10,
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 {
		t.Fatalf("应产生 1 条 API_CRITICAL_FINDING 告警, got %d", total)
	}
	a := list[0]
	if a.Severity != "CRITICAL" || a.Component != "API_SECURITY" || a.Status != "OPEN" {
		t.Errorf("告警内容错误: severity=%s component=%s status=%s", a.Severity, a.Component, a.Status)
	}
	if !strings.Contains(a.Message, "1 条") {
		t.Errorf("message 应含新增条数: %q", a.Message)
	}

	// finding 处置（离开 NEW）→ 再次评估自动恢复
	if _, err := env.db.Exec(ctx, `
UPDATE api_runtime_findings SET status='CONFIRMED' WHERE status='NEW'`); err != nil {
		t.Fatalf("update finding status: %v", err)
	}
	if err := engine.EvaluateAPIFindings(ctx); err != nil {
		t.Fatalf("再次评估: %v", err)
	}
	after, err := store.GetByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if after.Status != systemalerts.StatusResolved || after.ResolveType == nil || *after.ResolveType != systemalerts.ResolveRecovered {
		t.Errorf("finding 处置后告警应自动 RESOLVED(RECOVERED), got status=%s", after.Status)
	}

	// 已关闭告警不可静默（状态机保护，真实 DB 路径）
	until := time.Now().UTC().Add(30 * time.Minute)
	if err := store.Silence(ctx, a.ID, until); err == nil {
		t.Fatalf("RESOLVED 告警不可静默")
	}
}
