// stage8_api_reports_test.go API 安全报告集成测试（WDSP 任务书 P1-06，W7-RPT 分片，迁移 000059）。
// 覆盖：迁移落位（report_type 注释词表含四个 API 类型）；四种 API 报告采集
// 内容正确性（真实 SQL 造数 → CollectAPI 断言各章节数据）；空数据态；HTTP 全链路
// （创建 API_ASSET 报告 → Worker 真实生成 → 预览含章节内容 → 下载）；权限边界
// （审计管理员创建 403、非法类型 400）。
// 真实 PostgreSQL/Valkey，无口令环境 t.Skip（纪律同 stage8_api_security_test.go）。
package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/reports"
)

// s8rSeed 造 API 报告原料（端点/发现/弱点/敏感字段），返回报告统计区间与端点ID。
// 区间为 [now-72h, now+1h)，区间内/外各造对照数据以验证窗口过滤。
func s8rSeed(t *testing.T, env *testEnv) (start, end time.Time, epA, epB, epC, epD uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	start = now.Add(-72 * time.Hour)
	end = now.Add(time.Hour)

	// 端点：epA 发现态（新增）、epB 已确认（新增）、epC 僵尸（历史）、epD 已下线（历史）
	epA = s8SeedEndpoint(t, env, "GET", "/s8r-"+s5Rand()+"/order/{id}", 0.9).ID
	epB = s8SeedEndpoint(t, env, "POST", "/s8r-"+s5Rand()+"/pay/{id}", 0.9).ID
	epC = s8SeedEndpoint(t, env, "GET", "/s8r-"+s5Rand()+"/legacy/{id}", 0.8).ID
	epD = s8SeedEndpoint(t, env, "DELETE", "/s8r-"+s5Rand()+"/old/{id}", 0.8).ID
	s8Exec(t, env, `UPDATE api_endpoints SET asset_status='CONFIRMED', confirmed_at=now() WHERE id=$1`, epB)
	s8Exec(t, env, `UPDATE api_endpoints SET asset_status='ZOMBIE', zombie_since=now(), first_seen_at=$2 WHERE id=$1`, epC, now.Add(-10*24*time.Hour))
	s8Exec(t, env, `UPDATE api_endpoints SET asset_status='DEPRECATED', first_seen_at=$2 WHERE id=$1`, epD, now.Add(-10*24*time.Hour))

	// 运行时发现：区间内 4 条（含 1 条已关闭）+ 区间外 1 条历史未关闭
	s8Exec(t, env, `INSERT INTO api_runtime_findings (endpoint_id, finding_type, severity, status, title)
		VALUES ($1, 'SHADOW', 'MEDIUM', 'NEW', 'shadow-a')`, epA)
	s8Exec(t, env, `INSERT INTO api_runtime_findings (endpoint_id, finding_type, severity, status, title)
		VALUES ($1, 'SHADOW', 'LOW', 'IN_PROGRESS', 'shadow-b')`, epA)
	s8Exec(t, env, `INSERT INTO api_runtime_findings (endpoint_id, finding_type, severity, status, title, subject_type, subject_id)
		VALUES ($1, 'BOLA', 'HIGH', 'NEW', 'bola', 'IDENTITY', 'subj-fingerprint-0001')`, epB)
	s8Exec(t, env, `INSERT INTO api_runtime_findings (endpoint_id, finding_type, severity, status, title, created_at, updated_at)
		VALUES ($1, 'SENSITIVE_LEAK', 'MEDIUM', 'RESOLVED', 'leak', $2, now())`, epB, now.Add(-24*time.Hour))
	s8Exec(t, env, `INSERT INTO api_runtime_findings (endpoint_id, finding_type, severity, status, title, created_at)
		VALUES ($1, 'SHADOW', 'LOW', 'NEW', 'shadow-old', $2)`, epC, now.Add(-10*24*time.Hour))

	// 弱点：w1 待整改且超期（区间内派生）；w2 已整改（区间内派生+整改）
	var w1, w2 uuid.UUID
	if err := env.db.QueryRow(ctx, `
INSERT INTO api_weaknesses (endpoint_id, weakness_code, weakness_name, category, severity, status, first_seen, due_date)
VALUES ($1, 'UNAUTHENTICATED_SENSITIVE_API', '未认证敏感接口', 'AUTHN', 'HIGH', 'TO_FIX', $2, $3) RETURNING id`,
		epA, now.Add(-48*time.Hour), now.Add(-24*time.Hour)).Scan(&w1); err != nil {
		t.Fatalf("seed weakness w1: %v", err)
	}
	if err := env.db.QueryRow(ctx, `
INSERT INTO api_weaknesses (endpoint_id, weakness_code, weakness_name, category, severity, status, first_seen, fixed_at)
VALUES ($1, 'SENSITIVE_IN_QUERY', '查询串敏感参数', 'SENSITIVE', 'MEDIUM', 'FIXED', $2, $3) RETURNING id`,
		epB, now.Add(-48*time.Hour), now.Add(-24*time.Hour)).Scan(&w2); err != nil {
		t.Fatalf("seed weakness w2: %v", err)
	}
	s8Exec(t, env, `INSERT INTO api_weakness_actions (weakness_id, action, actor) VALUES ($1, 'RETEST_FAIL', 'tester')`, w1)
	s8Exec(t, env, `INSERT INTO api_weakness_actions (weakness_id, action, actor) VALUES ($1, 'RETEST_PASS', 'tester')`, w2)

	// 敏感字段：区间内 3 个（跨 2 天）+ 区间外 1 个
	s8Exec(t, env, `INSERT INTO api_sensitive_fields (endpoint_id, direction, structured_path, data_type, first_seen)
		VALUES ($1, 'REQUEST', 'query.phone', 'phone', $2)`, epA, now.Add(-24*time.Hour))
	s8Exec(t, env, `INSERT INTO api_sensitive_fields (endpoint_id, direction, structured_path, data_type, first_seen)
		VALUES ($1, 'RESPONSE', 'body.id_card', 'id_card', $2)`, epA, now.Add(-48*time.Hour))
	s8Exec(t, env, `INSERT INTO api_sensitive_fields (endpoint_id, direction, structured_path, data_type, first_seen)
		VALUES ($1, 'REQUEST', 'query.phone', 'phone', $2)`, epB, now.Add(-24*time.Hour))
	s8Exec(t, env, `INSERT INTO api_sensitive_fields (endpoint_id, direction, structured_path, data_type, first_seen)
		VALUES ($1, 'RESPONSE', 'body.bank_card', 'bank_card', $2)`, epB, now.Add(-10*24*time.Hour))
	return start, end, epA, epB, epC, epD
}

// TestStage8APIReportsCollect 四种 API 报告采集内容正确性（含空数据态）。
func TestStage8APIReportsCollect(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	start, end, _, _, _, _ := s8rSeed(t, env)
	collector := reports.NewCollector(env.db, nil, nil)
	in := reports.CollectInput{Start: start, End: end}

	// ---------- API 资产周报 ----------
	in.ReportType = reports.TypeAPIAsset
	asset, err := collector.CollectAPI(ctx, in)
	if err != nil {
		t.Fatalf("collect asset: %v", err)
	}
	a := asset.Asset
	if a.TotalEndpoints != 4 || a.NewEndpoints != 2 || a.Confirmed != 1 || a.Zombie != 1 || a.Deprecated != 1 {
		t.Fatalf("asset overview = %+v", a)
	}
	if a.ShadowOpen != 3 { // shadow-a(NEW) + shadow-b(IN_PROGRESS) + shadow-old(NEW)
		t.Fatalf("shadow open = %d, want 3", a.ShadowOpen)
	}
	if len(a.NewList) != 2 {
		t.Fatalf("new list = %d, want 2", len(a.NewList))
	}
	if len(a.ShadowList) != 2 || a.ShadowList[0].Path == "" {
		t.Fatalf("shadow list = %+v", a.ShadowList)
	}
	if len(a.StatusDist) != 4 {
		t.Fatalf("status dist = %+v", a.StatusDist)
	}
	if len(asset.Conclusions) == 0 || len(asset.Suggestions) == 0 {
		t.Fatal("asset conclusions/suggestions empty")
	}

	// ---------- API 风险周报 ----------
	in.ReportType = reports.TypeAPIRisk
	risk, err := collector.CollectAPI(ctx, in)
	if err != nil {
		t.Fatalf("collect risk: %v", err)
	}
	r := risk.Risk
	if r.NewFindings != 4 || r.ClosedFindings != 1 || r.OpenFindings != 4 {
		t.Fatalf("risk overview = %+v", r)
	}
	if len(r.TypeDist) != 3 || r.TypeDist[0].Key != "SHADOW" || r.TypeDist[0].Value != 2 {
		t.Fatalf("risk type dist = %+v", r.TypeDist)
	}
	if len(r.SeverityDist) == 0 {
		t.Fatal("risk severity dist empty")
	}
	if len(r.TopEndpoints) != 2 {
		t.Fatalf("risk top endpoints = %+v", r.TopEndpoints)
	}
	// epA/epB 各 2 条，epB 高危 1 条应排前
	if r.TopEndpoints[0].Findings != 2 || r.TopEndpoints[0].High != 1 {
		t.Fatalf("risk top endpoint[0] = %+v, want findings=2 high=1", r.TopEndpoints[0])
	}
	if len(r.TopSubjects) != 1 || r.TopSubjects[0].SubjectType != "IDENTITY" {
		t.Fatalf("risk top subjects = %+v", r.TopSubjects)
	}
	// 主体指纹展示截断（不落完整指纹）
	if !strings.HasSuffix(r.TopSubjects[0].SubjectID, "…") || len(r.TopSubjects[0].SubjectID) > 16 {
		t.Fatalf("subject id not truncated: %q", r.TopSubjects[0].SubjectID)
	}

	// ---------- 弱点整改报告 ----------
	in.ReportType = reports.TypeAPIWeak
	weak, err := collector.CollectAPI(ctx, in)
	if err != nil {
		t.Fatalf("collect weakness: %v", err)
	}
	w := weak.Weakness
	if w.NewInRange != 2 || w.FixedInRange != 1 || w.OverdueOpen != 1 {
		t.Fatalf("weakness overview = %+v", w)
	}
	if w.RetestPass != 1 || w.RetestFail != 1 {
		t.Fatalf("weakness retest = %+v", w)
	}
	if len(w.OverdueList) != 1 || w.OverdueList[0].Code != "UNAUTHENTICATED_SENSITIVE_API" {
		t.Fatalf("overdue list = %+v", w.OverdueList)
	}
	if len(w.RetestList) != 2 {
		t.Fatalf("retest list = %+v", w.RetestList)
	}
	if len(w.StatusDist) != 2 { // TO_FIX + FIXED
		t.Fatalf("weakness status dist = %+v", w.StatusDist)
	}
	if len(w.SeverityDist) != 1 || w.SeverityDist[0].Key != "HIGH" { // 未闭环仅 w1
		t.Fatalf("weakness severity dist = %+v", w.SeverityDist)
	}

	// ---------- 敏感数据报告 ----------
	in.ReportType = reports.TypeAPISens
	sens, err := collector.CollectAPI(ctx, in)
	if err != nil {
		t.Fatalf("collect sensitive: %v", err)
	}
	s := sens.Sensitive
	if s.TotalFields != 4 || s.NewInRange != 3 {
		t.Fatalf("sensitive overview = %+v", s)
	}
	if len(s.TypeDist) != 3 || s.TypeDist[0].Key != "phone" || s.TypeDist[0].Value != 2 {
		t.Fatalf("sensitive type dist = %+v", s.TypeDist)
	}
	if len(s.TopEndpoints) != 2 {
		t.Fatalf("sensitive top endpoints = %+v", s.TopEndpoints)
	}
	if len(s.DailyNew) != 2 { // now-24h 与 now-48h 两天
		t.Fatalf("sensitive daily trend = %+v", s.DailyNew)
	}

	// ---------- 空数据态（历史区间无任何数据） ----------
	emptyIn := reports.CollectInput{
		Start: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		End:   time.Date(2020, 1, 8, 0, 0, 0, 0, time.UTC),
	}
	for _, typ := range []string{reports.TypeAPIAsset, reports.TypeAPIRisk, reports.TypeAPIWeak, reports.TypeAPISens} {
		emptyIn.ReportType = typ
		d, err := collector.CollectAPI(ctx, emptyIn)
		if err != nil {
			t.Fatalf("%s empty collect: %v", typ, err)
		}
		if len(d.Conclusions) == 0 {
			t.Fatalf("%s empty conclusions empty", typ)
		}
	}
	// 资产报告空区间的窗口过滤：新增/清单应为空，但总量不受区间限制
	emptyIn.ReportType = reports.TypeAPIAsset
	d, err := collector.CollectAPI(ctx, emptyIn)
	if err != nil {
		t.Fatal(err)
	}
	if d.Asset.NewEndpoints != 0 || len(d.Asset.NewList) != 0 {
		t.Fatalf("empty-range asset new = %+v", d.Asset)
	}
	if d.Asset.TotalEndpoints != 4 { // 总量为全量口径，不受区间限制
		t.Fatalf("empty-range asset total = %d, want 4", d.Asset.TotalEndpoints)
	}

	// 未知类型 → 明确错误（不静默吞错）
	if _, err := collector.CollectAPI(ctx, reports.CollectInput{ReportType: "API_XXX", Start: start, End: end}); err == nil {
		t.Fatal("unknown api report type should fail")
	}
}

// TestStage8APIReportsHTTP API 报告 HTTP 全链路（创建 → 生成 → 预览/下载）与权限边界。
func TestStage8APIReportsHTTP(t *testing.T) {
	env := setupStage8Env(t)
	secCookies, secCSRF := env.s5Login(t, "s8rsec", "SECURITY_ADMIN")
	audCookies, audCSRF := env.s5Login(t, "s8raud", "AUDIT_ADMIN")
	start, end, _, _, _, _ := s8rSeed(t, env)

	// 迁移 000059 落位：report_type 注释词表含 API 类型
	var comment string
	if err := env.db.QueryRow(context.Background(), `
SELECT col_description('report_jobs'::regclass, ordinal_position)
FROM information_schema.columns
WHERE table_name='report_jobs' AND column_name='report_type'`).Scan(&comment); err != nil {
		t.Fatalf("read report_type comment: %v", err)
	}
	for _, typ := range []string{"API_ASSET", "API_RISK", "API_WEAK", "API_SENS"} {
		if !strings.Contains(comment, typ) {
			t.Fatalf("report_type comment missing %s: %q", typ, comment)
		}
	}

	// 创建 API 资产周报（显式区间）
	body := fmt.Sprintf(`{"report_type":"API_ASSET","start_time":%q,"end_time":%q,"format":"html"}`,
		start.Format(time.RFC3339), end.Format(time.RFC3339))
	resp := env.post(t, "/api/v1/reports", body, secCookies, secCSRF)
	result := s5OK(t, resp, "create api asset report")
	reportID, _ := s5Obj(t, result, "report")["id"].(string)
	if reportID == "" {
		t.Fatal("no report id")
	}

	// 驱动真实生成管线（采集 → 渲染 → 落盘 → 完成）。
	// 测试环境不启动后台 Worker（StartStage6Workers 仅 main.go 调用，
	// 纪律同 stage6 报告测试的生成环节），直接同步调用同一 Generate。
	jobUUID, err := uuid.Parse(reportID)
	if err != nil {
		t.Fatalf("parse report id: %v", err)
	}
	gen := reports.NewGenerator(reports.NewStore(env.db), env.db, nil,
		env.cfg.Gateway.DataDir, reports.DefaultFontPath(), nil)
	if err := gen.Generate(context.Background(), jobUUID); err != nil {
		t.Fatalf("generate api report: %v", err)
	}
	resp = env.get(t, "/api/v1/reports/"+reportID, secCookies)
	result = s5OK(t, resp, "get api report")
	job := s5Obj(t, result, "report")
	if job["status"] != "SUCCESS" {
		t.Fatalf("api report status = %v, want SUCCESS（failure=%v）", job["status"], job["failure_message"])
	}
	if h, _ := job["file_hash"].(string); len(h) != 64 {
		t.Errorf("file_hash len = %d", len(h))
	}

	// 预览含 API 报告章节内容
	resp = env.get(t, "/api/v1/reports/"+reportID+"/preview", secCookies)
	preview := readBodyString(t, resp)
	for _, m := range []string{"API资产周报", "资产总览", "资产状态分布", "新增端点清单", "Shadow端点清单", "结论和建议"} {
		if !strings.Contains(preview, m) {
			t.Errorf("preview missing %q", m)
		}
	}

	// 下载（创建者本人）
	resp = env.get(t, "/api/v1/reports/"+reportID+"/download", secCookies)
	if data := readBodyBytes(t, resp); !strings.Contains(string(data[:200]), "<") {
		t.Errorf("download not html")
	}

	// 列表按 API 类型过滤
	resp = env.get(t, "/api/v1/reports?report_type=API_ASSET", secCookies)
	page := s8Page(t, resp, "list api reports")
	if page.Data.Total < 1 {
		t.Fatalf("api report list total = %d", page.Data.Total)
	}

	// 非法报告类型 400
	resp = env.post(t, "/api/v1/reports", `{"report_type":"API_XXX","format":"html"}`, secCookies, secCSRF)
	s5Expect(t, resp, http.StatusBadRequest, "invalid api report type")

	// 审计管理员无 reports.create → 403
	resp = env.post(t, "/api/v1/reports", body, audCookies, audCSRF)
	s5Expect(t, resp, http.StatusForbidden, "audit create api report")

	// 系统管理员无 reports.read → 403
	sysCookies, _ := env.s5Login(t, "s8rsys", "SYSTEM_ADMIN")
	resp = env.get(t, "/api/v1/reports?report_type=API_RISK", sysCookies)
	s5Expect(t, resp, http.StatusForbidden, "sysadmin list api reports")
}
