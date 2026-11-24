package tests

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/backups"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/reports"
)

// readBodyBytes 读取响应体字节。
func readBodyBytes(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return data
}

// s6WaitStatus 轮询任务状态直到目标集合或超时。
func (e *testEnv) s6WaitStatus(t *testing.T, path string, cookies []*http.Cookie, want map[string]bool, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp := e.get(t, path, cookies)
		result := s5OK(t, resp, "poll "+path)
		for _, key := range []string{"job", "report", "check", "restore"} {
			if obj, ok := result.Data[key].(map[string]interface{}); ok {
				if st, _ := obj["status"].(string); want[st] {
					return st
				}
			}
		}
		if st, _ := result.Data["status"].(string); want[st] {
			return st
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("poll %s timeout, want one of %v", path, want)
	return ""
}

// s6RunBackupWorker 同步执行全部待处理备份任务。
// 测试环境不启动 StartStage6Workers 后台循环（仅 main.go 调用），与报告用例同纪律改为同步驱动；
// 要求测试先 t.Setenv("JIUZHANG_MASTER_KEY", ...) 固定主密钥，与应用侧加解密保持一致。
func s6RunBackupWorker(t *testing.T, env *testEnv) {
	t.Helper()
	enc, err := encryption.NewFromEnv()
	if err != nil {
		t.Fatalf("encryption: %v", err)
	}
	worker := backups.NewWorker(backups.NewStore(env.db), backups.NewExporter(env.db, enc, env.cfg.Gateway.DataDir), nil)
	for {
		claimed, err := worker.ProcessOnce(context.Background())
		if err != nil {
			t.Fatalf("backup worker: %v", err)
		}
		if !claimed {
			return
		}
	}
}

// TestStage6DashboardRBAC 态势接口三权边界与结构。
func TestStage6DashboardRBAC(t *testing.T) {
	env := setupTestEnv(t)
	secCookies, _ := env.s5Login(t, "s6sec", "SECURITY_ADMIN")
	sysCookies, _ := env.s5Login(t, "s6sys", "SYSTEM_ADMIN")
	audCookies, _ := env.s5Login(t, "s6aud", "AUDIT_ADMIN")

	// 安全管理员：安全态势 200
	resp := env.get(t, "/api/v1/dashboard/security-overview", secCookies)
	result := s5OK(t, resp, "security overview")
	if _, ok := result.Data["today"].(map[string]interface{}); !ok {
		t.Errorf("today missing: %+v", result.Data)
	}
	// 系统管理员无安全态势权限
	resp = env.get(t, "/api/v1/dashboard/security-overview", sysCookies)
	s5Expect(t, resp, http.StatusForbidden, "sysadmin security overview")
	// 系统管理员（dashboard.runtime.read）与运维管理员（000232 big_screen.runtime.read）：运行态势 200
	resp = env.get(t, "/api/v1/dashboard/runtime-overview", sysCookies)
	s5OK(t, resp, "runtime overview")
	resp = env.get(t, "/api/v1/dashboard/runtime-overview", secCookies)
	s5OK(t, resp, "operadmin runtime overview")
	// 审计管理员：000100 收紧为纯审计角色，审计态势 403（dashboard.audit.read 移除）；运行态势 403
	resp = env.get(t, "/api/v1/dashboard/audit-overview", audCookies)
	s5Expect(t, resp, http.StatusForbidden, "audit overview")
	resp = env.get(t, "/api/v1/dashboard/runtime-overview", audCookies)
	s5Expect(t, resp, http.StatusForbidden, "audit runtime overview")
}

// TestStage6Analytics 统计分析接口。
func TestStage6Analytics(t *testing.T) {
	env := setupTestEnv(t)
	secCookies, _ := env.s5Login(t, "s6sec", "SECURITY_ADMIN")
	audCookies, _ := env.s5Login(t, "s6aud", "AUDIT_ADMIN")

	paths := []string{
		"/api/v1/analytics/request-trend", "/api/v1/analytics/security-event-trend",
		"/api/v1/analytics/risk-levels", "/api/v1/analytics/attack-types",
		"/api/v1/analytics/top-source-ips", "/api/v1/analytics/top-applications",
		"/api/v1/analytics/top-rules", "/api/v1/analytics/top-uris",
		"/api/v1/analytics/cc-overview", "/api/v1/analytics/access-control-overview",
	}
	for _, p := range paths {
		resp := env.get(t, p, secCookies)
		s5Expect(t, resp, http.StatusOK, "analytics "+p)
	}
	// 非法时间参数
	for _, q := range []string{
		"?start_time=2026-07-01T00:00:00Z&end_time=2026-06-01T00:00:00Z", // 倒置
		"?start_time=2020-01-01T00:00:00Z&end_time=2026-07-01T00:00:00Z", // >366天
		"?start_time=not-a-time",
	} {
		resp := env.get(t, "/api/v1/analytics/request-trend"+q, secCookies)
		s5Expect(t, resp, http.StatusBadRequest, "analytics bad params "+q)
	}
	// 审计管理员：000100 纯审计角色，处置统计 403（analytics.disposition.read 移除），安全统计 403
	resp := env.get(t, "/api/v1/analytics/disposition-overview", audCookies)
	s5Expect(t, resp, http.StatusForbidden, "disposition overview")
	resp = env.get(t, "/api/v1/analytics/request-trend", audCookies)
	s5Expect(t, resp, http.StatusForbidden, "audit request-trend")
}

// TestStage6ReportsLifecycle 报告全生命周期（真实异步生成）。
func TestStage6ReportsLifecycle(t *testing.T) {
	env := setupTestEnv(t)
	secCookies, secCSRF := env.s5Login(t, "s6sec", "SECURITY_ADMIN")
	audCookies, audCSRF := env.s5Login(t, "s6aud", "AUDIT_ADMIN")

	start := time.Now().AddDate(0, 0, -7).UTC().Format(time.RFC3339)
	end := time.Now().UTC().Format(time.RFC3339)
	// 内容范围显式 WAF：000086+ 内容范围门禁下，WAF 产品形态拒绝缺省 WAF_API 范围
	body := fmt.Sprintf(`{"report_type":"CUSTOM","content_scope":"WAF","start_time":%q,"end_time":%q,"format":"html"}`, start, end)
	resp := env.post(t, "/api/v1/reports", body, secCookies, secCSRF)
	result := s5OK(t, resp, "create report")
	job := s5Obj(t, result, "report")
	reportID, _ := job["id"].(string)
	if reportID == "" {
		t.Fatal("no report id")
	}
	// 非法时间范围
	resp = env.post(t, "/api/v1/reports", `{"report_type":"CUSTOM","start_time":"2020-01-01T00:00:00Z","end_time":"2026-01-01T00:00:00Z"}`, secCookies, secCSRF)
	s5Expect(t, resp, http.StatusBadRequest, "create report bad range")
	// 驱动真实生成管线：测试环境不启动后台 Worker（StartStage6Workers 仅 main.go
	// 调用，纪律同 stage8 API 报告用例），直接同步调用同一 Generate 后确认 SUCCESS。
	jobUUID, err := uuid.Parse(reportID)
	if err != nil {
		t.Fatalf("parse report id: %v", err)
	}
	gen := reports.NewGenerator(reports.NewStore(env.db), env.db, nil,
		env.cfg.Gateway.DataDir, reports.DefaultFontPath(), nil)
	if err := gen.Generate(context.Background(), jobUUID); err != nil {
		t.Fatalf("generate report: %v", err)
	}
	// 详情含 64 位哈希
	resp = env.get(t, "/api/v1/reports/"+reportID, secCookies)
	result = s5OK(t, resp, "get report")
	job = s5Obj(t, result, "report")
	if h, _ := job["file_hash"].(string); len(h) != 64 {
		t.Errorf("file_hash len = %d", len(h))
	}
	// 预览
	resp = env.get(t, "/api/v1/reports/"+reportID+"/preview", secCookies)
	preview := readBodyString(t, resp)
	if !strings.Contains(preview, "九章") {
		t.Errorf("preview missing content")
	}
	// 下载
	resp = env.get(t, "/api/v1/reports/"+reportID+"/download", secCookies)
	data := readBodyBytes(t, resp)
	if !strings.Contains(string(data[:200]), "<") {
		t.Errorf("download not html")
	}
	// 审计管理员：000100 移除 reports.download_audit → 下载 403，创建 403
	resp = env.get(t, "/api/v1/reports/"+reportID+"/download", audCookies)
	s5Expect(t, resp, http.StatusForbidden, "audit download")
	resp = env.post(t, "/api/v1/reports", body, audCookies, audCSRF)
	s5Expect(t, resp, http.StatusForbidden, "audit create report")
	// 系统管理员 403
	sysCookies, _ := env.s5Login(t, "s6sys", "SYSTEM_ADMIN")
	resp = env.get(t, "/api/v1/reports", sysCookies)
	s5Expect(t, resp, http.StatusForbidden, "sysadmin list reports")
	// 审计管理员删除（无 reports.delete_own）→ 403（路由层拒绝）
	resp = env.do(t, http.MethodDelete, "/api/v1/reports/"+reportID, "", audCookies, audCSRF)
	s5Expect(t, resp, http.StatusForbidden, "audit delete report")
	// 另一安全管理员删除他人报告：reports.delete_all（000084）放行 → 200
	resp = env.post(t, "/api/v1/reports", body, secCookies, secCSRF)
	job2 := s5Obj(t, s5OK(t, resp, "create report 2"), "report")
	report2ID, _ := job2["id"].(string)
	if report2ID == "" {
		t.Fatal("no report 2 id")
	}
	sec2Cookies, sec2CSRF := env.s5Login(t, "s6sec2", "SECURITY_ADMIN")
	resp = env.do(t, http.MethodDelete, "/api/v1/reports/"+report2ID, "", sec2Cookies, sec2CSRF)
	s5Expect(t, resp, http.StatusOK, "delete_all admin deletes others report")
	// 删除（本人）
	req, _ := http.NewRequest(http.MethodDelete, env.server.URL+"/api/v1/reports/"+reportID, nil)
	for _, c := range secCookies {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", secCSRF)
	delResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	s5Expect(t, delResp, http.StatusOK, "delete report")
}

// TestStage6ReportTemplates 报告模板。
func TestStage6ReportTemplates(t *testing.T) {
	env := setupTestEnv(t)
	secCookies, secCSRF := env.s5Login(t, "s6sec", "SECURITY_ADMIN")

	resp := env.get(t, "/api/v1/report-templates", secCookies)
	result := s5OK(t, resp, "list templates")
	var builtinID string
	items, _ := result.Data["items"].([]interface{})
	for _, it := range items {
		m, _ := it.(map[string]interface{})
		if m["is_builtin"] == true {
			builtinID, _ = m["id"].(string)
		}
	}
	if builtinID == "" {
		t.Fatal("builtin template missing")
	}
	// 创建自定义模板
	resp = env.post(t, "/api/v1/report-templates",
		`{"name":"tpl-`+s5Rand()+`","company_name":"聚信得仁","product_name":"九章WAF","prepared_by":"安全运营"}`, secCookies, secCSRF)
	result = s5OK(t, resp, "create template")
	tpl := s5Obj(t, result, "template")
	tplID, _ := tpl["id"].(string)
	if tplID == "" {
		t.Fatal("no template id")
	}
	// 内置模板禁改禁删：契约 400 INVALID_ARGUMENT「内置模板不允许修改或删除」
	// （templateRequest 无 version 字段，请求体不得携带，否则 DecodeJSON 未知字段 400）
	resp = env.do(t, http.MethodPut, "/api/v1/report-templates/"+builtinID, `{"name":"改名"}`, secCookies, secCSRF)
	s5Expect(t, resp, http.StatusBadRequest, "modify builtin template")
	// 删除自定义模板
	req, _ := http.NewRequest(http.MethodDelete, env.server.URL+"/api/v1/report-templates/"+tplID, nil)
	for _, c := range secCookies {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", secCSRF)
	delResp, _ := http.DefaultClient.Do(req)
	s5Expect(t, delResp, http.StatusOK, "delete custom template")
}

// TestStage6SystemHealth 运行监控（000232 起运维管理员凭 big_screen.runtime.read 可读大屏所需只读接口，
// 但 /components 与 /metrics 仍仅限系统管理员 system_health.read）。
func TestStage6SystemHealth(t *testing.T) {
	env := setupTestEnv(t)
	sysCookies, _ := env.s5Login(t, "s6sys", "SYSTEM_ADMIN")
	secCookies, _ := env.s5Login(t, "s6sec", "SECURITY_ADMIN")
	audCookies, _ := env.s5Login(t, "s6aud", "AUDIT_ADMIN")

	for _, p := range []string{"/api/v1/system-health", "/api/v1/system-health/storage", "/api/v1/system-health/gateway-trend"} {
		s5Expect(t, env.get(t, p, sysCookies), http.StatusOK, "sys admin system health "+p)
		s5Expect(t, env.get(t, p, secCookies), http.StatusOK, "oper admin big-screen "+p)
		s5Expect(t, env.get(t, p, audCookies), http.StatusForbidden, "audit admin system health "+p)
	}
	for _, p := range []string{"/api/v1/system-health/components", "/api/v1/metrics"} {
		s5Expect(t, env.get(t, p, sysCookies), http.StatusOK, "sys admin ops-only "+p)
		s5Expect(t, env.get(t, p, secCookies), http.StatusForbidden, "oper admin forbidden "+p)
	}
	resp := env.get(t, "/api/v1/system-health/storage", sysCookies)
	result := s5OK(t, resp, "storage")
	if s5Num(t, result.Data, "postgres_size_bytes") <= 0 {
		t.Errorf("postgres_size_bytes = 0")
	}
}

// TestStage6SystemAlerts 系统告警流转（000232 起安全态势/系统告警归运维管理员 SECURITY_ADMIN；
// 系统管理员与审计管理员均无权访问）。
func TestStage6SystemAlerts(t *testing.T) {
	env := setupTestEnv(t)
	sysCookies, sysCSRF := env.s5Login(t, "s6sys", "SYSTEM_ADMIN")
	secCookies, secCSRF := env.s5Login(t, "s6sec", "SECURITY_ADMIN")
	audCookies, audCSRF := env.s5Login(t, "s6aud", "AUDIT_ADMIN")

	s5Expect(t, env.get(t, "/api/v1/system-alerts", sysCookies), http.StatusForbidden, "sysadmin list alerts forbidden")

	resp := env.get(t, "/api/v1/system-alerts", secCookies)
	result := s5OK(t, resp, "list alerts")
	if _, ok := result.Data["total"]; !ok {
		t.Fatalf("total missing")
	}
	// 找一条 OPEN 告警操作（无则跳过操作部分）
	var openID string
	items, _ := result.Data["items"].([]interface{})
	for _, it := range items {
		m, _ := it.(map[string]interface{})
		if m["status"] == "OPEN" {
			openID, _ = m["id"].(string)
			break
		}
	}
	if openID != "" {
		// 确认（运维管理员）
		resp = env.post(t, "/api/v1/system-alerts/"+openID+"/acknowledge", `{}`, secCookies, secCSRF)
		s5Expect(t, resp, http.StatusOK, "acknowledge alert")
		// 系统管理员操作 403
		resp = env.post(t, "/api/v1/system-alerts/"+openID+"/resolve", `{}`, sysCookies, sysCSRF)
		s5Expect(t, resp, http.StatusForbidden, "sysadmin resolve alert")
		// 审计管理员操作 403
		resp = env.post(t, "/api/v1/system-alerts/"+openID+"/resolve", `{}`, audCookies, audCSRF)
		s5Expect(t, resp, http.StatusForbidden, "audit resolve alert")
		// 备注（运维管理员）
		resp = env.post(t, "/api/v1/system-alerts/"+openID+"/notes", `{"note":"排查中"}`, secCookies, secCSRF)
		s5Expect(t, resp, http.StatusOK, "add note")
	}
	// 不存在 ID
	resp = env.get(t, "/api/v1/system-alerts/00000000-0000-0000-0000-000000000000", secCookies)
	s5Expect(t, resp, http.StatusNotFound, "alert not found")
}

// TestStage6SystemAlertsExport 系统告警导出（§11.4）：CSV、防公式注入。
// 权限语义按 000232 三权重划：系统告警归运维管理员（SECURITY_ADMIN）持有，可导出；
// SYSTEM_ADMIN 与 AUDIT_ADMIN 不含 system_alerts.* 权限，导出 403。
func TestStage6SystemAlertsExport(t *testing.T) {
	env := setupTestEnv(t)
	sysCookies, _ := env.s5Login(t, "s6sys", "SYSTEM_ADMIN")
	secCookies, _ := env.s5Login(t, "s6sec", "SECURITY_ADMIN")
	audCookies, _ := env.s5Login(t, "s6aud", "AUDIT_ADMIN")

	checkExport := func(cookies []*http.Cookie, who string) {
		t.Helper()
		resp := env.get(t, "/api/v1/system-alerts/export", cookies)
		body := readBodyString(t, resp)
		ct := resp.Header.Get("Content-Type")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s export alerts status = %d, body: %s", who, resp.StatusCode, body)
		}
		if !strings.HasPrefix(ct, "text/csv") {
			t.Errorf("%s export Content-Type = %q, want text/csv", who, ct)
		}
		if !strings.HasPrefix(body, "id,alert_type,severity,") {
			t.Errorf("%s export 缺少表头，body 前缀: %q", who, body[:min(len(body), 64)])
		}
	}
	checkExport(secCookies, "SECURITY_ADMIN")

	// 000232 角色收敛：SYSTEM_ADMIN 与 AUDIT_ADMIN 无 system_alerts.* 权限 → 导出 403
	s5Expect(t, env.get(t, "/api/v1/system-alerts/export", sysCookies), http.StatusForbidden, "sysadmin export")
	s5Expect(t, env.get(t, "/api/v1/system-alerts/export", audCookies), http.StatusForbidden, "audit admin export")

	// 非法筛选参数 → 400（用有权限角色验证，避免被 403 前置拦截掩盖参数校验）
	s5Expect(t, env.get(t, "/api/v1/system-alerts/export?severity=BOGUS", secCookies), http.StatusBadRequest, "export with invalid severity")
}

// TestStage6BackupsLifecycle 备份全生命周期。
func TestStage6BackupsLifecycle(t *testing.T) {
	// 固定主密钥：测试侧同步驱动备份执行器需与应用使用同一密钥加解密备份文件。
	t.Setenv("JIUZHANG_MASTER_KEY", strings.Repeat("ab", 32))
	env := setupTestEnv(t)
	sysCookies, sysCSRF := env.s5Login(t, "s6sys", "SYSTEM_ADMIN")
	secCookies, secCSRF := env.s5Login(t, "s6sec", "SECURITY_ADMIN")

	// 安全管理员无备份权限
	resp := env.post(t, "/api/v1/backups", `{"backup_type":"FULL"}`, secCookies, secCSRF)
	s5Expect(t, resp, http.StatusForbidden, "sec admin create backup")

	resp = env.post(t, "/api/v1/backups", `{"backup_type":"FULL"}`, sysCookies, sysCSRF)
	result := s5OK(t, resp, "create backup")
	job := s5Obj(t, result, "job")
	backupID, _ := job["id"].(string)
	// 测试环境不启动 StartStage6Workers 后台循环（仅 main.go 调用），同步驱动备份执行器。
	s6RunBackupWorker(t, env)
	st := env.s6WaitStatus(t, "/api/v1/backups/"+backupID, sysCookies,
		map[string]bool{"SUCCESS": true, "FAILED": true}, 10*time.Second)
	if st != "SUCCESS" {
		t.Fatalf("backup status = %s", st)
	}
	// 哈希与验证
	resp = env.get(t, "/api/v1/backups/"+backupID, sysCookies)
	result = s5OK(t, resp, "get backup")
	job = s5Obj(t, result, "job")
	if h, _ := job["file_hash"].(string); len(h) != 64 {
		t.Errorf("file_hash len = %d", len(h))
	}
	resp = env.post(t, "/api/v1/backups/"+backupID+"/verify", `{}`, sysCookies, sysCSRF)
	s5Expect(t, resp, http.StatusOK, "verify backup")
	// 下载（magic JZBK0001）
	resp = env.get(t, "/api/v1/backups/"+backupID+"/download", sysCookies)
	data := readBodyBytes(t, resp)
	if len(data) < 8 || string(data[:8]) != "JZBK0001" {
		t.Errorf("backup magic = %q", data[:8])
	}

	// 恢复：validate → create → AWAITING_CONFIRM → cancel
	resp = env.post(t, "/api/v1/restores/validate", fmt.Sprintf(`{"backup_job_id":%q}`, backupID), sysCookies, sysCSRF)
	s5Expect(t, resp, http.StatusOK, "restore validate")
	resp = env.post(t, "/api/v1/restores", fmt.Sprintf(`{"backup_job_id":%q,"scope":"CONFIG"}`, backupID), sysCookies, sysCSRF)
	result = s5OK(t, resp, "create restore")
	rJob := s5Obj(t, result, "job")
	restoreID, _ := rJob["id"].(string)
	st = env.s6WaitStatus(t, "/api/v1/restores/"+restoreID, sysCookies,
		map[string]bool{"AWAITING_CONFIRM": true, "FAILED": true}, 60*time.Second)
	if st != "AWAITING_CONFIRM" {
		t.Fatalf("restore status = %s", st)
	}
	resp = env.post(t, "/api/v1/restores/"+restoreID+"/cancel", `{}`, sysCookies, sysCSRF)
	s5Expect(t, resp, http.StatusOK, "cancel restore")

	// 导入：multipart 上传（先篡改一份必须失败）
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "backup.jzbk")
	_, _ = fw.Write(data)
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/api/v1/restores/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	for _, c := range sysCookies {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", sysCSRF)
	impResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	impResult := s5OK(t, impResp, "import backup")
	// 导入接口直接返回任务对象（response.JSON(job)，不包 "job" 键）
	impID, _ := impResult.Data["id"].(string)
	if impID == "" {
		t.Fatal("import no id")
	}
	// 篡改文件导入必须 400
	data[100] ^= 0xff
	var buf2 bytes.Buffer
	mw2 := multipart.NewWriter(&buf2)
	fw2, _ := mw2.CreateFormFile("file", "tampered.jzbk")
	_, _ = fw2.Write(data)
	_ = mw2.Close()
	req2, _ := http.NewRequest(http.MethodPost, env.server.URL+"/api/v1/restores/import", &buf2)
	req2.Header.Set("Content-Type", mw2.FormDataContentType())
	for _, c := range sysCookies {
		req2.AddCookie(c)
	}
	req2.Header.Set("X-CSRF-Token", sysCSRF)
	imp2, _ := http.DefaultClient.Do(req2)
	s5Expect(t, imp2, http.StatusBadRequest, "import tampered backup")

	// 删除备份（未被恢复任务引用的另一个备份记录）
	resp = env.post(t, "/api/v1/backups", `{"backup_type":"CONFIG_ONLY"}`, sysCookies, sysCSRF)
	result = s5OK(t, resp, "create config backup")
	job2 := s5Obj(t, result, "job")
	cfgBackupID, _ := job2["id"].(string)
	s6RunBackupWorker(t, env)
	env.s6WaitStatus(t, "/api/v1/backups/"+cfgBackupID, sysCookies,
		map[string]bool{"SUCCESS": true, "FAILED": true}, 10*time.Second)
	req3, _ := http.NewRequest(http.MethodDelete, env.server.URL+"/api/v1/backups/"+cfgBackupID, nil)
	for _, c := range sysCookies {
		req3.AddCookie(c)
	}
	req3.Header.Set("X-CSRF-Token", sysCSRF)
	delResp, _ := http.DefaultClient.Do(req3)
	s5Expect(t, delResp, http.StatusOK, "delete config backup")
	_ = io.EOF
}

// TestStage6UpgradePrecheck 升级包登记与预检。
func TestStage6UpgradePrecheck(t *testing.T) {
	env := setupTestEnv(t)
	sysCookies, sysCSRF := env.s5Login(t, "s6sys", "SYSTEM_ADMIN")
	secCookies, secCSRF := env.s5Login(t, "s6sec", "SECURITY_ADMIN")

	hash := strings.Repeat("a", 64)
	// 安全管理员无升级权限
	resp := env.post(t, "/api/v1/upgrades/packages",
		fmt.Sprintf(`{"file_name":"p.tar.gz","version_from":"2.0.0","version_to":"2.0.1","file_hash":%q,"file_size":1}`, hash), secCookies, secCSRF)
	s5Expect(t, resp, http.StatusForbidden, "sec admin register package")
	// 非法哈希：契约（UPGRADE_ROLLBACK_DESIGN）为 200 + REJECTED 登记留证并返回失败原因
	resp = env.post(t, "/api/v1/upgrades/packages",
		`{"file_name":"p.tar.gz","version_from":"2.0.0","version_to":"2.0.1","file_hash":"xyz","file_size":1}`, sysCookies, sysCSRF)
	result := s5OK(t, resp, "register bad hash")
	if pkg := s5Obj(t, result, "package"); pkg["status"] != "REJECTED" {
		t.Errorf("bad hash package status = %v, want REJECTED", pkg["status"])
	}
	// 非法版本：同样 200 + REJECTED 留证
	resp = env.post(t, "/api/v1/upgrades/packages",
		fmt.Sprintf(`{"file_name":"p.tar.gz","version_from":"x.y","version_to":"2.0.1","file_hash":%q,"file_size":1}`, hash), sysCookies, sysCSRF)
	result = s5OK(t, resp, "register bad version")
	if pkg := s5Obj(t, result, "package"); pkg["status"] != "REJECTED" {
		t.Errorf("bad version package status = %v, want REJECTED", pkg["status"])
	}
	// 正常登记 + 预检
	resp = env.post(t, "/api/v1/upgrades/packages",
		fmt.Sprintf(`{"file_name":"jiuzhang-2.0.1.tar.gz","version_from":"2.0.0","version_to":"2.0.1","file_hash":%q,"file_size":1024}`, hash), sysCookies, sysCSRF)
	result = s5OK(t, resp, "register package")
	pkg := s5Obj(t, result, "package")
	pkgID, _ := pkg["id"].(string)
	resp = env.post(t, "/api/v1/upgrades/precheck", fmt.Sprintf(`{"package_id":%q}`, pkgID), sysCookies, sysCSRF)
	result = s5OK(t, resp, "precheck")
	if _, ok := result.Data["precheck"].([]interface{}); !ok {
		t.Errorf("precheck items missing: %+v", result.Data)
	}
}

// TestStage6DeliveryCheck 交付检查。
func TestStage6DeliveryCheck(t *testing.T) {
	env := setupTestEnv(t)
	sysCookies, sysCSRF := env.s5Login(t, "s6sys", "SYSTEM_ADMIN")
	audCookies, audCSRF := env.s5Login(t, "s6aud", "AUDIT_ADMIN")

	resp := env.post(t, "/api/v1/delivery-checks/run", ``, sysCookies, sysCSRF)
	result := s5OK(t, resp, "run delivery check")
	chk := s5Obj(t, result, "check")
	checkID, _ := chk["id"].(string)
	if checkID == "" {
		t.Fatal("no check id")
	}
	time.Sleep(3 * time.Second)
	resp = env.get(t, "/api/v1/delivery-checks/"+checkID, sysCookies)
	result = s5OK(t, resp, "get delivery check")
	checkObj, ok := result.Data["check"].(map[string]interface{})
	if !ok {
		checkObj = result.Data
	}
	total := s5Num(t, checkObj, "total")
	if total < 20 {
		t.Errorf("total items = %v, want >=20", total)
	}
	overall, _ := checkObj["overall_result"].(string)
	switch overall {
	case "PASS", "WARNING", "FAIL":
	default:
		t.Errorf("overall_result = %q", overall)
	}
	// 审计管理员：000100 移除 delivery_checks.read → GET/run 均 403
	resp = env.get(t, "/api/v1/delivery-checks", audCookies)
	s5Expect(t, resp, http.StatusForbidden, "audit list checks")
	resp = env.post(t, "/api/v1/delivery-checks/run", ``, audCookies, audCSRF)
	s5Expect(t, resp, http.StatusForbidden, "audit run check")
}
