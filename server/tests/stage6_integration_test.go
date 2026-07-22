package tests

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"
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
	// 系统管理员：运行态势 200
	resp = env.get(t, "/api/v1/dashboard/runtime-overview", sysCookies)
	s5OK(t, resp, "runtime overview")
	// 审计管理员：审计态势 200；运行态势 403
	resp = env.get(t, "/api/v1/dashboard/audit-overview", audCookies)
	s5OK(t, resp, "audit overview")
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
	// 审计管理员：处置统计 200，安全统计 403
	resp := env.get(t, "/api/v1/analytics/disposition-overview", audCookies)
	s5OK(t, resp, "disposition overview")
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
	body := fmt.Sprintf(`{"report_type":"CUSTOM","start_time":%q,"end_time":%q,"format":"html"}`, start, end)
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
	// 轮询至 SUCCESS
	st := env.s6WaitStatus(t, "/api/v1/reports/"+reportID, secCookies, map[string]bool{"SUCCESS": true, "FAILED": true}, 120*time.Second)
	if st != "SUCCESS" {
		t.Fatalf("report status = %s", st)
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
	// 审计管理员可下载（download_audit），创建 403
	resp = env.get(t, "/api/v1/reports/"+reportID+"/download", audCookies)
	s5Expect(t, resp, http.StatusOK, "audit download")
	resp = env.post(t, "/api/v1/reports", body, audCookies, audCSRF)
	s5Expect(t, resp, http.StatusForbidden, "audit create report")
	// 系统管理员 403
	sysCookies, _ := env.s5Login(t, "s6sys", "SYSTEM_ADMIN")
	resp = env.get(t, "/api/v1/reports", sysCookies)
	s5Expect(t, resp, http.StatusForbidden, "sysadmin list reports")
	// 删除
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
	// 内置模板禁改禁删
	resp = env.do(t, http.MethodPut, "/api/v1/report-templates/"+builtinID, `{"name":"改名","version":1}`, secCookies, secCSRF)
	s5Expect(t, resp, http.StatusForbidden, "modify builtin template")
	// 删除自定义模板
	req, _ := http.NewRequest(http.MethodDelete, env.server.URL+"/api/v1/report-templates/"+tplID, nil)
	for _, c := range secCookies {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", secCSRF)
	delResp, _ := http.DefaultClient.Do(req)
	s5Expect(t, delResp, http.StatusOK, "delete custom template")
}

// TestStage6SystemHealth 运行监控。
func TestStage6SystemHealth(t *testing.T) {
	env := setupTestEnv(t)
	sysCookies, _ := env.s5Login(t, "s6sys", "SYSTEM_ADMIN")
	secCookies, _ := env.s5Login(t, "s6sec", "SECURITY_ADMIN")

	for _, p := range []string{"/api/v1/system-health", "/api/v1/system-health/components", "/api/v1/system-health/storage"} {
		resp := env.get(t, p, sysCookies)
		s5Expect(t, resp, http.StatusOK, "system health "+p)
		resp = env.get(t, p, secCookies)
		s5Expect(t, resp, http.StatusForbidden, "sec admin system health "+p)
	}
	resp := env.get(t, "/api/v1/system-health/storage", sysCookies)
	result := s5OK(t, resp, "storage")
	if s5Num(t, result.Data, "postgres_size_bytes") <= 0 {
		t.Errorf("postgres_size_bytes = 0")
	}
}

// TestStage6SystemAlerts 系统告警流转。
func TestStage6SystemAlerts(t *testing.T) {
	env := setupTestEnv(t)
	sysCookies, sysCSRF := env.s5Login(t, "s6sys", "SYSTEM_ADMIN")
	secCookies, secCSRF := env.s5Login(t, "s6sec", "SECURITY_ADMIN")
	audCookies, audCSRF := env.s5Login(t, "s6aud", "AUDIT_ADMIN")

	resp := env.get(t, "/api/v1/system-alerts", sysCookies)
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
		// 确认（系统管理员）
		resp = env.post(t, "/api/v1/system-alerts/"+openID+"/acknowledge", `{}`, sysCookies, sysCSRF)
		s5Expect(t, resp, http.StatusOK, "acknowledge alert")
		// 审计管理员操作 403
		resp = env.post(t, "/api/v1/system-alerts/"+openID+"/resolve", `{}`, audCookies, audCSRF)
		s5Expect(t, resp, http.StatusForbidden, "audit resolve alert")
		// 备注
		resp = env.post(t, "/api/v1/system-alerts/"+openID+"/notes", `{"note":"排查中"}`, sysCookies, sysCSRF)
		s5Expect(t, resp, http.StatusOK, "add note")
	}
	// 不存在 ID
	resp = env.get(t, "/api/v1/system-alerts/00000000-0000-0000-0000-000000000000", sysCookies)
	s5Expect(t, resp, http.StatusNotFound, "alert not found")
	_ = secCookies
	_ = secCSRF
}

// TestStage6BackupsLifecycle 备份全生命周期。
func TestStage6BackupsLifecycle(t *testing.T) {
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
	st := env.s6WaitStatus(t, "/api/v1/backups/"+backupID, sysCookies,
		map[string]bool{"SUCCESS": true, "FAILED": true}, 300*time.Second)
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
		map[string]bool{"AWAITING_CONFIRM": true, "FAILED": true}, 300*time.Second)
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
	impJob := s5Obj(t, impResult, "job")
	impID, _ := impJob["id"].(string)
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
	env.s6WaitStatus(t, "/api/v1/backups/"+cfgBackupID, sysCookies,
		map[string]bool{"SUCCESS": true, "FAILED": true}, 300*time.Second)
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
	// 非法哈希
	resp = env.post(t, "/api/v1/upgrades/packages",
		`{"file_name":"p.tar.gz","version_from":"2.0.0","version_to":"2.0.1","file_hash":"xyz","file_size":1}`, sysCookies, sysCSRF)
	s5Expect(t, resp, http.StatusBadRequest, "register bad hash")
	// 非法版本
	resp = env.post(t, "/api/v1/upgrades/packages",
		fmt.Sprintf(`{"file_name":"p.tar.gz","version_from":"x.y","version_to":"2.0.1","file_hash":%q,"file_size":1}`, hash), sysCookies, sysCSRF)
	s5Expect(t, resp, http.StatusBadRequest, "register bad version")
	// 正常登记 + 预检
	resp = env.post(t, "/api/v1/upgrades/packages",
		fmt.Sprintf(`{"file_name":"jiuzhang-2.0.1.tar.gz","version_from":"2.0.0","version_to":"2.0.1","file_hash":%q,"file_size":1024}`, hash), sysCookies, sysCSRF)
	result := s5OK(t, resp, "register package")
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
	// 审计管理员只读可 GET、不可 run
	resp = env.get(t, "/api/v1/delivery-checks", audCookies)
	s5Expect(t, resp, http.StatusOK, "audit list checks")
	resp = env.post(t, "/api/v1/delivery-checks/run", ``, audCookies, audCSRF)
	s5Expect(t, resp, http.StatusForbidden, "audit run check")
}
