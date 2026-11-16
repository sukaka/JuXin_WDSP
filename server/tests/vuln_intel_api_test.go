package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// vulnIntelImportBody 构造导入请求体。
func vulnIntelImportBody(cveID, severity string, score float64, techs []string) string {
	quoted := make([]string, len(techs))
	for i, tech := range techs {
		quoted[i] = fmt.Sprintf("%q", tech)
	}
	return fmt.Sprintf(`{"advisories":[{"cve_id":%q,"summary":"PHP vulnerability %s","severity":%q,"cvss_score":%v,"published_at":"2026-10-21T08:00:00Z","tech_tags":[%s],"references":["https://example.com/%s"]}]}`,
		cveID, cveID, severity, score, strings.Join(quoted, ","), cveID)
}

// TestVulnIntelAPI 漏洞情报接口闭环（VULN_INTEL MVP）：
// 导入校验与幂等、VULN_INTEL_NEW 告警聚合与 vuln_alerted 去重、受影响应用文案、
// 列表/详情/概览、订阅设置门槛、技术资产映射、SECURITY_ADMIN 只读、CSRF 强制。
func TestVulnIntelAPI(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	ctx := context.Background()

	// ---- 订阅设置默认值 ----
	resp := env.get(t, "/api/v1/vuln-intel/settings", cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get settings status = %d", resp.StatusCode)
	}
	var settingsResp apiResp
	readJSON(t, resp, &settingsResp)
	resp.Body.Close()
	techs, _ := settingsResp.Data["watch_techs"].([]interface{})
	if len(techs) != 1 || techs[0] != "php" || settingsResp.Data["min_severity"] != "HIGH" || settingsResp.Data["sync_enabled"] != false {
		t.Fatalf("默认订阅设置 = %v", settingsResp.Data)
	}

	// ---- 导入：1 条合法 + 1 条非法 CVE ----
	body := `{"advisories":[` +
		`{"cve_id":"CVE-2026-7001","summary":"PHP unserialize RCE","severity":"CRITICAL","cvss_score":9.8,"published_at":"2026-10-20T08:00:00Z","tech_tags":["php"],"references":["https://example.com/CVE-2026-7001"]},` +
		`{"cve_id":"BAD-2026-1","summary":"bad cve","tech_tags":["php"]}` +
		`]}`
	resp = env.post(t, "/api/v1/vuln-intel/import", body, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("import status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var importResp apiResp
	readJSON(t, resp, &importResp)
	resp.Body.Close()
	if importResp.Data["inserted"].(float64) != 1 || importResp.Data["invalid"].(float64) != 1 ||
		importResp.Data["alerts_raised"].(float64) != 1 {
		t.Fatalf("import 结果 = %v", importResp.Data)
	}

	// ---- VULN_INTEL_NEW 系统告警生成（CRITICAL）----
	if n := s8Count(t, env, `SELECT count(*) FROM system_alerts WHERE alert_type='VULN_INTEL_NEW' AND component='vuln_intel:php'`); n != 1 {
		t.Fatalf("VULN_INTEL_NEW 告警数 = %d, want 1", n)
	}
	var alertMsg, alertSev string
	if err := env.db.QueryRow(ctx,
		`SELECT message, severity FROM system_alerts WHERE alert_type='VULN_INTEL_NEW' AND component='vuln_intel:php'`).
		Scan(&alertMsg, &alertSev); err != nil {
		t.Fatal(err)
	}
	if alertSev != "CRITICAL" {
		t.Errorf("含 CRITICAL 批次应升 CRITICAL, got %s", alertSev)
	}
	for _, want := range []string{"CVE-2026-7001", "最高级别：CRITICAL", "发布日期：2026-10-20", "未标记使用 PHP 的应用"} {
		if !strings.Contains(alertMsg, want) {
			t.Errorf("告警文案缺少 %q\n%s", want, alertMsg)
		}
	}
	// vuln_alerted 去重记录
	if n := s8Count(t, env, `SELECT count(*) FROM vuln_alerted WHERE tech_name='php'`); n != 1 {
		t.Fatalf("vuln_alerted 记录 = %d, want 1", n)
	}

	// ---- 重复导入同 CVE：更新不新建、不重复提醒 ----
	resp = env.post(t, "/api/v1/vuln-intel/import", vulnIntelImportBody("CVE-2026-7001", "CRITICAL", 9.8, []string{"php"}), cookies, csrf)
	readJSON(t, resp, &importResp)
	resp.Body.Close()
	if importResp.Data["inserted"].(float64) != 0 || importResp.Data["updated"].(float64) != 1 ||
		importResp.Data["alerts_raised"].(float64) != 0 {
		t.Fatalf("重复导入应更新不提醒: %v", importResp.Data)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM system_alerts WHERE alert_type='VULN_INTEL_NEW'`); n != 1 {
		t.Fatalf("重复导入后告警数 = %d, want 1（不重复提醒）", n)
	}
	// 处置首条告警（RESOLVED），后续新漏洞产生全新告警（避免引擎合并冷却干扰文案断言）
	if _, err := env.db.Exec(ctx,
		`UPDATE system_alerts SET status='RESOLVED', resolved_at=now(), resolve_type='MANUAL' WHERE alert_type='VULN_INTEL_NEW'`); err != nil {
		t.Fatal(err)
	}

	// ---- 技术资产映射：标记 PHP 应用后告警文案含应用名 ----
	var appID string
	if err := env.db.QueryRow(ctx,
		`INSERT INTO applications(code,name) VALUES ('vi-shop','商城门户') RETURNING id`).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	resp = env.do(t, http.MethodPut, "/api/v1/vuln-intel/tech-assets",
		fmt.Sprintf(`{"items":[{"application_id":%q,"tech_tags":["php"]}]}`, appID), cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put tech-assets status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	resp.Body.Close()

	resp = env.get(t, "/api/v1/vuln-intel/tech-assets", cookies)
	var assetsResp apiResp
	readJSON(t, resp, &assetsResp)
	resp.Body.Close()
	items, _ := assetsResp.Data["items"].([]interface{})
	foundAsset := false
	for _, it := range items {
		m, _ := it.(map[string]interface{})
		if m["application_id"] == appID {
			tags, _ := m["tech_tags"].([]interface{})
			if len(tags) == 1 && tags[0] == "php" {
				foundAsset = true
			}
		}
	}
	if !foundAsset {
		t.Fatalf("tech-assets 未返回应用映射: %v", items)
	}

	// 导入第二条（HIGH）：聚合提醒 + 文案含受影响应用名（首条已 RESOLVED，产生全新告警）
	resp = env.post(t, "/api/v1/vuln-intel/import", vulnIntelImportBody("CVE-2026-7002", "HIGH", 8.1, []string{"php"}), cookies, csrf)
	readJSON(t, resp, &importResp)
	resp.Body.Close()
	if importResp.Data["alerts_raised"].(float64) != 1 {
		t.Fatalf("第二条导入 alerts_raised = %v", importResp.Data["alerts_raised"])
	}
	if n := s8Count(t, env, `SELECT count(*) FROM system_alerts WHERE alert_type='VULN_INTEL_NEW'`); n != 2 {
		t.Fatalf("VULN_INTEL_NEW 告警总数 = %d, want 2（1 RESOLVED + 1 OPEN）", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM system_alerts WHERE alert_type='VULN_INTEL_NEW' AND status='OPEN' AND severity='HIGH'`); n != 1 {
		t.Fatalf("新告警（HIGH/OPEN）= %d, want 1", n)
	}
	if err := env.db.QueryRow(ctx,
		`SELECT message FROM system_alerts WHERE alert_type='VULN_INTEL_NEW' AND status='OPEN'`).Scan(&alertMsg); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CVE-2026-7002", "商城门户"} {
		if !strings.Contains(alertMsg, want) {
			t.Errorf("新告警文案缺少 %q\n%s", want, alertMsg)
		}
	}
	if n := s8Count(t, env, `SELECT count(*) FROM vuln_alerted WHERE tech_name='php'`); n != 2 {
		t.Fatalf("vuln_alerted 记录 = %d, want 2", n)
	}

	// ---- 列表/详情/概览 ----
	resp = env.get(t, "/api/v1/vuln-intel/advisories?severity=CRITICAL&tech=php", cookies)
	var listResp apiResp
	readJSON(t, resp, &listResp)
	resp.Body.Close()
	if listResp.Data["total"].(float64) != 1 {
		t.Fatalf("severity=CRITICAL 过滤 total = %v", listResp.Data["total"])
	}
	resp = env.get(t, "/api/v1/vuln-intel/advisories/CVE-2026-7002", cookies)
	var detailResp apiResp
	readJSON(t, resp, &detailResp)
	resp.Body.Close()
	affected, _ := detailResp.Data["affected_apps"].([]interface{})
	if len(affected) != 1 {
		t.Fatalf("详情受影响应用 = %v", affected)
	}
	if m, _ := affected[0].(map[string]interface{}); m["name"] != "商城门户" || m["tech"] != "php" {
		t.Errorf("受影响应用 = %v", affected[0])
	}
	resp = env.get(t, "/api/v1/vuln-intel/advisories/CVE-2026-9999", cookies)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("不存在 CVE 应 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = env.get(t, "/api/v1/vuln-intel/advisories/bad-cve", cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("非法 CVE 形态应 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = env.get(t, "/api/v1/vuln-intel/advisories?severity=P0", cookies)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("非法 severity 过滤应 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = env.get(t, "/api/v1/vuln-intel/overview", cookies)
	var ovResp apiResp
	readJSON(t, resp, &ovResp)
	resp.Body.Close()
	if ovResp.Data["total"].(float64) != 2 || ovResp.Data["critical_count"].(float64) != 1 ||
		ovResp.Data["high_count"].(float64) != 1 {
		t.Fatalf("overview = %v", ovResp.Data)
	}
	st, _ := ovResp.Data["sync_state"].(map[string]interface{})
	if st["status"] != "IDLE" {
		t.Errorf("未同步过应 IDLE: %v", st)
	}

	// ---- 订阅设置：非法 400；调高门槛后 HIGH 不再提醒 ----
	resp = env.do(t, http.MethodPut, "/api/v1/vuln-intel/settings",
		`{"watch_techs":["php"],"min_severity":"P0","sync_enabled":false}`, cookies, csrf)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("非法 min_severity 应 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = env.do(t, http.MethodPut, "/api/v1/vuln-intel/settings",
		`{"watch_techs":["php"],"min_severity":"CRITICAL","sync_enabled":false}`, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put settings status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	resp.Body.Close()
	// min_severity=CRITICAL 时 HIGH 导入不提醒
	resp = env.post(t, "/api/v1/vuln-intel/import", vulnIntelImportBody("CVE-2026-7003", "HIGH", 7.2, []string{"php"}), cookies, csrf)
	readJSON(t, resp, &importResp)
	resp.Body.Close()
	if importResp.Data["alerts_raised"].(float64) != 0 {
		t.Errorf("min_severity=CRITICAL 时 HIGH 不应提醒: %v", importResp.Data["alerts_raised"])
	}
	if n := s8Count(t, env, `SELECT count(*) FROM vuln_alerted`); n != 2 {
		t.Errorf("未达门槛不应记 vuln_alerted: %d", n)
	}
	// 恢复默认门槛（不影响其他用例）
	resp = env.do(t, http.MethodPut, "/api/v1/vuln-intel/settings",
		`{"watch_techs":["php"],"min_severity":"HIGH","sync_enabled":false}`, cookies, csrf)
	resp.Body.Close()

	// ---- 写操作审计 ----
	if n := s8Count(t, env, `SELECT count(*) FROM operation_audits WHERE module='vuln_intel' AND action='import' AND result='SUCCESS'`); n < 2 {
		t.Errorf("导入审计缺失: %d", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM operation_audits WHERE module='vuln_intel' AND action IN ('replace_tech_assets','update_settings')`); n < 2 {
		t.Errorf("映射/设置审计缺失: %d", n)
	}
}

// TestVulnIntelAPIPermissions 权限矩阵：SECURITY_ADMIN 只读（manage 接口 403）；
// 未登录 401；CSRF 缺失 403；审计员无 vuln_intel.read 403。
func TestVulnIntelAPIPermissions(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "vi_secadmin", "SecAdmin@2026!", "SECURITY_ADMIN")
	env.createUserDirect(t, "vi_auditor", "Auditor@2026!", "AUDIT_ADMIN")
	secCookies, secCSRF := env.login(t, "vi_secadmin", "SecAdmin@2026!")
	audCookies, _ := env.login(t, "vi_auditor", "Auditor@2026!")

	// SECURITY_ADMIN：读接口 200
	for _, path := range []string{
		"/api/v1/vuln-intel/overview",
		"/api/v1/vuln-intel/advisories",
		"/api/v1/vuln-intel/tech-assets",
		"/api/v1/vuln-intel/settings",
	} {
		resp := env.get(t, path, secCookies)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("SECURITY_ADMIN GET %s = %d, want 200", path, resp.StatusCode)
		}
		resp.Body.Close()
	}
	// SECURITY_ADMIN：写接口 403（sync 在权限层拦截，不触发任何外呼）
	resp := env.post(t, "/api/v1/vuln-intel/import", `{"advisories":[]}`, secCookies, secCSRF)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("SECURITY_ADMIN import = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
	resp = env.post(t, "/api/v1/vuln-intel/sync", ``, secCookies, secCSRF)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("SECURITY_ADMIN sync = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
	resp = env.do(t, http.MethodPut, "/api/v1/vuln-intel/settings",
		`{"watch_techs":["php"],"min_severity":"HIGH","sync_enabled":false}`, secCookies, secCSRF)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("SECURITY_ADMIN put settings = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
	resp = env.do(t, http.MethodPut, "/api/v1/vuln-intel/tech-assets", `{"items":[]}`, secCookies, secCSRF)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("SECURITY_ADMIN put tech-assets = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// AUDITOR：无 vuln_intel.read → 403
	resp = env.get(t, "/api/v1/vuln-intel/overview", audCookies)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("AUDITOR overview = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// 未登录 → 401
	resp, err := http.Get(env.server.URL + "/api/v1/vuln-intel/overview")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("未登录 = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// 已登录但缺 CSRF → 403
	cookies, _ := env.login(t, "test_sysadmin", env.adminPwd)
	resp = env.post(t, "/api/v1/vuln-intel/import", `{"advisories":[]}`, cookies, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("缺 CSRF = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestVulnIntelImportValidation 导入边界校验：空批、超上限、非法级别、缺 tech_tags。
func TestVulnIntelImportValidation(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	resp := env.post(t, "/api/v1/vuln-intel/import", `{"advisories":[]}`, cookies, csrf)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("空批应 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp = env.post(t, "/api/v1/vuln-intel/import",
		`{"advisories":[{"cve_id":"CVE-2026-8001","severity":"P0","tech_tags":["php"]}]}`, cookies, csrf)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("非法级别应进入 invalid_entries（HTTP 200）, got %d", resp.StatusCode)
	}
	var result apiResp
	readJSON(t, resp, &result)
	resp.Body.Close()
	if result.Data["invalid"].(float64) != 1 || result.Data["inserted"].(float64) != 0 {
		t.Errorf("非法级别应判 invalid: %v", result.Data)
	}
	entries, _ := result.Data["invalid_entries"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("invalid_entries = %v", entries)
	}
	resp = env.post(t, "/api/v1/vuln-intel/import",
		`{"advisories":[{"cve_id":"CVE-2026-8002","tech_tags":[]}]}`, cookies, csrf)
	readJSON(t, resp, &result)
	resp.Body.Close()
	if result.Data["invalid"].(float64) != 1 {
		t.Errorf("空 tech_tags 应判 invalid: %v", result.Data)
	}
	// severity 缺省时按 cvss_score 派生
	resp = env.post(t, "/api/v1/vuln-intel/import",
		`{"advisories":[{"cve_id":"CVE-2026-8003","cvss_score":9.1,"tech_tags":["php"]}]}`, cookies, csrf)
	readJSON(t, resp, &result)
	resp.Body.Close()
	if result.Data["inserted"].(float64) != 1 {
		t.Fatalf("派生级别导入失败: %v", result.Data)
	}
	var sev string
	if err := env.db.QueryRow(context.Background(),
		`SELECT severity FROM vuln_advisories WHERE cve_id='CVE-2026-8003'`).Scan(&sev); err != nil {
		t.Fatal(err)
	}
	if sev != "CRITICAL" {
		t.Errorf("cvss 9.1 派生 = %s, want CRITICAL", sev)
	}
}

// TestVulnIntelTechAssetsReplace 技术资产整组替换语义与校验。
func TestVulnIntelTechAssetsReplace(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	ctx := context.Background()

	var app1, app2 string
	if err := env.db.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ('vi-a1','应用一') RETURNING id`).Scan(&app1); err != nil {
		t.Fatal(err)
	}
	if err := env.db.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ('vi-a2','应用二') RETURNING id`).Scan(&app2); err != nil {
		t.Fatal(err)
	}
	put := func(body string) *http.Response {
		return env.do(t, http.MethodPut, "/api/v1/vuln-intel/tech-assets", body, cookies, csrf)
	}
	resp := put(fmt.Sprintf(`{"items":[{"application_id":%q,"tech_tags":["PHP","php"]},{"application_id":%q,"tech_tags":["php","nodejs"]}]}`, app1, app2))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("首次替换 = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var result apiResp
	readJSON(t, resp, &result)
	resp.Body.Close()
	if result.Data["tags"].(float64) != 3 {
		t.Errorf("tags 总数 = %v（php 大小写归一去重）", result.Data["tags"])
	}
	// 全量替换：app2 未列出 → 清空
	resp = put(fmt.Sprintf(`{"items":[{"application_id":%q,"tech_tags":["php"]}]}`, app1))
	readJSON(t, resp, &result)
	resp.Body.Close()
	if n := s8Count(t, env, `SELECT count(*) FROM application_technologies`); n != 1 {
		t.Errorf("整组替换后映射行 = %d, want 1", n)
	}
	// 非法：重复应用 / 非法 tech / 不存在应用 / 非法 UUID
	for _, tc := range []struct {
		name string
		body string
	}{
		{"重复应用", fmt.Sprintf(`{"items":[{"application_id":%q,"tech_tags":[]},{"application_id":%q,"tech_tags":[]}]}`, app1, app1)},
		{"非法tech", fmt.Sprintf(`{"items":[{"application_id":%q,"tech_tags":["PHP;DROP"]}]}`, app1)},
		{"不存在应用", `{"items":[{"application_id":"00000000-0000-0000-0000-000000000000","tech_tags":["php"]}]}`},
		{"非法UUID", `{"items":[{"application_id":"not-a-uuid","tech_tags":["php"]}]}`},
	} {
		resp := put(tc.body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s 应 400, got %d", tc.name, resp.StatusCode)
		}
		resp.Body.Close()
	}
	// 删除应用级联清理映射
	if _, err := env.db.Exec(ctx, `DELETE FROM applications WHERE id = $1`, app1); err != nil {
		t.Fatal(err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM application_technologies`); n != 0 {
		t.Errorf("删应用应级联清理: %d", n)
	}
}
