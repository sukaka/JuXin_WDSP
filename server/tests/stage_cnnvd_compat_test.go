package tests

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestStageCNNVDCompat WAF 规则 CNNVD 兼容性 P1 契约端到端（docs/CNNVD_COMPATIBILITY_DESIGN.md §4）：
// 漏洞档案 CRUD/409/400/403、自定义规则编号标注与精确反查、事件详情编号联查、
// 档案详情交叉计数与样例事件。
func TestStageCNNVDCompat(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_cnnvd", "SecCNNVD@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_cnnvd", "SecCNNVD@Test2026!")

	// 1) 录入漏洞档案（小写编号 → 服务端大写归一）
	resp := env.post(t, "/api/v1/waf/vuln-refs",
		`{"cnnvd_id":"cnnvd-202401-2345","cve_id":"cve-2024-0001","title":"测试漏洞·虚拟补丁演示","severity":"高危","published_at":"2024-01-15","url":"https://www.cnnvd.org.cn/home/loophole"}`,
		cookies, csrf)
	var createResp apiResp
	readJSON(t, resp, &createResp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create vuln ref: status %d, resp %+v", resp.StatusCode, createResp)
	}
	refData, _ := createResp.Data["cnnvd_id"].(string)
	if refData != "CNNVD-202401-2345" {
		t.Errorf("cnnvd_id not normalized: %v", createResp.Data)
	}
	if createResp.Data["cve_id"] != "CVE-2024-0001" || createResp.Data["published_at"] != "2024-01-15" {
		t.Errorf("ref fields wrong: %+v", createResp.Data)
	}

	// 重复编号 → 409
	resp = env.post(t, "/api/v1/waf/vuln-refs", `{"cnnvd_id":"CNNVD-202401-2345","title":"重复"}`, cookies, csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate create status = %d, want 409", resp.StatusCode)
	}
	// 编号格式非法 → 400（中文错误）
	resp = env.post(t, "/api/v1/waf/vuln-refs", `{"cnnvd_id":"CNNVD-2024-1"}`, cookies, csrf)
	var badResp apiResp
	readJSON(t, resp, &badResp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || badResp.Code != "INVALID_ARGUMENT" {
		t.Errorf("bad id status = %d code = %s, want 400 INVALID_ARGUMENT", resp.StatusCode, badResp.Code)
	}

	// 2) 自定义规则标注编号（乱序小写 + 重复 → 归一去重）
	resp = env.post(t, "/api/v1/custom-rules",
		`{"rule_id":7100601,"name":"CNNVD演示虚拟补丁","operator":"rx","operator_value":"(?i)union\\s+select","target_variables":["ARGS"],"action":"BLOCK","phase":2,"attack_type":"SQL_INJECTION","cnnvd_ids":["cnnvd-202401-2345","CNNVD-202401-2345"],"cve_ids":["cve-2024-0001"]}`,
		cookies, csrf)
	var ruleResp apiResp
	readJSON(t, resp, &ruleResp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create rule: status %d, resp %+v", resp.StatusCode, ruleResp.Data)
	}
	if fmt.Sprint(ruleResp.Data["cnnvd_ids"]) != "[CNNVD-202401-2345]" {
		t.Errorf("rule cnnvd_ids not normalized: %v", ruleResp.Data["cnnvd_ids"])
	}
	ruleUUID, _ := ruleResp.Data["id"].(string)

	// 规则侧非法编号 → 400
	resp = env.post(t, "/api/v1/custom-rules",
		`{"rule_id":7100602,"name":"非法编号","operator":"rx","operator_value":"x","target_variables":["ARGS"],"action":"LOG","phase":2,"cve_ids":["CVE-2024-1"]}`,
		cookies, csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("rule with bad cve id status = %d, want 400", resp.StatusCode)
	}

	// 3) 规则列表按编号精确反查
	resp = env.get(t, "/api/v1/custom-rules?cnnvd_id=CNNVD-202401-2345", cookies)
	var listResp apiResp
	readJSON(t, resp, &listResp)
	resp.Body.Close()
	if total, _ := listResp.Data["total"].(float64); total != 1 {
		t.Errorf("cnnvd_id filter total = %v, want 1", listResp.Data["total"])
	}
	resp = env.get(t, "/api/v1/custom-rules?cve_id=CVE-2024-0001", cookies)
	readJSON(t, resp, &listResp)
	resp.Body.Close()
	if total, _ := listResp.Data["total"].(float64); total != 1 {
		t.Errorf("cve_id filter total = %v, want 1", listResp.Data["total"])
	}
	resp = env.get(t, "/api/v1/custom-rules?cnnvd_id=bad", cookies)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad filter id status = %d, want 400", resp.StatusCode)
	}

	// 4) 档案列表交叉计数（此时无事件）
	resp = env.get(t, "/api/v1/waf/vuln-refs?keyword=CNNVD-202401", cookies)
	readJSON(t, resp, &listResp)
	resp.Body.Close()
	items, _ := listResp.Data["items"].([]interface{})
	if len(items) != 1 {
		t.Fatalf("vuln-refs list items = %d, want 1", len(items))
	}
	item, _ := items[0].(map[string]interface{})
	if item["rule_count"] != float64(1) || item["event_count_30d"] != float64(0) {
		t.Errorf("cross counts wrong: %+v", item)
	}

	// 5) 档案详情：关联规则投影
	resp = env.get(t, "/api/v1/waf/vuln-refs/CNNVD-202401-2345", cookies)
	var detailResp apiResp
	readJSON(t, resp, &detailResp)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vuln ref detail: status %d", resp.StatusCode)
	}
	rules, _ := detailResp.Data["rules"].([]interface{})
	if len(rules) != 1 {
		t.Fatalf("detail rules = %d, want 1", len(rules))
	}
	rule0, _ := rules[0].(map[string]interface{})
	if rule0["rule_source"] != "USER_CUSTOM" || rule0["enabled"] != true || rule0["rule_id"] != float64(7100601) {
		t.Errorf("rule projection wrong: %+v", rule0)
	}

	// 6) 直接落库一条命中该规则的事件（采集通道之外的等效造数）
	var eventID string
	occurredAt := time.Now().Add(-time.Hour)
	err := env.db.QueryRow(context.Background(), `
INSERT INTO security_events (request_id, occurred_at, client_ip, request_method, request_uri, request_path,
  attack_type, severity, action)
VALUES ('req-cnnvd-e2e', $1, '203.0.113.66', 'GET', '/x?id=1 union select', '/x', 'SQL_INJECTION', 'HIGH', 'BLOCK')
RETURNING id`, occurredAt).Scan(&eventID)
	if err != nil {
		t.Fatalf("seed event: %v", err)
	}
	if _, err := env.db.Exec(context.Background(), `
INSERT INTO security_event_matches (event_id, event_occurred_at, rule_id, rule_name, rule_source)
VALUES ($1, $2, 7100601, 'CNNVD演示虚拟补丁', 'USER_CUSTOM')`, eventID, occurredAt); err != nil {
		t.Fatalf("seed match: %v", err)
	}

	// 7) 事件详情 matches 携带编号（联查现值）
	resp = env.get(t, "/api/v1/security-events/"+eventID, cookies)
	var eventResp apiResp
	readJSON(t, resp, &eventResp)
	resp.Body.Close()
	matches, _ := eventResp.Data["matches"].([]interface{})
	if len(matches) != 1 {
		t.Fatalf("event matches = %d, want 1", len(matches))
	}
	m0, _ := matches[0].(map[string]interface{})
	if fmt.Sprint(m0["cnnvd_ids"]) != "[CNNVD-202401-2345]" || fmt.Sprint(m0["cve_ids"]) != "[CVE-2024-0001]" {
		t.Errorf("event match ids wrong: %+v", m0)
	}

	// 8) 档案详情交叉计数/样例更新
	resp = env.get(t, "/api/v1/waf/vuln-refs/CNNVD-202401-2345", cookies)
	readJSON(t, resp, &detailResp)
	resp.Body.Close()
	if detailResp.Data["event_count_30d"] != float64(1) {
		t.Errorf("event_count_30d = %v, want 1", detailResp.Data["event_count_30d"])
	}
	samples, _ := detailResp.Data["sample_events"].([]interface{})
	if len(samples) != 1 {
		t.Fatalf("sample_events = %d, want 1", len(samples))
	}
	s0, _ := samples[0].(map[string]interface{})
	if s0["id"] != eventID || s0["client_ip"] != "203.0.113.66" || s0["request_path"] != "/x" || s0["action"] != "BLOCK" {
		t.Errorf("sample event projection wrong: %+v", s0)
	}

	// 9) 更新与删除
	resp = env.do(t, http.MethodPut, "/api/v1/waf/vuln-refs/CNNVD-202401-2345",
		`{"cve_id":"CVE-2024-0001","title":"更新后的规范名称","severity":"超危","published_at":null,"url":"https://www.cnnvd.org.cn/home/loophole"}`,
		cookies, csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("update status = %d, want 200", resp.StatusCode)
	}
	resp = env.do(t, http.MethodPut, "/api/v1/waf/vuln-refs/CNNVD-202401-2345", `{"cnnvd_id":"CNNVD-202402-0007"}`, cookies, csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("immutable cnnvd_id update status = %d, want 400", resp.StatusCode)
	}
	resp = env.get(t, "/api/v1/waf/vuln-refs/CNNVD-209901-999", cookies)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing ref status = %d, want 404", resp.StatusCode)
	}

	// 10) 权限口径：审计管理员在 000100 角色再平衡后已收紧为纯审计角色，
	// 无 waf_rules.read——读/写 vuln-refs 均应 403（本特性不新增其授权）。
	env.createUserDirect(t, "aud_cnnvd", "AudCNNVD@Test2026!", "AUDIT_ADMIN")
	audCookies, _ := env.login(t, "aud_cnnvd", "AudCNNVD@Test2026!")
	resp = env.get(t, "/api/v1/waf/vuln-refs", audCookies)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("AUDIT_ADMIN read status = %d, want 403（000100 后无 waf_rules.read）", resp.StatusCode)
	}
	resp = env.post(t, "/api/v1/waf/vuln-refs", `{"cnnvd_id":"CNNVD-202402-0001","title":"越权写入"}`, audCookies, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("AUDIT_ADMIN write status = %d, want 403", resp.StatusCode)
	}

	// 11) 删除后详情 404
	resp = env.do(t, http.MethodDelete, "/api/v1/waf/vuln-refs/CNNVD-202401-2345", "", cookies, csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("delete status = %d, want 200", resp.StatusCode)
	}
	resp = env.get(t, "/api/v1/waf/vuln-refs/CNNVD-202401-2345", cookies)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("deleted ref status = %d, want 404", resp.StatusCode)
	}

	// 清理规则，避免影响同库其他套件
	resp = env.do(t, http.MethodDelete, "/api/v1/custom-rules/"+ruleUUID, "", cookies, csrf)
	resp.Body.Close()
}
