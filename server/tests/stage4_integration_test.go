package tests

import (
	"net/http"
	"testing"
)

// TestStage4BuiltinPolicies 内置策略存在且不可修改删除。
func TestStage4BuiltinPolicies(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s4_pol", "SecS4@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s4_pol", "SecS4@Test2026!")

	// 内置三套策略
	resp := env.get(t, "/api/v1/protection-policies", cookies)
	defer resp.Body.Close()
	var list apiRespPage2
	readJSON(t, resp, &list)
	builtins := map[string]bool{}
	var strictID string
	for _, item := range list.Data.Items {
		if item["is_builtin"] == true {
			builtins[item["code"].(string)] = true
			if item["code"] == "strict" {
				strictID = item["id"].(string)
			}
		}
	}
	for _, code := range []string{"relaxed", "standard", "strict"} {
		if !builtins[code] {
			t.Errorf("builtin policy %s missing", code)
		}
	}

	// 内置策略不可修改
	resp2 := env.do(t, http.MethodPut, "/api/v1/protection-policies/"+strictID,
		`{"name":"改","protection_mode":"OFF","version":1}`, cookies, csrf)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("modify builtin status = %d, want 403", resp2.StatusCode)
	}
	// 内置策略不可删除
	req, _ := http.NewRequest(http.MethodDelete, env.server.URL+"/api/v1/protection-policies/"+strictID, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req.Header.Set("X-CSRF-Token", csrf)
	resp3, _ := http.DefaultClient.Do(req)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusForbidden {
		t.Errorf("delete builtin status = %d, want 403", resp3.StatusCode)
	}
}

// TestStage4CreateCustomPolicy 创建自定义策略。
func TestStage4CreateCustomPolicy(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s4_cp", "SecS4@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s4_cp", "SecS4@Test2026!")

	resp := env.post(t, "/api/v1/protection-policies",
		`{"code":"custom-p1","name":"自定义策略1","protection_mode":"PROTECT","paranoia_level":2,"inbound_anomaly_threshold":3,"outbound_anomaly_threshold":2}`, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create policy status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	// 重复编码冲突
	resp2 := env.post(t, "/api/v1/protection-policies",
		`{"code":"custom-p1","name":"重复","protection_mode":"OBSERVE"}`, cookies, csrf)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("duplicate policy code status = %d, want 409", resp2.StatusCode)
	}
	// 无效参数（阈值超范围）
	resp3 := env.post(t, "/api/v1/protection-policies",
		`{"code":"bad-p","name":"坏","inbound_anomaly_threshold":0,"protection_mode":"X"}`, cookies, csrf)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid param status = %d, want 400", resp3.StatusCode)
	}
}

// TestStage4WafRulesQuery WAF规则查询与分类。
func TestStage4WafRulesQuery(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s4_wr", "SecS4@Test2026!", "SECURITY_ADMIN")
	cookies, _ := env.login(t, "sec_s4_wr", "SecS4@Test2026!")

	// 触发同步（无 CRS 目录时可能失败，但接口应响应）
	resp := env.get(t, "/api/v1/waf-rules?page_size=5", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("waf-rules list status = %d", resp.StatusCode)
	}
	// 分类统计
	resp2 := env.get(t, "/api/v1/waf-rules/categories", cookies)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("categories status = %d", resp2.StatusCode)
	}
	// 按攻击类型筛选
	resp3 := env.get(t, "/api/v1/waf-rules?attack_type=SQL_INJECTION&page_size=5", cookies)
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("filter by attack_type status = %d", resp3.StatusCode)
	}
}

// TestStage4CustomRuleValidation 自定义规则校验。
func TestStage4CustomRuleValidation(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s4_cr", "SecS4@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s4_cr", "SecS4@Test2026!")

	// 合法规则校验
	resp := env.post(t, "/api/v1/custom-rules/00000000-0000-0000-0000-000000000000/validate",
		`{"rule_id":7100001,"name":"测试","operator":"rx","operator_value":"(?i)union select","target_variables":["ARGS"],"action":"BLOCK","phase":2,"attack_type":"SQL_INJECTION","severity":"CRITICAL"}`, cookies, csrf)
	defer resp.Body.Close()
	var result apiResp
	readJSON(t, resp, &result)
	if result.Data["valid"] != true {
		t.Errorf("valid rule rejected: %v", result.Data)
	}

	// ID 超范围
	resp2 := env.post(t, "/api/v1/custom-rules",
		`{"rule_id":942100,"name":"冲突ID","operator":"rx","operator_value":"x","target_variables":["ARGS"],"action":"BLOCK","phase":2}`, cookies, csrf)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("out-of-range id status = %d, want 400", resp2.StatusCode)
	}
	// 危险内容
	resp3 := env.post(t, "/api/v1/custom-rules",
		`{"rule_id":7100002,"name":"危险","operator":"rx","operator_value":"@exec(/bin/cat)","target_variables":["ARGS"],"action":"BLOCK","phase":2}`, cookies, csrf)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("dangerous content status = %d, want 400", resp3.StatusCode)
	}
}

// TestStage4CustomRuleCRUD 自定义规则增删改查。
func TestStage4CustomRuleCRUD(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s4_cc", "SecS4@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s4_cc", "SecS4@Test2026!")

	resp := env.post(t, "/api/v1/custom-rules",
		`{"rule_id":7100010,"name":"测试规则","operator":"rx","operator_value":"(?i)test","target_variables":["ARGS"],"action":"BLOCK","phase":2,"attack_type":"OTHER","severity":"WARNING"}`, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create custom rule status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var result apiResp
	readJSON(t, resp, &result)
	// 重复 ID 冲突
	resp2 := env.post(t, "/api/v1/custom-rules",
		`{"rule_id":7100010,"name":"重复ID","operator":"rx","operator_value":"y","target_variables":["ARGS"],"action":"BLOCK","phase":2}`, cookies, csrf)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("duplicate rule id status = %d, want 400", resp2.StatusCode)
	}
	_ = result
}

// TestStage4ExceptionPrecise 精确例外创建。
func TestStage4ExceptionPrecise(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s4_ex", "SecS4@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s4_ex", "SecS4@Test2026!")

	// 精确例外
	resp := env.post(t, "/api/v1/exceptions",
		`{"name":"富文本误报例外","scope_type":"APPLICATION","uri_prefix":"/api/richtext","param_names":["content"],"rule_ids":[942100],"exception_action":"REMOVE_RULE","reason":"富文本误报"}`, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create precise exception status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
}

// TestStage4ExceptionBroadNeedsAck 宽泛例外需风险确认。
func TestStage4ExceptionBroadNeedsAck(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s4_eb", "SecS4@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s4_eb", "SecS4@Test2026!")

	// 宽泛例外（全局无条件）无风险确认 → 拒绝
	resp := env.post(t, "/api/v1/exceptions",
		`{"name":"全部SQLi例外","scope_type":"GLOBAL","attack_types":["SQL_INJECTION"],"exception_action":"REMOVE_RULE_TAG","rule_tags":["attack-sqli"]}`, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("broad exception without ack status = %d, want 400", resp.StatusCode)
	}
}

// TestStage4SecurityEventsQuery 安全事件查询。
func TestStage4SecurityEventsQuery(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s4_ev", "SecS4@Test2026!", "SECURITY_ADMIN")
	cookies, _ := env.login(t, "sec_s4_ev", "SecS4@Test2026!")

	resp := env.get(t, "/api/v1/security-events?page_size=10", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("security-events list status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	// 筛选
	resp2 := env.get(t, "/api/v1/security-events?attack_type=SQL_INJECTION&page_size=5", cookies)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("filter by attack_type status = %d", resp2.StatusCode)
	}
}

// TestStage4SysAdminCannotManagePolicies 系统管理员不能管理业务策略（三权边界）。
func TestStage4SysAdminCannotManagePolicies(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)
	resp := env.post(t, "/api/v1/protection-policies",
		`{"code":"sys-p","name":"越权","protection_mode":"PROTECT"}`, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("sysadmin create policy status = %d, want 403", resp.StatusCode)
	}
}

// TestStage4AuditAdminReadOnly 审计管理员（000100 收紧为纯审计角色）：策略/规则/事件读写均无权限。
func TestStage4AuditAdminReadOnly(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "audit_s4", "AuditS4@Test2026!", "AUDIT_ADMIN")
	cookies, csrf := env.login(t, "audit_s4", "AuditS4@Test2026!")

	// 纯审计角色不再持有 waf_policies/waf_rules/security_events 读权限点 → 403
	for _, path := range []string{"/api/v1/protection-policies", "/api/v1/waf-rules", "/api/v1/security-events"} {
		resp := env.get(t, path, cookies)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("audit admin GET %s status = %d, want 403", path, resp.StatusCode)
		}
	}
	// 不可创建策略
	resp := env.post(t, "/api/v1/protection-policies",
		`{"code":"audit-p","name":"越权","protection_mode":"PROTECT"}`, cookies, csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("audit admin create policy status = %d, want 403", resp.StatusCode)
	}
}
