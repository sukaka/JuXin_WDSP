package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/guardjanitor"
	"github.com/jiuzhang-waf/server/internal/temporaryblocks"
)

// apiRespPage5 是分页响应（含 page/page_size/total）。
type apiRespPage5 struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Items    []map[string]interface{} `json:"items"`
		Page     int                      `json:"page"`
		PageSize int                      `json:"page_size"`
		Total    int64                    `json:"total"`
	} `json:"data"`
}

// s5Rand 生成短随机后缀（保证用例可重入）。
func s5Rand() string {
	return strings.ReplaceAll(uuid.NewString()[:8], "-", "")
}

// s5Login 创建指定角色的随机用户并登录，返回 cookie 与 CSRF token。
func (e *testEnv) s5Login(t *testing.T, prefix, roleCode string) ([]*http.Cookie, string) {
	t.Helper()
	username := prefix + "_" + s5Rand()
	password := "S5@Test2026!"
	e.createUserDirect(t, username, password, roleCode)
	cookies, csrf := e.login(t, username, password)
	return cookies, csrf
}

// s5OK 断言响应 200 并解析统一响应体（失败即 Fatal 并附带响应原文）。
func s5OK(t *testing.T, resp *http.Response, what string) apiResp {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s status = %d, want 200, body: %s", what, resp.StatusCode, readBodyString(t, resp))
	}
	var result apiResp
	readJSON(t, resp, &result)
	return result
}

// s5Expect 断言响应状态码（附带响应原文便于诊断）。
func s5Expect(t *testing.T, resp *http.Response, want int, what string) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != want {
		t.Errorf("%s status = %d, want %d, body: %s", what, resp.StatusCode, want, readBodyString(t, resp))
	}
}

// s5Obj 从统一响应 data 中取命名对象（如 proxy/rule/address）。
func s5Obj(t *testing.T, result apiResp, key string) map[string]interface{} {
	t.Helper()
	obj, ok := result.Data[key].(map[string]interface{})
	if !ok {
		t.Fatalf("data.%s missing or not an object: %+v", key, result.Data)
	}
	return obj
}

// s5Num 从 map 中取数字字段（JSON 数字解析为 float64）。
func s5Num(t *testing.T, m map[string]interface{}, key string) float64 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("field %s missing or not a number: %+v", key, m)
	}
	return v
}

// TestStage5TrustedProxyCRUD 可信代理全生命周期：创建/列表/详情/更新(乐观锁)/停用/启用/删除，
// 以及非法 CIDR、CUSTOM 缺头名、重复创建等边界。
func TestStage5TrustedProxyCRUD(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "s5sec", "SECURITY_ADMIN")

	// 非法 CIDR：域名 / 带端口 / 通配符 → 400
	for _, bad := range []string{"proxy.example.com", "10.1.2.3:8080", "10.1.2.*"} {
		resp := env.post(t, "/api/v1/trusted-proxies",
			fmt.Sprintf(`{"name":"bad","cidr":%q,"header_type":"X_FORWARDED_FOR","priority":10}`, bad), cookies, csrf)
		s5Expect(t, resp, http.StatusBadRequest, "create proxy with cidr "+bad)
	}
	// CUSTOM 头类型缺少自定义头名 → 400
	resp := env.post(t, "/api/v1/trusted-proxies",
		`{"name":"bad-custom","cidr":"10.20.0.0/16","header_type":"CUSTOM","priority":10}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "CUSTOM header without custom_header_name")

	// 创建（X_FORWARDED_FOR / CIDR / 优先级）
	name := "tp-" + s5Rand()
	resp = env.post(t, "/api/v1/trusted-proxies",
		fmt.Sprintf(`{"name":%q,"cidr":"10.10.0.0/16","header_type":"X_FORWARDED_FOR","priority":100,"description":"办公出口"}`, name),
		cookies, csrf)
	result := s5OK(t, resp, "create trusted proxy")
	proxy := s5Obj(t, result, "proxy")
	id, _ := proxy["id"].(string)
	version := int(s5Num(t, proxy, "version"))
	if id == "" {
		t.Fatal("created proxy id empty")
	}

	// 重复创建（相同 CIDR+节点）→ 409
	resp = env.post(t, "/api/v1/trusted-proxies",
		fmt.Sprintf(`{"name":%q,"cidr":"10.10.0.0/16","header_type":"X_REAL_IP","priority":50}`, name+"-dup"),
		cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "duplicate proxy cidr")

	// 列表可见（按随机后缀过滤）
	resp = env.get(t, "/api/v1/trusted-proxies?keyword="+name, cookies)
	var list apiRespPage5
	func() {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list proxies status = %d", resp.StatusCode)
		}
		readJSON(t, resp, &list)
	}()
	if list.Data.Total != 1 || len(list.Data.Items) != 1 || list.Data.Items[0]["id"] != id {
		t.Errorf("list by keyword total = %d, want 1 item with id %s", list.Data.Total, id)
	}

	// 详情
	resp = env.get(t, "/api/v1/trusted-proxies/"+id, cookies)
	result = s5OK(t, resp, "get trusted proxy")
	proxy = s5Obj(t, result, "proxy")
	if proxy["cidr"] != "10.10.0.0/16" || proxy["header_type"] != "X_FORWARDED_FOR" {
		t.Errorf("proxy detail cidr=%v header_type=%v", proxy["cidr"], proxy["header_type"])
	}

	// 更新（回传乐观锁 version）
	resp = env.do(t, http.MethodPut, "/api/v1/trusted-proxies/"+id,
		fmt.Sprintf(`{"name":%q,"cidr":"10.10.0.0/16","header_type":"X_FORWARDED_FOR","priority":200,"description":"更新","version":%d}`,
			name+"-u", version), cookies, csrf)
	result = s5OK(t, resp, "update trusted proxy")
	proxy = s5Obj(t, result, "proxy")
	if int(s5Num(t, proxy, "version")) != version+1 {
		t.Errorf("after update version = %v, want %d", proxy["version"], version+1)
	}
	if s5Num(t, proxy, "priority") != 200 {
		t.Errorf("after update priority = %v, want 200", proxy["priority"])
	}
	// 过期 version 更新 → 409
	resp = env.do(t, http.MethodPut, "/api/v1/trusted-proxies/"+id,
		fmt.Sprintf(`{"name":%q,"cidr":"10.10.0.0/16","header_type":"X_FORWARDED_FOR","priority":300,"version":%d}`,
			name+"-stale", version), cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "update with stale version")

	// 停用 → 状态 DISABLED
	resp = env.post(t, "/api/v1/trusted-proxies/"+id+"/disable", "", cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "disable proxy")
	resp = env.get(t, "/api/v1/trusted-proxies/"+id, cookies)
	result = s5OK(t, resp, "get disabled proxy")
	if s5Obj(t, result, "proxy")["status"] != "DISABLED" {
		t.Errorf("status after disable = %v, want DISABLED", s5Obj(t, result, "proxy")["status"])
	}
	// 启用 → 状态 ENABLED
	resp = env.post(t, "/api/v1/trusted-proxies/"+id+"/enable", "", cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "enable proxy")
	resp = env.get(t, "/api/v1/trusted-proxies/"+id, cookies)
	result = s5OK(t, resp, "get enabled proxy")
	if s5Obj(t, result, "proxy")["status"] != "ENABLED" {
		t.Errorf("status after enable = %v, want ENABLED", s5Obj(t, result, "proxy")["status"])
	}

	// 删除 → 详情 404
	resp = env.do(t, http.MethodDelete, "/api/v1/trusted-proxies/"+id, "", cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "delete proxy")
	resp = env.get(t, "/api/v1/trusted-proxies/"+id, cookies)
	s5Expect(t, resp, http.StatusNotFound, "get deleted proxy")
}

// TestStage5TrustedProxyTest 可信代理命中测试：输入 CIDR 与测试 IP 返回命中结果。
func TestStage5TrustedProxyTest(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "s5sec", "SECURITY_ADMIN")

	// 创建启用中的可信代理（会出现在 matched_proxies 中）
	resp := env.post(t, "/api/v1/trusted-proxies",
		`{"name":"tp-test-`+s5Rand()+`","cidr":"172.16.0.0/12","header_type":"X_REAL_IP","priority":10}`, cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "create proxy for test")

	// 命中测试
	resp = env.post(t, "/api/v1/trusted-proxies/test",
		`{"cidr":"172.16.0.0/12","test_ips":["172.16.5.6","8.8.8.8","not-an-ip"]}`, cookies, csrf)
	result := s5OK(t, resp, "proxy hit test")
	results, ok := result.Data["results"].([]interface{})
	if !ok || len(results) != 3 {
		t.Fatalf("results len = %v, want 3", result.Data["results"])
	}
	r0 := results[0].(map[string]interface{})
	if r0["valid"] != true || r0["matched"] != true {
		t.Errorf("172.16.5.6 valid=%v matched=%v, want true/true", r0["valid"], r0["matched"])
	}
	if hits, _ := r0["matched_proxies"].([]interface{}); len(hits) < 1 {
		t.Errorf("172.16.5.6 matched_proxies empty, want >= 1")
	}
	r1 := results[1].(map[string]interface{})
	if r1["valid"] != true || r1["matched"] != false {
		t.Errorf("8.8.8.8 valid=%v matched=%v, want true/false", r1["valid"], r1["matched"])
	}
	r2 := results[2].(map[string]interface{})
	if r2["valid"] != false {
		t.Errorf("not-an-ip valid=%v, want false", r2["valid"])
	}

	// 空 test_ips → 400
	resp = env.post(t, "/api/v1/trusted-proxies/test", `{"cidr":"172.16.0.0/12","test_ips":[]}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "empty test_ips")
	// 非法 CIDR → 400
	resp = env.post(t, "/api/v1/trusted-proxies/test", `{"cidr":"bad-cidr","test_ips":["1.2.3.4"]}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "invalid cidr in test")
}

// TestStage5ProtectedAddresses 保护地址：列表/创建/删除/系统地址刷新，审计管理员创建被拒。
func TestStage5ProtectedAddresses(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "s5sec", "SECURITY_ADMIN")
	auditCookies, auditCSRF := env.s5Login(t, "s5aud", "AUDIT_ADMIN")

	// 列表 200
	resp := env.get(t, "/api/v1/protected-addresses", cookies)
	s5OK(t, resp, "list protected addresses")

	// 审计管理员创建 → 403
	resp = env.post(t, "/api/v1/protected-addresses",
		`{"name":"x","address":"198.51.100.99"}`, auditCookies, auditCSRF)
	s5Expect(t, resp, http.StatusForbidden, "audit admin create protected address")

	// 创建自定义保护地址
	resp = env.post(t, "/api/v1/protected-addresses",
		fmt.Sprintf(`{"name":%q,"address":"198.51.100.10","description":"业务保留地址"}`, "pa-"+s5Rand()), cookies, csrf)
	result := s5OK(t, resp, "create protected address")
	addr := s5Obj(t, result, "address")
	id, _ := addr["id"].(string)
	if id == "" {
		t.Fatal("created protected address id empty")
	}

	// 列表可见
	resp = env.get(t, "/api/v1/protected-addresses", cookies)
	result = s5OK(t, resp, "list protected addresses after create")
	found := false
	for _, it := range result.Data["items"].([]interface{}) {
		if it.(map[string]interface{})["id"] == id {
			found = true
		}
	}
	if !found {
		t.Errorf("created protected address %s not in list", id)
	}

	// 刷新系统保护地址：首次有新增，第二次全部跳过（幂等）
	resp = env.post(t, "/api/v1/protected-addresses/refresh", "", cookies, csrf)
	result = s5OK(t, resp, "refresh protected addresses")
	if s5Num(t, result.Data, "added") < 1 {
		t.Errorf("first refresh added = %v, want >= 1", result.Data["added"])
	}
	resp = env.post(t, "/api/v1/protected-addresses/refresh", "", cookies, csrf)
	result = s5OK(t, resp, "second refresh protected addresses")
	if s5Num(t, result.Data, "added") != 0 || s5Num(t, result.Data, "skipped") < 1 {
		t.Errorf("second refresh added=%v skipped=%v, want added=0 skipped>=1",
			result.Data["added"], result.Data["skipped"])
	}

	// 系统保护地址不可删除 → 409
	resp = env.get(t, "/api/v1/protected-addresses", cookies)
	result = s5OK(t, resp, "list protected addresses for system entry")
	var systemID string
	for _, it := range result.Data["items"].([]interface{}) {
		m := it.(map[string]interface{})
		if m["source_type"] == "SYSTEM" {
			systemID, _ = m["id"].(string)
			break
		}
	}
	if systemID == "" {
		t.Fatal("no SYSTEM protected address after refresh")
	}
	resp = env.do(t, http.MethodDelete, "/api/v1/protected-addresses/"+systemID, "", cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "delete system protected address")

	// 删除自定义保护地址 → 200
	resp = env.do(t, http.MethodDelete, "/api/v1/protected-addresses/"+id, "", cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "delete manual protected address")
}

// TestStage5AccessRuleCRUD IP访问控制规则全生命周期：
// 创建(临时1小时)/详情/延期/解封/停用/启用/删除，以及非法地址与应用范围缺参。
func TestStage5AccessRuleCRUD(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "s5sec", "SECURITY_ADMIN")

	// 非法地址 → 400
	resp := env.post(t, "/api/v1/access-rules",
		`{"name":"bad","rule_type":"DENY","scope_type":"GLOBAL","address":"not-an-address"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "create rule with invalid address")
	// APPLICATION 范围缺少 application_id → 400
	resp = env.post(t, "/api/v1/access-rules",
		`{"name":"bad2","rule_type":"DENY","scope_type":"APPLICATION","address":"203.0.113.5"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "application scope without application_id")

	// 创建 DENY GLOBAL 临时规则（1 小时后失效）
	name := "rule-" + s5Rand()
	until1 := time.Now().Add(time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	resp = env.post(t, "/api/v1/access-rules",
		fmt.Sprintf(`{"name":%q,"rule_type":"DENY","scope_type":"GLOBAL","address":"203.0.113.66",`+
			`"validity_type":"TEMPORARY","effective_until":%q,"reason":"测试封禁"}`, name, until1), cookies, csrf)
	result := s5OK(t, resp, "create access rule")
	rule := s5Obj(t, result, "rule")
	id, _ := rule["id"].(string)
	if id == "" {
		t.Fatal("created rule id empty")
	}
	if rule["status"] != "ACTIVE" || rule["validity_type"] != "TEMPORARY" || rule["address"] != "203.0.113.66" {
		t.Errorf("rule status=%v validity=%v address=%v", rule["status"], rule["validity_type"], rule["address"])
	}

	// 详情
	resp = env.get(t, "/api/v1/access-rules/"+id, cookies)
	s5OK(t, resp, "get access rule")

	// 延期到 2 小时后
	until2 := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	resp = env.post(t, "/api/v1/access-rules/"+id+"/extend",
		fmt.Sprintf(`{"effective_until":%q}`, until2.Format(time.RFC3339)), cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "extend access rule")
	resp = env.get(t, "/api/v1/access-rules/"+id, cookies)
	result = s5OK(t, resp, "get extended rule")
	rule = s5Obj(t, result, "rule")
	gotUntil, err := time.Parse(time.RFC3339, rule["effective_until"].(string))
	if err != nil || !gotUntil.Equal(until2) {
		t.Errorf("effective_until = %v, want %s", rule["effective_until"], until2.Format(time.RFC3339))
	}

	// 解封 → 状态 DISABLED
	resp = env.post(t, "/api/v1/access-rules/"+id+"/release", "", cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "release access rule")
	resp = env.get(t, "/api/v1/access-rules/"+id, cookies)
	result = s5OK(t, resp, "get released rule")
	if s5Obj(t, result, "rule")["status"] != "DISABLED" {
		t.Errorf("status after release = %v, want DISABLED", s5Obj(t, result, "rule")["status"])
	}

	// 停用 / 启用
	resp = env.post(t, "/api/v1/access-rules/"+id+"/disable", "", cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "disable access rule")
	resp = env.post(t, "/api/v1/access-rules/"+id+"/enable", "", cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "enable access rule")
	resp = env.get(t, "/api/v1/access-rules/"+id, cookies)
	result = s5OK(t, resp, "get enabled rule")
	if s5Obj(t, result, "rule")["status"] != "ACTIVE" {
		t.Errorf("status after enable = %v, want ACTIVE", s5Obj(t, result, "rule")["status"])
	}

	// 删除 → 详情 404
	resp = env.do(t, http.MethodDelete, "/api/v1/access-rules/"+id, "", cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "delete access rule")
	resp = env.get(t, "/api/v1/access-rules/"+id, cookies)
	s5Expect(t, resp, http.StatusNotFound, "get deleted rule")
}

// TestStage5AccessRuleProtectedRejected 保护地址拒绝加入黑名单。
func TestStage5AccessRuleProtectedRejected(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "s5sec", "SECURITY_ADMIN")

	// 先登记保护地址
	resp := env.post(t, "/api/v1/protected-addresses",
		`{"name":"pa-`+s5Rand()+`","address":"198.51.100.200","description":"核心业务IP"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "create protected address")

	// 对该地址创建 DENY 规则 → 400
	resp = env.post(t, "/api/v1/access-rules",
		`{"name":"block-protected","rule_type":"DENY","scope_type":"GLOBAL","address":"198.51.100.200","reason":"x"}`,
		cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "deny rule on protected address")
}

// TestStage5AccessRuleImport 批量导入：dry_run 预览 / ALL_OR_NOTHING 整体失败 / SKIP_ERRORS 部分入库 / text 格式。
func TestStage5AccessRuleImport(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "s5sec", "SECURITY_ADMIN")

	countByAddress := func(address string) int64 {
		resp := env.get(t, "/api/v1/access-rules?address="+address, cookies)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list rules by address status = %d", resp.StatusCode)
		}
		var page apiRespPage5
		readJSON(t, resp, &page)
		return page.Data.Total
	}

	csvContent := "address,rule_type,reason\n203.0.113.1,DENY,批量1\nbad-address,DENY,坏行\n203.0.113.2,DENY,批量2"

	// dry_run 预览：total/valid/invalid 与错误行号定位（表头第1行，坏行在第3行）
	resp := env.post(t, "/api/v1/access-rules/import",
		fmt.Sprintf(`{"content":%q,"format":"csv","mode":"ALL_OR_NOTHING","dry_run":true,"rule_type":"DENY","scope_type":"GLOBAL"}`,
			csvContent), cookies, csrf)
	result := s5OK(t, resp, "import dry_run")
	if s5Num(t, result.Data, "total") != 3 || s5Num(t, result.Data, "valid") != 2 || s5Num(t, result.Data, "invalid") != 1 {
		t.Errorf("dry_run total=%v valid=%v invalid=%v, want 3/2/1",
			result.Data["total"], result.Data["valid"], result.Data["invalid"])
	}
	errs, _ := result.Data["errors"].([]interface{})
	if len(errs) != 1 {
		t.Fatalf("dry_run errors len = %d, want 1", len(errs))
	}
	rowErr := errs[0].(map[string]interface{})
	if s5Num(t, rowErr, "line") != 3 {
		t.Errorf("error row line = %v, want 3", rowErr["line"])
	}
	if preview, _ := result.Data["preview"].([]interface{}); len(preview) != 2 {
		t.Errorf("dry_run preview len = %d, want 2", len(preview))
	}
	// dry_run 不落库
	if n := countByAddress("203.0.113.1"); n != 0 {
		t.Errorf("after dry_run rule count for 203.0.113.1 = %d, want 0", n)
	}

	// ALL_OR_NOTHING 含错误行 → 整体失败不落库
	resp = env.post(t, "/api/v1/access-rules/import",
		fmt.Sprintf(`{"content":%q,"format":"csv","mode":"ALL_OR_NOTHING","dry_run":false,"rule_type":"DENY","scope_type":"GLOBAL"}`,
			csvContent), cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "import ALL_OR_NOTHING with error row")
	if n := countByAddress("203.0.113.1"); n != 0 {
		t.Errorf("after failed ALL_OR_NOTHING import count for 203.0.113.1 = %d, want 0", n)
	}
	if n := countByAddress("203.0.113.2"); n != 0 {
		t.Errorf("after failed ALL_OR_NOTHING import count for 203.0.113.2 = %d, want 0", n)
	}

	// SKIP_ERRORS → 有效行入库
	resp = env.post(t, "/api/v1/access-rules/import",
		fmt.Sprintf(`{"content":%q,"format":"csv","mode":"SKIP_ERRORS","rule_type":"DENY","scope_type":"GLOBAL"}`,
			csvContent), cookies, csrf)
	result = s5OK(t, resp, "import SKIP_ERRORS")
	if s5Num(t, result.Data, "imported") != 2 || s5Num(t, result.Data, "invalid") != 1 {
		t.Errorf("SKIP_ERRORS imported=%v invalid=%v, want 2/1", result.Data["imported"], result.Data["invalid"])
	}
	if n := countByAddress("203.0.113.1"); n != 1 {
		t.Errorf("after SKIP_ERRORS count for 203.0.113.1 = %d, want 1", n)
	}

	// text 格式导入 2 个 IP（每行一个，支持注释与空行）
	resp = env.post(t, "/api/v1/access-rules/import",
		`{"content":"# 注释行\n203.0.113.10\n\n203.0.113.11\n","format":"text","mode":"ALL_OR_NOTHING","rule_type":"DENY","scope_type":"GLOBAL"}`,
		cookies, csrf)
	result = s5OK(t, resp, "import text format")
	if s5Num(t, result.Data, "imported") != 2 {
		t.Errorf("text import imported = %v, want 2", result.Data["imported"])
	}
	if n := countByAddress("203.0.113.10"); n != 1 {
		t.Errorf("after text import count for 203.0.113.10 = %d, want 1", n)
	}
}

// TestStage5AccessRuleExport 规则导出 CSV：表头、Content-Type 与公式注入转义。
func TestStage5AccessRuleExport(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "s5sec", "SECURITY_ADMIN")

	// 创建 reason 以 = 开头的规则（公式注入样本）
	resp := env.post(t, "/api/v1/access-rules",
		`{"name":"exp-`+s5Rand()+`","rule_type":"DENY","scope_type":"GLOBAL","address":"203.0.113.77","reason":"=SUM(1,2)"}`,
		cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "create rule with formula-like reason")

	resp = env.get(t, "/api/v1/access-rules/export", cookies)
	body := readBodyString(t, resp)
	ct := resp.Header.Get("Content-Type")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export status = %d, body: %s", resp.StatusCode, body)
	}
	if !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("export Content-Type = %q, want text/csv", ct)
	}
	if !strings.HasPrefix(body, "id,name,rule_type,scope_type,") {
		t.Errorf("export header missing, body starts with: %.80q", body)
	}
	// 以 = 开头的字段必须被 ' 转义（防公式注入）
	if !strings.Contains(body, "'=SUM(1,2)") {
		t.Errorf("formula-like reason not escaped in export, body: %q", body)
	}
}

// TestStage5RateLimitPolicyCRUD CC防护策略全生命周期与参数校验边界。
func TestStage5RateLimitPolicyCRUD(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "s5sec", "SECURITY_ADMIN")

	base := `"scope_type":"GLOBAL","uri_match_type":"ALL","dimension":"CLIENT_IP","algorithm":"TOKEN_BUCKET"`
	// 零窗口 → 400
	resp := env.post(t, "/api/v1/rate-limit-policies",
		`{"name":"zero-window",`+base+`,"requests_limit":100,"window_seconds":0,"action":"REJECT"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "zero window_seconds")
	// 负数阈值 → 400
	resp = env.post(t, "/api/v1/rate-limit-policies",
		`{"name":"neg-limit",`+base+`,"requests_limit":-5,"window_seconds":60,"action":"REJECT"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "negative requests_limit")
	// TEMP_BLOCK 缺少 block_duration_seconds → 400
	resp = env.post(t, "/api/v1/rate-limit-policies",
		`{"name":"no-block-duration",`+base+`,"requests_limit":100,"window_seconds":60,"action":"TEMP_BLOCK"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "TEMP_BLOCK without block_duration_seconds")
	// REGEX 非法正则 → 400
	resp = env.post(t, "/api/v1/rate-limit-policies",
		`{"name":"bad-regex","scope_type":"GLOBAL","uri_match_type":"REGEX","uri_pattern":"([invalid",`+
			`"dimension":"CLIENT_IP","algorithm":"TOKEN_BUCKET","requests_limit":100,"window_seconds":60,"action":"REJECT"}`,
		cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "REGEX with invalid pattern")

	// 创建（CLIENT_IP / TOKEN_BUCKET / 100次60秒 / 突发20 / REJECT）
	name := "rl-" + s5Rand()
	resp = env.post(t, "/api/v1/rate-limit-policies",
		fmt.Sprintf(`{"name":%q,%s,"requests_limit":100,"window_seconds":60,"burst_capacity":20,"action":"REJECT","priority":10}`,
			name, base), cookies, csrf)
	result := s5OK(t, resp, "create rate limit policy")
	policy := result.Data
	id, _ := policy["id"].(string)
	if id == "" {
		t.Fatal("created policy id empty")
	}
	if policy["status"] != "ACTIVE" {
		t.Errorf("policy status = %v, want ACTIVE", policy["status"])
	}

	// 更新（回传乐观锁 version）
	version := int(s5Num(t, policy, "version"))
	resp = env.do(t, http.MethodPut, "/api/v1/rate-limit-policies/"+id,
		fmt.Sprintf(`{"name":%q,%s,"requests_limit":200,"window_seconds":60,"burst_capacity":40,"action":"REJECT","priority":20,"version":%d}`,
			name+"-u", base, version), cookies, csrf)
	result = s5OK(t, resp, "update rate limit policy")
	if s5Num(t, result.Data, "requests_limit") != 200 || int(s5Num(t, result.Data, "version")) != version+1 {
		t.Errorf("after update requests_limit=%v version=%v", result.Data["requests_limit"], result.Data["version"])
	}

	// 停用 / 启用
	resp = env.post(t, "/api/v1/rate-limit-policies/"+id+"/disable", "", cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "disable policy")
	resp = env.get(t, "/api/v1/rate-limit-policies/"+id, cookies)
	result = s5OK(t, resp, "get disabled policy")
	if result.Data["status"] != "DISABLED" {
		t.Errorf("status after disable = %v, want DISABLED", result.Data["status"])
	}
	resp = env.post(t, "/api/v1/rate-limit-policies/"+id+"/enable", "", cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "enable policy")
	resp = env.get(t, "/api/v1/rate-limit-policies/"+id, cookies)
	result = s5OK(t, resp, "get enabled policy")
	if result.Data["status"] != "ACTIVE" {
		t.Errorf("status after enable = %v, want ACTIVE", result.Data["status"])
	}

	// 删除 → 详情 404
	resp = env.do(t, http.MethodDelete, "/api/v1/rate-limit-policies/"+id, "", cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "delete policy")
	resp = env.get(t, "/api/v1/rate-limit-policies/"+id, cookies)
	s5Expect(t, resp, http.StatusNotFound, "get deleted policy")
}

// TestStage5RateLimitPolicyTest 限速策略干跑模拟：150 个请求打向 100次/60秒 策略。
func TestStage5RateLimitPolicyTest(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "s5sec", "SECURITY_ADMIN")

	resp := env.post(t, "/api/v1/rate-limit-policies",
		`{"name":"rl-sim-`+s5Rand()+`","scope_type":"GLOBAL","uri_match_type":"ALL","dimension":"CLIENT_IP",`+
			`"algorithm":"TOKEN_BUCKET","requests_limit":100,"window_seconds":60,"burst_capacity":20,"action":"REJECT"}`,
		cookies, csrf)
	result := s5OK(t, resp, "create policy for simulate")
	id, _ := result.Data["id"].(string)

	// 模拟 150 个请求（10ms 间隔）：突发容量 20，必然产生拒绝
	resp = env.post(t, "/api/v1/rate-limit-policies/"+id+"/test",
		`{"requests":150,"uri":"/api/x"}`, cookies, csrf)
	result = s5OK(t, resp, "simulate policy")
	allowed := s5Num(t, result.Data, "allowed")
	rejected := s5Num(t, result.Data, "rejected")
	if allowed+rejected != 150 {
		t.Errorf("allowed(%v) + rejected(%v) != 150", allowed, rejected)
	}
	if rejected <= 0 {
		t.Errorf("rejected = %v, want > 0 (limit 100/60s with burst 20)", rejected)
	}
	if note, _ := result.Data["dimension_note"].(string); note == "" {
		t.Errorf("dimension_note empty")
	}
	if result.Data["algorithm"] != "TOKEN_BUCKET" {
		t.Errorf("algorithm = %v, want TOKEN_BUCKET", result.Data["algorithm"])
	}

	// 模拟请求数超上限 → 400
	resp = env.post(t, "/api/v1/rate-limit-policies/"+id+"/test", `{"requests":10001}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "simulate with too many requests")
}

// TestStage5TemporaryBlocksList 临时封禁列表分页结构。
func TestStage5TemporaryBlocksList(t *testing.T) {
	env := setupTestEnv(t)
	cookies, _ := env.s5Login(t, "s5sec", "SECURITY_ADMIN")

	resp := env.get(t, "/api/v1/temporary-blocks", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list temporary blocks status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var page apiRespPage5
	readJSON(t, resp, &page)
	if page.Code != "SUCCESS" || page.Data.Page != 1 || page.Data.PageSize != 20 {
		t.Errorf("page struct code=%s page=%d page_size=%d", page.Code, page.Data.Page, page.Data.PageSize)
	}

	// 非法状态筛选 → 400
	resp2 := env.get(t, "/api/v1/temporary-blocks?status=BOGUS", cookies)
	s5Expect(t, resp2, http.StatusBadRequest, "list with invalid status filter")
}

// TestStage5AccessControlEventsList 访问控制事件列表与导出。
func TestStage5AccessControlEventsList(t *testing.T) {
	env := setupTestEnv(t)
	cookies, _ := env.s5Login(t, "s5sec", "SECURITY_ADMIN")

	resp := env.get(t, "/api/v1/access-control-events", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list access control events status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var page apiRespPage5
	readJSON(t, resp, &page)
	if page.Code != "SUCCESS" || page.Data.Page != 1 || page.Data.PageSize != 20 {
		t.Errorf("page struct code=%s page=%d page_size=%d", page.Code, page.Data.Page, page.Data.PageSize)
	}

	// 导出 CSV
	resp2 := env.get(t, "/api/v1/access-control-events/export", cookies)
	body := readBodyString(t, resp2)
	ct := resp2.Header.Get("Content-Type")
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("export events status = %d, body: %s", resp2.StatusCode, body)
	}
	if !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("events export Content-Type = %q, want text/csv", ct)
	}
	if body == "" {
		t.Errorf("events export body empty (should at least contain header)")
	}
}

// TestStage5VersionsList 访问控制配置版本列表分页结构。
func TestStage5VersionsList(t *testing.T) {
	env := setupTestEnv(t)
	cookies, _ := env.s5Login(t, "s5sec", "SECURITY_ADMIN")

	resp := env.get(t, "/api/v1/access-control/versions", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list versions status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var page apiRespPage5
	readJSON(t, resp, &page)
	if page.Code != "SUCCESS" || page.Data.Page != 1 || page.Data.PageSize != 20 {
		t.Errorf("page struct code=%s page=%d page_size=%d", page.Code, page.Data.Page, page.Data.PageSize)
	}
}

// TestStage5AccessRuleValidate 规则校验接口（不落库）。
func TestStage5AccessRuleValidate(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "s5sec", "SECURITY_ADMIN")

	// 合法输入 → valid=true
	resp := env.post(t, "/api/v1/access-rules/validate",
		`{"name":"v1","rule_type":"DENY","scope_type":"GLOBAL","address":"203.0.113.99"}`, cookies, csrf)
	result := s5OK(t, resp, "validate valid rule")
	if result.Data["valid"] != true {
		t.Errorf("valid = %v, want true, errors: %v", result.Data["valid"], result.Data["errors"])
	}

	// 非法地址 → valid=false
	resp = env.post(t, "/api/v1/access-rules/validate",
		`{"name":"v2","rule_type":"DENY","scope_type":"GLOBAL","address":"bad-address!!"}`, cookies, csrf)
	result = s5OK(t, resp, "validate invalid rule")
	if result.Data["valid"] != false {
		t.Errorf("valid = %v, want false", result.Data["valid"])
	}
}

// TestStage5RBACBoundary 阶段5 RBAC 边界：审计管理员只读、系统管理员仅可信代理/保护地址。
func TestStage5RBACBoundary(t *testing.T) {
	env := setupTestEnv(t)
	auditCookies, auditCSRF := env.s5Login(t, "s5aud", "AUDIT_ADMIN")
	sysCookies, sysCSRF := env.s5Login(t, "s5sys", "SYSTEM_ADMIN")

	// 审计管理员 GET 全部 5 类列表 → 200
	for _, path := range []string{
		"/api/v1/trusted-proxies",
		"/api/v1/protected-addresses",
		"/api/v1/access-rules",
		"/api/v1/rate-limit-policies",
		"/api/v1/temporary-blocks",
	} {
		resp := env.get(t, path, auditCookies)
		s5Expect(t, resp, http.StatusOK, "audit admin GET "+path)
	}
	// 审计管理员创建 trusted-proxy / access-rule / rate-limit → 403
	resp := env.post(t, "/api/v1/trusted-proxies",
		`{"name":"x","cidr":"10.30.0.0/16","header_type":"X_REAL_IP","priority":10}`, auditCookies, auditCSRF)
	s5Expect(t, resp, http.StatusForbidden, "audit admin POST trusted-proxies")
	resp = env.post(t, "/api/v1/access-rules",
		`{"name":"x","rule_type":"DENY","scope_type":"GLOBAL","address":"203.0.113.120"}`, auditCookies, auditCSRF)
	s5Expect(t, resp, http.StatusForbidden, "audit admin POST access-rules")
	resp = env.post(t, "/api/v1/rate-limit-policies",
		`{"name":"x","scope_type":"GLOBAL","uri_match_type":"ALL","dimension":"CLIENT_IP","algorithm":"TOKEN_BUCKET",`+
			`"requests_limit":100,"window_seconds":60,"action":"REJECT"}`, auditCookies, auditCSRF)
	s5Expect(t, resp, http.StatusForbidden, "audit admin POST rate-limit-policies")

	// 系统管理员：trusted-proxies 可写（200），业务规则/CC策略不可写（403）
	resp = env.post(t, "/api/v1/trusted-proxies",
		`{"name":"sys-tp-`+s5Rand()+`","cidr":"192.168.0.0/16","header_type":"X_REAL_IP","priority":50}`,
		sysCookies, sysCSRF)
	s5Expect(t, resp, http.StatusOK, "system admin POST trusted-proxies")
	resp = env.post(t, "/api/v1/access-rules",
		`{"name":"x","rule_type":"DENY","scope_type":"GLOBAL","address":"203.0.113.121"}`, sysCookies, sysCSRF)
	s5Expect(t, resp, http.StatusForbidden, "system admin POST access-rules")
	resp = env.post(t, "/api/v1/rate-limit-policies",
		`{"name":"x","scope_type":"GLOBAL","uri_match_type":"ALL","dimension":"CLIENT_IP","algorithm":"TOKEN_BUCKET",`+
			`"requests_limit":100,"window_seconds":60,"action":"REJECT"}`, sysCookies, sysCSRF)
	s5Expect(t, resp, http.StatusForbidden, "system admin POST rate-limit-policies")
}

// TestStage5JanitorExpiry 到期自动失效调度：临时规则与临时封禁到期标记 EXPIRED + 系统审计。
func TestStage5JanitorExpiry(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "sec_s5_jan", "SECURITY_ADMIN")

	// 创建 2 秒后过期的临时规则
	until := time.Now().Add(2 * time.Second).UTC().Format(time.RFC3339)
	resp := env.post(t, "/api/v1/access-rules",
		fmt.Sprintf(`{"name":"jan-rule-%s","rule_type":"DENY","scope_type":"GLOBAL","address":"203.0.113.230","validity_type":"TEMPORARY","effective_until":%q}`,
			s5Rand(), until), cookies, csrf)
	result := s5OK(t, resp, "create temporary rule")
	ruleID, _ := result.Data["rule"].(map[string]interface{})["id"].(string)
	if ruleID == "" {
		ruleID, _ = result.Data["id"].(string)
	}
	if ruleID == "" {
		t.Fatalf("no rule id in response: %+v", result.Data)
	}

	// 直接插入一条已过期的临时封禁
	_, err := env.db.Exec(context.Background(), `
INSERT INTO temporary_blocks (client_ip, application_id, trigger_type, block_expires_at, status)
VALUES ('203.0.113.231', NULL, 'CC_AUTO', now() - interval '1 minute', 'ACTIVE')`)
	if err != nil {
		t.Fatalf("insert temp block: %v", err)
	}

	// 等待临时规则到期后执行一次清扫
	time.Sleep(3 * time.Second)
	rulesStore := accessrules.NewStore(env.db)
	blocksStore := temporaryblocks.NewStore(env.db, env.cache)
	auditSvc := audits.NewService(env.db)
	re, be, err := guardjanitor.SweepOnce(context.Background(), rulesStore, blocksStore, auditSvc)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if re < 1 || be < 1 {
		t.Errorf("sweep counts: rules=%d blocks=%d, want >=1", re, be)
	}

	// 规则状态已为 EXPIRED
	resp = env.get(t, "/api/v1/access-rules/"+ruleID, cookies)
	result = s5OK(t, resp, "get expired rule")
	rule := result.Data["rule"].(map[string]interface{})
	if rule["status"] != "EXPIRED" {
		t.Errorf("rule status = %v, want EXPIRED", rule["status"])
	}

	// 封禁状态已为 EXPIRED
	var st string
	err = env.db.QueryRow(context.Background(),
		`SELECT status FROM temporary_blocks WHERE client_ip='203.0.113.231'`).Scan(&st)
	if err != nil || st != "EXPIRED" {
		t.Errorf("block status = %s, err=%v, want EXPIRED", st, err)
	}

	// 系统审计已记录
	var auditCount int
	err = env.db.QueryRow(context.Background(),
		`SELECT count(*) FROM operation_audits WHERE module='access_control' AND action='auto_expire'`).Scan(&auditCount)
	if err != nil || auditCount < 1 {
		t.Errorf("auto_expire audit count = %d, err=%v, want >=1", auditCount, err)
	}
}

// TestStage5CertificateBindUnbind 证书绑定/解绑独立接口。
func TestStage5CertificateBindUnbind(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "sec_s5_bind", "SECURITY_ADMIN")
	host := "bind-" + s5Rand() + ".example.com"

	// 上传证书
	certPEM, keyPEM := generateTestCertPEM(t, host, []string{host})
	resp := env.post(t, "/api/v1/certificates",
		fmt.Sprintf(`{"name":"bind-cert-%s","cert_pem":%q,"key_pem":%q}`, s5Rand(), certPEM, keyPEM), cookies, csrf)
	result := s5OK(t, resp, "upload cert")
	certID, _ := result.Data["id"].(string)

	// 创建应用 + HTTPS 域名
	resp = env.post(t, "/api/v1/applications",
		fmt.Sprintf(`{"code":"bindapp-%s","name":"绑定测试应用","description":"","business_owner":"t","technical_owner":"t","protection_mode":"OFF"}`, s5Rand()), cookies, csrf)
	result = s5OK(t, resp, "create app")
	appID, _ := result.Data["id"].(string)
	if appID == "" {
		appID, _ = result.Data["application"].(map[string]interface{})["id"].(string)
	}
	resp = env.post(t, fmt.Sprintf("/api/v1/applications/%s/domains", appID),
		fmt.Sprintf(`{"hostname":%q,"is_primary":true,"http_enabled":false,"https_enabled":true,"https_port":8443,"redirect_http_to_https":false}`, host), cookies, csrf)
	s5OK(t, resp, "create https domain")

	// 绑定（独立接口）
	resp = env.post(t, fmt.Sprintf("/api/v1/certificates/%s/bind", certID),
		fmt.Sprintf(`{"application_id":%q}`, appID), cookies, csrf)
	s5OK(t, resp, "bind certificate")

	// 绑定关系可见
	resp = env.get(t, fmt.Sprintf("/api/v1/certificates/%s/applications", certID), cookies)
	result = s5OK(t, resp, "list cert applications")
	raw, _ := json.Marshal(result.Data)
	if !strings.Contains(string(raw), appID) {
		t.Errorf("cert applications not contain app: %s", raw)
	}

	// 域名不匹配的绑定应失败
	resp = env.post(t, "/api/v1/applications",
		fmt.Sprintf(`{"code":"otherapp-%s","name":"其他应用","description":"","business_owner":"t","technical_owner":"t","protection_mode":"OFF"}`, s5Rand()), cookies, csrf)
	result = s5OK(t, resp, "create other app")
	otherID, _ := result.Data["id"].(string)
	if otherID == "" {
		otherID, _ = result.Data["application"].(map[string]interface{})["id"].(string)
	}
	resp = env.post(t, fmt.Sprintf("/api/v1/applications/%s/domains", otherID),
		`{"hostname":"other.example.com","is_primary":true,"http_enabled":false,"https_enabled":true,"https_port":8443,"redirect_http_to_https":false}`, cookies, csrf)
	s5OK(t, resp, "create other domain")
	resp = env.post(t, fmt.Sprintf("/api/v1/certificates/%s/bind", certID),
		fmt.Sprintf(`{"application_id":%q}`, otherID), cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "bind mismatched domain")

	// 解绑
	resp = env.post(t, fmt.Sprintf("/api/v1/certificates/%s/unbind", certID),
		fmt.Sprintf(`{"application_id":%q}`, appID), cookies, csrf)
	s5OK(t, resp, "unbind certificate")
}
