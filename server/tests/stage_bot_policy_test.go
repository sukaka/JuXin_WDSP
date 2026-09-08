// stage_bot_policy_test.go 应用级 Bot 挑战策略管理面接口测试（WDSP P1-02 B1；
// 真实 PG/Valkey，未设置环境或 -short 即 skip）。覆盖：迁移建表与权限种子；
// 三个接口的权限拒绝/404/字段错误/409 并发/审计写入/路由保留冲突预检；
// 跨应用隔离；Store.ListForGuard 真实 DB 下发契约；迁移 down/up 实跑。
// 真实网关发布、节点回执与挑战链路（B2/B3）不在本文件。
package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/botpolicy"
	"github.com/jiuzhang-waf/server/internal/database"
)

// botNested 从 map 中取嵌套对象（对应 s5Obj 的 map 版本，s5Obj 只接 apiResp）。
func botNested(t *testing.T, m map[string]interface{}, key string) map[string]interface{} {
	t.Helper()
	obj, ok := m[key].(map[string]interface{})
	if !ok {
		t.Fatalf("field %s missing or not an object: %+v", key, m)
	}
	return obj
}

// botTestApp 创建测试应用，返回应用 ID。
func botTestApp(t *testing.T, env *testEnv, cookies []*http.Cookie, csrf, code string) string {
	t.Helper()
	resp := env.post(t, "/api/v1/applications",
		fmt.Sprintf(`{"code":%q,"name":"Bot测试","protection_mode":"OBSERVE"}`, code), cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create app status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var result apiResp
	readJSON(t, resp, &result)
	appID, _ := result.Data["id"].(string)
	if appID == "" {
		t.Fatal("no app id")
	}
	return appID
}

// botObserveBody 合法 OBSERVE 草稿请求体（两行为组信号 + 保留已启用）。
func botObserveBody(expectedVersion int) string {
	return fmt.Sprintf(`{"mode":"OBSERVE","expected_version":%d,"reason":"开启 Bot 观测",
"selectors":[{"path_prefix":"/docs"}],
"signal_rules":{"min_independent_groups":2,"require_behavior_group":true,"rules":[
{"id":"rb_4xx","group":"request_behavior","metric":"status_family_ratio","params":{"family":"4xx"},"window_seconds":300,"weight":1,"threshold":0.6},
{"id":"as_known","group":"access_sequence","metric":"known_uri_ratio","window_seconds":300,"weight":1,"threshold":0.3}]},
"route_reservation":{"state":"ENABLED","namespace":"/_wdsp/bot/v1/"}}`, expectedVersion)
}

// botProtectBody 合法 PROTECT 草稿请求体（PROTECT 要求保留 ENABLED）。
func botProtectBody(expectedVersion int) string {
	return fmt.Sprintf(`{"mode":"PROTECT","expected_version":%d,"reason":"升级挑战强制",
"selectors":[{"path_prefix":"/docs"}],
"signal_rules":{"min_independent_groups":2,"require_behavior_group":true,"rules":[
{"id":"rb_4xx","group":"request_behavior","metric":"status_family_ratio","params":{"family":"4xx"},"window_seconds":300,"weight":1,"threshold":0.6},
{"id":"as_known","group":"access_sequence","metric":"known_uri_ratio","window_seconds":300,"weight":1,"threshold":0.3},
{"id":"cc_ua","group":"client_claim","metric":"ua_class_match","params":{"class":"BOT"},"window_seconds":300,"weight":1,"threshold":0}]},
"challenge":{"type":"JS","nonce_ttl_seconds":90,"clearance_ttl_seconds":900,"difficulty":14,"max_attempts":3,"key_ref":"bot-hmac-2026"},
"route_reservation":{"state":"ENABLED","namespace":"/_wdsp/bot/v1/"}}`, expectedVersion)
}

// TestBotPolicyMigrations 迁移后表/权限/角色授权种子存在。
func TestBotPolicyMigrations(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	var n int
	for _, table := range []string{"bot_policies", "bot_policy_versions"} {
		if err := env.db.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables
WHERE table_name=$1`, table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("table %s missing: n=%d err=%v", table, n, err)
		}
	}
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM permissions
WHERE code IN ('bot_policy.read','bot_policy.edit')`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("bot_policy permissions = %d, want 2 (err %v)", n, err)
	}
	// read 三角色全授；edit 仅 SYSTEM_ADMIN/SECURITY_ADMIN
	if err := env.db.QueryRow(ctx, `SELECT count(DISTINCT r.code) FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
WHERE p.code = 'bot_policy.read' AND r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN','AUDIT_ADMIN')`).Scan(&n); err != nil || n != 3 {
		t.Errorf("bot_policy.read granted roles = %d, want 3 (err %v)", n, err)
	}
	if err := env.db.QueryRow(ctx, `SELECT count(DISTINCT r.code) FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
WHERE p.code = 'bot_policy.edit' AND r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN')`).Scan(&n); err != nil || n != 2 {
		t.Errorf("bot_policy.edit granted roles = %d, want 2 (err %v)", n, err)
	}
}

// TestBotPolicyLifecycle GET 默认 OFF / PUT 草稿（400 矩阵）/ 409 并发 / 审计 / 预检。
func TestBotPolicyLifecycle(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "bot_sec", "SECURITY_ADMIN")
	appID := botTestApp(t, env, cookies, csrf, "bot-app-"+s5Rand())
	path := "/api/v1/applications/" + appID + "/bot-policy"
	ctx := context.Background()

	// 未配置应用 GET → 默认 OFF 空策略（version=0, NOT_CONFIGURED, found=false）
	result := s5OK(t, env.get(t, path, cookies), "get default bot policy")
	policy := s5Obj(t, result, "policy")
	if policy["mode"] != "OFF" || int(s5Num(t, policy, "version")) != 0 {
		t.Fatalf("default policy = %+v", policy)
	}
	summary := s5Obj(t, result, "summary")
	if summary["state"] != "NOT_CONFIGURED" || int(s5Num(t, summary, "draft_version")) != 0 {
		t.Fatalf("default summary = %+v", summary)
	}
	published := botNested(t, summary, "published")
	if published["found"] != false || int(s5Num(t, published, "policy_version")) != 0 {
		t.Fatalf("default published = %+v", published)
	}

	// 不存在应用 → 404；非法应用 ID → 400
	s5Expect(t, env.get(t, "/api/v1/applications/"+uuid.NewString()+"/bot-policy", cookies),
		http.StatusNotFound, "get bot policy of missing app")
	s5Expect(t, env.get(t, "/api/v1/applications/not-a-uuid/bot-policy", cookies),
		http.StatusBadRequest, "get bot policy with bad id")

	// PUT 缺 reason → 400
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OFF","expected_version":0}`, cookies, csrf), http.StatusBadRequest, "put without reason")
	// PUT 非法 mode → 400
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"BLOCK","expected_version":0,"reason":"t"}`, cookies, csrf), http.StatusBadRequest, "put bad mode")
	// PUT OBSERVE 缺 selectors → 400
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OBSERVE","expected_version":0,"reason":"t"}`, cookies, csrf), http.StatusBadRequest, "put observe without selectors")
	// PUT 挑战参数越界（difficulty 19 > 18）→ 400
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OBSERVE","expected_version":0,"reason":"t","selectors":[{"path_prefix":"/docs"}],
"signal_rules":{"rules":[{"id":"rb_4xx","group":"request_behavior","metric":"status_family_ratio","params":{"family":"4xx"},"window_seconds":300,"weight":1,"threshold":0.6}]},
"challenge":{"type":"JS","difficulty":19}}`, cookies, csrf), http.StatusBadRequest, "put difficulty out of bounds")
	// PUT 全站通配选择器 → 400
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OBSERVE","expected_version":0,"reason":"t","selectors":[{"path_prefix":"/"}],
"signal_rules":{"rules":[{"id":"rb_4xx","group":"request_behavior","metric":"status_family_ratio","params":{"family":"4xx"},"window_seconds":300,"weight":1,"threshold":0.6}]}}`,
		cookies, csrf), http.StatusBadRequest, "put wildcard selector")
	// PUT 选择器覆盖保留命名空间 → 400
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OBSERVE","expected_version":0,"reason":"t","selectors":[{"path_prefix":"/_wdsp"}],
"signal_rules":{"rules":[{"id":"rb_4xx","group":"request_behavior","metric":"status_family_ratio","params":{"family":"4xx"},"window_seconds":300,"weight":1,"threshold":0.6}]}}`,
		cookies, csrf), http.StatusBadRequest, "put selector covering reserved namespace")
	// PUT 声明组阈值非 0（可伪造弱信号命中即触发）→ 400
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OBSERVE","expected_version":0,"reason":"t","selectors":[{"path_prefix":"/docs"}],
"signal_rules":{"rules":[{"id":"cc_ua","group":"client_claim","metric":"ua_class_match","params":{"class":"BOT"},"window_seconds":300,"weight":1,"threshold":0.5}]}}`,
		cookies, csrf), http.StatusBadRequest, "put claim metric with threshold")

	// PUT 合法 OBSERVE 草稿 → 200 + version=1 + 挑战默认值应用
	result = s5OK(t, env.do(t, http.MethodPut, path, botObserveBody(0), cookies, csrf), "put valid observe draft")
	policy = s5Obj(t, result, "policy")
	if int(s5Num(t, policy, "version")) != 1 || policy["mode"] != "OBSERVE" {
		t.Fatalf("policy after put = %+v", policy)
	}
	challenge := botNested(t, policy, "challenge")
	if int(s5Num(t, challenge, "nonce_ttl_seconds")) != 90 ||
		int(s5Num(t, challenge, "clearance_ttl_seconds")) != 900 ||
		int(s5Num(t, challenge, "difficulty")) != 14 ||
		int(s5Num(t, challenge, "max_attempts")) != 3 {
		t.Errorf("challenge defaults not applied: %+v", challenge)
	}

	// GET 显示 DRAFT_PENDING（草稿领先已发布；发布状态分离，不混成 enabled）
	result = s5OK(t, env.get(t, path, cookies), "get after put")
	summary = s5Obj(t, result, "summary")
	if summary["state"] != "DRAFT_PENDING" || int(s5Num(t, summary, "draft_version")) != 1 {
		t.Errorf("summary after put = %+v, want DRAFT_PENDING/1", summary)
	}

	// PUT expected_version 过期 → 409；已有草稿以 0 创建 → 409
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OFF","expected_version":9,"reason":"并发冲突测试"}`, cookies, csrf),
		http.StatusConflict, "put with stale expected_version")
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OFF","expected_version":0,"reason":"重复首建"}`, cookies, csrf),
		http.StatusConflict, "put create over existing draft")

	// PUT 升级 PROTECT 草稿 → 200 + version=2
	result = s5OK(t, env.do(t, http.MethodPut, path, botProtectBody(1), cookies, csrf), "put protect draft")
	policy = s5Obj(t, result, "policy")
	if int(s5Num(t, policy, "version")) != 2 || policy["mode"] != "PROTECT" {
		t.Fatalf("policy after protect put = %+v", policy)
	}
	rr := botNested(t, policy, "route_reservation")
	if rr["state"] != "ENABLED" {
		t.Errorf("route_reservation = %+v, want ENABLED", rr)
	}

	// 不可变版本记录 = 2 行且 reason 留存
	var n int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM bot_policy_versions
WHERE application_id=$1`, appID).Scan(&n); err != nil || n != 2 {
		t.Errorf("version records = %d, want 2 (err %v)", n, err)
	}
	var reason string
	if err := env.db.QueryRow(ctx, `SELECT reason FROM bot_policy_versions
WHERE application_id=$1 AND version=2`, appID).Scan(&reason); err != nil || reason != "升级挑战强制" {
		t.Errorf("version record reason = %q (err %v)", reason, err)
	}

	// 审计：update（OBSERVE→PROTECT 为高风险）+ 内容含理由与 key_ref 引用名
	var auditCount int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM operation_audits
WHERE object_type='bot_policy' AND action='update'`).Scan(&auditCount); err != nil || auditCount < 2 {
		t.Errorf("bot_policy update audits = %d, want >= 2 (err %v)", auditCount, err)
	}
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM operation_audits
WHERE object_type='bot_policy' AND action='update' AND risk_level='HIGH'`).Scan(&auditCount); err != nil || auditCount < 1 {
		t.Errorf("OBSERVE→PROTECT high-risk audit missing (err %v)", err)
	}
	var afterSummary string
	if err := env.db.QueryRow(ctx, `SELECT after_summary FROM operation_audits
WHERE object_type='bot_policy' AND action='update' AND risk_level='HIGH'
ORDER BY occurred_at DESC LIMIT 1`).Scan(&afterSummary); err != nil {
		t.Fatalf("query audit summary: %v", err)
	}
	if !strings.Contains(afterSummary, "升级挑战强制") || !strings.Contains(afterSummary, "bot-hmac-2026") {
		t.Errorf("audit summary must contain reason and key_ref reference name: %s", afterSummary)
	}

	// 预检当前 PROTECT 草稿：结构 PASS、无冲突、共享状态已配置（测试环境 Valkey 就绪）→ 可发布
	result = s5OK(t, env.post(t, path+"/preflight", "", cookies, csrf), "preflight protect draft")
	data := result.Data
	if data["publishable"] != true {
		t.Errorf("preflight publishable = %v, want true: %+v", data["publishable"], data)
	}
	checks, _ := data["checks"].([]interface{})
	seen := map[string]string{}
	for _, c := range checks {
		cm := c.(map[string]interface{})
		seen[cm["name"].(string)] = cm["status"].(string)
	}
	for name, want := range map[string]string{"structure": "PASS", "route_conflicts": "PASS", "shared_state": "PASS"} {
		if seen[name] != want {
			t.Errorf("check %s = %q, want %s (checks=%v)", name, seen[name], want, checks)
		}
	}
	if conflicts, _ := data["conflicts"].([]interface{}); len(conflicts) != 0 {
		t.Errorf("unexpected conflicts: %+v", conflicts)
	}

	// 预检审计（低风险）
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM operation_audits
WHERE object_type='bot_policy' AND action='preflight' AND risk_level='LOW'`).Scan(&auditCount); err != nil || auditCount < 1 {
		t.Errorf("preflight audit missing (err %v)", err)
	}
}

// TestBotPolicyPermissions 权限口径：AUDIT_ADMIN 只读（GET 200 / PUT / preflight 403）；
// 未登录 401；缺 CSRF 403。（角色种子见迁移 000129）
func TestBotPolicyPermissions(t *testing.T) {
	env := setupTestEnv(t)
	secCookies, secCSRF := env.s5Login(t, "bot_psec", "SECURITY_ADMIN")
	appID := botTestApp(t, env, secCookies, secCSRF, "bot-perm-"+s5Rand())
	path := "/api/v1/applications/" + appID + "/bot-policy"

	auditCookies, auditCSRF := env.s5Login(t, "bot_pa", "AUDIT_ADMIN")
	s5Expect(t, env.get(t, path, auditCookies), http.StatusOK, "audit admin get bot policy")
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OFF","expected_version":0,"reason":"t"}`, auditCookies, auditCSRF),
		http.StatusForbidden, "audit admin put bot policy")
	s5Expect(t, env.post(t, path+"/preflight", "", auditCookies, auditCSRF),
		http.StatusForbidden, "audit admin preflight")

	// 未登录
	s5Expect(t, env.get(t, path, nil), http.StatusUnauthorized, "anonymous get bot policy")
	// 缺 CSRF（已登录但无 token）
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OFF","expected_version":0,"reason":"t"}`, secCookies, ""),
		http.StatusForbidden, "put without csrf token")
}

// TestBotPolicyCrossAppIsolation 跨应用隔离：应用 A 保存草稿不影响应用 B——
// GET B 仍返回默认 OFF 空策略；对 B 的 PUT 携带 A 的版本号按 B 自身状态判定（409）。
func TestBotPolicyCrossAppIsolation(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "bot_iso", "SECURITY_ADMIN")
	appA := botTestApp(t, env, cookies, csrf, "bot-iso-a-"+s5Rand())
	appB := botTestApp(t, env, cookies, csrf, "bot-iso-b-"+s5Rand())
	pathA := "/api/v1/applications/" + appA + "/bot-policy"
	pathB := "/api/v1/applications/" + appB + "/bot-policy"
	ctx := context.Background()

	result := s5OK(t, env.do(t, http.MethodPut, pathA, botObserveBody(0), cookies, csrf), "put app A draft")
	if v := int(s5Num(t, s5Obj(t, result, "policy"), "version")); v != 1 {
		t.Fatalf("app A policy version = %d, want 1", v)
	}

	// GET 应用 B → 默认 OFF 空策略，不得泄露 A 的内容
	result = s5OK(t, env.get(t, pathB, cookies), "get app B default policy")
	policy := s5Obj(t, result, "policy")
	if policy["application_id"] != appB || policy["mode"] != "OFF" || int(s5Num(t, policy, "version")) != 0 {
		t.Errorf("app B default policy = %+v", policy)
	}
	if sels, _ := policy["selectors"].([]interface{}); len(sels) != 0 {
		t.Errorf("app B selectors = %v, want empty (must not leak app A)", sels)
	}

	// 对 B 的 PUT 携带 A 的 version 号 → 按 B 自身状态判定 409
	s5Expect(t, env.do(t, http.MethodPut, pathB,
		`{"mode":"OFF","expected_version":1,"reason":"携带A版本号"}`, cookies, csrf),
		http.StatusConflict, "put app B with app A's expected_version")

	// DB 直查：草稿行与版本记录按 application_id 隔离
	var n int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM bot_policies
WHERE application_id=$1 AND version=1 AND mode='OBSERVE'`, appA).Scan(&n); err != nil || n != 1 {
		t.Errorf("bot_policies row for A = %d, want 1 (err %v)", n, err)
	}
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM bot_policy_versions
WHERE application_id=$1`, appB).Scan(&n); err != nil || n != 0 {
		t.Errorf("version records for B = %d, want 0 (err %v)", n, err)
	}
}

// TestBotPolicyPreflightConflicts 路由保留冲突预检：L7 拒绝规则覆盖 verify（FAIL 阻断）、
// L7 放行规则覆盖（WARN）、既有应用路径落入命名空间（FAIL）、路径转发前缀覆盖（FAIL）、
// 全量保护地址段（WARN）；冲突清除后恢复可发布。
func TestBotPolicyPreflightConflicts(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "bot_cf", "SECURITY_ADMIN")
	appID := botTestApp(t, env, cookies, csrf, "bot-cf-"+s5Rand())
	path := "/api/v1/applications/" + appID + "/bot-policy"
	ctx := context.Background()

	// 直接落库构造冲突面（预检读取的是登记数据而非策略本身）：
	// L7 拒绝规则 uri prefix /_wdsp（覆盖 verify）；L7 放行规则 uri prefix /（覆盖全部）；
	// api_endpoints 已登记路径落入保留命名空间；路径转发前缀 /；全量保护地址段
	if _, err := env.db.Exec(ctx, `
INSERT INTO l7_access_rules (name, priority, enabled, conditions, action, action_config) VALUES
('bot-cf-deny', 100, true, '[{"type":"uri","op":"prefix","value":"/_wdsp"}]'::jsonb, 'block', '{"status":403}'::jsonb),
('bot-cf-allow', 200, true, '[{"type":"uri","op":"prefix","value":"/"}]'::jsonb, 'allow', '{}'::jsonb)`); err != nil {
		t.Fatalf("insert l7 rules: %v", err)
	}
	if _, err := env.db.Exec(ctx, `
INSERT INTO api_endpoints (application_id, http_method, normalized_path, endpoint_key)
VALUES ($1, 'POST', '/_wdsp/bot/v1/legacy', 'POST /_wdsp/bot/v1/legacy')`, appID); err != nil {
		t.Fatalf("insert api endpoint: %v", err)
	}
	if _, err := env.db.Exec(ctx, `
INSERT INTO app_path_routes (application_id, path_prefix, upstream_scheme, upstream_host, upstream_port)
VALUES ($1, '/', 'http', '10.0.0.1', 80)`, appID); err != nil {
		t.Fatalf("insert path route: %v", err)
	}
	if _, err := env.db.Exec(ctx, `
INSERT INTO protected_addresses (name, cidr, address_type, source_type)
VALUES ('bot-cf-all', '0.0.0.0/0', 'CUSTOM', 'MANUAL')`); err != nil {
		t.Fatalf("insert protected address: %v", err)
	}

	// 预检候选 OBSERVE 策略（保留 ENABLED）→ 冲突列表齐备且 publishable=false
	result := s5OK(t, env.post(t, path+"/preflight",
		`{"mode":"OBSERVE","selectors":[{"path_prefix":"/docs"}],
"signal_rules":{"rules":[{"id":"rb_4xx","group":"request_behavior","metric":"status_family_ratio","params":{"family":"4xx"},"window_seconds":300,"weight":1,"threshold":0.6}]},
"route_reservation":{"state":"ENABLED"}}`, cookies, csrf), "preflight with conflicts")
	data := result.Data
	if data["publishable"] != false {
		t.Errorf("publishable = %v, want false (FAIL conflicts present)", data["publishable"])
	}
	byType := map[string]string{}
	conflicts, _ := data["conflicts"].([]interface{})
	for _, c := range conflicts {
		cm := c.(map[string]interface{})
		byType[cm["type"].(string)] = cm["status"].(string)
	}
	for typ, want := range map[string]string{
		"l7_deny_rule":            "FAIL",
		"l7_allow_rule":           "WARN",
		"reserved_path_asset":     "FAIL",
		"path_route":              "FAIL",
		"protected_address_scope": "WARN",
	} {
		if byType[typ] != want {
			t.Errorf("conflict %s = %q, want %s (conflicts=%v)", typ, byType[typ], want, conflicts)
		}
	}

	// 候选为 OFF 且保留已解除 → 无冲突面（SKIP）
	result = s5OK(t, env.post(t, path+"/preflight",
		`{"mode":"OFF","route_reservation":{"state":"RELEASED"}}`, cookies, csrf), "preflight off released")
	data = result.Data
	if data["publishable"] != true {
		t.Errorf("OFF+RELEASED publishable = %v, want true", data["publishable"])
	}
	if conflicts, _ := data["conflicts"].([]interface{}); len(conflicts) != 0 {
		t.Errorf("OFF+RELEASED must have no conflicts: %+v", conflicts)
	}

	// 清除冲突源后恢复可发布
	if _, err := env.db.Exec(ctx, `DELETE FROM l7_access_rules WHERE name LIKE 'bot-cf-%'`); err != nil {
		t.Fatalf("cleanup l7: %v", err)
	}
	if _, err := env.db.Exec(ctx, `DELETE FROM api_endpoints WHERE application_id=$1`, appID); err != nil {
		t.Fatalf("cleanup endpoints: %v", err)
	}
	if _, err := env.db.Exec(ctx, `DELETE FROM app_path_routes WHERE application_id=$1`, appID); err != nil {
		t.Fatalf("cleanup path routes: %v", err)
	}
	if _, err := env.db.Exec(ctx, `DELETE FROM protected_addresses WHERE name='bot-cf-all'`); err != nil {
		t.Fatalf("cleanup protected: %v", err)
	}
	result = s5OK(t, env.post(t, path+"/preflight",
		`{"mode":"OBSERVE","selectors":[{"path_prefix":"/docs"}],
"signal_rules":{"rules":[{"id":"rb_4xx","group":"request_behavior","metric":"status_family_ratio","params":{"family":"4xx"},"window_seconds":300,"weight":1,"threshold":0.6}]},
"route_reservation":{"state":"ENABLED"}}`, cookies, csrf), "preflight after cleanup")
	if result.Data["publishable"] != true {
		t.Errorf("publishable after cleanup = %v, want true: %+v", result.Data["publishable"], result.Data)
	}
}

// TestBotPolicyListForGuard Store.ListForGuard 真实 DB 下发契约（guardconfig 供应链）：
// 字段与保存内容一致（含挑战默认值与保留状态），无策略应用不出现在下发集合，
// OFF 策略同样下发（覆盖网关旧配置残留）。
func TestBotPolicyListForGuard(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "bot_guard", "SECURITY_ADMIN")
	codeA := "botg-a-" + s5Rand()
	codeB := "botg-b-" + s5Rand()
	appA := botTestApp(t, env, cookies, csrf, codeA)
	botTestApp(t, env, cookies, csrf, codeB) // 无策略应用：不得出现在下发集合
	pathA := "/api/v1/applications/" + appA + "/bot-policy"
	ctx := context.Background()
	store := botpolicy.NewStore(env.db)

	s5OK(t, env.do(t, http.MethodPut, pathA, botObserveBody(0), cookies, csrf), "put guard draft v1")

	out, err := store.ListForGuard(ctx)
	if err != nil {
		t.Fatalf("ListForGuard: %v", err)
	}
	gp, ok := out[codeA]
	if !ok {
		t.Fatalf("ListForGuard missing app %s: keys=%v", codeA, out)
	}
	if _, ok := out[codeB]; ok {
		t.Errorf("app %s has no policy but appears in guard contract", codeB)
	}
	if gp.SchemaVersion != botpolicy.SchemaVersion || gp.ApplicationID != appA ||
		gp.Mode != "OBSERVE" || gp.Version != 1 {
		t.Errorf("guard policy header = %+v, want schema=%d app=%s OBSERVE/1",
			gp, botpolicy.SchemaVersion, appA)
	}
	if len(gp.Selectors) != 1 || gp.Selectors[0].PathPrefix != "/docs" {
		t.Errorf("guard selectors = %+v, mismatch with saved draft", gp.Selectors)
	}
	if gp.SignalRules.MinIndependentGroups != 2 || !gp.SignalRules.RequireBehaviorGroup ||
		len(gp.SignalRules.Rules) != 2 {
		t.Errorf("guard signal rules = %+v, mismatch", gp.SignalRules)
	}
	r0 := gp.SignalRules.Rules[0]
	if r0.ID != "rb_4xx" || r0.Group != "request_behavior" || r0.Metric != "status_family_ratio" ||
		r0.Params["family"] != "4xx" || r0.WindowSeconds != 300 || r0.Weight != 1 || r0.Threshold != 0.6 {
		t.Errorf("guard rule = %+v, mismatch", r0)
	}
	if gp.Challenge.Type != "JS" || gp.Challenge.NonceTTLSeconds != 90 ||
		gp.Challenge.ClearanceTTLSeconds != 900 || gp.Challenge.Difficulty != 14 || gp.Challenge.MaxAttempts != 3 {
		t.Errorf("guard challenge = %+v, want defaults", gp.Challenge)
	}
	if gp.RouteReservation.State != "ENABLED" || gp.RouteReservation.Namespace != "/_wdsp/bot/v1/" {
		t.Errorf("guard reservation = %+v", gp.RouteReservation)
	}

	// 保存 OFF 草稿 → 同样下发（网关按 mode 关闭判定，同时覆盖旧配置残留）
	s5OK(t, env.do(t, http.MethodPut, pathA,
		`{"mode":"OFF","expected_version":1,"reason":"关闭观测","route_reservation":{"state":"RESERVED_TOMBSTONE"}}`,
		cookies, csrf), "put off draft v2")
	out, err = store.ListForGuard(ctx)
	if err != nil {
		t.Fatalf("ListForGuard after off: %v", err)
	}
	gp2 := out[codeA]
	if gp2 == nil || gp2.Mode != "OFF" || gp2.Version != 2 || gp2.RouteReservation.State != "RESERVED_TOMBSTONE" {
		t.Errorf("guard policy after off = %+v, want OFF/2/TOMBSTONE", gp2)
	}
}

// TestBotPolicyMigrationDownUp 迁移 down/up 在测试库实跑：从当前头版本一路回滚到
// 000128 之下（bot_policy 的 000128 表 / 000129 权限种子上方可能已有更新迁移，按
// version>=128 的应用数动态确定回滚步数），表与权限不存在；up 全部恢复
// （迁移幂等——IF NOT EXISTS / ON CONFLICT）。
func TestBotPolicyMigrationDownUp(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	tableExists := func(table string) bool {
		var n int
		if err := env.db.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables
WHERE table_name=$1`, table).Scan(&n); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		return n == 1
	}
	permCount := func() int {
		var n int
		if err := env.db.QueryRow(ctx, `SELECT count(*) FROM permissions
WHERE code IN ('bot_policy.read','bot_policy.edit')`).Scan(&n); err != nil {
			t.Fatalf("check perms: %v", err)
		}
		return n
	}

	// 回滚 000128 及以上全部已应用版本（含 000129 权限种子与其后的更新迁移）
	var steps int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version >= 128`).Scan(&steps); err != nil {
		t.Fatalf("count applied versions: %v", err)
	}
	if steps < 2 {
		t.Fatalf("expected at least 2 bot policy migrations applied, got %d", steps)
	}
	for i := 0; i < steps; i++ {
		if err := database.Migrate(ctx, env.db, "../migrations", "down"); err != nil {
			t.Fatalf("migrate down #%d: %v", i+1, err)
		}
	}
	if tableExists("bot_policies") || tableExists("bot_policy_versions") {
		t.Error("bot policy tables must be dropped after down")
	}
	if permCount() != 0 {
		t.Error("bot_policy permissions must be removed after down")
	}

	// up 一次性应用全部待执行迁移恢复
	if err := database.Migrate(ctx, env.db, "../migrations", "up"); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	if !tableExists("bot_policies") || !tableExists("bot_policy_versions") {
		t.Error("bot policy tables must exist after re-up")
	}
	if permCount() != 2 {
		t.Error("bot_policy permissions must be reseeded after re-up")
	}
}
