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
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/l7rules"
	"github.com/jiuzhang-waf/server/internal/product"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
)

// setupL7Env 初始化 L7 集成测试环境。
// 与 setupTestEnv 同一套纪律（真实 postgres/valkey、独立测试库重建、全量迁移、
// 真实应用 + httptest.Server + setup 阶段导入公共测试授权），差异仅在显式以
// WAF 产品形态装配：L7 路由在 app 层按 cfg.Product.WebWAFProtectionEnabled()
// 门控，不开启时一律 404。
func setupL7Env(t *testing.T) *testEnv {
	t.Helper()
	cfg := baseTestCfg()
	// WAF 形态：Web 防护能力开启（默认交付形态，与 product.Load 缺省一致）
	cfg.Product = product.Settings{
		Edition:            product.EditionWAF,
		WebWAFEnabled:      true,
		MaxBodyParseBytes:  1 << 20,
		MaxBodySampleBytes: 64 << 10,
		MaxJSONDepth:       32,
		MaxFieldCount:      2048,
	}
	env := newTestEnv(t, cfg)
	env.importBaseLicense(t)
	return env
}

// l7RuleBody 构造一条六条件 block 规则的请求体（名称随机后缀保证可重入）。
func l7RuleBody(name string) string {
	return fmt.Sprintf(`{"name":%q,"priority":100,"enabled":true,`+
		`"conditions":[`+
		`{"type":"uri","op":"prefix","value":"/admin"},`+
		`{"type":"method","values":["GET","POST"]},`+
		`{"type":"header","name":"X-Env","op":"eq","value":"prod"},`+
		`{"type":"cookie","name":"session","op":"exists"},`+
		`{"type":"query","name":"debug","op":"ne","value":"1"},`+
		`{"type":"client_ip","values":["10.0.0.0/8","192.168.1.5"]}`+
		`],"action":"block","action_config":{"status":403,"message":"访问被拦截"}}`, name)
}

// TestL7RuleCRUD L7 规则全生命周期：创建/详情/列表过滤/PATCH 全量更新/删除。
func TestL7RuleCRUD(t *testing.T) {
	env := setupL7Env(t)
	cookies, csrf := env.s5Login(t, "l7sec", "SECURITY_ADMIN")

	// 创建（六条件 block）
	name := "l7rule-" + s5Rand()
	resp := env.post(t, "/api/v1/l7-rules", l7RuleBody(name), cookies, csrf)
	result := s5OK(t, resp, "create l7 rule")
	rule := s5Obj(t, result, "rule")
	id, _ := rule["id"].(string)
	if id == "" {
		t.Fatal("created rule id empty")
	}
	if rule["enabled"] != true || s5Num(t, rule, "priority") != 100 || rule["action"] != "block" {
		t.Errorf("unexpected rule: %+v", rule)
	}
	// action_config 六键恒出（契约形状）
	ac, ok := rule["action_config"].(map[string]interface{})
	if !ok || len(ac) != 6 {
		t.Fatalf("action_config 应为六键对象: %+v", rule["action_config"])
	}
	for _, k := range []string{"status", "message", "redirect_url", "redirect_status", "content_type", "body"} {
		if _, ok := ac[k]; !ok {
			t.Fatalf("action_config 缺少键 %s: %+v", k, ac)
		}
	}
	// 条件 round-trip：六条完整回读
	conds, ok := rule["conditions"].([]interface{})
	if !ok || len(conds) != 6 {
		t.Fatalf("conditions 应为六条: %+v", rule["conditions"])
	}

	// 详情
	resp = env.get(t, "/api/v1/l7-rules/"+id, cookies)
	s5OK(t, resp, "get l7 rule")

	// 列表：关键字 + enabled 过滤 + hit_count_24h 字段存在
	resp = env.get(t, "/api/v1/l7-rules?keyword="+name, cookies)
	result = s5OK(t, resp, "list l7 rules by keyword")
	items, ok := result.Data["items"].([]interface{})
	if !ok || len(items) != 1 {
		t.Fatalf("keyword 列表应恰一条: %+v", result.Data)
	}
	if _, ok := items[0].(map[string]interface{})["hit_count_24h"]; !ok {
		t.Fatalf("列表项缺少 hit_count_24h: %+v", items[0])
	}
	resp = env.get(t, "/api/v1/l7-rules?enabled=false", cookies)
	result = s5OK(t, resp, "list enabled=false")
	if items, _ = result.Data["items"].([]interface{}); len(items) != 0 {
		t.Fatalf("enabled=false 应为空列表: %+v", items)
	}
	// enabled 非法值 → 400（不静默忽略）
	resp = env.get(t, "/api/v1/l7-rules?enabled=maybe", cookies)
	s5Expect(t, resp, http.StatusBadRequest, "invalid enabled filter")

	// PATCH 全量更新：改优先级 + 停用 + 换 host 条件 + redirect（301 + 保留路径和查询参数）动作
	updated := fmt.Sprintf(`{"name":%q,"priority":50,"enabled":false,`+
		`"conditions":[{"type":"host","op":"eq","value":"JXDR.CN"}],`+
		`"action":"redirect","action_config":{"redirect_url":"https://www.jxdr.cn","redirect_status":301,"preserve_path_query":true}}`, name)
	resp = env.do(t, http.MethodPatch, "/api/v1/l7-rules/"+id, updated, cookies, csrf)
	result = s5OK(t, resp, "update l7 rule")
	rule = s5Obj(t, result, "rule")
	if rule["enabled"] != false || s5Num(t, rule, "priority") != 50 || rule["action"] != "redirect" {
		t.Errorf("updated rule unexpected: %+v", rule)
	}
	if uconds, ok := rule["conditions"].([]interface{}); !ok || len(uconds) != 1 ||
		uconds[0].(map[string]interface{})["type"] != "host" || uconds[0].(map[string]interface{})["value"] != "jxdr.cn" {
		t.Errorf("host condition not normalized: %+v", rule["conditions"])
	}
	if uac, ok := rule["action_config"].(map[string]interface{}); !ok || uac["preserve_path_query"] != true {
		t.Errorf("preserve_path_query expected true: %+v", rule["action_config"])
	}

	// 删除 → 详情 404
	resp = env.do(t, http.MethodDelete, "/api/v1/l7-rules/"+id, "", cookies, csrf)
	s5Expect(t, resp, http.StatusOK, "delete l7 rule")
	resp = env.get(t, "/api/v1/l7-rules/"+id, cookies)
	s5Expect(t, resp, http.StatusNotFound, "get deleted l7 rule")
}

// TestL7RuleValidationRejected 非法输入拒绝（400）。
func TestL7RuleValidationRejected(t *testing.T) {
	env := setupL7Env(t)
	cookies, csrf := env.s5Login(t, "l7sec", "SECURITY_ADMIN")

	cases := []struct{ name, body string }{
		{"缺条件", `{"name":"x","action":"allow","conditions":[]}`},
		{"未知条件类型", `{"name":"x","conditions":[{"type":"body","op":"eq","value":"1"}],"action":"allow"}`},
		{"uri不以斜杠开头", `{"name":"x","conditions":[{"type":"uri","op":"prefix","value":"admin"}],"action":"allow"}`},
		{"host带端口拒绝", `{"name":"x","conditions":[{"type":"host","op":"eq","value":"jxdr.cn:443"}],"action":"allow"}`},
		{"host带协议拒绝", `{"name":"x","conditions":[{"type":"host","op":"eq","value":"https://jxdr.cn"}],"action":"allow"}`},
		{"正则不合法", `{"name":"x","conditions":[{"type":"uri","op":"regex","value":"([bad"}],"action":"allow"}`},
		{"非法方法", `{"name":"x","conditions":[{"type":"method","values":["HACK"]}],"action":"allow"}`},
		{"非法来源IP", `{"name":"x","conditions":[{"type":"client_ip","values":["999.1.1.1"]}],"action":"allow"}`},
		{"未知动作", `{"name":"x","conditions":[{"type":"uri","op":"prefix","value":"/a"}],"action":"drop"}`},
		{"redirect缺URL", `{"name":"x","conditions":[{"type":"uri","op":"prefix","value":"/a"}],"action":"redirect"}`},
		{"redirect非http", `{"name":"x","conditions":[{"type":"uri","op":"prefix","value":"/a"}],"action":"redirect","action_config":{"redirect_url":"javascript:alert(1)"}}`},
		{"block状态码越界", `{"name":"x","conditions":[{"type":"uri","op":"prefix","value":"/a"}],"action":"block","action_config":{"status":200}}`},
		{"自定义页面缺内容", `{"name":"x","conditions":[{"type":"uri","op":"prefix","value":"/a"}],"action":"custom_page","action_config":{"status":403}}`},
		{"自定义页面超64KB", fmt.Sprintf(`{"name":"x","conditions":[{"type":"uri","op":"prefix","value":"/a"}],"action":"custom_page","action_config":{"body":%q}}`, strings.Repeat("a", 64*1024+1))},
		{"条件超10条", `{"name":"x","conditions":[` + strings.Repeat(`{"type":"uri","op":"prefix","value":"/a"},`, 10) + `{"type":"uri","op":"prefix","value":"/b"}],"action":"allow"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.post(t, "/api/v1/l7-rules", tc.body, cookies, csrf)
			s5Expect(t, resp, http.StatusBadRequest, "create invalid rule: "+tc.name)
		})
	}
}

// TestL7RuleTester 规则测试器：首中即停、停用跳过、未命中文案、输入校验。
func TestL7RuleTester(t *testing.T) {
	env := setupL7Env(t)
	cookies, csrf := env.s5Login(t, "l7sec", "SECURITY_ADMIN")

	// 低优先级 block（/admin 前缀）
	resp := env.post(t, "/api/v1/l7-rules", fmt.Sprintf(
		`{"name":"low-%s","priority":200,"conditions":[{"type":"uri","op":"prefix","value":"/admin"}],"action":"block"}`,
		s5Rand()), cookies, csrf)
	s5OK(t, resp, "create low priority rule")
	// 高优先级 custom_page（/admin/api 前缀）
	resp = env.post(t, "/api/v1/l7-rules", fmt.Sprintf(
		`{"name":"high-%s","priority":50,"conditions":[{"type":"uri","op":"prefix","value":"/admin/api"}],`+
			`"action":"custom_page","action_config":{"status":403,"body":"<h1>维护中</h1>"}}`, s5Rand()), cookies, csrf)
	result := s5OK(t, resp, "create high priority rule")
	highID, _ := s5Obj(t, result, "rule")["id"].(string)

	// 命中高优先级（首中即停）
	resp = env.post(t, "/api/v1/l7-rules/test",
		`{"uri":"/admin/api/users","method":"GET","client_ip":"8.8.8.8"}`, cookies, csrf)
	result = s5OK(t, resp, "test match high")
	if result.Data["matched"] != true || result.Data["rule_id"] != highID || result.Data["action"] != "custom_page" {
		t.Fatalf("测试器应命中高优先级规则: %+v", result.Data)
	}
	// 命中低优先级
	resp = env.post(t, "/api/v1/l7-rules/test",
		`{"uri":"/admin/console","method":"GET","client_ip":"8.8.8.8"}`, cookies, csrf)
	result = s5OK(t, resp, "test match low")
	if result.Data["matched"] != true || result.Data["action"] != "block" {
		t.Fatalf("测试器应命中低优先级规则: %+v", result.Data)
	}
	// 未命中
	resp = env.post(t, "/api/v1/l7-rules/test",
		`{"uri":"/home","method":"GET","client_ip":"8.8.8.8"}`, cookies, csrf)
	result = s5OK(t, resp, "test no match")
	if result.Data["matched"] != false {
		t.Fatalf("应未命中: %+v", result.Data)
	}
	reason, _ := result.Data["reason"].(string)
	if !strings.Contains(reason, "不命中任何规则") {
		t.Fatalf("未命中 reason 文案异常: %s", reason)
	}
	// 停用后不再命中
	resp = env.do(t, http.MethodPatch, "/api/v1/l7-rules/"+highID, fmt.Sprintf(
		`{"name":"high-off","priority":50,"enabled":false,"conditions":[{"type":"uri","op":"prefix","value":"/admin/api"}],`+
			`"action":"custom_page","action_config":{"status":403,"body":"<h1>维护中</h1>"}}`), cookies, csrf)
	s5OK(t, resp, "disable high rule")
	resp = env.post(t, "/api/v1/l7-rules/test",
		`{"uri":"/admin/api/users","method":"GET","client_ip":"8.8.8.8"}`, cookies, csrf)
	result = s5OK(t, resp, "test after disable")
	if s5ObjID(t, result) == highID || result.Data["action"] != "block" {
		t.Fatalf("停用规则应跳过，命中低优先级 block: %+v", result.Data)
	}
	// 输入校验：URI 非斜杠开头 / 非法 IP → 400
	resp = env.post(t, "/api/v1/l7-rules/test", `{"uri":"admin","method":"GET"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "test invalid uri")
	resp = env.post(t, "/api/v1/l7-rules/test", `{"uri":"/a","method":"GET","client_ip":"bad-ip"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "test invalid ip")

	// 请求域名（Host）+ 301 重定向保留路径和查询参数测试
	resp = env.post(t, "/api/v1/l7-rules", fmt.Sprintf(
		`{"name":"apex-%s","priority":10,"conditions":[{"type":"host","op":"eq","value":"jxdr.cn"}],`+
			`"action":"redirect","action_config":{"redirect_url":"https://www.jxdr.cn","redirect_status":301,"preserve_path_query":true}}`,
		s5Rand()), cookies, csrf)
	s5OK(t, resp, "create host redirect rule")
	resp = env.post(t, "/api/v1/l7-rules/test",
		`{"uri":"/news?id=1","host":"JXDR.CN:443","method":"GET","client_ip":"8.8.8.8"}`, cookies, csrf)
	result = s5OK(t, resp, "test host redirect rule")
	if result.Data["matched"] != true || result.Data["action"] != "redirect" ||
		s5Num(t, result.Data, "redirect_status") != 301 ||
		result.Data["redirect_location"] != "https://www.jxdr.cn/news?id=1" {
		t.Fatalf("host 重定向测试器结果异常: %+v", result.Data)
	}
}

// s5ObjID 取测试器响应 rule_id。
func s5ObjID(t *testing.T, result apiResp) string {
	t.Helper()
	s, _ := result.Data["rule_id"].(string)
	return s
}

// TestL7RulePermissions 权限点：审计管理员 000100 收紧后无 l7rules 权限（读/写均 403）。
func TestL7RulePermissions(t *testing.T) {
	env := setupL7Env(t)
	auditCookies, _ := env.s5Login(t, "l7aud", "AUDIT_ADMIN")

	// 只读接口同样拒绝（纯审计角色不再持有 l7rules.read）
	resp := env.get(t, "/api/v1/l7-rules", auditCookies)
	s5Expect(t, resp, http.StatusForbidden, "audit admin list l7 rules")
	// 写接口拒绝（无 l7rules.create）
	resp = env.post(t, "/api/v1/l7-rules", l7RuleBody("perm-"+s5Rand()), auditCookies, "")
	s5Expect(t, resp, http.StatusForbidden, "audit admin create l7 rule")
	// 发布拒绝（无 l7rules.publish）
	resp = env.post(t, "/api/v1/l7-rules/publish", `{}`, auditCookies, "")
	s5Expect(t, resp, http.StatusForbidden, "audit admin publish l7 rules")
}

// TestL7RulePublishChain 发布链：
//  1. 发布接口复用 gateway 发布通道（集成环境无真实 Caddy Admin Socket，
//     任务应停在 VALIDATE_FAILED——证明 guard 配置快照组装（含 l7_rules）已通过）；
//  2. 用真实仓储直调 guardconfig.Provider：BuildGuardConfig 组装契约一 l7_rules 段，
//     SaveVersionSnapshot 落入 access_control_versions 并可回读（复用版本机制）。
func TestL7RulePublishChain(t *testing.T) {
	env := setupL7Env(t)
	cookies, csrf := env.s5Login(t, "l7sec", "SECURITY_ADMIN")
	ctx := context.Background()

	// 建一条规则（发布内容）
	resp := env.post(t, "/api/v1/l7-rules", l7RuleBody("pub-"+s5Rand()), cookies, csrf)
	result := s5OK(t, resp, "create rule for publish")
	ruleID, _ := s5Obj(t, result, "rule")["id"].(string)

	// 发布（复用发布通道；同步返回最终任务）。
	// 集成环境无 Caddy Admin Socket：任务应停在快照组装之后的环节（GENERATE/VALIDATE），
	// 若停在 GUARD_SNAPSHOT_FAILED 才说明 l7_rules 组装破坏了发布链。
	resp = env.post(t, "/api/v1/l7-rules/publish", `{}`, cookies, csrf)
	result = s5OK(t, resp, "publish l7 rules")
	if result.Data["id"] == nil {
		t.Fatalf("发布应返回任务: %+v", result.Data)
	}
	failCode, _ := result.Data["failure_code"].(string)
	if result.Data["status"] != "FAILED" || (failCode != "GENERATE_FAILED" && failCode != "VALIDATE_FAILED") {
		t.Fatalf("无 Caddy 环境下任务应停在 GENERATE/VALIDATE（说明快照组装已通过）: %+v", result.Data)
	}

	// 真实仓储直调组装器：契约一 l7_rules 段 + 版本快照机制
	l7Store := l7rules.NewStore(env.db)
	acVersionStore := accesscontrolversions.NewStore(env.db)
	provider := guardconfig.NewProvider(
		trustedproxies.NewStore(env.db), protectedaddresses.NewStore(env.db),
		accessrules.NewStore(env.db), ratelimitpolicies.NewStore(env.db), acVersionStore,
		guardconfig.Config{GatewayNode: "gw-test", EventsLog: "/var/log/caddy/guard-events.log"})
	provider.SetL7Rules(l7Store)
	cfg, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("BuildGuardConfig: %v", err)
	}
	if cfg.L7Rules == nil || len(cfg.L7Rules.Rules) != 1 {
		t.Fatalf("GuardConfig 应含一条 L7 规则: %+v", cfg.L7Rules)
	}
	gr := cfg.L7Rules.Rules[0]
	if gr.ID != ruleID || gr.Action != "block" || len(gr.Conditions) != 6 {
		t.Fatalf("L7 载荷规则异常: %+v", gr)
	}
	if gr.ActionConfig.Status != 403 || gr.ActionConfig.RedirectStatus != 302 ||
		gr.ActionConfig.ContentType != "text/html; charset=utf-8" {
		t.Fatalf("action_config 默认值异常: %+v", gr.ActionConfig)
	}
	// 未注入 SetL7Rules 时不得出现 l7_rules 段（API 形态/历史一致）
	plain := guardconfig.NewProvider(
		trustedproxies.NewStore(env.db), protectedaddresses.NewStore(env.db),
		accessrules.NewStore(env.db), ratelimitpolicies.NewStore(env.db), acVersionStore,
		guardconfig.Config{GatewayNode: "gw-test"})
	plainCfg, err := plain.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("BuildGuardConfig plain: %v", err)
	}
	if plainCfg.L7Rules != nil {
		t.Fatal("未注入 L7 仓储时 GuardConfig 不应含 l7_rules 段")
	}

	// 版本快照落库并可回读（复用 accesscontrolversions 机制）
	versionID, err := provider.SaveVersionSnapshot(ctx, cfg, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("SaveVersionSnapshot: %v", err)
	}
	back, err := provider.GetVersionConfig(ctx, versionID)
	if err != nil {
		t.Fatalf("GetVersionConfig: %v", err)
	}
	if back.L7Rules == nil || len(back.L7Rules.Rules) != 1 || back.L7Rules.Rules[0].ID != ruleID {
		t.Fatalf("版本快照回读 L7 规则异常: %+v", back.L7Rules)
	}
	raw, err := json.Marshal(back)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"l7_rules"`) {
		t.Fatalf("快照 JSON 应含 l7_rules 段: %s", raw)
	}
}

// TestL7RuleHitCount 命中数：插入 L7_RULE_* 事件后列表 24h 命中数聚合正确。
func TestL7RuleHitCount(t *testing.T) {
	env := setupL7Env(t)
	cookies, csrf := env.s5Login(t, "l7sec", "SECURITY_ADMIN")

	resp := env.post(t, "/api/v1/l7-rules", l7RuleBody("hit-"+s5Rand()), cookies, csrf)
	result := s5OK(t, resp, "create rule for hit count")
	ruleID, _ := s5Obj(t, result, "rule")["id"].(string)

	// 模拟网关命中事件（L7_RULE_BLOCK × 2 + L7_RULE_ALLOW × 1，access_rule_id=规则ID）
	for _, et := range []string{"L7_RULE_BLOCK", "L7_RULE_BLOCK", "L7_RULE_ALLOW"} {
		_, err := env.db.Exec(context.Background(), `
INSERT INTO access_control_events (request_id, occurred_at, client_ip, event_type, action, access_rule_id, gateway_node_id, message)
VALUES ('', $1, '10.1.2.3', $2, 'REJECT', $3, 'gw-test', '集成测试注入')`, time.Now().UTC(), et, ruleID)
		if err != nil {
			t.Fatalf("insert hit event: %v", err)
		}
	}
	// 其他规则的事件不计入
	_, err := env.db.Exec(context.Background(), `
INSERT INTO access_control_events (request_id, occurred_at, client_ip, event_type, action, access_rule_id, gateway_node_id, message)
VALUES ('', $1, '10.1.2.4', 'L7_RULE_BLOCK', 'REJECT', $2, 'gw-test', '其他规则')`,
		time.Now().UTC(), "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("insert other rule event: %v", err)
	}

	resp = env.get(t, "/api/v1/l7-rules/"+ruleID, cookies)
	result = s5OK(t, resp, "get rule with hit count")
	if got := s5Num(t, s5Obj(t, result, "rule"), "hit_count_24h"); got != 3 {
		t.Fatalf("hit_count_24h = %v, want 3", got)
	}
}
