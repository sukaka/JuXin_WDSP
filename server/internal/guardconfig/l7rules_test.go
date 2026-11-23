package guardconfig

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/l7rules"
)

// TestToGuardL7Rules_ContractShape 契约一逐字段比对：
// 载荷序列化后必须与冻结契约示例的键集合与取值完全一致。
func TestToGuardL7Rules_ContractShape(t *testing.T) {
	id := uuid.New()
	rules := []l7rules.Rule{{
		ID:       id,
		Name:     "规则名",
		Priority: 100,
		Enabled:  true,
		Conditions: []l7rules.Condition{
			{Type: "uri", Op: "prefix", Value: "/admin"},
			{Type: "method", Values: []string{"GET", "POST"}},
			{Type: "header", Name: "X-Env", Op: "eq", Value: "prod"},
			{Type: "cookie", Name: "session", Op: "exists"},
			{Type: "query", Name: "debug", Op: "ne", Value: "1"},
			{Type: "client_ip", Values: []string{"10.0.0.0/8", "192.168.1.5"}},
		},
		Action: "block",
		ActionConfig: l7rules.ActionConfig{
			Status:         403,
			Message:        "访问被拦截",
			RedirectURL:    "",
			RedirectStatus: 302,
			ContentType:    "text/html; charset=utf-8",
			Body:           "",
		},
		CreatedAt: time.Now(),
	}}

	payload := toGuardL7Rules(rules)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	// 冻结契约一示例（id 为占位符，断言时替换为实际值）
	contract := `{"rules":[{"id":"` + id.String() + `","name":"规则名","priority":100,"enabled":true,` +
		`"conditions":[` +
		`{"type":"uri","op":"prefix","value":"/admin"},` +
		`{"type":"method","values":["GET","POST"]},` +
		`{"type":"header","name":"X-Env","op":"eq","value":"prod"},` +
		`{"type":"cookie","name":"session","op":"exists"},` +
		`{"type":"query","name":"debug","op":"ne","value":"1"},` +
		`{"type":"client_ip","values":["10.0.0.0/8","192.168.1.5"]}` +
		`],"action":"block","action_config":{"status":403,"message":"访问被拦截","redirect_url":"",` +
		`"redirect_status":302,"content_type":"text/html; charset=utf-8","body":""}}]}`

	var gotObj, wantObj interface{}
	if err := json.Unmarshal(raw, &gotObj); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(contract), &wantObj); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotObj, wantObj) {
		t.Fatalf("下发载荷与契约一不一致:\ngot:  %s\nwant: %s", raw, contract)
	}
}

// TestToGuardL7Rules_RuleKeySet 规则与条件键集合白名单断言（防字段漂移破坏契约）。
func TestToGuardL7Rules_RuleKeySet(t *testing.T) {
	rules := []l7rules.Rule{{
		ID: uuid.New(), Name: "r", Priority: 1, Enabled: true,
		Conditions: []l7rules.Condition{
			{Type: "uri", Op: "eq", Value: "/a"},
			{Type: "method", Values: []string{"GET"}},
			{Type: "header", Name: "H", Op: "exists"},
			{Type: "client_ip", Values: []string{"1.1.1.1"}},
		},
		Action: "allow",
		ActionConfig: l7rules.ActionConfig{
			Status: 403, RedirectStatus: 302, ContentType: "text/html; charset=utf-8",
		},
	}}
	raw, err := json.Marshal(toGuardL7Rules(rules))
	if err != nil {
		t.Fatal(err)
	}
	var top map[string][]map[string]interface{}
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	rule := top["rules"][0]
	wantRuleKeys := []string{"id", "name", "priority", "enabled", "conditions", "action", "action_config"}
	if len(rule) != len(wantRuleKeys) {
		t.Fatalf("规则键数量异常: %v", keysOf(rule))
	}
	for _, k := range wantRuleKeys {
		if _, ok := rule[k]; !ok {
			t.Fatalf("规则缺少键 %s", k)
		}
	}
	// action_config 六键恒出
	ac := rule["action_config"].(map[string]interface{})
	for _, k := range []string{"status", "message", "redirect_url", "redirect_status", "content_type", "body"} {
		if _, ok := ac[k]; !ok {
			t.Fatalf("action_config 缺少键 %s", k)
		}
	}
	if len(ac) != 6 {
		t.Fatalf("action_config 键数量应为 6: %v", keysOf(ac))
	}
	// 各条件类型键集合
	conds := rule["conditions"].([]interface{})
	wantCondKeys := []map[string]bool{
		{"type": true, "op": true, "value": true}, // uri
		{"type": true, "values": true},            // method
		{"type": true, "name": true, "op": true},  // header exists（无 value 键）
		{"type": true, "values": true},            // client_ip
	}
	for i, want := range wantCondKeys {
		cond := conds[i].(map[string]interface{})
		if len(cond) != len(want) {
			t.Fatalf("条件%d键集合异常: %v", i, keysOf(cond))
		}
		for k := range want {
			if _, ok := cond[k]; !ok {
				t.Fatalf("条件%d缺少键 %s", i, k)
			}
		}
	}
}

// TestToGuardL7Rules_Empty 空规则集恒输出 {"rules":[]}（发布空集用于清空网关旧规则）。
func TestToGuardL7Rules_Empty(t *testing.T) {
	raw, err := json.Marshal(toGuardL7Rules(nil))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"rules":[]}` {
		t.Fatalf("空规则集载荷应为 {\"rules\":[]}，实际: %s", raw)
	}
}

// TestGuardConfigL7OmitWhenNil GuardConfig 未注入 L7 时不得出现 l7_rules 键
// （API 形态与历史版本下发 JSON 完全一致）；注入后恒出现。
func TestGuardConfigL7OmitWhenNil(t *testing.T) {
	without, err := json.Marshal(&gatewayconfig.GuardConfig{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(without, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["l7_rules"]; ok {
		t.Fatal("L7Rules 为 nil 时不应出现 l7_rules 键")
	}
	with, err := json.Marshal(&gatewayconfig.GuardConfig{L7Rules: toGuardL7Rules(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(with, &m); err != nil {
		t.Fatal(err)
	}
	if v, ok := m["l7_rules"].(map[string]interface{}); !ok || v["rules"] == nil {
		t.Fatalf("注入后应出现 l7_rules.rules 数组: %s", with)
	}
}

func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestToGuardL7Rules_HostAndPreservePathQuery 验证 host 条件与 redirect preserve_path_query=true 透传下发网关。
func TestToGuardL7Rules_HostAndPreservePathQuery(t *testing.T) {
	id := uuid.New()
	rules := []l7rules.Rule{{
		ID:       id,
		Name:     "裸域跳转www",
		Priority: 10,
		Enabled:  true,
		Conditions: []l7rules.Condition{
			{Type: l7rules.CondTypeHost, Op: l7rules.OpEq, Value: "jxdr.cn"},
		},
		Action: l7rules.ActionRedirect,
		ActionConfig: l7rules.ActionConfig{
			Status:            403,
			RedirectURL:       "https://www.jxdr.cn",
			RedirectStatus:    301,
			PreservePathQuery: true,
			ContentType:       "text/html; charset=utf-8",
		},
	}}
	raw, err := json.Marshal(toGuardL7Rules(rules))
	if err != nil {
		t.Fatal(err)
	}
	var top map[string][]map[string]interface{}
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	cond := top["rules"][0]["conditions"].([]interface{})[0].(map[string]interface{})
	if cond["type"] != "host" || cond["op"] != "eq" || cond["value"] != "jxdr.cn" {
		t.Fatalf("host 条件载荷异常: %+v", cond)
	}
	ac := top["rules"][0]["action_config"].(map[string]interface{})
	if ac["redirect_url"] != "https://www.jxdr.cn" || ac["redirect_status"].(float64) != 301 || ac["preserve_path_query"] != true {
		t.Fatalf("redirect action_config 载荷异常: %+v", ac)
	}
}
