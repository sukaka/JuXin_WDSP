package tests

import (
	"fmt"
	"net/http"
	"testing"
)

func TestL7ContentRuleCRUDAndTester(t *testing.T) {
	env := setupL7Env(t)
	cookies, csrf := env.s5Login(t, "l7content", "SECURITY_ADMIN")
	name := "l7-content-" + s5Rand()
	body := fmt.Sprintf(`{"name":%q,"priority":100,"enabled":true,"conditions":[`+
		`{"type":"request_body","op":"contains","value":"request-secret"},`+
		`{"type":"response_header","name":"X-Result","op":"eq","value":"private"},`+
		`{"type":"response_body","op":"contains","value":"response-secret"}],"action":"block"}`, name)
	resp := env.post(t, "/api/v1/l7-rules", body, cookies, csrf)
	result := s5OK(t, resp, "create content l7 rule")
	rule := s5Obj(t, result, "rule")
	ruleID, _ := rule["id"].(string)
	conditions, _ := rule["conditions"].([]interface{})
	if ruleID == "" || len(conditions) != 3 {
		t.Fatalf("内容条件创建回读异常: %+v", rule)
	}

	testBody := `{"uri":"/api/orders","method":"POST","client_ip":"203.0.113.66",` +
		`"request_body":"request-secret","response_headers":{"X-Result":"private"},"response_body":"response-secret"}`
	resp = env.post(t, "/api/v1/l7-rules/test", testBody, cookies, csrf)
	result = s5OK(t, resp, "test content l7 rule")
	if result.Data["matched"] != true || result.Data["rule_id"] != ruleID {
		t.Fatalf("内容规则测试器应命中: %+v", result.Data)
	}
	resp = env.post(t, "/api/v1/l7-rules/test", `{"uri":"/api/orders","method":"POST","client_ip":"203.0.113.66",`+
		`"request_body":"request-secret","response_headers":{"X-Result":"private"},"response_body":"safe"}`, cookies, csrf)
	result = s5OK(t, resp, "test content l7 rule no match")
	if result.Data["matched"] != false {
		t.Fatalf("安全响应体不应命中: %+v", result.Data)
	}

	resp = env.do(t, http.MethodPatch, "/api/v1/l7-rules/"+ruleID,
		fmt.Sprintf(`{"name":%q,"conditions":[{"type":"response_header","name":"","op":"contains","value":"x"}],"action":"block"}`, name), cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "response header name required")
}
