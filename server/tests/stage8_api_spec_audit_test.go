// 规范路径、参数、响应与鉴权安全声明按需只读审计的真实导入集成测试。
// 无 PostgreSQL/Valkey 凭据时沿用 setupStage8Env 的约定跳过；不使用 mock 或静态响应。
package tests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestStage8SpecAudit(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8specaudit", "SECURITY_ADMIN")
	kw := "s8audit" + s5Rand()
	doc := fmt.Sprintf(`{
  "spec": {
    "openapi": "3.0.3",
    "info": {"title": "audit-%s", "version": "1.0.0"},
    "security": [{"queryKey": []}, {"missingInherited": []}],
    "components": {"securitySchemes": {
      "queryKey": {"type": "apiKey", "in": "query", "name": "api_key",
        "x-key-value": "key-value-do-not-return"},
      "unusedQuery": {"type": "apiKey", "in": "query", "name": "unused_key",
        "x-key-value": "unused-key-value-do-not-return"}
    }},
    "paths": {
      "/%s/orders/{missing}/{optional}": {"get": {"parameters": [
        {"name": "optional", "in": "path", "required": false,
         "schema": {"type": "string", "example": "path-value-do-not-return"}},
        {"name": "orphan", "in": "path", "required": true, "schema": {"type": "string"}},
        {"name": "Access-Token", "in": "query",
         "schema": {"type": "string", "example": "query-value-do-not-return"}}
      ], "responses": {"200": {"description": "ok"}}}},
      "/%s/public": {"get": {"security": [],
        "responses": {"200": {"description": "ok"}, "default": {"description": "error"}}}}
    }
  },
  "name": "spec-audit-%s"
}`, kw, kw, kw, kw)
	imported := s5OK(t, env.post(t, "/api/v1/api-security/specs/import", doc, cookies, csrf), "import spec for audit")
	spec := s5Obj(t, imported, "spec")
	specID, _ := spec["id"].(string)
	if specID == "" {
		t.Fatalf("导入响应缺少 spec.id: %+v", spec)
	}

	result := s5OK(t, env.get(t, "/api/v1/api-security/specs/"+specID+"/audit", cookies), "audit imported spec")
	if result.Data["spec_id"] != specID || result.Data["format"] != "openapi3" {
		t.Fatalf("审计规范元数据不符: %+v", result.Data)
	}
	if s5Num(t, result.Data, "operation_count") != 2 || s5Num(t, result.Data, "issue_count") != 7 ||
		s5Num(t, result.Data, "high_count") != 4 || s5Num(t, result.Data, "medium_count") != 3 {
		t.Fatalf("审计计数不符: %+v", result.Data)
	}
	if truncated, ok := result.Data["truncated"].(bool); !ok || truncated {
		t.Fatalf("truncated = %v, want false", result.Data["truncated"])
	}
	if len(result.Data) != 8 {
		t.Fatalf("审计 data 字段数 = %d, want 8: %+v", len(result.Data), result.Data)
	}
	items, ok := result.Data["items"].([]interface{})
	if !ok || len(items) != 7 {
		t.Fatalf("审计 items = %+v, want 7 条", result.Data["items"])
	}
	want := []struct {
		ruleID, severity, paramIn, paramName string
	}{
		{"API_KEY_IN_QUERY", "HIGH", "QUERY", "queryKey"},
		{"ERROR_RESPONSE_MISSING", "MEDIUM", "", ""},
		{"PATH_PARAMETER_MISSING", "HIGH", "PATH", "missing"},
		{"PATH_PARAMETER_NOT_REQUIRED", "MEDIUM", "PATH", "optional"},
		{"PATH_PARAMETER_UNDECLARED", "MEDIUM", "PATH", "orphan"},
		{"SECURITY_SCHEME_UNDEFINED", "HIGH", "", "missingInherited"},
		{"SENSITIVE_QUERY_PARAMETER", "HIGH", "QUERY", "Access-Token"},
	}
	endpointKey := "GET /" + kw + "/orders/{missing}/{optional}"
	for i, expected := range want {
		item, ok := items[i].(map[string]interface{})
		if !ok || len(item) != 6 {
			t.Fatalf("items[%d] 字段契约不符: %+v", i, items[i])
		}
		if item["rule_id"] != expected.ruleID || item["severity"] != expected.severity ||
			item["endpoint_key"] != endpointKey || item["param_in"] != expected.paramIn ||
			item["param_name"] != expected.paramName || item["message"] == "" {
			t.Errorf("items[%d] = %+v, want %+v endpoint=%s", i, item, expected, endpointKey)
		}
	}
	encoded, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatalf("序列化审计响应失败: %v", err)
	}
	for _, forbidden := range []string{"do-not-return", "spec_json", "api_key", "unused_key", "unusedQuery"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("审计响应泄露参数值、方案参数名、未使用方案或完整规范 %q: %s", forbidden, encoded)
		}
	}

	s5Expect(t, env.get(t, "/api/v1/api-security/specs/not-a-uuid/audit", cookies),
		http.StatusBadRequest, "audit invalid spec id")
	s5Expect(t, env.get(t, "/api/v1/api-security/specs/"+uuid.NewString()+"/audit", cookies),
		http.StatusNotFound, "audit missing spec")
	auditCookies, _ := env.s5Login(t, "s8specauditdeny", "AUDIT_ADMIN")
	s5Expect(t, env.get(t, "/api/v1/api-security/specs/"+specID+"/audit", auditCookies),
		http.StatusForbidden, "audit without api_spec.read")
}
