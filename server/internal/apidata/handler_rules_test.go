// handler_rules_test.go 脱敏规则接口测试：CRUD、作用域一致性、算法/路径/排除结构校验。
package apidata

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// validRuleReq 合法创建请求（GLOBAL + field_path）。
func validRuleReq() map[string]any {
	return map[string]any{
		"name":        "规则-" + uuid.NewString()[:8],
		"scope":       "GLOBAL",
		"field_path":  "json.phone",
		"algorithm":   "MASK",
		"params_json": map[string]any{"keep_head": 3, "keep_tail": 4},
	}
}

// createRule 创建规则并解码响应。
func createRule(t *testing.T, mux http.Handler, req map[string]any) MaskingRule {
	t.Helper()
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/masking-rules", req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create rule status=%d body=%s", rr.Code, rr.Body.String())
	}
	var created MaskingRule
	decodeData(t, rr, &created)
	return created
}

// TestRuleCRUD 创建 → 读取 → 列表过滤 → 编辑 → 启停 → 删除。
func TestRuleCRUD(t *testing.T) {
	mux := newTestMux(NewHandler(NewMemStore(), nil))

	created := createRule(t, mux, validRuleReq())
	if created.ID == uuid.Nil || !created.Enabled || created.Scope != "GLOBAL" {
		t.Fatalf("created=%+v", created)
	}
	if created.CreatedBy == nil || *created.CreatedBy != "tester" {
		t.Fatalf("created_by=%v", created.CreatedBy)
	}

	// 读取
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/masking-rules/"+created.ID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get status=%d", rr.Code)
	}

	// 列表过滤
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/masking-rules?scope=GLOBAL&enabled=true", nil)
	var page struct {
		Items []MaskingRule `json:"items"`
		Total int64         `json:"total"`
	}
	decodeData(t, rr, &page)
	if page.Total != 1 {
		t.Fatalf("list total=%d", page.Total)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/masking-rules?scope=ENDPOINT", nil)
	decodeData(t, rr, &page)
	if page.Total != 0 {
		t.Fatalf("scope filter total=%d", page.Total)
	}

	// 编辑（改算法 + 排除对象）
	patch := map[string]any{
		"algorithm": "HASH",
		"exclusions_json": map[string]any{
			"identity": []string{"fp-admin"},
			"ip":       []string{"10.0.0.0/8", "192.168.1.1"},
		},
	}
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/masking-rules/"+created.ID.String(), patch)
	if rr.Code != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", rr.Code, rr.Body.String())
	}
	var updated MaskingRule
	decodeData(t, rr, &updated)
	if updated.Algorithm != "HASH" {
		t.Fatalf("updated=%+v", updated)
	}
	exc, err := ParseMaskExclusions(updated.Exclusions)
	if err != nil || len(exc.Identity) != 1 || len(exc.IP) != 2 {
		t.Fatalf("exclusions=%v err=%v", exc, err)
	}

	// 禁用
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/masking-rules/"+created.ID.String(),
		map[string]any{"enabled": false})
	var disabled MaskingRule
	decodeData(t, rr, &disabled)
	if disabled.Enabled {
		t.Fatalf("expected disabled")
	}

	// 删除
	rr = doJSON(t, mux, http.MethodDelete, "/api/v1/api-security/masking-rules/"+created.ID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/masking-rules/"+created.ID.String(), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("get after delete status=%d", rr.Code)
	}
}

// TestRuleScopeCoherence 作用域一致性校验（与表 CHECK 同口径）。
func TestRuleScopeCoherence(t *testing.T) {
	mux := newTestMux(NewHandler(NewMemStore(), nil))
	appID := uuid.NewString()
	epKey := "GET /orders/{id}"

	// GLOBAL 不允许 application_id/endpoint_key
	req := validRuleReq()
	req["application_id"] = appID
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/masking-rules", req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("global with app status=%d", rr.Code)
	}
	// APPLICATION 必须有 application_id
	req = validRuleReq()
	req["scope"] = "APPLICATION"
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/masking-rules", req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("app without app_id status=%d", rr.Code)
	}
	// APPLICATION 合法
	req["application_id"] = appID
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/masking-rules", req)
	if rr.Code != http.StatusOK {
		t.Fatalf("app rule status=%d body=%s", rr.Code, rr.Body.String())
	}
	// APPLICATION 不允许 endpoint_key
	req["endpoint_key"] = epKey
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/masking-rules", req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("app with endpoint status=%d", rr.Code)
	}
	// ENDPOINT 必须有 endpoint_key
	req = validRuleReq()
	req["scope"] = "ENDPOINT"
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/masking-rules", req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("endpoint without key status=%d", rr.Code)
	}
	req["endpoint_key"] = epKey
	created := createRule(t, mux, req)
	if created.EndpointKey == nil || *created.EndpointKey != epKey {
		t.Fatalf("endpoint rule=%+v", created)
	}

	// PATCH 切换 scope：APPLICATION←ENDPOINT 未清除 endpoint_key → 400；清除后 200
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/masking-rules/"+created.ID.String(),
		map[string]any{"scope": "GLOBAL"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("scope switch without clear status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/masking-rules/"+created.ID.String(),
		map[string]any{"scope": "GLOBAL", "endpoint_key": ""})
	if rr.Code != http.StatusOK {
		t.Fatalf("scope switch with clear status=%d body=%s", rr.Code, rr.Body.String())
	}
}

// TestRuleValidation 算法/目标/排除结构校验。
func TestRuleValidation(t *testing.T) {
	mux := newTestMux(NewHandler(NewMemStore(), nil))

	cases := []struct {
		name   string
		mutate func(req map[string]any)
	}{
		{"空名称", func(req map[string]any) { req["name"] = "" }},
		{"非法scope", func(req map[string]any) { req["scope"] = "TENANT" }},
		{"非法algorithm", func(req map[string]any) { req["algorithm"] = "UNKNOWN" }},
		{"无目标", func(req map[string]any) { delete(req, "field_path") }},
		{"非法application_id", func(req map[string]any) { req["scope"] = "APPLICATION"; req["application_id"] = "x" }},
		{"params非对象", func(req map[string]any) { req["params_json"] = []any{1} }},
		{"exclusions非法键", func(req map[string]any) {
			req["exclusions_json"] = map[string]any{"user": []string{"a"}}
		}},
		{"exclusions值非数组", func(req map[string]any) {
			req["exclusions_json"] = map[string]any{"identity": "a"}
		}},
		{"exclusions非法IP", func(req map[string]any) {
			req["exclusions_json"] = map[string]any{"ip": []string{"999.1.1.1"}}
		}},
	}
	for _, tc := range cases {
		req := validRuleReq()
		tc.mutate(req)
		rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/masking-rules", req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d body=%s", tc.name, rr.Code, rr.Body.String())
		}
	}

	// data_type 整类目标（无 field_path）合法
	req := validRuleReq()
	delete(req, "field_path")
	req["data_type"] = "phone"
	created := createRule(t, mux, req)
	if created.DataType == nil || *created.DataType != "phone" {
		t.Fatalf("data_type rule=%+v", created)
	}
	// role 排除合法
	req = validRuleReq()
	req["exclusions_json"] = map[string]any{"role": []string{"SECURITY_ADMIN"}}
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/masking-rules", req)
	if rr.Code != http.StatusOK {
		t.Fatalf("role exclusions status=%d body=%s", rr.Code, rr.Body.String())
	}
}
