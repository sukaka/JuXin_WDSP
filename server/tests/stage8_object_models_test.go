// stage8_object_models_test.go 对象模型只读接口（WDSP 访问微模型·对象维度）。
// 覆盖：GET /api/v1/api-security/object-models（api_runtime.read）分页形状、
// 过滤（endpoint_id / object_segment / identifier_type）、非法 UUID 400、
// 权限底线（无权限角色 403 / 未认证 401）。数据由 apiauthz.SweepObjectModelsOnce
// 生产（生产侧覆盖见 stage8_api_table_producers_test.go），本测试直接种子
// api_object_models 行验证只读查询。真实 PostgreSQL/Valkey，无口令环境 t.Skip
// （纪律同 stage8_api_security_test.go）。
package tests

import (
	"net/http"
	"testing"
)

// TestStage8ObjectModels 对象模型只读接口端到端验证。
func TestStage8ObjectModels(t *testing.T) {
	env := setupStage8Env(t)
	cookies, _ := env.s5Login(t, "s8om", "SECURITY_ADMIN")

	ep := s8SeedEndpoint(t, env, "GET", "/s8om-"+s5Rand()+"/orders/{id}", 0.9)
	ep2 := s8SeedEndpoint(t, env, "GET", "/s8om-"+s5Rand()+"/users/{uid}", 0.9)

	// 种子对象模型行：ep 两行（path 段 + query 参数），ep2 一行（跨端点隔离用）
	s8Exec(t, env, `
INSERT INTO api_object_models (endpoint_id, object_segment, identifier_type, example_hash, sample_count)
VALUES ($1, 'path:2', 'numeric', 'hash-a', 10),
       ($1, 'query:account_id', 'uuid', 'hash-b', 3),
       ($2, 'path:2', 'hash', 'hash-c', 5)`, ep.ID, ep2.ID)

	// 全量分页形状：3 行，带出 endpoint_key 与观测字段
	page := s8Page(t, env.get(t, "/api/v1/api-security/object-models", cookies), "object models list")
	if page.Data.Total != 3 {
		t.Fatalf("object models total = %d, want 3", page.Data.Total)
	}
	item := page.Data.Items[0]
	if _, ok := item["object_segment"]; !ok {
		t.Fatalf("object model item missing object_segment: %v", item)
	}

	// 过滤：endpoint_id（2 行）；object_segment 精确匹配；identifier_type 精确匹配
	page = s8Page(t, env.get(t,
		"/api/v1/api-security/object-models?endpoint_id="+ep.ID.String(), cookies), "by endpoint")
	if page.Data.Total != 2 {
		t.Fatalf("by endpoint total = %d, want 2", page.Data.Total)
	}
	if item = page.Data.Items[0]; item["endpoint_key"] != ep.EndpointKey {
		t.Errorf("endpoint_key = %v, want %s", item["endpoint_key"], ep.EndpointKey)
	}
	page = s8Page(t, env.get(t,
		"/api/v1/api-security/object-models?object_segment=query:account_id", cookies), "by segment")
	if page.Data.Total != 1 {
		t.Fatalf("by segment total = %d, want 1", page.Data.Total)
	}
	if item = page.Data.Items[0]; item["identifier_type"] != "uuid" || item["sample_count"] != float64(3) {
		t.Errorf("segment item = %v/%v, want uuid/3", item["identifier_type"], item["sample_count"])
	}
	page = s8Page(t, env.get(t,
		"/api/v1/api-security/object-models?identifier_type=hash", cookies), "by identifier_type")
	if page.Data.Total != 1 {
		t.Fatalf("by identifier_type total = %d, want 1", page.Data.Total)
	}

	// 非法 endpoint_id → 400；未命中过滤 → 空集
	resp := env.get(t, "/api/v1/api-security/object-models?endpoint_id=not-a-uuid", cookies)
	s5Expect(t, resp, http.StatusBadRequest, "object models with invalid endpoint_id")
	page = s8Page(t, env.get(t,
		"/api/v1/api-security/object-models?object_segment=path:99", cookies), "segment miss")
	if page.Data.Total != 0 {
		t.Errorf("segment miss total = %d, want 0", page.Data.Total)
	}

	// 权限底线：无权限角色 403；未认证 401
	s8Exec(t, env, `INSERT INTO roles (code, name, description) VALUES ('S8OM_NOPERM','无权限角色','对象模型接口权限测试')`)
	nopCookies, _ := env.s5Login(t, "s8omn", "S8OM_NOPERM")
	s5Expect(t, env.get(t, "/api/v1/api-security/object-models", nopCookies),
		http.StatusForbidden, "no-perm GET object-models")
	resp = env.do(t, http.MethodGet, "/api/v1/api-security/object-models", "", nil, "")
	s5Expect(t, resp, http.StatusUnauthorized, "unauthenticated object-models query")
}
