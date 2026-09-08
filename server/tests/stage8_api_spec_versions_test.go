// W3-C 规范中心增强（P0-12）接口集成测试。
//
// 覆盖：同名再导入版本自增与旧版降 HISTORICAL、activate 切换 ACTIVE、
// 跨版本 CHANGED 级 diff（导入时落库 + version-diff 按需对比）、Swagger 2.0 导入、
// URL 导入 SSRF 拦截、规范端点回写 api_endpoints 的幂等与不影响已有资产、
// api_spec.manage 权限点 403。
//
// 运行方式与 TestStage8 一致（无 PG/Valkey 凭据时 t.Skip）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8SpecVersions -count=1
package tests

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// TestStage8SpecVersions 规范版本状态机与 CHANGED 级对比全流程。
func TestStage8SpecVersions(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8spec", "SECURITY_ADMIN")
	kw := "s8v" + s5Rand()

	// 运行时已有端点：GET orders/{id}（在两个版本规范内）。
	// 直接 SQL 造数（等价 apiassets.UpsertDiscovery 插入分支；本波其他分片正在改
	// apiassets 扫描链，直接 SQL 避免与其并行改动耦合）。
	seededKey := "GET /" + kw + "/orders/{id}"
	s8Exec(t, env, `
INSERT INTO api_endpoints (http_method, normalized_path, raw_path_example,
  directory_path, endpoint_key, api_confidence, is_api, hit_count, asset_status)
VALUES ('GET', $1, $1, $2, $3, 0.8, TRUE, 1, 'DISCOVERED')`,
		"/"+kw+"/orders/{id}", "/"+kw+"/orders", seededKey)

	// ---------- v1 导入（包装形式，name 取 file_name） ----------
	v1 := fmt.Sprintf(`{
  "spec": {
    "openapi": "3.0.3",
    "info": {"title": "订单API", "version": "1.0.0"},
    "paths": {
      "/%s/orders/{id}": {"get": {"parameters": [
        {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}},
        {"name": "verbose", "in": "query", "schema": {"type": "boolean"}}
      ]}},
      "/%s/users": {"get": {}}
    }
  },
  "file_name": "orders-api-%s.json"
}`, kw, kw, kw)
	result := s5OK(t, env.post(t, "/api/v1/api-security/specs/import", v1, cookies, csrf), "import v1")
	spec := s5Obj(t, result, "spec")
	v1ID, _ := spec["id"].(string)
	if s5Num(t, spec, "version_no") != 1 || spec["status"] != "ACTIVE" {
		t.Fatalf("v1 version/status = %v/%v, want 1/ACTIVE", spec["version_no"], spec["status"])
	}
	if spec["name"] != "orders-api-"+kw+".json" {
		t.Fatalf("v1 name = %v, want orders-api-%s.json", spec["name"], kw)
	}
	// users 运行时缺失 → 登记 1 个；orders/{id} 已在运行时
	if s5Num(t, result.Data, "missing_in_runtime") != 1 || s5Num(t, result.Data, "registered_endpoints") != 1 {
		t.Fatalf("v1 missing_in_runtime/registered = %v/%v, want 1/1",
			result.Data["missing_in_runtime"], result.Data["registered_endpoints"])
	}
	if s5Num(t, result.Data, "changed") != 0 {
		t.Fatalf("v1 changed = %v, want 0（首版无对比基线）", result.Data["changed"])
	}
	// 规范端点回写落库（DISCOVERED / hit_count=0，来源规范导入）
	if n := s8Count(t, env,
		`SELECT count(*) FROM api_endpoints WHERE endpoint_key = $1 AND asset_status = 'DISCOVERED' AND hit_count = 0`,
		"GET /"+kw+"/users"); n != 1 {
		t.Fatalf("规范端点回写失败: GET /%s/users count = %d, want 1", kw, n)
	}

	// ---------- 同内容再导入 → 409 ----------
	resp := env.post(t, "/api/v1/api-security/specs/import", v1, cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "reimport unchanged spec")

	// ---------- v2 导入（同名，参数变化 + 新端点） ----------
	v2 := fmt.Sprintf(`{
  "spec": {
    "openapi": "3.0.3",
    "info": {"title": "订单API", "version": "2.0.0"},
    "paths": {
      "/%s/orders/{id}": {"get": {"parameters": [
        {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}},
        {"name": "verbose", "in": "query", "schema": {"type": "integer"}},
        {"name": "page", "in": "query", "required": true, "schema": {"type": "integer"}}
      ]}},
      "/%s/users": {"get": {}},
      "/%s/admin": {"post": {}}
    }
  },
  "file_name": "orders-api-%s.json"
}`, kw, kw, kw, kw)
	result = s5OK(t, env.post(t, "/api/v1/api-security/specs/import", v2, cookies, csrf), "import v2")
	spec = s5Obj(t, result, "spec")
	v2ID, _ := spec["id"].(string)
	if s5Num(t, spec, "version_no") != 2 || spec["status"] != "ACTIVE" {
		t.Fatalf("v2 version/status = %v/%v, want 2/ACTIVE", spec["version_no"], spec["status"])
	}
	// CHANGED：verbose 类型 boolean→integer、page PARAM_ADDED、admin ENDPOINT_ADDED
	if s5Num(t, result.Data, "changed") != 3 {
		t.Fatalf("v2 changed = %v, want 3", result.Data["changed"])
	}
	// users 已被 v1 回写进运行时 → 本版仅 admin 缺失
	if s5Num(t, result.Data, "missing_in_runtime") != 1 || s5Num(t, result.Data, "registered_endpoints") != 1 {
		t.Fatalf("v2 missing_in_runtime/registered = %v/%v, want 1/1",
			result.Data["missing_in_runtime"], result.Data["registered_endpoints"])
	}
	// 旧版降 HISTORICAL；同名 ACTIVE 唯一
	if n := s8Count(t, env,
		`SELECT count(*) FROM api_import_specs WHERE name = $1 AND status = 'HISTORICAL'`,
		"orders-api-"+kw+".json"); n != 1 {
		t.Fatalf("HISTORICAL 版本数 = %d, want 1", n)
	}
	if n := s8Count(t, env,
		`SELECT count(*) FROM api_import_specs WHERE name = $1 AND status = 'ACTIVE'`,
		"orders-api-"+kw+".json"); n != 1 {
		t.Fatalf("ACTIVE 版本数 = %d, want 1", n)
	}
	// v2 的 parent_id 指向 v1
	if n := s8Count(t, env,
		`SELECT count(*) FROM api_import_specs WHERE id = $1 AND parent_id = $2`,
		v2ID, v1ID); n != 1 {
		t.Fatalf("v2 parent_id 未指向 v1")
	}

	// ---------- v2 diff 明细含 CHANGED ----------
	result = s5OK(t, env.get(t, "/api/v1/api-security/specs/"+v2ID+"/diff", cookies), "v2 diff")
	diffs, _ := result.Data["diffs"].([]interface{})
	byType := map[string]int{}
	for _, d := range diffs {
		byType[d.(map[string]interface{})["diff_type"].(string)]++
	}
	if byType["CHANGED"] != 3 || byType["MISSING_IN_RUNTIME"] != 1 {
		t.Fatalf("v2 diff 类型分布 = %v, want CHANGED=3 MISSING_IN_RUNTIME=1", byType)
	}

	// ---------- 按需跨版本 diff（v1 → v2） ----------
	result = s5OK(t, env.get(t,
		"/api/v1/api-security/specs/"+v1ID+"/version-diff?other="+v2ID, cookies), "version-diff")
	changes, _ := result.Data["changes"].([]interface{})
	if len(changes) != 3 {
		t.Fatalf("version-diff changes = %d, want 3 (%v)", len(changes), changes)
	}
	// 同一 ID 对比 → 400；缺 other → 400
	resp = env.get(t, "/api/v1/api-security/specs/"+v1ID+"/version-diff?other="+v1ID, cookies)
	s5Expect(t, resp, http.StatusBadRequest, "version-diff same id")
	resp = env.get(t, "/api/v1/api-security/specs/"+v1ID+"/version-diff", cookies)
	s5Expect(t, resp, http.StatusBadRequest, "version-diff missing other")

	// ---------- activate：v1 重新激活，v2 降 HISTORICAL ----------
	result = s5OK(t, env.post(t, "/api/v1/api-security/specs/"+v1ID+"/activate", "", cookies, csrf), "activate v1")
	spec = s5Obj(t, result, "spec")
	if spec["status"] != "ACTIVE" || s5Num(t, spec, "version_no") != 1 {
		t.Fatalf("activate 后 v1 status/version = %v/%v, want ACTIVE/1", spec["status"], spec["version_no"])
	}
	if n := s8Count(t, env,
		`SELECT count(*) FROM api_import_specs WHERE id = $1 AND status = 'HISTORICAL'`, v2ID); n != 1 {
		t.Fatalf("activate v1 后 v2 应为 HISTORICAL")
	}
	// 重复激活 → 409；不存在 → 404
	resp = env.post(t, "/api/v1/api-security/specs/"+v1ID+"/activate", "", cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "activate already active")
	resp = env.post(t, "/api/v1/api-security/specs/"+uuid.NewString()+"/activate", "", cookies, csrf)
	s5Expect(t, resp, http.StatusNotFound, "activate missing spec")

	// ---------- Swagger 2.0 导入 ----------
	swagger2 := fmt.Sprintf(`{
  "swagger": "2.0",
  "info": {"title": "legacy-%s", "version": "1.0"},
  "host": "api.example.com",
  "basePath": "/v1",
  "paths": {
    "/%s/legacy/things": {"get": {"parameters": [
      {"name": "q", "in": "query", "type": "string"}
    ], "responses": {"200": {"description": "ok"}}}}
  }
}`, kw, kw)
	result = s5OK(t, env.post(t, "/api/v1/api-security/specs/import", swagger2, cookies, csrf), "import swagger2")
	spec = s5Obj(t, result, "spec")
	if spec["format"] != "swagger2" || spec["name"] != "legacy-"+kw {
		t.Fatalf("swagger2 format/name = %v/%v, want swagger2/legacy-%s", spec["format"], spec["name"], kw)
	}
	if s5Num(t, spec, "endpoint_count") != 1 || s5Num(t, result.Data, "registered_endpoints") != 1 {
		t.Fatalf("swagger2 endpoints/registered = %v/%v, want 1/1",
			spec["endpoint_count"], result.Data["registered_endpoints"])
	}

	// ---------- URL 导入：SSRF 拦截 ----------
	for _, u := range []string{
		"http://127.0.0.1:9/spec.json",
		"http://192.168.1.1/spec.json",
		"http://169.254.169.254/latest/meta-data",
		"file:///etc/passwd",
	} {
		resp = env.post(t, "/api/v1/api-security/specs/import-url",
			fmt.Sprintf(`{"url":%q}`, u), cookies, csrf)
		s5Expect(t, resp, http.StatusBadRequest, "import-url ssrf "+u)
	}
	// 缺 url → 400
	resp = env.post(t, "/api/v1/api-security/specs/import-url", `{"name":"x"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "import-url missing url")

	// ---------- 回写幂等与不影响已有资产 ----------
	// 种子端点（在规范内）未经 UpsertDiscovery 之外的写入：hit_count 保持 1（登记未覆盖）
	if n := s8Count(t, env,
		`SELECT count(*) FROM api_endpoints WHERE endpoint_key = $1 AND hit_count = 1`, seededKey); n != 1 {
		t.Fatalf("已有资产被导入覆盖: %s hit_count != 1", seededKey)
	}

	// ---------- 权限：AUDIT_ADMIN（000100 纯审计角色）读/写均 403 ----------
	auditCookies, auditCSRF := env.s5Login(t, "s8specaud", "AUDIT_ADMIN")
	s5Expect(t, env.get(t, "/api/v1/api-security/specs", auditCookies), http.StatusForbidden, "auditor list specs")
	s5Expect(t, env.get(t,
		"/api/v1/api-security/specs/"+v1ID+"/version-diff?other="+v2ID, auditCookies),
		http.StatusForbidden, "auditor version-diff")
	s5Expect(t, env.post(t, "/api/v1/api-security/specs/import", v1, auditCookies, auditCSRF),
		http.StatusForbidden, "auditor import")
	s5Expect(t, env.post(t, "/api/v1/api-security/specs/import-url",
		`{"url":"http://93.184.216.34/x.json"}`, auditCookies, auditCSRF),
		http.StatusForbidden, "auditor import-url")
	s5Expect(t, env.post(t, "/api/v1/api-security/specs/"+v2ID+"/activate", "", auditCookies, auditCSRF),
		http.StatusForbidden, "auditor activate")

	// ---------- 列表过滤（name / status） ----------
	page := s8Page(t, env.get(t,
		"/api/v1/api-security/specs?name=orders-api-"+kw+".json&status=HISTORICAL", cookies), "filter specs")
	if page.Data.Total != 1 {
		t.Fatalf("name+status 过滤结果 = %d, want 1", page.Data.Total)
	}
	resp = env.get(t, "/api/v1/api-security/specs?status=BOGUS", cookies)
	s5Expect(t, resp, http.StatusBadRequest, "invalid status filter")
}
