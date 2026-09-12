// W14-SRC 源码 API 发现 v1（P2-07）接口集成测试。
//
// 覆盖：tools/apisrc 产物（OpenAPI3 最小骨架，顶层 source=SOURCE_CODE + x-apisrc
// 工具元数据 + 操作级 x-apisrc-source 扩展）经规范导入接口全链路落库 ——
// 现有流水线天然接受（识别为 openapi3）、端点解析与回写 api_endpoints、
// 来源标记随 spec_json 落库（api_import_specs 无来源列，见 spec_source.go 注释）、
// 同内容再导入 409。
//
// 运行方式与 TestStage8 一致（无 PG/Valkey 凭据时 t.Skip）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8SpecSourceCodeImport -count=1
package tests

import (
	"fmt"
	"net/http"
	"testing"
)

// TestStage8SpecSourceCodeImport apisrc 产物导入全链路。
func TestStage8SpecSourceCodeImport(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8src", "SECURITY_ADMIN")
	kw := "s8src" + s5Rand()

	// 模拟 tools/apisrc -dir ./demo -out inventory.json 的输出结构
	// （路径带 kw 防用例间冲突；x-apisrc 含本机路径属采集侧元数据，流水线原样落库）。
	doc := fmt.Sprintf(`{
  "spec": {
    "source": "SOURCE_CODE",
    "openapi": "3.0.3",
    "info": {"title": "apisrc source inventory (./demo-%s)", "version": "0.0.0"},
    "paths": {
      "/%s/users/{id}": {
        "get": {"x-apisrc-source": ["nethttp.go:8"]},
        "delete": {"x-apisrc-source": ["chiapp.go:7"]}
      },
      "/%s/orders": {
        "post": {"x-apisrc-source": ["nethttp.go:9"]}
      },
      "/%s/legacy": {
        "get": {"x-apisrc-source": ["nethttp.go:10"]},
        "post": {"x-apisrc-source": ["nethttp.go:10"]}
      }
    },
    "x-apisrc": {
      "dir": "/home/runner/demo-%s",
      "files_scanned": 4,
      "files_failed": 1,
      "parse_errors": [{"file": "broken.go", "error": "expected ')', found '{'"}]
    }
  },
  "file_name": "apisrc-%s.json"
}`, kw, kw, kw, kw, kw, kw)

	result := s5OK(t, env.post(t, "/api/v1/api-security/specs/import", doc, cookies, csrf), "import apisrc inventory")
	spec := s5Obj(t, result, "spec")
	specID, _ := spec["id"].(string)
	if specID == "" {
		t.Fatal("导入响应缺少 spec.id")
	}
	if s5Num(t, spec, "version_no") != 1 || spec["status"] != "ACTIVE" {
		t.Fatalf("version/status = %v/%v, want 1/ACTIVE", spec["version_no"], spec["status"])
	}
	if spec["format"] != "openapi3" {
		t.Fatalf("format = %v, want openapi3（apisrc 骨架被识别为 OpenAPI3）", spec["format"])
	}
	if spec["name"] != "apisrc-"+kw+".json" {
		t.Fatalf("name = %v, want apisrc-%s.json", spec["name"], kw)
	}
	// 5 个操作（get/delete users/{id}、post orders、get/post legacy），全部运行时缺失
	if s5Num(t, spec, "endpoint_count") != 5 {
		t.Fatalf("endpoint_count = %v, want 5", spec["endpoint_count"])
	}
	if s5Num(t, result.Data, "missing_in_runtime") != 5 || s5Num(t, result.Data, "registered_endpoints") != 5 {
		t.Fatalf("missing_in_runtime/registered = %v/%v, want 5/5",
			result.Data["missing_in_runtime"], result.Data["registered_endpoints"])
	}

	// 来源标记随 spec_json 落库（api_import_specs 无来源列，v1 经文档顶层 source 键标识）
	if n := s8Count(t, env,
		`SELECT count(*) FROM api_import_specs WHERE id = $1 AND spec_json->>'source' = 'SOURCE_CODE'`,
		specID); n != 1 {
		t.Fatalf("spec_json->>'source' = SOURCE_CODE 落库断言失败: count = %d, want 1", n)
	}
	// 规范端点回写 api_endpoints（DISCOVERED / hit_count=0，MISSING_IN_RUNTIME 登记）
	if n := s8Count(t, env,
		`SELECT count(*) FROM api_endpoints WHERE endpoint_key LIKE $1 AND asset_status = 'DISCOVERED' AND hit_count = 0`,
		"%/"+kw+"/%"); n != 5 {
		t.Fatalf("规范端点回写: count = %d, want 5", n)
	}
	// 对比结果落库（MISSING_IN_RUNTIME × 5）
	if n := s8Count(t, env,
		`SELECT count(*) FROM api_spec_diffs WHERE spec_id = $1 AND diff_type = 'MISSING_IN_RUNTIME'`,
		specID); n != 5 {
		t.Fatalf("MISSING_IN_RUNTIME diffs: count = %d, want 5", n)
	}

	// 同内容再导入 → 409（内容哈希一致）
	resp := env.post(t, "/api/v1/api-security/specs/import", doc, cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "reimport unchanged apisrc inventory")
}
