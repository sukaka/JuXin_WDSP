// spec_test.go 规范解析/对比纯逻辑单元测试（不依赖数据库）。
package apisecurity

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// mustDoc JSON 字符串转文档对象。
func mustDoc(t *testing.T, raw string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("测试数据不是合法 JSON: %v", err)
	}
	return doc
}

// keysOf 提取端点键列表。
func keysOf(eps []SpecEndpoint) []string {
	out := make([]string, 0, len(eps))
	for _, ep := range eps {
		out = append(out, ep.Key)
	}
	return out
}

func TestParseOpenAPI3Basic(t *testing.T) {
	doc := mustDoc(t, `{
		"openapi": "3.0.3",
		"info": {"title": "demo", "version": "1.0"},
		"paths": {
			"/pets/{id}": {
				"get": {"summary": "按ID查询"},
				"put": {"summary": "更新"},
				"parameters": [{"name": "id", "in": "path"}]
			},
			"/pets": {
				"get": {},
				"post": {},
				"summary": "非方法键应被跳过"
			}
		}
	}`)
	eps, err := ParseOpenAPI3(doc)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	want := []string{"GET /pets", "GET /pets/{id}", "POST /pets", "PUT /pets/{id}"}
	got := keysOf(eps)
	if len(got) != len(want) {
		t.Fatalf("端点数量不符: got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("端点键不符（应按序）: got=%v want=%v", got, want)
		}
	}
	// {param} 保留原样、方法大写
	for _, ep := range eps {
		if ep.Key != ep.Method+" "+ep.Path {
			t.Fatalf("endpoint_key 格式错误: %+v", ep)
		}
	}
}

func TestParseOpenAPI3MethodCaseInsensitive(t *testing.T) {
	doc := mustDoc(t, `{"openapi": "3.1.0", "paths": {"/a": {"Get": {}, "DELETE": {}}}}`)
	eps, err := ParseOpenAPI3(doc)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	want := []string{"DELETE /a", "GET /a"}
	got := keysOf(eps)
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("方法大小写归一失败: got=%v want=%v", got, want)
	}
}

func TestParseOpenAPI3RejectNonV3(t *testing.T) {
	cases := map[string]string{
		"缺少 openapi 字段": `{"paths": {"/a": {"get": {}}}}`,
		"Swagger 2.0":   `{"swagger": "2.0", "paths": {"/a": {"get": {}}}}`,
		"openapi 2.x":   `{"openapi": "2.0", "paths": {"/a": {"get": {}}}}`,
		"openapi 非字符串":  `{"openapi": 3, "paths": {"/a": {"get": {}}}}`,
	}
	for name, raw := range cases {
		if _, err := ParseOpenAPI3(mustDoc(t, raw)); !errors.Is(err, ErrSpecNotOpenAPI3) {
			t.Errorf("%s: 期望 ErrSpecNotOpenAPI3，实际 %v", name, err)
		}
	}
}

func TestParseOpenAPI3RejectBadPaths(t *testing.T) {
	cases := map[string]string{
		"缺少 paths":     `{"openapi": "3.0.0"}`,
		"paths 非对象":    `{"openapi": "3.0.0", "paths": []}`,
		"paths 为空对象":   `{"openapi": "3.0.0", "paths": {}}`,
		"paths 为字符串":   `{"openapi": "3.0.0", "paths": "x"}`,
		"PathItem 非对象": `{"openapi": "3.0.0", "paths": {"/a": "x"}}`,
	}
	for name, raw := range cases {
		_, err := ParseOpenAPI3(mustDoc(t, raw))
		if name == "PathItem 非对象" {
			// Path Item 非对象时跳过该路径，最终无有效端点但不报错
			if err != nil {
				t.Errorf("%s: 期望跳过非对象 Path Item，实际错误 %v", name, err)
			}
			continue
		}
		if !errors.Is(err, ErrSpecNoPaths) {
			t.Errorf("%s: 期望 ErrSpecNoPaths，实际 %v", name, err)
		}
	}
}

func TestDiffEndpointKeys(t *testing.T) {
	spec := []string{"GET /a", "GET /b", "POST /c"}
	runtime := []string{"GET /b", "GET /d"}
	missingInRuntime, missingInSpec := DiffEndpointKeys(spec, runtime)
	// 规范有而运行时无
	wantR := []string{"GET /a", "POST /c"}
	if len(missingInRuntime) != len(wantR) || missingInRuntime[0] != wantR[0] || missingInRuntime[1] != wantR[1] {
		t.Fatalf("MISSING_IN_RUNTIME 不符: got=%v want=%v", missingInRuntime, wantR)
	}
	// 运行时有而规范无
	wantS := []string{"GET /d"}
	if len(missingInSpec) != 1 || missingInSpec[0] != wantS[0] {
		t.Fatalf("MISSING_IN_SPEC 不符: got=%v want=%v", missingInSpec, wantS)
	}
}

func TestDiffEndpointKeysEmpty(t *testing.T) {
	mr, ms := DiffEndpointKeys(nil, nil)
	if len(mr) != 0 || len(ms) != 0 {
		t.Fatalf("空输入应得空结果: mr=%v ms=%v", mr, ms)
	}
	// 完全一致
	mr, ms = DiffEndpointKeys([]string{"GET /a"}, []string{"GET /a"})
	if len(mr) != 0 || len(ms) != 0 {
		t.Fatalf("一致输入应得空结果: mr=%v ms=%v", mr, ms)
	}
}

func TestHashSpecContent(t *testing.T) {
	h1 := HashSpecContent([]byte(`{"a":1}`))
	h2 := HashSpecContent([]byte(`{"a":1}`))
	h3 := HashSpecContent([]byte(`{"a":2}`))
	if h1 != h2 {
		t.Fatal("同内容哈希应一致")
	}
	if h1 == h3 {
		t.Fatal("不同内容哈希应不同")
	}
	if len(h1) != 64 {
		t.Fatalf("SHA-256 十六进制应为 64 字符，实际 %d", len(h1))
	}
}

// TestRegisterRoutesNoPanic 注册全部路由不得出现模式冲突。
func TestRegisterRoutesNoPanic(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, func(h http.Handler) http.Handler { return h }, NewHandler(nil, nil))
}
