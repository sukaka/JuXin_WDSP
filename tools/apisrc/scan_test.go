// scan_test.go apisrc 扫描器单元测试：
// 样例源码（testdata/sample，覆盖 net/http ServeMux 方法模式、http.HandleFunc、
// chi/echo/gin 字面量方法路由、gin Handle(method,path)、去重聚合、变量路径跳过）
// 提取正确率；语法错误文件容错；OpenAPI 骨架结构。
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// sampleExpect 样例源码预期发现（method+path → 来源列表，与 testdata/sample 行号严格对应）。
var sampleExpect = map[string][]string{
	// nethttp.go：Go 1.22 方法模式 / 无方法模式展开 / 通配与 {$} 归一
	"GET /users/{id}":   {"testdata/sample/nethttp.go:8"},
	"POST /orders":      {"testdata/sample/nethttp.go:9"},
	"GET /files/{path}": {"testdata/sample/nethttp.go:11"},
	"GET /exact":        {"testdata/sample/nethttp.go:12"},
	"HEAD /healthz":     {"testdata/sample/nethttp.go:13"},
	"GET /ping":         {"testdata/sample/nethttp.go:14"},
	// chiapp.go：chi 首字母大写方法名、{id} 保留、正则约束收敛、跨文件去重
	"GET /chi/users/{id}":    {"testdata/sample/chiapp.go:5"},
	"POST /chi/users":        {"testdata/sample/chiapp.go:6"},
	"DELETE /chi/users/{id}": {"testdata/sample/chiapp.go:7"},
	"PUT /dup/{id}":          {"testdata/sample/chiapp.go:8", "testdata/sample/echoapp.go:7"},
	// echoapp.go：echo 全大写方法名、:id 归一、无名通配
	"GET /echo/users/{id}":       {"testdata/sample/echoapp.go:5"},
	"POST /echo/users":           {"testdata/sample/echoapp.go:6"},
	"GET /echo/files/{wildcard}": {"testdata/sample/echoapp.go:8"},
	"HEAD /echo/head":            {"testdata/sample/echoapp.go:9"},
	// ginapp.go：gin :id / *path 归一、Handle(method,path)、同文件重复注册
	"GET /gin/users/{id}":     {"testdata/sample/ginapp.go:5"},
	"POST /gin/users":         {"testdata/sample/ginapp.go:6"},
	"PATCH /gin/files/{path}": {"testdata/sample/ginapp.go:7"},
	"TRACE /gin/raw":          {"testdata/sample/ginapp.go:8"},
	"OPTIONS /gin/cors":       {"testdata/sample/ginapp.go:9"},
	"GET /gin/dup":            {"testdata/sample/ginapp.go:10", "testdata/sample/ginapp.go:11"},
}

// TestScanSampleExtraction 样例源码提取正确率：全部预期端点 + 来源（文件:行号）精确匹配，
// 且无方法模式 /legacy 恰好展开为 8 个标准方法。
func TestScanSampleExtraction(t *testing.T) {
	res, err := ScanDir("testdata/sample")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	got := map[string][]string{}
	for _, f := range res.Findings {
		k := f.Method + " " + f.Path
		if _, dup := got[k]; dup {
			t.Fatalf("重复端点键（聚合失效）: %s", k)
		}
		got[k] = f.Sources
	}
	// /legacy 无方法模式展开 8 方法（合并进期望表断言）
	for _, m := range httpMethods {
		sampleExpect[m+" /legacy"] = []string{"testdata/sample/nethttp.go:10"}
	}
	defer func() {
		for _, m := range httpMethods {
			delete(sampleExpect, m+" /legacy")
		}
	}()
	if len(got) != len(sampleExpect) {
		t.Fatalf("端点数 = %d, want %d\ngot: %v", len(got), len(sampleExpect), got)
	}
	for k, wantSrc := range sampleExpect {
		src, ok := got[k]
		if !ok {
			t.Errorf("缺失端点: %s", k)
			continue
		}
		if strings.Join(src, ",") != strings.Join(wantSrc, ",") {
			t.Errorf("%s sources = %v, want %v", k, src, wantSrc)
		}
	}
	// 变量路径 / 非字符串参数 / 非识别集合方法（r.Method）不得出现
	for _, k := range []string{"/dynamic", "/chi/custom", "123"} {
		for g := range got {
			if strings.Contains(g, k) {
				t.Errorf("不应提取的注册被提取: %s", g)
			}
		}
	}
}

// TestScanToleratesBrokenFile 语法错误文件容错：记入 ParseErrors 并跳过，
// 其余文件正常解析（进程不中断、不静默）。
func TestScanToleratesBrokenFile(t *testing.T) {
	res, err := ScanDir("testdata/sample")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	if res.FilesScanned != 4 || res.FilesFailed != 1 {
		t.Fatalf("FilesScanned/FilesFailed = %d/%d, want 4/1", res.FilesScanned, res.FilesFailed)
	}
	if len(res.ParseErrors) != 1 || !strings.Contains(res.ParseErrors[0].File, "broken.go") {
		t.Fatalf("ParseErrors = %+v, want 含 broken.go 一条", res.ParseErrors)
	}
}

// TestScanDirInvalid 目录不存在 / 非目录：整体报错（不静默吞错）。
func TestScanDirInvalid(t *testing.T) {
	if _, err := ScanDir("testdata/no-such-dir"); err == nil {
		t.Fatal("不存在目录应返回错误")
	}
	if _, err := ScanDir("testdata/sample/nethttp.go"); err == nil {
		t.Fatal("文件（非目录）应返回错误")
	}
}

// TestNormalizePath 路径参数归一（表驱动）。
func TestNormalizePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/users/{id}", "/users/{id}"},        // chi {id} 保留
		{"/users/{id:[0-9]+}", "/users/{id}"}, // chi 正则约束收敛
		{"/users/:id", "/users/{id}"},         // gin/echo :id
		{"/files/*path", "/files/{path}"},     // gin 具名通配
		{"/files/*", "/files/{wildcard}"},     // echo 无名通配
		{"/files/{path...}", "/files/{path}"}, // Go 1.22 后缀通配
		{"/exact/{$}", "/exact"},              // Go 1.22 精确匹配标记
		{"/a/:b/{c}/d", "/a/{b}/{c}/d"},       // 混合形态
		{"/healthz", "/healthz"},              // 无参数原样
	}
	for _, c := range cases {
		if got := NormalizePath(c.in); got != c.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestOpenAPIDocStructure OpenAPI 骨架结构：source/openapi 标记、paths 方法键小写、
// 操作带 x-apisrc-source 扩展；JSON 可序列化往返。
func TestOpenAPIDocStructure(t *testing.T) {
	res, err := ScanDir("testdata/sample")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	doc := res.OpenAPIDoc()
	if doc["source"] != SourceCodeMarker {
		t.Fatalf("source = %v, want %s", doc["source"], SourceCodeMarker)
	}
	if doc["openapi"] != "3.0.3" {
		t.Fatalf("openapi = %v, want 3.0.3", doc["openapi"])
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok || len(paths) != 20 {
		t.Fatalf("paths 条目数 = %d, want 20", len(paths))
	}
	item, ok := paths["/users/{id}"].(map[string]any)
	if !ok {
		t.Fatal("paths[/users/{id}] 缺失")
	}
	op, ok := item["get"].(map[string]any)
	if !ok {
		t.Fatal("paths[/users/{id}].get 缺失")
	}
	src, ok := op["x-apisrc-source"].([]any)
	if !ok || len(src) != 1 || src[0] != "testdata/sample/nethttp.go:8" {
		t.Fatalf("x-apisrc-source = %v, want [testdata/sample/nethttp.go:8]", src)
	}
	// 骨架可 JSON 序列化（导入通道为 JSON 文档）
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if round["source"] != SourceCodeMarker {
		t.Fatalf("往返后 source = %v", round["source"])
	}
}

// TestInventory 清单文本：含统计行与端点行、解析失败明细可见（容错不静默）。
func TestInventory(t *testing.T) {
	res, err := ScanDir("testdata/sample")
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}
	text := res.Inventory()
	for _, want := range []string{
		"解析文件: 4 成功 / 1 失败",
		"发现端点: 28",
		"GET /users/{id}",
		"broken.go",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("清单文本缺少 %q", want)
		}
	}
}
