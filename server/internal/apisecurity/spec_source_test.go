// spec_source_test.go W14-SRC SOURCE_CODE 学习来源接入单元测试（不依赖数据库）：
// apisrc 产物（OpenAPI3 最小骨架）被现有解析流水线接受、来源标记识别、
// 导入前元数据剥离。
package apisecurity

import (
	"strings"
	"testing"
)

// apisrcSampleDoc 模拟 tools/apisrc 对样例源码的扫描产物
// （与 tools/apisrc 输出结构一致：顶层 source 标记 + x-apisrc 工具元数据 +
// paths 操作带 x-apisrc-source 来源扩展；路径参数已归一为 {id} 形态）。
const apisrcSampleDoc = `{
	"source": "SOURCE_CODE",
	"openapi": "3.0.3",
	"info": {"title": "apisrc source inventory (./demo)", "version": "0.0.0"},
	"paths": {
		"/users/{id}": {
			"get": {"x-apisrc-source": ["nethttp.go:8"]},
			"delete": {"x-apisrc-source": ["chiapp.go:7"]}
		},
		"/orders": {
			"post": {"x-apisrc-source": ["nethttp.go:9"]}
		},
		"/files/{path}": {
			"get": {"x-apisrc-source": ["nethttp.go:11", "ginapp.go:7"]}
		}
	},
	"x-apisrc": {
		"dir": "/home/runner/demo",
		"files_scanned": 4,
		"files_failed": 1,
		"parse_errors": [{"file": "broken.go", "error": "expected ')', found '{'"}]
	}
}`

// TestSourceCodeSpecAcceptedByParser apisrc 产物被现有规范解析流水线接受：
// ParseSpecDocument 识别为 openapi3，端点/归一参数路径/{id} 形态正确，
// x-apisrc-source 扩展键不影响解析（跳过非方法键）。
func TestSourceCodeSpecAcceptedByParser(t *testing.T) {
	doc := mustDoc(t, apisrcSampleDoc)
	format, normalized, ops, err := ParseSpecDocument(doc)
	if err != nil {
		t.Fatalf("ParseSpecDocument 应接受 apisrc 产物: %v", err)
	}
	if format != SpecFormatOpenAPI3 {
		t.Fatalf("format = %q, want %q", format, SpecFormatOpenAPI3)
	}
	want := []string{
		"DELETE /users/{id}",
		"GET /files/{path}",
		"GET /users/{id}",
		"POST /orders",
	}
	if len(ops) != len(want) {
		t.Fatalf("操作数 = %d, want %d: %v", len(ops), len(want), ops)
	}
	for i, op := range ops {
		if op.Key != want[i] {
			t.Fatalf("ops[%d].Key = %q, want %q（应按序）", i, op.Key, want[i])
		}
		if op.Path == "" || strings.Contains(op.Path, ":") || strings.Contains(op.Path, "*") {
			t.Fatalf("路径参数未按 {param} 归一: %q", op.Path)
		}
	}
	// normalized 即原文档（openapi3 不转换），顶层 source 标记保留 → 随 spec_json 落库
	if DetectSpecSource(normalized) != SpecSourceSourceCode {
		t.Fatal("normalized 顶层 source=SOURCE_CODE 标记应保留")
	}
}

// TestDetectSpecSource 来源标记识别：apisrc 产物 → SOURCE_CODE；普通文档 / 其他取值 → ""。
func TestDetectSpecSource(t *testing.T) {
	if got := DetectSpecSource(mustDoc(t, apisrcSampleDoc)); got != SpecSourceSourceCode {
		t.Fatalf("apisrc 产物来源 = %q, want %q", got, SpecSourceSourceCode)
	}
	for name, raw := range map[string]string{
		"普通 openapi3 文档": `{"openapi":"3.0.3","paths":{"/x":{"get":{}}}}`,
		"source 其他取值":    `{"source":"UPLOAD","openapi":"3.0.3","paths":{"/x":{"get":{}}}}`,
		"source 非字符串":    `{"source":123,"openapi":"3.0.3","paths":{"/x":{"get":{}}}}`,
	} {
		if got := DetectSpecSource(mustDoc(t, raw)); got != "" {
			t.Errorf("%s 来源 = %q, want 空（由入口决定 UPLOAD/URL）", name, got)
		}
	}
}

// TestSourceCodeSpecForImport 导入前元数据剥离：x-apisrc（含本机路径）移除、
// source/openapi/paths 保留、入参不被修改；非 apisrc 产物原样返回。
func TestSourceCodeSpecForImport(t *testing.T) {
	doc := mustDoc(t, apisrcSampleDoc)
	out := SourceCodeSpecForImport(doc)
	if _, ok := out[apisrcMetaKey]; ok {
		t.Fatal("x-apisrc 工具元数据应被剥离")
	}
	if DetectSpecSource(out) != SpecSourceSourceCode {
		t.Fatal("source=SOURCE_CODE 标记应保留")
	}
	if out["openapi"] != "3.0.3" {
		t.Fatalf("openapi = %v, want 3.0.3", out["openapi"])
	}
	if _, ok := doc[apisrcMetaKey]; !ok {
		t.Fatal("入参原文档不应被修改")
	}
	// 剥离后仍被解析流水线接受
	if _, _, ops, err := ParseSpecDocument(out); err != nil || len(ops) != 4 {
		t.Fatalf("剥离后解析: ops=%d err=%v, want 4/nil", len(ops), err)
	}
	// 非 apisrc 产物（无 x-apisrc 键）原样返回
	plain := mustDoc(t, `{"openapi":"3.0.3","paths":{"/x":{"get":{}}}}`)
	got := SourceCodeSpecForImport(plain)
	if len(got) != len(plain) || got["openapi"] != "3.0.3" {
		t.Fatalf("非 apisrc 产物应原样返回: %v", got)
	}
}
