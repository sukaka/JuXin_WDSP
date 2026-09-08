// compiler_test.go Runtime Model Compiler 单测（纯函数，不依赖数据库）：
// 全量 confirmed 词汇序列化、规范序列化/hash 稳定性、输入变更产生新 hash、预留占位恒 null。
package apimodels

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// testCompileInput 构造含全量 confirmed 词汇的编译输入。
func testCompileInput() CompileInput {
	return CompileInput{
		EndpointID:     uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		EndpointKey:    "POST /v1/orders/{id}",
		Method:         "post", // 编译期归一为大写
		NormalizedPath: "/v1/orders/{id}",
		ProtocolType:   "REST",
		AssetStatus:    "CONFIRMED",
		ModelVersionID: uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		// schema 乱序构造（验证规范序列化与插入序无关）
		Schema: map[string]string{"note": "string", "amount": "number", "buyer.name": "string"},
		Parameters: []Parameter{
			{
				Location: "BODY", StructuredPath: "note", ParameterName: "note", BaseType: "string",
				Required: true, Nullable: true, EmptyAllowed: true, SensitivityLevel: "LOW",
				ConfirmedConstraints: map[string]any{"max_length": float64(32), "enum": []any{"A", "B"}},
			},
			{
				Location: "QUERY", StructuredPath: "page", ParameterName: "page", BaseType: "number",
				Required:             true,
				ConfirmedConstraints: map[string]any{"minimum": float64(1), "maximum": float64(1000)},
			},
		},
	}
}

// TestCompileVocabulary 编译输出含全量 confirmed 词汇与固定结构键。
func TestCompileVocabulary(t *testing.T) {
	policy, err := Compile(testCompileInput())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CanonicalJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	// 固定结构键
	if m["endpoint_key"] != "POST /v1/orders/{id}" || m["method"] != "POST" ||
		m["content_type"] != "application/json" || m["lifecycle"] != "CONFIRMED" ||
		m["compiler_version"] != CompilerVersion {
		t.Fatalf("policy head = %v", m)
	}
	// 预留占位恒为 null（auth_requirement P0-15/16、response_schema P0-06 后续波次补全）
	if v, ok := m["auth_requirement"]; !ok || v != nil {
		t.Fatalf("auth_requirement must be present and null: %v", m["auth_requirement"])
	}
	if v, ok := m["response_schema"]; !ok || v != nil {
		t.Fatalf("response_schema must be present and null: %v", m["response_schema"])
	}
	// 请求 schema 原样编入
	schema := m["request_schema"].(map[string]any)
	if len(schema) != 3 || schema["amount"] != "number" || schema["buyer.name"] != "string" {
		t.Fatalf("request_schema = %v", schema)
	}
	// 参数约束：确定性排序（location → path → name），BODY 在 QUERY 前
	params := m["parameter_constraints"].([]any)
	if len(params) != 2 {
		t.Fatalf("parameter_constraints = %v", params)
	}
	first := params[0].(map[string]any)
	if first["location"] != "BODY" || first["path"] != "note" {
		t.Fatalf("constraints not sorted by location/path: %v", params)
	}
	// 全量 confirmed 词汇：required/nullable/empty_allowed/base_type/sensitivity/constraints
	if first["required"] != true || first["nullable"] != true || first["empty_allowed"] != true ||
		first["base_type"] != "string" || first["sensitivity_level"] != "LOW" {
		t.Fatalf("confirmed vocabulary = %v", first)
	}
	cons := first["constraints"].(map[string]any)
	if cons["max_length"] != float64(32) || len(cons["enum"].([]any)) != 2 {
		t.Fatalf("confirmed constraints = %v", cons)
	}
	second := params[1].(map[string]any)
	if second["location"] != "QUERY" || second["required"] != true ||
		second["nullable"] != false || second["empty_allowed"] != false {
		t.Fatalf("second constraint = %v", second)
	}
}

// TestCompileHashStable 同输入（含 map 乱序）恒得同 content_hash。
func TestCompileHashStable(t *testing.T) {
	in1 := testCompileInput()
	// 同内容不同插入序
	in2 := testCompileInput()
	in2.Schema = map[string]string{"buyer.name": "string", "note": "string", "amount": "number"}
	in2.Parameters[0].ConfirmedConstraints = map[string]any{"enum": []any{"A", "B"}, "max_length": float64(32)}
	p1, _ := Compile(in1)
	p2, _ := Compile(in2)
	h1, _, err := ContentHash(p1)
	if err != nil {
		t.Fatal(err)
	}
	h2, _, err := ContentHash(p2)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("same input must produce same hash: %s != %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("hash must be sha256 hex: %s", h1)
	}
}

// TestCompileHashChanges 任一输入变更产生新 hash（schema/约束/端点/来源版本）。
func TestCompileHashChanges(t *testing.T) {
	base, _ := Compile(testCompileInput())
	baseHash, _, err := ContentHash(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(in *CompileInput){
		"schema 字段类型变化": func(in *CompileInput) { in.Schema["amount"] = "string" },
		"schema 新增字段":   func(in *CompileInput) { in.Schema["extra"] = "bool" },
		"约束词汇变化": func(in *CompileInput) {
			in.Parameters[0].ConfirmedConstraints["max_length"] = float64(64)
		},
		"required 翻转": func(in *CompileInput) { in.Parameters[0].Required = false },
		"端点变化":        func(in *CompileInput) { in.EndpointKey = "POST /v1/orders" },
		"来源版本变化":      func(in *CompileInput) { in.ModelVersionNumber = 2 },
		"生命周期变化":      func(in *CompileInput) { in.AssetStatus = "DEPRECATED" },
	}
	for name, mutate := range mutations {
		in := testCompileInput()
		mutate(&in)
		p, _ := Compile(in)
		h, _, err := ContentHash(p)
		if err != nil {
			t.Fatal(err)
		}
		if h == baseHash {
			t.Errorf("%s must produce new hash", name)
		}
	}
}

// TestDeriveContentType 协议类型 → content_type 映射（REST/空/GRAPHQL → JSON；其余不约束）。
func TestDeriveContentType(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"REST", "application/json"},
		{"", "application/json"},
		{" rest ", "application/json"},
		{"GRAPHQL", "application/json"},
		{"graphql", "application/json"},
		{"GRPC", ""},
		{"SOAP", ""},
		{"WEBSOCKET", ""},
	} {
		if got := deriveContentType(tt.in); got != tt.want {
			t.Errorf("deriveContentType(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

// TestCompileDeterministicSerialization 规范序列化字节级稳定（同一输入两次序列化完全一致）。
func TestCompileDeterministicSerialization(t *testing.T) {
	p1, _ := Compile(testCompileInput())
	p2, _ := Compile(testCompileInput())
	r1, _ := CanonicalJSON(p1)
	r2, _ := CanonicalJSON(p2)
	if string(r1) != string(r2) {
		t.Fatalf("canonical serialization not stable:\n%s\n%s", r1, r2)
	}
	// 预留占位序列化为 null 字面量
	if !strings.Contains(string(r1), `"auth_requirement":null`) ||
		!strings.Contains(string(r1), `"response_schema":null`) {
		t.Fatalf("placeholders must serialize as null: %s", r1)
	}
}
