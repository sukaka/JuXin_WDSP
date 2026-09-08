package response

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestParseMaskRuleOK(t *testing.T) {
	r, err := ParseMaskRule("GET /v1/users", "users[].phone", "phone", "MASK", map[string]any{"keep_head": float64(2)})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Algorithm != AlgorithmMask || r.KeepHead != 2 || r.KeepTail != DefaultKeepTail {
		t.Fatalf("rule: %+v", r)
	}
	// 无参数：默认 3/4
	r2, err := ParseMaskRule("GET /v1/users", "a.b", "", "HASH", nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r2.KeepHead != DefaultKeepHead || r2.KeepTail != DefaultKeepTail {
		t.Fatalf("defaults: %+v", r2)
	}
}

func TestParseMaskRuleErrors(t *testing.T) {
	cases := []struct {
		name               string
		ek, path, dt, algo string
		params             map[string]any
	}{
		{"empty endpoint", "", "a", "", "MASK", nil},
		{"empty path", "ek", "", "", "MASK", nil},
		{"empty segment", "ek", "a..b", "", "MASK", nil},
		{"only wildcard", "ek", "[]", "", "MASK", nil},
		{"bad algorithm", "ek", "a", "", "ENCRYPT", nil},
		{"bad param key", "ek", "a", "", "MASK", map[string]any{"bogus": 1}},
		{"negative keep", "ek", "a", "", "MASK", map[string]any{"keep_head": float64(-1)}},
		{"fractional keep", "ek", "a", "", "MASK", map[string]any{"keep_tail": float64(1.5)}},
		{"string keep", "ek", "a", "", "MASK", map[string]any{"keep_head": "3"}},
		{"oversized keep", "ek", "a", "", "MASK", map[string]any{"keep_head": float64(1024)}},
		{"oversized data type", "ek", "a", string(make([]byte, 65)), "MASK", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseMaskRule(tc.ek, tc.path, tc.dt, tc.algo, tc.params); err == nil {
				t.Fatal("expect error")
			}
		})
	}
}

func TestBuildTransformPlan(t *testing.T) {
	fields := map[string]string{
		"user":        "object",
		"user.phone":  "string",
		"user.tags":   "array",
		"user.tags[]": "string",
	}
	rules := []MaskRule{
		{EndpointKey: "ek", FieldPath: "user.phone", Algorithm: AlgorithmMask, KeepHead: 3, KeepTail: 4},
		{EndpointKey: "ek", FieldPath: "user.missing", Algorithm: AlgorithmMask},                // 路径不存在 → 不收
		{EndpointKey: "ek", FieldPath: "user", Algorithm: AlgorithmMask},                        // object 目标 MASK 空转 → 不收
		{EndpointKey: "ek", FieldPath: "user", Algorithm: AlgorithmRemove, DataType: "payload"}, // object REMOVE → 收
		{EndpointKey: "ek", FieldPath: "user.tags[]", Algorithm: AlgorithmHash},                 // 数组元素标量 → 收
	}
	plan := BuildTransformPlan(rules, fields)
	if len(plan) != 3 {
		t.Fatalf("plan len = %d, want 3: %+v", len(plan), plan)
	}
	if plan[0].FieldPath != "user.phone" || plan[1].FieldPath != "user" || plan[2].FieldPath != "user.tags[]" {
		t.Fatalf("plan order/content: %+v", plan)
	}
	if plan[1].DataType != "payload" {
		t.Fatalf("data type carried: %+v", plan[1])
	}
	// 无规则/无字段 → 空计划（决策不升级 MASK_RESPONSE）
	if p := BuildTransformPlan(nil, fields); len(p) != 0 {
		t.Fatalf("nil rules must yield empty plan, got %+v", p)
	}
	if p := BuildTransformPlan(rules, map[string]string{}); len(p) != 0 {
		t.Fatalf("no fields must yield empty plan, got %+v", p)
	}
}

func TestIsJSONContentType(t *testing.T) {
	if !IsJSONContentType("application/json; charset=utf-8", nil) {
		t.Fatal("application/json")
	}
	if !IsJSONContentType("application/problem+json", nil) {
		t.Fatal("+json suffix")
	}
	if !IsJSONContentType("", []byte(` {"a":1}`)) {
		t.Fatal("empty content type with json body sniff")
	}
	if IsJSONContentType("", []byte(`plain text`)) {
		t.Fatal("empty content type with text body")
	}
	if IsJSONContentType("text/plain", []byte(`{"a":1}`)) {
		t.Fatal("explicit non-json type must skip")
	}
}

func TestWalkJSONFields(t *testing.T) {
	fields, ok := WalkJSONFields([]byte(`{"user":{"phone":"1"},"tags":["a","b"],"n":1e2,"big":123456789012345678901234567890}`), dsctx.DefaultParseLimits())
	if !ok {
		t.Fatal("expect json")
	}
	want := map[string]string{
		"user": "object", "user.phone": "string",
		"tags": "array", "tags[]": "string",
		"n": "number", "big": "number",
	}
	for k, v := range want {
		if fields[k] != v {
			t.Fatalf("field %q = %q, want %q (all: %+v)", k, fields[k], v, fields)
		}
	}
	if _, ok := WalkJSONFields([]byte(`{bad`), dsctx.DefaultParseLimits()); ok {
		t.Fatal("invalid json must report not-json")
	}
	// 深度上限
	deep := `{"a":{"b":{"c":{"d":1}}}}`
	lim := dsctx.DefaultParseLimits()
	lim.MaxJSONDepth = 2
	fields, ok = WalkJSONFields([]byte(deep), lim)
	if !ok {
		t.Fatal("expect json")
	}
	if _, exists := fields["a.b.c.d"]; exists {
		t.Fatalf("depth limit must stop walk: %+v", fields)
	}
}
