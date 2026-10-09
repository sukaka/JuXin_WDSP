// schema_test.go Schema 冻结子集求值矩阵（六关键字/缺省关闭世界/嵌套/枚举/
// 不支持关键字登记降级/词表外类型缺席）。
package mcpguard

import (
	"encoding/json"
	"testing"
)

func mustCompile(raw string) *Schema { return CompileSchema(json.RawMessage(raw)) }

func TestSchemaTypesAndKeywords(t *testing.T) {
	s := mustCompile(`{"type":"object","properties":{
		"s":{"type":"string"},"n":{"type":"number"},"i":{"type":"integer"},
		"b":{"type":"boolean"},"nil":{"type":"null"},"arr":{"type":"array","items":{"type":"integer"}},
		"obj":{"type":"object","properties":{"x":{"type":"string"}},"additionalProperties":false}
	},"required":["s"],"additionalProperties":false}`)
	cases := []struct {
		name string
		doc  any
		rule string // "" = 通过
	}{
		{"全通过", map[string]any{"s": "a", "n": 1.5, "i": float64(2), "b": true, "nil": nil,
			"arr": []any{float64(1)}, "obj": map[string]any{"x": "y"}}, ""},
		{"string 类型不符", map[string]any{"s": 1}, "type_mismatch"},
		{"number 类型不符", map[string]any{"s": "a", "n": "1"}, "type_mismatch"},
		{"integer 小数不符", map[string]any{"s": "a", "i": 1.5}, "type_mismatch"},
		{"integer 整数通过", map[string]any{"s": "a", "i": float64(3)}, ""},
		{"boolean 不符", map[string]any{"s": "a", "b": "true"}, "type_mismatch"},
		{"null 非 nil 不符", map[string]any{"s": "a", "nil": 0}, "type_mismatch"},
		{"required 缺失", map[string]any{}, "required_missing"},
		{"required null 视为存在", map[string]any{"s": nil}, "type_mismatch"}, // 存在但类型不符——不冒充缺失
		{"未知字段关闭世界", map[string]any{"s": "a", "ghost": 1}, "unknown_field"},
		{"嵌套对象未知字段", map[string]any{"s": "a", "obj": map[string]any{"x": "y", "g": 1}}, "unknown_field"},
		{"嵌套对象类型不符", map[string]any{"s": "a", "obj": map[string]any{"x": 1}}, "type_mismatch"},
		{"数组元素类型不符", map[string]any{"s": "a", "arr": []any{float64(1), "x"}}, "type_mismatch"},
		{"数组非数组不符", map[string]any{"s": "a", "arr": "x"}, "type_mismatch"},
	}
	for _, tc := range cases {
		violations := ValidateSchema(s, tc.doc)
		if tc.rule == "" {
			if len(violations) != 0 {
				t.Errorf("%s: 应通过，得 %v", tc.name, violations)
			}
			continue
		}
		if len(violations) == 0 || violations[0].Rule != tc.rule {
			t.Errorf("%s: 应 %s，得 %v", tc.name, tc.rule, violations)
		}
	}
}

func TestSchemaClosedWorldDefault(t *testing.T) {
	// additionalProperties 缺省 = 关闭世界（nil 按 false 处置）
	s := mustCompile(`{"type":"object","properties":{"a":{"type":"string"}}}`)
	violations := ValidateSchema(s, map[string]any{"a": "x", "b": 1})
	if len(violations) == 0 || violations[0].Rule != "unknown_field" {
		t.Fatalf("缺省应关闭世界: %v", violations)
	}
	// 显式 true = 开放
	s2 := mustCompile(`{"type":"object","properties":{"a":{"type":"string"}},"additionalProperties":true}`)
	if violations := ValidateSchema(s2, map[string]any{"a": "x", "b": 1}); len(violations) != 0 {
		t.Fatalf("显式开放应通过: %v", violations)
	}
}

func TestSchemaEnum(t *testing.T) {
	s := mustCompile(`{"enum":["active","paused",1,true,null]}`)
	cases := []struct {
		v    any
		pass bool
	}{
		{"active", true},
		{"ARCHIVED", false},
		{float64(1), true},
		{true, true},
		{nil, true},
		{float64(1.5), false},
		{"1", false}, // 文本 "1" ≠ 数值 1（形态敏感口径）
	}
	for _, tc := range cases {
		violations := ValidateSchema(s, tc.v)
		if tc.pass && len(violations) != 0 {
			t.Errorf("%v 应通过: %v", tc.v, violations)
		}
		if !tc.pass && (len(violations) == 0 || violations[0].Rule != "enum_violation") {
			t.Errorf("%v 应 enum_violation: %v", tc.v, violations)
		}
	}
}

func TestSchemaCompileRobustness(t *testing.T) {
	for _, raw := range []string{"", "null", `{"type":"ghost"}`, `{"type":123}`, `not-json`} {
		if CompileSchema(json.RawMessage(raw)) != nil {
			t.Errorf("%s 应按缺席（nil）处理", raw)
		}
	}
	// properties/items 递归编译
	s := mustCompile(`{"type":"array","items":{"type":"object","properties":{"x":{"type":"integer"}},"required":["x"]}}`)
	violations := ValidateSchema(s, []any{map[string]any{}})
	if len(violations) == 0 || violations[0].Rule != "required_missing" || violations[0].Path != "[0].x" {
		t.Fatalf("递归 items 校验: %v", violations)
	}
	// 无 type 约束：enum 仍求值、对象关键字不展开
	s2 := mustCompile(`{"enum":[1]}`)
	if violations := ValidateSchema(s2, float64(2)); len(violations) == 0 {
		t.Fatal("无类型约束 enum 应求值")
	}
}

func TestDetectUnsupportedKeywords(t *testing.T) {
	cases := []struct {
		raw  string
		want int // 命中数（0=不降级）
	}{
		{`{"type":"object","properties":{"a":{"type":"string"}}}`, 0},
		{`{"type":"string","pattern":"^a+$"}`, 1},
		{`{"$ref":"#/$defs/x"}`, 1},
		{`{"anyOf":[{"type":"string"}]}`, 1},
		{`{"type":"string","minLength":1,"maxLength":9}`, 2},
		{`{"type":"string","format":"email"}`, 1},
		{`{"type":"string","description":"注解容忍","title":"t","default":"x","$schema":"http://x"}`, 0},
		{`not-an-object`, 0},
		{`{"oneOf":[],"not":{},"allOf":[],"contains":{},"uniqueItems":true}`, 5},
	}
	for _, tc := range cases {
		got := DetectUnsupportedKeywords(json.RawMessage(tc.raw))
		if len(got) != tc.want {
			t.Errorf("%s: 命中 %v，应 %d", tc.raw, got, tc.want)
		}
	}
}
