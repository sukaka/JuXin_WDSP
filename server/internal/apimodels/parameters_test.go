package apimodels

import "testing"

// mapSchemaTypeToBaseType：schema_json 词汇向网关粗类型词表对齐。
func TestMapSchemaTypeToBaseType(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"integer", "number"},
		{"number", "number"},
		{"float", "number"},
		{"double", "number"},
		{"boolean", "bool"},
		{"bool", "bool"},
		{"string", "string"},
		{"object", "object"},
		{"array", "array"},
		{"null", "null"},
		{"INTEGER", "number"},    // 大小写不敏感
		{" string ", "string"},   // 空白裁剪
		{"datetime", "datetime"}, // 未识别词汇小写原样保留
		{"", ""},
	}
	for _, tt := range tests {
		if got := mapSchemaTypeToBaseType(tt.in); got != tt.want {
			t.Errorf("mapSchemaTypeToBaseType(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

// deriveParameterName：结构化路径末段名（去 [] 数组元素标记）。
func TestDeriveParameterName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"name", "name"},
		{"buyer.name", "name"},
		{"items[]", "items"},
		{"items[].sku", "sku"},
		{"a.b.c", "c"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := deriveParameterName(tt.in); got != tt.want {
			t.Errorf("deriveParameterName(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}
