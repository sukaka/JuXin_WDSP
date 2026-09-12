package parser

import (
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// RetainJSONScalarValues=true：标量值按路径留存（截断 256），object/array/null 不留存。
func TestParseRequestRetainsJSONScalarValues(t *testing.T) {
	long := strings.Repeat("长", 300)
	body := `{"name":"alice","age":30,"admin":true,"note":null,"tags":["a"],"obj":{"x":1},"long":"` + long + `"}`
	r, _ := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	limits := dsctx.DefaultParseLimits()
	limits.RetainJSONScalarValues = true
	p, err := ParseRequest(r, dsctx.New("r-retain", limits))
	if err != nil {
		t.Fatal(err)
	}
	if p.JSONValues["name"] != "alice" || p.JSONValues["age"] != "30" || p.JSONValues["admin"] != "true" {
		t.Fatalf("scalar values not retained: %v", p.JSONValues)
	}
	for _, path := range []string{"note", "tags", "obj"} {
		if _, ok := p.JSONValues[path]; ok {
			t.Fatalf("non-scalar %s must not be retained: %v", path, p.JSONValues)
		}
	}
	if got := utf8.RuneCountInString(p.JSONValues["long"]); got != maxScalarValueLen {
		t.Fatalf("long value runes = %d, want truncated to %d", got, maxScalarValueLen)
	}
	// 字段类型表行为不变
	if p.JSONFields["tags"] != "array" || p.JSONFields["obj"] != "object" || p.JSONFields["note"] != "null" {
		t.Fatalf("fields changed: %v", p.JSONFields)
	}
}

// 默认（false）：零行为变化，JSONValues 恒空。
func TestParseRequestNoRetentionByDefault(t *testing.T) {
	body := `{"name":"alice","age":30}`
	r, _ := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	p, err := ParseRequest(r, dsctx.New("r-noretain", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.JSONValues) != 0 {
		t.Fatalf("default must not retain values: %v", p.JSONValues)
	}
}

// 留存受 MaxFieldCount 约束：字段上限后不继续取值。
func TestParseRequestRetentionRespectsFieldCap(t *testing.T) {
	limits := dsctx.DefaultParseLimits()
	limits.RetainJSONScalarValues = true
	limits.MaxFieldCount = 2
	body := `{"a":"1","b":"2","c":"3"}`
	r, _ := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	p, err := ParseRequest(r, dsctx.New("r-retain-cap", limits))
	if err != nil {
		t.Fatal(err)
	}
	if !p.FieldCapped {
		t.Fatal("expected field cap")
	}
	if len(p.JSONValues) > 2 {
		t.Fatalf("retained values exceed field cap: %v", p.JSONValues)
	}
}

// RetainFormScalarValues=true：表单标量值按字段名留存（截断 256）；默认关闭时零留存。
func TestParseRequestRetainsFormScalarValues(t *testing.T) {
	body := "name=alice&note=" + strings.Repeat("长", 300)
	r, _ := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	limits := dsctx.DefaultParseLimits()
	limits.RetainFormScalarValues = true
	p, err := ParseRequest(r, dsctx.New("r-form-retain", limits))
	if err != nil {
		t.Fatal(err)
	}
	if p.FormValues["name"] != "alice" {
		t.Fatalf("form value not retained: %v", p.FormValues)
	}
	if got := p.FormValues["note"]; utf8.RuneCountInString(got) != 256 {
		t.Fatalf("form value must be truncated to 256 runes, got %d", utf8.RuneCountInString(got))
	}

	// 默认关闭：零留存（零行为变化）
	r2, _ := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(body))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p2, err := ParseRequest(r2, dsctx.New("r-form-default", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.FormValues) != 0 {
		t.Fatalf("default limits must not retain form values, got %v", p2.FormValues)
	}
	if p2.FormFields["name"] != "string" {
		t.Fatalf("form field schema must still be recorded, got %v", p2.FormFields)
	}
}
