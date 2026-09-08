package parser

import (
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// findAmbiguity 按位置+参数名查找歧义记录（测试辅助）。
func findAmbiguity(p *Parsed, location, name string) *ParamAmbiguity {
	for i := range p.Ambiguities {
		a := &p.Ambiguities[i]
		if a.Location == location && a.ParameterName == name {
			return a
		}
	}
	return nil
}

// 多值 query：保留首值语义（仍取 vs[0]），登记一条歧义（总数）；单值参数不登记。
func TestParseRequestQueryMultiValueAmbiguity(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "http://x/api?a=1&a=2&a=3&b=x", nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseRequest(r, dsctx.New("", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if p.Query["a"] != "1" || p.Query["b"] != "x" {
		t.Fatalf("first-value semantics broken: %v", p.Query)
	}
	a := findAmbiguity(p, AmbLocationQuery, "a")
	if a == nil || a.ValueCount != 3 {
		t.Fatalf("want query ambiguity a x3, got %+v", p.Ambiguities)
	}
	if a.Path != "" {
		t.Fatalf("query ambiguity must not carry path: %+v", a)
	}
	if findAmbiguity(p, AmbLocationQuery, "b") != nil {
		t.Fatalf("single-value param must not be ambiguous: %+v", p.Ambiguities)
	}
}

// 多头：保留首值语义，登记歧义；脱敏头（authorization）多头计数在脱敏分支之前统计，
// 只记名+次数（ParamAmbiguity 无值字段，编译期保证不落值）。
func TestParseRequestHeaderMultiValueAmbiguity(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "http://x/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Add("X-Dup", "v1")
	r.Header.Add("X-Dup", "v2")
	r.Header.Add("Authorization", "Bearer secret-one")
	r.Header.Add("Authorization", "Bearer secret-two")
	p, err := ParseRequest(r, dsctx.New("", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if p.Headers["x-dup"] != "v1" {
		t.Fatalf("first-value semantics broken: %v", p.Headers)
	}
	if p.Headers["authorization"] != "[redacted]" {
		t.Fatalf("redaction broken: %v", p.Headers)
	}
	a := findAmbiguity(p, AmbLocationHeader, "x-dup")
	if a == nil || a.ValueCount != 2 {
		t.Fatalf("want header ambiguity x-dup x2, got %+v", p.Ambiguities)
	}
	ra := findAmbiguity(p, AmbLocationHeader, "authorization")
	if ra == nil || ra.ValueCount != 2 {
		t.Fatalf("redacted multi-header must still be counted (name+count only): %+v", p.Ambiguities)
	}
	// 负例：单值头不登记
	if findAmbiguity(p, AmbLocationHeader, "x-single") != nil {
		t.Fatalf("single header must not be ambiguous: %+v", p.Ambiguities)
	}
}

// JSON 重复键：顶层 last-wins 语义不变（字段类型照落），重复键可追溯（含三次出现记总数）。
func TestParseRequestJSONDuplicateKey(t *testing.T) {
	body := `{"count":10,"count":-999,"name":"x"}`
	r, err := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	p, err := ParseRequest(r, dsctx.New("", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if !p.IsJSON || p.JSONFields["count"] != "number" {
		t.Fatalf("json parse broken: isJSON=%v fields=%v", p.IsJSON, p.JSONFields)
	}
	a := findAmbiguity(p, AmbLocationJSON, "count")
	if a == nil || a.ValueCount != 2 || a.Path != "count" {
		t.Fatalf("want json ambiguity count x2 path=count, got %+v", p.Ambiguities)
	}
	if findAmbiguity(p, AmbLocationJSON, "name") != nil {
		t.Fatalf("unique key must not be ambiguous: %+v", p.Ambiguities)
	}

	// 三次出现：一条记录记总数 3（不重复发记录）
	r2, _ := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(`{"a":1,"a":2,"a":3}`))
	r2.Header.Set("Content-Type", "application/json")
	p2, err := ParseRequest(r2, dsctx.New("", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.Ambiguities) != 1 {
		t.Fatalf("triple duplicate must be one record, got %+v", p2.Ambiguities)
	}
	if p2.Ambiguities[0].ValueCount != 3 || p2.Ambiguities[0].Path != "a" {
		t.Fatalf("want a x3, got %+v", p2.Ambiguities[0])
	}
}

// JSON 重复键：嵌套对象与数组内对象均可追溯（路径与 walkJSON 同口径）。
func TestParseRequestJSONDuplicateKeyNested(t *testing.T) {
	body := `{"a":{"b":1,"b":2},"c":[{"d":1,"d":2}],"e":{"f":{"g":true,"g":false}}}`
	r, err := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	p, err := ParseRequest(r, dsctx.New("", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := map[string]int{"a.b": 2, "c[].d": 2, "e.f.g": 2}
	if len(p.Ambiguities) != len(wantPaths) {
		t.Fatalf("want %d ambiguities, got %+v", len(wantPaths), p.Ambiguities)
	}
	for _, a := range p.Ambiguities {
		if a.Location != AmbLocationJSON {
			t.Fatalf("unexpected location: %+v", a)
		}
		if n, ok := wantPaths[a.Path]; !ok || n != a.ValueCount {
			t.Fatalf("unexpected ambiguity: %+v (all: %+v)", a, p.Ambiguities)
		}
		delete(wantPaths, a.Path)
	}
	if len(wantPaths) != 0 {
		t.Fatalf("missing paths %v in %+v", wantPaths, p.Ambiguities)
	}
}

// 截断体跳过重复键扫描（样本非完整 JSON，扫描必误报）；IsJSON 标记不受影响。
func TestParseRequestJSONTruncatedSkipsDupScan(t *testing.T) {
	limits := dsctx.DefaultParseLimits()
	limits.MaxBodyParseBytes = 16
	limits.MaxBodySampleBytes = 16
	body := `{"count":10,"count":-999,"pad":"xxxxxxxxxxxxxxxx"}`
	r, err := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	p, err := ParseRequest(r, dsctx.New("", limits))
	if err != nil {
		t.Fatal(err)
	}
	if !p.BodyTruncated || !p.IsJSON {
		t.Fatalf("expected truncated json: %+v", p)
	}
	if len(p.Ambiguities) != 0 {
		t.Fatalf("truncated body must skip dup scan, got %+v", p.Ambiguities)
	}
}

// 非法 JSON：不产出歧义（丢弃半份扫描，与字段解析失败零字段同语义），不 panic。
func TestParseRequestJSONInvalidNoAmbiguity(t *testing.T) {
	r, err := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(`{"a":1,"a":`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	p, err := ParseRequest(r, dsctx.New("", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Ambiguities) != 0 {
		t.Fatalf("invalid json must not yield ambiguity, got %+v", p.Ambiguities)
	}
	if len(p.JSONFields) != 0 {
		t.Fatalf("invalid json must not yield fields, got %v", p.JSONFields)
	}
}

// 深度上限：超 MaxJSONDepth 停止下钻（深层重复键不记录），深度内已扫记录保留。
func TestParseRequestJSONDupScanDepthCap(t *testing.T) {
	limits := dsctx.DefaultParseLimits()
	limits.MaxJSONDepth = 2
	// 深度内重复（root→x 帧内 z）可记录；深度外（root→x→y 帧内 z）停止下钻
	r, err := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(`{"x":{"y":{"z":1,"z":2}}}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	p, err := ParseRequest(r, dsctx.New("", limits))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Ambiguities) != 0 {
		t.Fatalf("dup beyond depth cap must not be recorded, got %+v", p.Ambiguities)
	}
}

// form 重复键：保留首值语义（schema 去重不变），登记一条歧义（总次数）。
func TestParseRequestFormDuplicateParamAmbiguity(t *testing.T) {
	body := "a=1&a=2&a=3&b=x"
	r, err := http.NewRequest(http.MethodPost, "http://x/submit", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p, err := ParseRequest(r, dsctx.New("", dsctx.DefaultParseLimits()))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.FormFields) != 2 || p.FormFields["a"] != "number" || p.FormFields["b"] != "string" {
		t.Fatalf("first-value schema semantics broken: %v", p.FormFields)
	}
	a := findAmbiguity(p, AmbLocationForm, "a")
	if a == nil || a.ValueCount != 3 {
		t.Fatalf("want form ambiguity a x3, got %+v", p.Ambiguities)
	}
	if findAmbiguity(p, AmbLocationForm, "b") != nil {
		t.Fatalf("single form key must not be ambiguous: %+v", p.Ambiguities)
	}
}
