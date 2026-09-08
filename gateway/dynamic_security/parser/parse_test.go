package parser

import (
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestParseRequestJSONAndNormalize(t *testing.T) {
	body := `{"user_id":1,"name":"alice","nested":{"x":true}}`
	r, err := http.NewRequest(http.MethodPost, "http://x/users/42?q=1", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer secret-token")
	r.Header.Set("X-Request-Id", "rid-parse-1")

	ctx := dsctx.New("", dsctx.DefaultParseLimits())
	p, err := ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.NormalizedPath != "/users/{id}" {
		t.Fatalf("path=%s", p.NormalizedPath)
	}
	if ctx.NormalizedPath != "/users/{id}" || ctx.RequestID != "rid-parse-1" {
		t.Fatalf("ctx not filled: %+v", ctx)
	}
	if p.Headers["authorization"] != "[redacted]" {
		t.Fatal("auth must be redacted")
	}
	if p.JSONFields["user_id"] != "number" || p.JSONFields["name"] != "string" {
		t.Fatalf("fields=%v", p.JSONFields)
	}
	if p.Query["q"] != "1" {
		t.Fatal(p.Query)
	}
}

func TestParseRequestBodyAndFieldCaps(t *testing.T) {
	// force tiny limits
	limits := dsctx.ParseLimits{
		MaxBodyParseBytes:  20,
		MaxBodySampleBytes: 10,
		MaxJSONDepth:       8,
		MaxFieldCount:      2,
		MaxXMLDepth:        8,
		MaxFileMetaCount:   4,
	}
	// body larger than MaxBodyParseBytes
	body := `{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6}`
	r, _ := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := dsctx.New("r2", limits)
	p, err := ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !p.BodyTruncated && !ctx.BodyTruncated {
		// body len > 20 should truncate
		if len(body) > 20 && !p.BodyTruncated {
			t.Fatal("expected body truncated")
		}
	}
	// field cap: even without body truncate, field limit 2
	r2, _ := http.NewRequest(http.MethodPost, "http://x/api", strings.NewReader(`{"a":1,"b":2,"c":3}`))
	r2.Header.Set("Content-Type", "application/json")
	ctx2 := dsctx.New("r3", limits)
	p2, err := ParseRequest(r2, ctx2)
	if err != nil {
		t.Fatal(err)
	}
	if !p2.FieldCapped && !ctx2.FieldCountCapped {
		t.Fatalf("expected field cap, fields=%v count=%d", p2.JSONFields, p2.FieldCount)
	}
}

// Query/Body 字段配额独立（MED-4 回归）：≥MaxFieldCount 个 distinct query 键只置 QueryCapped，
// 不得消耗 Body 侧 FieldCount 预算把 JSONFields/JSONValues 排空（体侧检测——LLM 形态确认、
// 敏感字段、schema 偏离、BODY 参数约束——不得被 query 风暴静默跳过）；反向同样成立。
func TestParseRequestQueryBodyIndependentCaps(t *testing.T) {
	limits := dsctx.ParseLimits{
		MaxBodyParseBytes:  4096,
		MaxBodySampleBytes: 1024,
		MaxJSONDepth:       8,
		MaxFieldCount:      3,
		MaxXMLDepth:        8,
		MaxFileMetaCount:   4,
	}
	// 5 个 distinct query 键（超 MaxFieldCount=3）+ JSON 体 2 字段
	r, _ := http.NewRequest(http.MethodPost, "http://x/api?q1=1&q2=2&q3=3&q4=4&q5=5", strings.NewReader(`{"a":1,"b":2}`))
	r.Header.Set("Content-Type", "application/json")
	p, err := ParseRequest(r, dsctx.New("r-qb-1", limits))
	if err != nil {
		t.Fatal(err)
	}
	if !p.QueryCapped {
		t.Fatalf("expected query cap, query=%v", p.Query)
	}
	if len(p.Query) != 3 {
		t.Fatalf("query must be capped at MaxFieldCount=3, got %v", p.Query)
	}
	if p.FieldCapped {
		t.Fatalf("body fields must not consume query-exhausted shared quota: %+v", p.JSONFields)
	}
	if len(p.JSONFields) != 2 || p.JSONFields["a"] != "number" || p.JSONFields["b"] != "number" {
		t.Fatalf("json fields must be fully parsed despite query cap: %v", p.JSONFields)
	}

	// 反向：body 字段超限不置 QueryCapped，query 全量保留
	r2, _ := http.NewRequest(http.MethodPost, "http://x/api?ok=1", strings.NewReader(`{"a":1,"b":2,"c":3,"d":4}`))
	r2.Header.Set("Content-Type", "application/json")
	p2, err := ParseRequest(r2, dsctx.New("r-qb-2", limits))
	if err != nil {
		t.Fatal(err)
	}
	if !p2.FieldCapped {
		t.Fatalf("expected body field cap, fields=%v", p2.JSONFields)
	}
	if p2.QueryCapped || len(p2.Query) != 1 || p2.Query["ok"] != "1" {
		t.Fatalf("query must be unaffected by body field cap: %+v", p2.Query)
	}
}
