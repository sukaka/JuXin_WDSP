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
