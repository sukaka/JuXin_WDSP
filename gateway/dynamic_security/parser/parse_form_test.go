package parser

import (
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestParseRequestFormURLEncoded(t *testing.T) {
	body := "name=alice&age=30&admin=true&empty=&encoded=hello+world&name=dup"
	r, err := http.NewRequest(http.MethodPost, "http://x/submit", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	ctx := dsctx.New("", dsctx.DefaultParseLimits())
	p, err := ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"name":    "string",
		"age":     "number",
		"admin":   "bool",
		"empty":   "string",
		"encoded": "string",
	}
	if len(p.FormFields) != len(want) {
		t.Fatalf("fields=%v", p.FormFields)
	}
	for k, typ := range want {
		if p.FormFields[k] != typ {
			t.Fatalf("field %s: got %q want %q (all=%v)", k, p.FormFields[k], typ, p.FormFields)
		}
	}
	if p.IsJSON {
		t.Fatal("form body must not be marked JSON")
	}
	// 不落明文值
	for _, v := range p.FormFields {
		if v == "alice" || v == "30" || v == "hello world" {
			t.Fatalf("plaintext value leaked: %v", p.FormFields)
		}
	}
	ext, ok := ctx.Extensions[ExtFormFields].(map[string]string)
	if !ok || ext["age"] != "number" {
		t.Fatalf("ctx extension missing: %v", ctx.Extensions)
	}
}

func TestParseRequestFormFieldCap(t *testing.T) {
	limits := dsctx.DefaultParseLimits()
	limits.MaxFieldCount = 2
	r, err := http.NewRequest(http.MethodPost, "http://x/submit", strings.NewReader("a=1&b=2&c=3&d=4"))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := dsctx.New("", limits)
	p, err := ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !p.FieldCapped || !ctx.FieldCountCapped {
		t.Fatalf("expected field cap: fields=%v", p.FormFields)
	}
	if len(p.FormFields) != 2 {
		t.Fatalf("cap not enforced: %v", p.FormFields)
	}
}
