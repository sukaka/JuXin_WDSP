package parser

import (
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestParseRequestXMLFields(t *testing.T) {
	body := `<?xml version="1.0"?>
<order><user><name>alice</name><age>30</age><vip>true</vip></user><item>book</item><item>pen</item></order>`
	r, err := http.NewRequest(http.MethodPost, "http://x/xml", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/xml")
	ctx := dsctx.New("", dsctx.DefaultParseLimits())
	p, err := ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"order.user.name": "string",
		"order.user.age":  "number",
		"order.user.vip":  "bool",
		"order.item":      "string",
	}
	for k, typ := range want {
		if p.XMLFields[k] != typ {
			t.Fatalf("path %s: got %q want %q (all=%v)", k, p.XMLFields[k], typ, p.XMLFields)
		}
	}
	if p.XMLTruncated || p.XMLDTDBlocked || p.FieldCapped {
		t.Fatalf("unexpected flags: %+v", p)
	}
	if _, ok := ctx.Extensions[ExtXMLFields].(map[string]string); !ok {
		t.Fatalf("ctx extension missing: %v", ctx.Extensions)
	}

	// +xml 后缀类型同样按 XML 解析
	r2, err := http.NewRequest(http.MethodPost, "http://x/feed", strings.NewReader(`<feed><title>t</title></feed>`))
	if err != nil {
		t.Fatal(err)
	}
	r2.Header.Set("Content-Type", "application/atom+xml; charset=utf-8")
	p2, err := ParseRequest(r2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p2.XMLFields["feed.title"] != "string" {
		t.Fatalf("+xml suffix not dispatched: %v", p2.XMLFields)
	}
}

func TestParseRequestXMLRejectsDOCTYPE(t *testing.T) {
	// XXE：DOCTYPE 内定义外部实体，必须拒绝解析
	body := `<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>`
	r, err := http.NewRequest(http.MethodPost, "http://x/xml", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "text/xml")
	ctx := dsctx.New("", dsctx.DefaultParseLimits())
	p, err := ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !p.XMLDTDBlocked {
		t.Fatalf("DOCTYPE must be blocked: %+v", p)
	}
	if len(p.XMLFields) != 0 {
		t.Fatalf("no fields may be extracted after DOCTYPE: %v", p.XMLFields)
	}
	if ctx.Extensions[ExtXMLDTDBlocked] != true {
		t.Fatalf("ctx flag missing: %v", ctx.Extensions)
	}
}

func TestParseRequestXMLDepthCap(t *testing.T) {
	limits := dsctx.DefaultParseLimits()
	limits.MaxXMLDepth = 2
	body := `<a><name>bob</name><b><c>deep</c></b></a>`
	r, err := http.NewRequest(http.MethodPost, "http://x/xml", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/xml")
	ctx := dsctx.New("", limits)
	p, err := ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !p.XMLTruncated {
		t.Fatalf("expected depth truncation: %+v", p)
	}
	// 截断前已解析的叶子保留
	if p.XMLFields["a.name"] != "string" || len(p.XMLFields) != 1 {
		t.Fatalf("partial fields=%v", p.XMLFields)
	}
	if ctx.Extensions[ExtXMLTruncated] != true {
		t.Fatalf("ctx flag missing: %v", ctx.Extensions)
	}
}
