package pipeline

import (
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 解析歧义经管线真实产生 finding：重复 JSON 键 + 多值 query 各一条；
// PROTECT 模式下定案 OBSERVE（api_parser 非可信阻断源，歧义永不实断）。
func TestProcessParserAmbiguity(t *testing.T) {
	body := `{"count":10,"count":-999}`
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/orders?id=1&id=2", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer s3cr3t-token-0123456789abcdef")
	r.Header.Set("X-Request-Id", "pipe-parser-amb")
	res, err := Process(r, Config{Enabled: true, Mode: "PROTECT"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{"parser.duplicate_json_key", "parser.duplicate_query_param"} {
		if !hasRule(res, rule) {
			t.Fatalf("expected match %s, got %+v", rule, res.Context.CopyMatches())
		}
	}
	// finding 属性：OBSERVE/MEDIUM，detector=api_parser，置信度默认 1.0
	n := 0
	for _, m := range res.Context.CopyMatches() {
		if m.Detector != "api_parser" {
			continue
		}
		n++
		if m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
			t.Fatalf("parser finding = %s/%s, want OBSERVE/MEDIUM: %+v", m.Category, m.Severity, m)
		}
		if m.Confidence != 1.0 {
			t.Fatalf("parser finding confidence = %v, want 1.0", m.Confidence)
		}
	}
	if n != 2 {
		t.Fatalf("want 2 api_parser findings, got %d: %+v", n, res.Context.CopyMatches())
	}
	// 红线：定案 OBSERVE，绝不 BLOCK
	if res.FinalAction != dsctx.ActionObserve {
		t.Fatalf("final=%s, want OBSERVE", res.FinalAction)
	}
}

// 负例：无歧义请求不产生 api_parser finding（首值语义请求零噪声）。
func TestProcessParserAmbiguityNegative(t *testing.T) {
	body := `{"count":10}`
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/orders?id=1", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer s3cr3t-token-0123456789abcdef")
	res, err := Process(r, Config{Enabled: true, Mode: "PROTECT"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range res.Context.CopyMatches() {
		if m.Detector == "api_parser" {
			t.Fatalf("clean request must not produce parser finding: %+v", m)
		}
	}
}
