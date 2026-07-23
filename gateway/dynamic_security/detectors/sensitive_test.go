package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func defaultPatterns(t *testing.T) []CompiledSensitivePattern {
	t.Helper()
	p, err := CompileSensitivePatterns(nil)
	if err != nil {
		t.Fatalf("compile default patterns: %v", err)
	}
	return p
}

func TestSensitive_JSONFieldMatch(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{JSONFields: map[string]string{
		"user.phone":   "string",
		"user.address": "string",
		"amount":       "number",
	}}
	CheckSensitiveData(ctx, p, defaultPatterns(t))
	m := findMatch(ctx, "sensitive.field")
	if m == nil {
		t.Fatalf("expected SENSITIVE_FIELD, got %+v", ctx.CopyMatches())
	}
	if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 10 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["data_type"] != "phone" || m.Evidence["location"] != "json" || m.Evidence["field"] != "user.phone" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	if ctx.MatchCount() != 1 {
		t.Fatalf("benign fields must not match, got %+v", ctx.CopyMatches())
	}
}

func TestSensitive_QueryMatchIsBlockClass(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{Query: map[string]string{"id_card": "110101**********34", "page": "1"}}
	CheckSensitiveData(ctx, p, defaultPatterns(t))
	m := findMatch(ctx, "sensitive.in_query")
	if m == nil {
		t.Fatalf("expected SENSITIVE_IN_QUERY, got %+v", ctx.CopyMatches())
	}
	if m.Category != "BLOCK" || m.Severity != "HIGH" || m.ScoreDelta != 40 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["location"] != "query" || m.Evidence["data_type"] != "id_card" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	// 值不得出现在证据中
	for _, v := range m.Evidence {
		if strings.Contains(v, "110101") {
			t.Fatalf("sensitive value leaked into evidence: %+v", m.Evidence)
		}
	}
}

func TestSensitive_NoMatchOnBenignNames(t *testing.T) {
	// 负例：常见易误伤命名（hotel/company/panel 含 tel/pan 子串）不得命中
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		JSONFields: map[string]string{"hotel_name": "string", "company": "string", "panel_id": "number"},
		FormFields: map[string]string{"title": "string", "content": "string"},
	}
	CheckSensitiveData(ctx, p, defaultPatterns(t))
	if ctx.MatchCount() != 0 {
		t.Fatalf("benign fields must not match, got %+v", ctx.CopyMatches())
	}
}

func TestSensitive_FormAndXMLAndChinese(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		FormFields: map[string]string{"password": "string"},
		XMLFields:  map[string]string{"root.shouji": "string"},
	}
	CheckSensitiveData(ctx, p, defaultPatterns(t))
	var formHit, xmlHit bool
	for _, m := range ctx.CopyMatches() {
		if m.Evidence["location"] == "form" && m.Evidence["data_type"] == "credential" {
			formHit = true
		}
		if m.Evidence["location"] == "xml" && m.Evidence["data_type"] == "phone" {
			xmlHit = true
		}
	}
	if !formHit || !xmlHit {
		t.Fatalf("form/xml matches missing: %+v", ctx.CopyMatches())
	}
}

func TestSensitive_CustomPatternsOverride(t *testing.T) {
	patterns, err := CompileSensitivePatterns([]SensitivePattern{
		{DataType: "internal_id", Pattern: `(?i)^biz_secret_`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	// 自定义表覆盖默认：phone 不再命中，biz_secret_ 命中
	p := &parser.Parsed{JSONFields: map[string]string{"phone": "string", "biz_secret_no": "string"}}
	CheckSensitiveData(ctx, p, patterns)
	m := findMatch(ctx, "sensitive.field")
	if m == nil || m.Evidence["data_type"] != "internal_id" {
		t.Fatalf("custom pattern should match, got %+v", ctx.CopyMatches())
	}
	if ctx.MatchCount() != 1 {
		t.Fatalf("default patterns must be replaced, got %+v", ctx.CopyMatches())
	}
}

func TestSensitive_BadPatternReturnsError(t *testing.T) {
	if _, err := CompileSensitivePatterns([]SensitivePattern{{DataType: "x", Pattern: "([unclosed"}}); err == nil {
		t.Fatal("bad regex must return error (no silent swallow)")
	}
	if _, err := CompileSensitivePatterns([]SensitivePattern{{DataType: "", Pattern: "x"}}); err == nil {
		t.Fatal("empty data_type must return error")
	}
}

func TestSensitive_NilParsedNoPanic(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckSensitiveData(ctx, nil, defaultPatterns(t))
	if ctx.MatchCount() != 0 {
		t.Fatal("nil parsed must produce no match")
	}
}
