package classifier

import (
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestClassifyNotOnlyAPIPrefix(t *testing.T) {
	// HTML page under /api-docs should not dominate alone if no other signals
	p := &parser.Parsed{Method: "GET", RawPath: "/docs", ContentType: "text/html"}
	r := Classify(p)
	if r.IsAPI {
		t.Fatalf("should not be API: %+v", r)
	}
	// JSON REST without /api/
	p2 := &parser.Parsed{
		Method: "POST", RawPath: "/v1/orders", ContentType: "application/json",
		IsJSON: true, JSONFields: map[string]string{"id": "number"},
		Headers: map[string]string{"accept": "application/json"},
	}
	r2 := Classify(p2)
	if !r2.IsAPI || r2.Confidence < 0.35 {
		t.Fatalf("expected API: %+v", r2)
	}
	// /api/ alone is weak but with GET may still be borderline
	p3 := &parser.Parsed{Method: "GET", RawPath: "/api/health"}
	r3 := Classify(p3)
	// may or may not pass threshold with only prefix; ensure prefix is not required for p2
	_ = r3
}
