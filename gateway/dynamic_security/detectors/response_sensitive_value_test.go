package detectors

import (
	"fmt"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

func responsePhoneValueRules(t *testing.T) []CompiledSensitiveValueRule {
	t.Helper()
	rules, err := CompileResponseSensitiveValueRules([]SensitiveValueRule{{
		DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"response_body"}, Level: "SENSITIVE",
	}})
	if err != nil {
		t.Fatalf("compile response value rules: %v", err)
	}
	return rules
}

func parseResponseValueRoot(t *testing.T, body string) any {
	t.Helper()
	_, root, ok := response.ParseJSON([]byte(body), dsctx.DefaultParseLimits())
	if !ok {
		t.Fatalf("parse response JSON: %s", body)
	}
	return root
}

func newResponseValueContext(id string) *dsctx.RequestContext {
	ctx := dsctx.New(id, dsctx.DefaultParseLimits())
	ctx.Response = &dsctx.ResponseContext{IsJSON: true}
	return ctx
}

func assertResponseValueMatch(t *testing.T, m dsctx.DetectorMatch, path, dataType string) {
	t.Helper()
	if m.RuleID != "sensitive.response_value" || m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
		t.Fatalf("unexpected response value match attributes: %+v", m)
	}
	if m.ScoreDelta != 15 || m.Confidence != 1.0 {
		t.Fatalf("unexpected response value scoring: %+v", m)
	}
	want := map[string]string{
		"field": path, "data_type": dataType, "level": "SENSITIVE",
		"location": "response_body", "direction": "RESPONSE",
	}
	if len(m.Evidence) != len(want) {
		t.Fatalf("evidence keys must be restricted to the response value contract: %+v", m.Evidence)
	}
	for key, value := range want {
		if m.Evidence[key] != value {
			t.Fatalf("evidence[%s] = %q, want %q (all: %+v)", key, m.Evidence[key], value, m.Evidence)
		}
	}
}

func assertNoResponseValuePlaintext(t *testing.T, ctx *dsctx.RequestContext, values ...string) {
	t.Helper()
	recorded := fmt.Sprintf("%+v", ctx.CopyMatches()) + fmt.Sprintf("%+v", ctx.Response)
	for _, value := range values {
		if strings.Contains(recorded, value) {
			t.Fatalf("response plaintext %q leaked into matches or response context: %s", value, recorded)
		}
	}
}

func TestResponseSensitiveValueNestedArraysAndFieldPermissionDedup(t *testing.T) {
	root := parseResponseValueRoot(t, `{"profile":{"contacts":[{"display":"13800138000"},{"display":"ordinary text"},{"display":"13912345678"}]}}`)
	ctx := newResponseValueContext("response-nested-array")
	CheckResponseSensitiveValues(ctx, root, responsePhoneValueRules(t), dsctx.DefaultParseLimits())

	matches := ctx.CopyMatches()
	if len(matches) != 2 {
		t.Fatalf("every array element must be scanned, got %+v", matches)
	}
	for _, m := range matches {
		assertResponseValueMatch(t, m, "profile.contacts[].display", "phone")
	}
	wantFields := []dsctx.SensitiveFieldHit{
		{Path: "profile.contacts[].display", DataType: "phone"},
		{Path: "profile.contacts[].display", DataType: "phone"},
	}
	if fmt.Sprintf("%+v", ctx.Response.SensitiveFields) != fmt.Sprintf("%+v", wantFields) {
		t.Fatalf("sensitive fields = %+v, want %+v", ctx.Response.SensitiveFields, wantFields)
	}
	assertNoResponseValuePlaintext(t, ctx, "13800138000", "13912345678")

	perms := []FieldPermission{{
		EndpointKey: "GET /v1/profile", FieldPath: "json.profile.contacts[].display",
		Direction: "RESPONSE", Attribute: "SENSITIVE",
	}}
	fields := map[string]string{"profile.contacts[].display": "string"}
	CheckResponseFieldPermissions(ctx, nil, "GET /v1/profile", perms, fields, nil, ctx.Response.SensitiveFields)
	if ctx.MatchCount() != 2 {
		t.Fatalf("value-level sensitive field must dedup response field permission: %+v", ctx.CopyMatches())
	}
}

func TestResponseSensitiveValueJSONNumberPreservesLiteral(t *testing.T) {
	const literal = "123456789012345678901234567890"
	rules, err := CompileResponseSensitiveValueRules([]SensitiveValueRule{{
		DataType: "external_identifier", Regex: `^` + literal + `$`,
		Locations: []string{"response_body"}, Level: "SENSITIVE",
	}})
	if err != nil {
		t.Fatalf("compile numeric rule: %v", err)
	}
	root := parseResponseValueRoot(t, `{"external_ref":`+literal+`}`)
	ctx := newResponseValueContext("response-number-literal")
	CheckResponseSensitiveValues(ctx, root, rules, dsctx.DefaultParseLimits())
	matches := ctx.CopyMatches()
	if len(matches) != 1 {
		t.Fatalf("json.Number literal must be matched without float64 conversion: %+v", matches)
	}
	assertResponseValueMatch(t, matches[0], "external_ref", "external_identifier")
	assertNoResponseValuePlaintext(t, ctx, literal)
}

func TestResponseSensitiveValueDeterministicMapOrder(t *testing.T) {
	want := []string{"a-contact", "m-contact", "z-contact"}
	for i := 0; i < 8; i++ {
		root := parseResponseValueRoot(t, `{"z-contact":"13611112222","a-contact":"13800138000","m-contact":"13912345678"}`)
		ctx := newResponseValueContext("response-order")
		CheckResponseSensitiveValues(ctx, root, responsePhoneValueRules(t), dsctx.DefaultParseLimits())
		matches := ctx.CopyMatches()
		if len(matches) != len(want) {
			t.Fatalf("run %d: got %+v", i, matches)
		}
		for j, m := range matches {
			if m.Evidence["field"] != want[j] {
				t.Fatalf("run %d: field[%d] = %q, want %q (all: %+v)", i, j, m.Evidence["field"], want[j], matches)
			}
		}
	}
}

func TestResponseSensitiveValueLocationAndCacheIsolation(t *testing.T) {
	in := []SensitiveValueRule{{
		DataType: "phone", Regex: `^1[3-9]\d{9}$`,
		Locations: []string{"json", "response_body"}, Level: "SENSITIVE",
	}}
	requestRules, err := CompileSensitiveValueRules(in)
	if err != nil {
		t.Fatalf("compile request rules: %v", err)
	}
	responseRules, err := CompileResponseSensitiveValueRules(in)
	if err != nil {
		t.Fatalf("compile response rules: %v", err)
	}
	if len(requestRules) != 1 || len(requestRules[0].locations) != 1 || !requestRules[0].locations["json"] {
		t.Fatalf("request cache product has wrong locations: %+v", requestRules)
	}
	if len(responseRules) != 1 || len(responseRules[0].locations) != 1 || !responseRules[0].locations["response_body"] {
		t.Fatalf("response cache product has wrong locations: %+v", responseRules)
	}

	root := parseResponseValueRoot(t, `{"display":"13800138000"}`)
	ctx := newResponseValueContext("response-request-rules")
	CheckResponseSensitiveValues(ctx, root, requestRules, dsctx.DefaultParseLimits())
	if ctx.MatchCount() != 0 {
		t.Fatalf("request-location rules must not inspect responses: %+v", ctx.CopyMatches())
	}
	requestCtx := dsctx.New("request-response-rules", dsctx.DefaultParseLimits())
	CheckSensitiveData(requestCtx, &parser.Parsed{JSONValues: map[string]string{"display": "13800138000"}}, nil, responseRules)
	if requestCtx.MatchCount() != 0 {
		t.Fatalf("response-location rules must not inspect requests: %+v", requestCtx.CopyMatches())
	}

	onlyRequest, err := CompileResponseSensitiveValueRules([]SensitiveValueRule{{
		DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"json"},
	}})
	if err != nil {
		t.Fatalf("compile request-only location: %v", err)
	}
	if len(onlyRequest) != 0 {
		t.Fatalf("response compiler must skip rules without response_body: %+v", onlyRequest)
	}
}

func TestResponseSensitiveValueNoRulesAndNilInputs(t *testing.T) {
	root := parseResponseValueRoot(t, `{"display":"13800138000"}`)
	rules := responsePhoneValueRules(t)
	ctx := newResponseValueContext("response-empty-input")
	CheckResponseSensitiveValues(ctx, root, nil, dsctx.DefaultParseLimits())
	CheckResponseSensitiveValues(ctx, nil, rules, dsctx.DefaultParseLimits())
	CheckResponseSensitiveValues(nil, root, rules, dsctx.DefaultParseLimits())
	if ctx.MatchCount() != 0 || len(ctx.Response.SensitiveFields) != 0 {
		t.Fatalf("empty rules/root must produce no findings: %+v", ctx.CopyMatches())
	}
	compiled, err := CompileResponseSensitiveValueRules(nil)
	if err != nil || len(compiled) != 0 {
		t.Fatalf("nil rules must compile to an empty result: %+v, %v", compiled, err)
	}

	withoutResponse := dsctx.New("response-context-absent", dsctx.DefaultParseLimits())
	CheckResponseSensitiveValues(withoutResponse, root, rules, dsctx.DefaultParseLimits())
	if withoutResponse.MatchCount() != 1 {
		t.Fatalf("missing ResponseContext must not suppress the finding: %+v", withoutResponse.CopyMatches())
	}
}

func TestCompileResponseSensitiveValueRulesRejectsInvalidRules(t *testing.T) {
	tests := []struct {
		name  string
		rules []SensitiveValueRule
	}{
		{name: "empty data type", rules: []SensitiveValueRule{{Regex: "x", Locations: []string{"response_body"}}}},
		{name: "empty regex", rules: []SensitiveValueRule{{DataType: "x", Locations: []string{"response_body"}}}},
		{name: "bad regex", rules: []SensitiveValueRule{{DataType: "x", Regex: "([bad", Locations: []string{"response_body"}}}},
		{name: "oversized regex", rules: []SensitiveValueRule{{DataType: "x", Regex: strings.Repeat("a", maxSensitiveValueRegexLen+1), Locations: []string{"response_body"}}}},
	}
	tooMany := make([]SensitiveValueRule, maxSensitiveValueRules+1)
	for i := range tooMany {
		tooMany[i] = SensitiveValueRule{DataType: "x", Regex: "x", Locations: []string{"response_body"}}
	}
	tests = append(tests, struct {
		name  string
		rules []SensitiveValueRule
	}{name: "too many rules", rules: tooMany})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := CompileResponseSensitiveValueRules(tt.rules); err == nil {
				t.Fatal("invalid response value rules must return an error")
			}
		})
	}
}

func TestResponseSensitiveValueInputLengthBudget(t *testing.T) {
	rules, err := CompileResponseSensitiveValueRules([]SensitiveValueRule{{
		DataType: "phone", Regex: `1[3-9]\d{9}`, Locations: []string{"response_body"}, Level: "SENSITIVE",
	}})
	if err != nil {
		t.Fatalf("compile response rules: %v", err)
	}
	ctx := newResponseValueContext("response-input-beyond-cap")
	beyond := strings.Repeat("界", maxSensitiveValueInputLen) + "13800138000"
	CheckResponseSensitiveValues(ctx, map[string]any{"note": beyond}, rules, dsctx.DefaultParseLimits())
	if ctx.MatchCount() != 0 {
		t.Fatalf("value beyond the 4096-rune cap must not be inspected: %+v", ctx.CopyMatches())
	}

	ctx = newResponseValueContext("response-input-within-cap")
	within := strings.Repeat("界", maxSensitiveValueInputLen-len("13800138000")) + "13800138000"
	CheckResponseSensitiveValues(ctx, map[string]any{"note": within}, rules, dsctx.DefaultParseLimits())
	if ctx.MatchCount() != 1 {
		t.Fatalf("value ending at the 4096-rune boundary must be inspected: %+v", ctx.CopyMatches())
	}
}

func TestResponseSensitiveValueDepthAndFieldLimits(t *testing.T) {
	rules := responsePhoneValueRules(t)
	limits := dsctx.DefaultParseLimits()
	limits.MaxJSONDepth = 1
	root := map[string]any{
		"nested":  map[string]any{"display": "13912345678"},
		"surface": "13800138000",
	}
	ctx := newResponseValueContext("response-depth-limit")
	CheckResponseSensitiveValues(ctx, root, rules, limits)
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["field"] != "surface" {
		t.Fatalf("values deeper than MaxJSONDepth must be skipped: %+v", matches)
	}

	limits = dsctx.DefaultParseLimits()
	limits.MaxFieldCount = 1
	root = map[string]any{"a-note": "ordinary text", "z-note": "13800138000"}
	ctx = newResponseValueContext("response-field-limit")
	CheckResponseSensitiveValues(ctx, root, rules, limits)
	if ctx.MatchCount() != 0 {
		t.Fatalf("values beyond MaxFieldCount must be skipped: %+v", ctx.CopyMatches())
	}
}

func TestResponseSensitiveValueScanBudget(t *testing.T) {
	rules := responsePhoneValueRules(t)
	root := make(map[string]any, maxSensitiveValueScans+1)
	for i := 0; i < maxSensitiveValueScans; i++ {
		root[fmt.Sprintf("f%04d", i)] = "ordinary text"
	}
	root["zzzz"] = "13800138000"
	ctx := newResponseValueContext("response-scan-cap")
	CheckResponseSensitiveValues(ctx, root, rules, dsctx.DefaultParseLimits())
	if ctx.MatchCount() != 0 {
		t.Fatalf("value after the scan budget must not be evaluated: %+v", ctx.CopyMatches())
	}

	root[fmt.Sprintf("f%04d", maxSensitiveValueScans-1)] = "13912345678"
	ctx = newResponseValueContext("response-scan-last-allowed")
	CheckResponseSensitiveValues(ctx, root, rules, dsctx.DefaultParseLimits())
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["field"] != fmt.Sprintf("f%04d", maxSensitiveValueScans-1) {
		t.Fatalf("last evaluation inside the scan budget must remain effective: %+v", matches)
	}
}

func TestResponseSensitiveValueMatchBudget(t *testing.T) {
	root := make(map[string]any, maxSensitiveMatches+5)
	for i := 0; i < maxSensitiveMatches+5; i++ {
		root[fmt.Sprintf("contact-%02d", i)] = "13800138000"
	}
	ctx := newResponseValueContext("response-match-cap")
	CheckResponseSensitiveValues(ctx, root, responsePhoneValueRules(t), dsctx.DefaultParseLimits())
	if ctx.MatchCount() != maxSensitiveMatches || len(ctx.Response.SensitiveFields) != maxSensitiveMatches {
		t.Fatalf("matches and sensitive fields must both stop at %d: matches=%d fields=%d",
			maxSensitiveMatches, ctx.MatchCount(), len(ctx.Response.SensitiveFields))
	}
}
