package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestFileSensitiveContentNestedJSON(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "contacts.json", Extension: "json", MIME: "application/json"}
	ctx := dsctx.New("json", dsctx.DefaultParseLimits())
	body := []byte(`{"contacts":[{"phone":"13800138000","email":"alex@example.test"}]}`)
	CheckFileSensitiveContent(ctx, obs, body, true, false, fileSensitiveTestRules(t))
	if got := strings.Join(obs.SensitiveTypes, ","); got != "email,phone" {
		t.Fatalf("JSON sensitive types=%q", got)
	}
	matches := ctx.CopyMatches()
	if len(matches) != 2 {
		t.Fatalf("want two structured JSON matches: %+v", matches)
	}
	fields := map[string]bool{}
	for _, match := range matches {
		if match.RuleID != "file.sensitive_content" || match.Evidence["scope"] != "JSON_DOCUMENT" {
			t.Fatalf("unexpected structured match: %+v", match)
		}
		fields[match.Evidence["field"]] = true
		for _, value := range match.Evidence {
			if strings.Contains(value, "13800138000") || strings.Contains(value, "alex@example.test") {
				t.Fatalf("JSON value leaked: %+v", match.Evidence)
			}
		}
	}
	if !fields["contacts[].phone"] || !fields["contacts[].email"] {
		t.Fatalf("JSON paths missing: %+v", fields)
	}
}

func TestFileSensitiveContentJSONLCompleteLines(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "UPLOAD", FileName: "contacts.jsonl", Extension: "jsonl", MIME: "application/x-ndjson"}
	ctx := dsctx.New("jsonl", dsctx.DefaultParseLimits())
	body := []byte("{\"phone\":\"13800138000\"}\n{\"email\":\"alex@example.test\"}\n{\"phone\":\"13900139000\"")
	CheckFileSensitiveContent(ctx, obs, body, false, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 2 {
		t.Fatalf("only complete JSONL records may contribute: %+v", matches)
	}
	for _, match := range matches {
		if match.Evidence["scope"] != "COMPLETE_LINES" || match.Evidence["sample_truncated"] != "true" {
			t.Fatalf("JSONL coverage must be explicit: %+v", match)
		}
		for _, value := range match.Evidence {
			if strings.Contains(value, "13800138000") || strings.Contains(value, "alex@example.test") {
				t.Fatalf("JSONL value leaked: %+v", match.Evidence)
			}
		}
	}
}

func TestFileSensitiveContentInvalidAndDuplicateJSON(t *testing.T) {
	for name, body := range map[string][]byte{
		"truncated":  []byte(`{"phone":"13800138000"`),
		"invalid":    []byte(`{"phone":bad}`),
		"duplicated": []byte(`{"phone":"13900139000","phone":"13800138000"}`),
	} {
		t.Run(name, func(t *testing.T) {
			obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "contacts.json", Extension: "json", MIME: "application/json"}
			ctx := dsctx.New(name, dsctx.DefaultParseLimits())
			complete := name != "truncated"
			CheckFileSensitiveContent(ctx, obs, body, complete, false, fileSensitiveTestRules(t))
			matches := ctx.CopyMatches()
			if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" {
				t.Fatalf("unsafe JSON must not be treated as inspected: %+v", matches)
			}
		})
	}
}

func TestFileSensitiveContentNormalJSON(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "status.json", Extension: "json", MIME: "application/json"}
	ctx := dsctx.New("normal-json", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, []byte(`{"active":true,"count":3}`), true, false, fileSensitiveTestRules(t))
	if ctx.MatchCount() != 0 || len(obs.SensitiveTypes) != 0 {
		t.Fatalf("normal JSON must not alert: %+v types=%v", ctx.CopyMatches(), obs.SensitiveTypes)
	}
}

func TestUploadFileSensitiveJSONPropagatesLabels(t *testing.T) {
	parts := uploadContentParts(t, "contacts.json", []byte(`{"contacts":[{"phone":"13800138000"}]}`), dsctx.DefaultParseLimits())
	ctx := dsctx.New("upload-json", dsctx.DefaultParseLimits())
	CheckUploadFileSensitiveContent(ctx, parts, false, fileSensitiveTestRules(t))
	observations := parser.BuildUploadFileObservations(parts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("JSON upload labels missing: %+v", observations)
	}
	for _, match := range ctx.CopyMatches() {
		if match.Evidence["field"] != "contacts[].phone" {
			t.Fatalf("JSON upload path missing: %+v", match)
		}
		for _, value := range match.Evidence {
			if strings.Contains(value, "13800138000") {
				t.Fatalf("JSON upload value leaked: %+v", match.Evidence)
			}
		}
	}
}

func TestFileSensitiveContentInvalidJSONL(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "bad.jsonl", Extension: "jsonl", MIME: "application/x-ndjson"}
	ctx := dsctx.New("invalid-jsonl", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, []byte("{\"phone\":bad}\n"), true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != "INVALID_JSONL" {
		t.Fatalf("invalid JSONL must disclose its coverage: %+v", matches)
	}
}
