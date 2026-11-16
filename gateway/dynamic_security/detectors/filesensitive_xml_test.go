package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestFileSensitiveContentXML(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "contacts.xml", Extension: "xml", MIME: "application/xml"}
	ctx := dsctx.New("xml", dsctx.DefaultParseLimits())
	body := []byte(`<contacts><contact><phone>13800138000</phone><email>alex@example.test</email></contact></contacts>`)
	CheckFileSensitiveContent(ctx, obs, body, true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 2 || strings.Join(obs.SensitiveTypes, ",") != "email,phone" {
		t.Fatalf("unexpected XML matches=%+v types=%v", matches, obs.SensitiveTypes)
	}
	fields := map[string]bool{}
	for _, match := range matches {
		if match.Evidence["scope"] != "XML_DOCUMENT" {
			t.Fatalf("unexpected XML coverage: %+v", match)
		}
		fields[match.Evidence["field"]] = true
		for _, value := range match.Evidence {
			if strings.Contains(value, "13800138000") || strings.Contains(value, "alex@example.test") {
				t.Fatalf("XML value leaked: %+v", match.Evidence)
			}
		}
	}
	if !fields["contacts.contact.phone"] || !fields["contacts.contact.email"] {
		t.Fatalf("XML paths missing: %+v", fields)
	}
}

func TestFileSensitiveContentXMLAttribute(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "UPLOAD", FileName: "contact.xml", Extension: "xml", MIME: "application/xml"}
	ctx := dsctx.New("xml-attribute", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, []byte(`<contact phone="13800138000"/>`), true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["field"] != "contact.@phone" {
		t.Fatalf("XML attribute evidence missing: %+v", matches)
	}
}

func TestFileSensitiveContentXMLNormalAndTruncated(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "status.xml", Extension: "xml", MIME: "application/xml"}
	ctx := dsctx.New("normal-xml", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, []byte(`<status><active>true</active></status>`), true, false, fileSensitiveTestRules(t))
	if ctx.MatchCount() != 0 || len(obs.SensitiveTypes) != 0 {
		t.Fatalf("normal XML must not alert: %+v types=%v", ctx.CopyMatches(), obs.SensitiveTypes)
	}

	obs = &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "partial.xml", Extension: "xml", MIME: "application/xml"}
	ctx = dsctx.New("partial-xml", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, []byte(`<phone>13800138000`), false, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != "TRUNCATED_XML" {
		t.Fatalf("truncated XML must not be treated as a full document: %+v", matches)
	}
}

func TestFileSensitiveContentXMLRejectsDirective(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "contacts.xml", Extension: "xml", MIME: "application/xml"}
	ctx := dsctx.New("dtd-xml", dsctx.DefaultParseLimits())
	body := []byte(`<!DOCTYPE contacts [<!ENTITY phone "13800138000">]><contacts><phone>&phone;</phone></contacts>`)
	CheckFileSensitiveContent(ctx, obs, body, true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != "UNSUPPORTED_XML_DIRECTIVE" {
		t.Fatalf("DTD must be rejected before entity evaluation: %+v", matches)
	}
}

func TestFileSensitiveContentXMLRejectsInvalidAndDeepDocuments(t *testing.T) {
	for name, body := range map[string][]byte{
		"invalid": []byte(`<phone>13800138000`),
		"deep":    []byte(strings.Repeat("<a>", 33)),
	} {
		t.Run(name, func(t *testing.T) {
			obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "bad.xml", Extension: "xml", MIME: "application/xml"}
			ctx := dsctx.New(name, dsctx.DefaultParseLimits())
			CheckFileSensitiveContent(ctx, obs, body, true, false, fileSensitiveTestRules(t))
			matches := ctx.CopyMatches()
			if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" {
				t.Fatalf("invalid/deep XML must not be treated as fully inspected: %+v", matches)
			}
		})
	}
}

func TestUploadFileSensitiveXMLPropagatesLabels(t *testing.T) {
	parts := uploadContentParts(t, "contacts.xml", []byte(`<contacts><contact><phone>13800138000</phone></contact></contacts>`), dsctx.DefaultParseLimits())
	ctx := dsctx.New("upload-xml", dsctx.DefaultParseLimits())
	CheckUploadFileSensitiveContent(ctx, parts, false, fileSensitiveTestRules(t))
	observations := parser.BuildUploadFileObservations(parts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("XML upload labels missing: %+v", observations)
	}
	for _, match := range ctx.CopyMatches() {
		if match.Evidence["field"] != "contacts.contact.phone" {
			t.Fatalf("XML upload path missing: %+v", match)
		}
		for _, value := range match.Evidence {
			if strings.Contains(value, "13800138000") {
				t.Fatalf("XML upload value leaked: %+v", match.Evidence)
			}
		}
	}
}
