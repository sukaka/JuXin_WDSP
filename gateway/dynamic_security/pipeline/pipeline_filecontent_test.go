package pipeline

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func TestProcessResponseFileContentType(t *testing.T) {
	rules := fileCompRules(t, []detectors.FileComplianceRule{{Direction: "DOWNLOAD", Match: "MIME", Value: "image/", Action: "OBSERVE"}})
	ctx := dsctx.New("download-mismatch", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "image/jpeg", ContentDisposition: `attachment; filename="avatar.jpg"`,
		Body: []byte("MZ\x90\x00\x03file-payload"), BodySize: 16,
	}, ResponseConfig{Mode: "PROTECT", FileComplianceRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	if act == dsctx.ActionBlock {
		t.Fatalf("content-type observation must not block: %+v", ctx.CopyMatches())
	}
	found := false
	for _, match := range ctx.CopyMatches() {
		if match.RuleID != "file.content_type_mismatch" {
			continue
		}
		found = true
		if match.Category != "OBSERVE" || match.Evidence["detected_type"] != "windows_executable" || match.Evidence["declared_class"] != "image" {
			t.Fatalf("unexpected mismatch: %+v", match)
		}
		for _, value := range match.Evidence {
			if strings.Contains(value, "file-payload") {
				t.Fatalf("file content leaked: %+v", match.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("mismatch not detected: %+v", ctx.CopyMatches())
	}
}

func TestProcessResponseFileContentValidAndUnavailable(t *testing.T) {
	rules := fileCompRules(t, []detectors.FileComplianceRule{{Direction: "DOWNLOAD", Match: "MIME", Value: "image/", Action: "OBSERVE"}})
	ctx := dsctx.New("download-valid", dsctx.DefaultParseLimits())
	_, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "image/png", ContentDisposition: `attachment; filename="photo.png"`,
		Body: []byte("\x89PNG\r\n\x1a\nrest"), BodySize: 12,
	}, ResponseConfig{Mode: "PROTECT", FileComplianceRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range ctx.CopyMatches() {
		if match.RuleID == "file.content_type_mismatch" || match.RuleID == "file.content_unrecognized" {
			t.Fatalf("valid image must not alert: %+v", match)
		}
	}

	ctx = dsctx.New("download-stream", dsctx.DefaultParseLimits())
	_, err = ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "image/png", ContentDisposition: `attachment; filename="photo.png"`,
		Streamed: true, BodySize: 1024,
	}, ResponseConfig{Mode: "PROTECT", FileComplianceRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, match := range ctx.CopyMatches() {
		if match.RuleID == "file.content_not_inspected" && match.Evidence["reason"] == "STREAMED" {
			found = true
		}
		if match.RuleID == "file.content_type_mismatch" {
			t.Fatalf("unavailable content must not produce mismatch: %+v", match)
		}
	}
	if !found {
		t.Fatalf("missing inspection disclosure: %+v", ctx.CopyMatches())
	}
}
