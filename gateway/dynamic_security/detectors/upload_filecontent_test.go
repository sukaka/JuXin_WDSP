package detectors

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func uploadContentParts(t *testing.T, filename string, content []byte, limits dsctx.ParseLimits) []parser.PartMeta {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://h/v1/files/upload", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	parsed, err := parser.ParseRequest(req, dsctx.New("upload-content", limits))
	if err != nil {
		t.Fatal(err)
	}
	return parsed.MultipartParts
}

func uploadContentRules(t *testing.T) *FileComplianceRuleSet {
	t.Helper()
	return fileCompCompile(t, []FileComplianceRule{{Direction: "UPLOAD", Match: "MIME", Value: "image/", Action: "OBSERVE"}})
}

func TestUploadFileContentTypes(t *testing.T) {
	rules := uploadContentRules(t)
	tests := []struct {
		name     string
		filename string
		body     []byte
		wantRule string
		wantType string
	}{
		{name: "valid png", filename: "photo.png", body: []byte("\x89PNG\r\n\x1a\nrest")},
		{name: "plain text", filename: "notes.txt", body: []byte("ordinary text")},
		{name: "matching executable", filename: "setup.exe", body: []byte("MZ\x90\x00\x03payload")},
		{name: "executable disguised as image", filename: "avatar.png", body: []byte("MZ\x90\x00\x03payload"), wantRule: "file.content_type_mismatch", wantType: "windows_executable"},
		{name: "script disguised as image", filename: "avatar.jpg", body: []byte("<?php echo 'x';"), wantRule: "file.content_type_mismatch", wantType: "php_script"},
		{name: "unknown upload is not mismatch", filename: "avatar.jpg", body: []byte("ordinary text"), wantRule: "file.content_unrecognized", wantType: "unrecognized"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := dsctx.New("upload", dsctx.DefaultParseLimits())
			parts := uploadContentParts(t, tt.filename, tt.body, dsctx.DefaultParseLimits())
			CheckUploadFileContentTypes(ctx, parts, false, rules)
			matches := ctx.CopyMatches()
			if tt.wantRule == "" {
				if len(matches) != 0 {
					t.Fatalf("valid upload must not alert: %+v", matches)
				}
				return
			}
			if len(matches) != 1 || matches[0].RuleID != tt.wantRule || matches[0].Evidence["detected_type"] != tt.wantType || matches[0].Evidence["direction"] != "UPLOAD" {
				t.Fatalf("unexpected upload finding: %+v", matches)
			}
			for _, value := range matches[0].Evidence {
				if strings.Contains(value, "payload") || strings.Contains(value, "echo") {
					t.Fatalf("upload content leaked: %+v", matches[0].Evidence)
				}
			}
		})
	}
}

func TestUploadFileContentTruncatedPrefix(t *testing.T) {
	limits := dsctx.DefaultParseLimits()
	limits.MaxBodyParseBytes = 4096 + 15
	ctx := dsctx.New("truncated-upload", dsctx.DefaultParseLimits())
	CheckUploadFileContentTypes(ctx, uploadContentParts(t, "avatar.png", []byte("MZ"+strings.Repeat("X", 8192)), limits), false, uploadContentRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "file.content_type_mismatch" || matches[0].Evidence["inspection"] != "PREFIX_ONLY" {
		t.Fatalf("truncated upload must be limited to prefix evidence: %+v", matches)
	}

	limits.MaxBodyParseBytes = 50
	ctx = dsctx.New("truncated-unknown-upload", dsctx.DefaultParseLimits())
	CheckUploadFileContentTypes(ctx, uploadContentParts(t, "avatar.jpg", []byte("not an image"), limits), false, uploadContentRules(t))
	matches = ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "file.content_not_inspected" || matches[0].Evidence["reason"] != "TRUNCATED_BODY_UNAVAILABLE" {
		t.Fatalf("unknown truncated upload must not be called mismatch: %+v", matches)
	}
}

func TestUploadFileContentCappedPartsAndNoRules(t *testing.T) {
	ctx := dsctx.New("capped-upload", dsctx.DefaultParseLimits())
	parts := uploadContentParts(t, "photo.png", []byte("\x89PNG\r\n\x1a\nrest"), dsctx.DefaultParseLimits())
	CheckUploadFileContentTypes(ctx, parts, true, uploadContentRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "file.content_not_inspected" || matches[0].Evidence["reason"] != "MULTIPART_PARTS_CAPPED" {
		t.Fatalf("part cap must disclose missing coverage: %+v", matches)
	}
	ctx = dsctx.New("no-upload-rules", dsctx.DefaultParseLimits())
	CheckUploadFileContentTypes(ctx, parts, true, nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("no upload policy must be zero behavior: %+v", ctx.CopyMatches())
	}
}
