package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func fileContentTestRules(t *testing.T) *FileComplianceRuleSet {
	t.Helper()
	return fileCompCompile(t, []FileComplianceRule{{Direction: "DOWNLOAD", Match: "MIME", Value: "application/octet-stream", Action: "OBSERVE"}})
}

func TestFileContentTypeValidation(t *testing.T) {
	rules := fileContentTestRules(t)
	tar := make([]byte, 512)
	copy(tar[257:262], []byte("ustar"))
	tests := []struct {
		name      string
		filename  string
		mime      string
		body      []byte
		wantRule  string
		wantType  string
		wantClass string
	}{
		{name: "valid pdf", filename: "guide.pdf", mime: "application/pdf", body: []byte("%PDF-1.7\n")},
		{name: "valid png", filename: "photo.png", mime: "image/png", body: []byte("\x89PNG\r\n\x1a\nrest")},
		{name: "valid ooxml archive", filename: "report.xlsx", mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", body: []byte("PK\x03\x04rest")},
		{name: "valid tar", filename: "bundle.tar", mime: "application/x-tar", body: tar},
		{name: "valid bzip2", filename: "bundle.bz2", mime: "application/x-bzip2", body: []byte("BZh91AYrest")},
		{name: "valid ico", filename: "favicon.ico", mime: "image/x-icon", body: []byte("\x00\x00\x01\x00\x01\x00")},
		{name: "plain text", filename: "notes.txt", mime: "text/plain", body: []byte("ordinary text")},
		{name: "plain script", filename: "worker.js", mime: "text/javascript", body: []byte("console.log('ok')")},
		{name: "executable disguised as image", filename: "avatar.jpg", mime: "image/jpeg", body: []byte("MZ\x90\x00\x03payload"), wantRule: "file.content_type_mismatch", wantType: "windows_executable", wantClass: "image"},
		{name: "elf disguised as document", filename: "manual.pdf", mime: "application/pdf", body: []byte("\x7fELF\x02\x01\x01payload"), wantRule: "file.content_type_mismatch", wantType: "elf_executable", wantClass: "document"},
		{name: "script disguised as image", filename: "photo.png", mime: "image/png", body: []byte("  <?php echo 'x';"), wantRule: "file.content_type_mismatch", wantType: "php_script", wantClass: "image"},
		{name: "archive disguised as image", filename: "photo.png", mime: "image/png", body: []byte("PK\x03\x04rest"), wantRule: "file.content_type_mismatch", wantType: "zip_or_ooxml", wantClass: "image"},
		{name: "unknown signature is not mismatch", filename: "avatar.jpg", mime: "image/jpeg", body: []byte("not an image"), wantRule: "file.content_unrecognized", wantType: "unrecognized", wantClass: "image"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := dsctx.New("file-content", dsctx.DefaultParseLimits())
			obs := fileCompTestObs("DOWNLOAD", tt.filename, tt.mime)
			CheckFileContentType(ctx, obs, tt.body, false, false, rules)
			matches := ctx.CopyMatches()
			if tt.wantRule == "" {
				if len(matches) != 0 {
					t.Fatalf("valid file must not alert: %+v", matches)
				}
				return
			}
			if len(matches) != 1 || matches[0].RuleID != tt.wantRule {
				t.Fatalf("unexpected matches: %+v", matches)
			}
			match := matches[0]
			if match.Category != "OBSERVE" || match.Evidence["detected_type"] != tt.wantType || match.Evidence["declared_class"] != tt.wantClass {
				t.Fatalf("unexpected evidence: %+v", match)
			}
			for _, value := range match.Evidence {
				if strings.Contains(value, "payload") || strings.Contains(value, "echo") {
					t.Fatalf("file content leaked into evidence: %+v", match.Evidence)
				}
			}
		})
	}
}

func TestFileContentInspectionLimits(t *testing.T) {
	rules := fileContentTestRules(t)
	obs := fileCompTestObs("DOWNLOAD", "avatar.jpg", "image/jpeg")
	ctx := dsctx.New("streamed", dsctx.DefaultParseLimits())
	CheckFileContentType(ctx, obs, nil, false, true, rules)
	if matches := ctx.CopyMatches(); len(matches) != 1 || matches[0].RuleID != "file.content_not_inspected" || matches[0].Evidence["reason"] != "STREAMED" || matches[0].Severity != "INFO" {
		t.Fatalf("streamed file must disclose missing inspection: %+v", matches)
	}

	ctx = dsctx.New("truncated-unknown", dsctx.DefaultParseLimits())
	CheckFileContentType(ctx, obs, []byte("tiny"), true, false, rules)
	if matches := ctx.CopyMatches(); len(matches) != 1 || matches[0].RuleID != "file.content_not_inspected" || matches[0].Evidence["reason"] != "TRUNCATED_UNKNOWN_SIGNATURE" {
		t.Fatalf("truncated unknown body must not be called mismatch: %+v", matches)
	}

	ctx = dsctx.New("truncated-known", dsctx.DefaultParseLimits())
	CheckFileContentType(ctx, obs, []byte("MZ\x90\x00\x03payload"), true, false, rules)
	if matches := ctx.CopyMatches(); len(matches) != 1 || matches[0].RuleID != "file.content_type_mismatch" || matches[0].Evidence["inspection"] != "PREFIX_ONLY" {
		t.Fatalf("known prefix should be identified with limited scope: %+v", matches)
	}
}

func TestFileContentTypeZeroBehavior(t *testing.T) {
	ctx := dsctx.New("zero", dsctx.DefaultParseLimits())
	CheckFileContentType(ctx, fileCompTestObs("DOWNLOAD", "avatar.jpg", "image/jpeg"), []byte("MZ\x90\x00"), false, false, nil)
	CheckFileContentType(ctx, fileCompTestObs("UPLOAD", "avatar.jpg", "image/jpeg"), []byte("MZ\x90\x00"), false, false, fileContentTestRules(t))
	CheckFileContentType(nil, fileCompTestObs("DOWNLOAD", "avatar.jpg", "image/jpeg"), []byte("MZ\x90\x00"), false, false, fileContentTestRules(t))
	if ctx.MatchCount() != 0 {
		t.Fatalf("missing policy or upload direction must not produce findings: %+v", ctx.CopyMatches())
	}
}
