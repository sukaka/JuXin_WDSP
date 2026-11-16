package pipeline

import (
	"encoding/json"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestProcessUploadFileContentType(t *testing.T) {
	rules := fileCompRules(t, []detectors.FileComplianceRule{{Direction: "UPLOAD", Match: "MIME", Value: "image/", Action: "OBSERVE"}})
	res, err := Process(fileCompUploadReq(t, "avatar.png", "MZ-FAKE-UPLOAD-CONTENT"), Config{
		Enabled: true, Mode: "PROTECT", FileComplianceRules: rules,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalAction == dsctx.ActionBlock {
		t.Fatalf("content signature observation must not block: %+v", res.Context.CopyMatches())
	}
	found := false
	for _, match := range res.Context.CopyMatches() {
		if match.RuleID == "file.content_type_mismatch" {
			found = true
			if match.Evidence["direction"] != "UPLOAD" || match.Evidence["detected_type"] != "windows_executable" {
				t.Fatalf("unexpected upload evidence: %+v", match)
			}
			for _, value := range match.Evidence {
				if strings.Contains(value, "FAKE-UPLOAD-CONTENT") {
					t.Fatalf("upload body leaked: %+v", match.Evidence)
				}
			}
		}
	}
	if !found {
		t.Fatalf("upload signature mismatch missing: %+v", res.Context.CopyMatches())
	}
	parts, ok := res.Context.Extensions[parser.ExtMultipartParts].([]parser.PartMeta)
	if !ok || len(parts) != 1 {
		t.Fatalf("multipart metadata missing: %+v", res.Context.Extensions)
	}
	if prefix, complete := parts[0].ContentPrefix(); !complete || len(prefix) == 0 {
		t.Fatalf("small upload should have a complete prefix: len=%d complete=%v", len(prefix), complete)
	}
	encoded, err := json.Marshal(parts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "FAKE-UPLOAD-CONTENT") {
		t.Fatal("raw upload prefix must not be serialized")
	}
}

func TestProcessUploadFileContentValid(t *testing.T) {
	rules := fileCompRules(t, []detectors.FileComplianceRule{{Direction: "UPLOAD", Match: "MIME", Value: "image/", Action: "OBSERVE"}})
	res, err := Process(fileCompUploadReq(t, "photo.png", "\x89PNG\r\n\x1a\nrest"), Config{
		Enabled: true, Mode: "PROTECT", FileComplianceRules: rules,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range res.Context.CopyMatches() {
		if match.RuleID == "file.content_type_mismatch" || match.RuleID == "file.content_unrecognized" {
			t.Fatalf("valid upload must not alert: %+v", match)
		}
	}
}
