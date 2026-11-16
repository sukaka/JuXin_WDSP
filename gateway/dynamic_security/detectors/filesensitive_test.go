package detectors

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func fileSensitiveTestRules(t *testing.T) []CompiledSensitiveValueRule {
	t.Helper()
	rules, err := CompileSensitiveValueRules([]SensitiveValueRule{
		{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"file"}, Level: "SENSITIVE"},
		{DataType: "email", Regex: `^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`, Locations: []string{"file"}, Level: "IMPORTANT"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func TestFileSensitiveContentCSV(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "contacts.csv", Extension: "csv", MIME: "text/csv"}
	body := []byte("name,phone,email\nAlex,13800138000,alex@example.test\n")
	CheckFileSensitiveContent(dsctx.New("csv", dsctx.DefaultParseLimits()), obs, body, true, false, fileSensitiveTestRules(t))
	if got := strings.Join(obs.SensitiveTypes, ","); got != "email,phone" {
		t.Fatalf("sensitive types=%q", got)
	}
	ctx := dsctx.New("csv", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, body, true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 2 {
		t.Fatalf("want phone and email matches: %+v", matches)
	}
	for _, match := range matches {
		if match.RuleID != "file.sensitive_content" || match.Category != "OBSERVE" || match.Evidence["scope"] != "FULL_TEXT" {
			t.Fatalf("unexpected match: %+v", match)
		}
		for _, value := range match.Evidence {
			if strings.Contains(value, "13800138000") || strings.Contains(value, "alex@example.test") {
				t.Fatalf("sensitive value leaked: %+v", match.Evidence)
			}
		}
	}
}

func TestFileSensitiveContentCompleteLinesOnly(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "UPLOAD", FileName: "contacts.csv", Extension: "csv", MIME: "text/csv"}
	ctx := dsctx.New("partial", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, []byte("phone\n13800138000\n13900139000"), false, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content" || matches[0].Evidence["match_count"] != "1" || matches[0].Evidence["scope"] != "COMPLETE_LINES" {
		t.Fatalf("only the complete line may contribute: %+v", matches)
	}

	obs = &dsctx.FileObservation{Direction: "UPLOAD", FileName: "contacts.csv", Extension: "csv", MIME: "text/csv"}
	ctx = dsctx.New("partial-line", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, []byte("13900139000"), false, false, fileSensitiveTestRules(t))
	matches = ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != "TRUNCATED_TEXT_LINE" {
		t.Fatalf("partial line must disclose missing inspection: %+v", matches)
	}
}

func TestFileSensitiveContentNormalAndLocationBoundary(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "notes.csv", Extension: "csv", MIME: "text/csv"}
	ctx := dsctx.New("normal", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, []byte("name,note\nAlex,hello\n"), true, false, fileSensitiveTestRules(t))
	if ctx.MatchCount() != 0 || len(obs.SensitiveTypes) != 0 {
		t.Fatalf("normal CSV must not alert: %+v types=%v", ctx.CopyMatches(), obs.SensitiveTypes)
	}
	rules, err := CompileSensitiveValueRules([]SensitiveValueRule{{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"json"}}})
	if err != nil {
		t.Fatal(err)
	}
	CheckFileSensitiveContent(ctx, obs, []byte("phone\n13800138000\n"), true, false, rules)
	if ctx.MatchCount() != 0 {
		t.Fatalf("other protocol locations must not enable file scanning: %+v", ctx.CopyMatches())
	}
}

func TestFileSensitiveContentRejectsInvalidText(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "data.csv", Extension: "csv", MIME: "text/csv"}
	ctx := dsctx.New("encoding", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, []byte{0xff, 0xfe, 0x00}, true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != "UNSUPPORTED_TEXT_ENCODING" {
		t.Fatalf("invalid text must not be called sensitive content: %+v", matches)
	}
}

func TestUploadFileSensitiveContentPropagatesTypesWithoutValues(t *testing.T) {
	parts := uploadContentParts(t, "contacts.csv", []byte("name,phone\nAlex,13800138000\n"), dsctx.DefaultParseLimits())
	ctx := dsctx.New("upload-sensitive", dsctx.DefaultParseLimits())
	CheckUploadFileSensitiveContent(ctx, parts, false, fileSensitiveTestRules(t))
	if len(parts) != 1 || len(parts[0].SensitiveTypes) != 1 || parts[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("part sensitive types missing: %+v", parts)
	}
	observations := parser.BuildUploadFileObservations(parts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("file observation sensitive types missing: %+v", observations)
	}
	encoded, err := json.Marshal(parts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "13800138000") {
		t.Fatal("raw phone number must not enter event metadata")
	}
}

func TestUploadFileSensitiveContentSharedBudget(t *testing.T) {
	rules := make([]SensitiveValueRule, 0, 21)
	parts := make([]parser.PartMeta, 0, 21)
	for i := 0; i < 21; i++ {
		rules = append(rules, SensitiveValueRule{
			DataType: fmt.Sprintf("kind_%02d", i), Regex: fmt.Sprintf("^kind_%02d$", i), Locations: []string{"file"}, Level: "SENSITIVE",
		})
		parts = append(parts, uploadContentParts(t, fmt.Sprintf("part-%d.txt", i), []byte(fmt.Sprintf("kind_%02d", i)), dsctx.DefaultParseLimits())...)
	}
	compiled, err := CompileSensitiveValueRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	ctx := dsctx.New("budget", dsctx.DefaultParseLimits())
	CheckUploadFileSensitiveContent(ctx, parts, false, compiled)
	matches := ctx.CopyMatches()
	sensitive, skipped := 0, 0
	for _, match := range matches {
		switch match.RuleID {
		case "file.sensitive_content":
			sensitive++
		case "file.sensitive_content_not_inspected":
			skipped++
			if match.Evidence["reason"] != "SCAN_BUDGET_EXCEEDED" {
				t.Fatalf("unexpected budget disclosure: %+v", match)
			}
		}
	}
	if sensitive != maxSensitiveMatches || skipped != 1 || len(matches) != maxSensitiveMatches+1 {
		t.Fatalf("shared budget must cap findings and disclose once: sensitive=%d skipped=%d total=%d", sensitive, skipped, len(matches))
	}
}
