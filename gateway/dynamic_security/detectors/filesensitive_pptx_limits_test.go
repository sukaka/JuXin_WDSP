package detectors

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestPPTXRejectsAggregateTextBudget(t *testing.T) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for i := 0; i <= 3; i++ {
		name := "ppt/presentation.xml"
		body := `<p:presentation/>`
		if i > 0 {
			name = fmt.Sprintf("ppt/slides/slide%d.xml", i)
			body = ""
		}
		part, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, body); err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			if _, err := io.WriteString(part, `<p:sld><a:p><a:t>`); err != nil {
				t.Fatal(err)
			}
			if _, err := io.CopyN(part, strings.NewReader(strings.Repeat(" ", 6<<20)), 6<<20); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(part, `</a:t></a:p></p:sld>`); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > 1<<20 {
		t.Fatalf("compressed budget fixture is unexpectedly large: %d", buf.Len())
	}
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "large.pptx", Extension: "pptx"}
	ctx := dsctx.New("pptx-aggregate-budget", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, buf.Bytes(), true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != "PPTX_CONTENT_TOO_LARGE" {
		t.Fatalf("aggregate PPTX text budget must be disclosed: %+v", matches)
	}
}
