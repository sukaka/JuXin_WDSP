package parser

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func buildMultipartBody(t *testing.T, files bool, fields int) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for i := 0; i < fields; i++ {
		name := "field" + string(rune('a'+i))
		if err := w.WriteField(name, "value-value-value"); err != nil {
			t.Fatal(err)
		}
	}
	if files {
		fw, err := w.CreateFormFile("upload", "a.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte("file-content-123")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return w.FormDataContentType(), buf.Bytes()
}

func TestParseRequestMultipartMeta(t *testing.T) {
	ct, body := buildMultipartBody(t, true, 1)
	r, err := http.NewRequest(http.MethodPost, "http://x/upload", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", ct)
	ctx := dsctx.New("", dsctx.DefaultParseLimits())
	p, err := ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.MultipartParts) != 2 {
		t.Fatalf("parts=%+v", p.MultipartParts)
	}
	f, file := p.MultipartParts[0], p.MultipartParts[1]
	if f.FieldName != "fielda" || f.FileName != "" || f.Size != int64(len("value-value-value")) {
		t.Fatalf("field part=%+v", f)
	}
	if file.FieldName != "upload" || file.FileName != "a.txt" ||
		file.ContentType != "application/octet-stream" || file.Size != 16 {
		t.Fatalf("file part=%+v", file)
	}
	if prefix, complete := file.ContentPrefix(); !complete || string(prefix) != "file-content-123" {
		t.Fatalf("small file prefix must be complete: len=%d complete=%v", len(prefix), complete)
	}
	if !p.HasFiles || p.MultipartCapped || p.BodyTruncated {
		t.Fatalf("flags: %+v", p)
	}
	// 流式累计的 BodySize/BodyHash 与整体一致
	if p.BodySize != len(body) || p.BodyHash != shortHash(body) {
		t.Fatalf("size=%d hash=%s want %d/%s", p.BodySize, p.BodyHash, len(body), shortHash(body))
	}
	if parts, ok := ctx.Extensions[ExtMultipartParts].([]PartMeta); !ok || len(parts) != 2 {
		t.Fatalf("ctx extension missing: %v", ctx.Extensions)
	}
	if ctx.Extensions[ExtHasFiles] != true {
		t.Fatalf("has_files flag missing: %v", ctx.Extensions)
	}
}

func TestParseRequestMultipartFileMetaCap(t *testing.T) {
	limits := dsctx.DefaultParseLimits()
	limits.MaxFileMetaCount = 1
	ct, body := buildMultipartBody(t, true, 2) // 3 parts 总量
	r, err := http.NewRequest(http.MethodPost, "http://x/upload", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", ct)
	ctx := dsctx.New("", limits)
	p, err := ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !p.MultipartCapped {
		t.Fatalf("expected part cap: %+v", p.MultipartParts)
	}
	if len(p.MultipartParts) != 1 {
		t.Fatalf("cap not enforced: %+v", p.MultipartParts)
	}
	if ctx.Extensions[ExtMultipartCapped] != true {
		t.Fatalf("ctx flag missing: %v", ctx.Extensions)
	}
}

func TestParseRequestMultipartBodyTruncated(t *testing.T) {
	limits := dsctx.DefaultParseLimits()
	limits.MaxBodyParseBytes = 50
	ct, body := buildMultipartBody(t, true, 2)
	if len(body) <= 50 {
		t.Fatal("fixture body too small")
	}
	r, err := http.NewRequest(http.MethodPost, "http://x/upload", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", ct)
	ctx := dsctx.New("", limits)
	p, err := ParseRequest(r, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !p.BodyTruncated || !ctx.BodyTruncated {
		t.Fatalf("expected body truncation: %+v", p)
	}
}
