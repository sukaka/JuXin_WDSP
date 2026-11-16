package parser

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestMultipartPrefixPartAndMemoryCaps(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	payload := bytes.Repeat([]byte("X"), 1024)
	for i := 0; i < 4; i++ {
		part, err := writer.CreateFormFile("file", "avatar.png")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://x/upload", &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	limits := dsctx.DefaultParseLimits()
	limits.MaxFileMetaCount = 3
	parsed, err := ParseRequest(req, dsctx.New("prefix-cap", limits))
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.MultipartCapped || len(parsed.MultipartParts) != 3 {
		t.Fatalf("part cap not enforced: %+v", parsed)
	}
	total := 0
	for _, part := range parsed.MultipartParts {
		prefix, complete := part.ContentPrefix()
		if complete || len(prefix) != maxFileContentPrefix {
			t.Fatalf("unexpected part prefix: len=%d complete=%v", len(prefix), complete)
		}
		total += len(prefix)
	}
	if total > limits.MaxFileMetaCount*maxFileContentPrefix {
		t.Fatalf("prefix memory cap exceeded: %d", total)
	}
}
