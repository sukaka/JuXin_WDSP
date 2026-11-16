package parser

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func multipartPrefixRequest(t *testing.T, filename string, content []byte) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("upload", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return writer.FormDataContentType(), buf.Bytes()
}

func parseMultipartPrefix(t *testing.T, contentType string, body []byte, limits dsctx.ParseLimits) *Parsed {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://x/upload", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	parsed, err := ParseRequest(req, dsctx.New("prefix", limits))
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestMultipartPrefixBoundedAndExcludedFromEvents(t *testing.T) {
	payload := []byte(strings.Repeat("PRIVATE-FILE-MARKER", 400))
	contentType, body := multipartPrefixRequest(t, "avatar.png", payload)
	parsed := parseMultipartPrefix(t, contentType, body, dsctx.DefaultParseLimits())
	if len(parsed.MultipartParts) != 1 {
		t.Fatalf("parts=%d", len(parsed.MultipartParts))
	}
	part := parsed.MultipartParts[0]
	prefix, complete := part.ContentPrefix()
	if complete || len(prefix) != maxFileContentPrefix || part.Size != int64(len(payload)) {
		t.Fatalf("prefix must be bounded without changing part size: len=%d size=%d complete=%v", len(prefix), part.Size, complete)
	}
	if parsed.BodySize != len(body) || parsed.BodyHash != shortHash(body) {
		t.Fatal("prefix collection must not alter streaming body accounting")
	}
	encoded, err := json.Marshal(parsed.MultipartParts)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("PRIVATE-FILE-MARKER")) {
		t.Fatal("raw file prefix must not be serialized into event metadata")
	}
}

func TestMultipartPrefixTruncation(t *testing.T) {
	limits := dsctx.DefaultParseLimits()
	limits.MaxBodyParseBytes = 4096 + 15
	contentType, body := multipartPrefixRequest(t, "avatar.png", []byte("MZ"+strings.Repeat("X", 8192)))
	parsed := parseMultipartPrefix(t, contentType, body, limits)
	if len(parsed.MultipartParts) != 1 {
		t.Fatalf("expected one multipart file: %+v", parsed)
	}
	prefix, complete := parsed.MultipartParts[0].ContentPrefix()
	if complete || len(prefix) == 0 || len(prefix) > 16 {
		t.Fatalf("unexpected truncated prefix: len=%d complete=%v", len(prefix), complete)
	}
}

func TestMultipartPrefixUnavailableAtLowLimit(t *testing.T) {
	limits := dsctx.DefaultParseLimits()
	limits.MaxBodyParseBytes = 50
	contentType, body := multipartPrefixRequest(t, "avatar.png", []byte("MZ"+strings.Repeat("X", 8192)))
	parsed := parseMultipartPrefix(t, contentType, body, limits)
	if !parsed.BodyTruncated || len(parsed.MultipartParts) != 1 {
		t.Fatalf("expected truncated multipart with one file: %+v", parsed)
	}
	prefix, complete := parsed.MultipartParts[0].ContentPrefix()
	if complete || len(prefix) != 0 {
		t.Fatalf("low limit must disclose unavailable prefix: len=%d complete=%v", len(prefix), complete)
	}
}
