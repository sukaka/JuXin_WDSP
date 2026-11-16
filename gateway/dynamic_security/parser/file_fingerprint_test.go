package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestMultipartContentFingerprint(t *testing.T) {
	payload := []byte("synthetic-file-content")
	contentType, body := multipartPrefixRequest(t, "report.txt", payload)
	parsed := parseMultipartPrefix(t, contentType, body, dsctx.DefaultParseLimits())
	if len(parsed.MultipartParts) != 1 {
		t.Fatalf("parts=%d", len(parsed.MultipartParts))
	}
	part := parsed.MultipartParts[0]
	fingerprint, complete := part.ContentFingerprint()
	sum := sha256.Sum256(payload)
	if !complete || fingerprint != hex.EncodeToString(sum[:]) {
		t.Fatalf("fingerprint=%q complete=%v", fingerprint, complete)
	}
	observations := BuildUploadFileObservations(parsed.MultipartParts)
	if len(observations) != 1 || observations[0].ContentSHA256 != fingerprint {
		t.Fatalf("upload observation fingerprint missing: %+v", observations)
	}
	prefix, prefixComplete := part.ContentPrefix()
	if !prefixComplete || string(prefix) != string(payload) {
		t.Fatalf("small file prefix behavior changed: %q complete=%v", prefix, prefixComplete)
	}
}

func TestMultipartContentFingerprintBeyondPrefixCap(t *testing.T) {
	payload := []byte(strings.Repeat("synthetic-data-", 100))
	contentType, body := multipartPrefixRequest(t, "large.txt", payload)
	parsed := parseMultipartPrefix(t, contentType, body, dsctx.DefaultParseLimits())
	part := parsed.MultipartParts[0]
	prefix, prefixComplete := part.ContentPrefix()
	if prefixComplete || len(prefix) != maxFileContentPrefix {
		t.Fatalf("prefix cap changed: len=%d complete=%v", len(prefix), prefixComplete)
	}
	fingerprint, complete := part.ContentFingerprint()
	sum := sha256.Sum256(payload)
	if !complete || fingerprint != hex.EncodeToString(sum[:]) {
		t.Fatalf("full streaming fingerprint must cover beyond the prefix: %q complete=%v", fingerprint, complete)
	}
}

func TestMultipartContentFingerprintTruncation(t *testing.T) {
	limits := dsctx.DefaultParseLimits()
	limits.MaxBodyParseBytes = 64
	payload := []byte(strings.Repeat("partial-content-", 100))
	contentType, body := multipartPrefixRequest(t, "partial.txt", payload)
	parsed := parseMultipartPrefix(t, contentType, body, limits)
	if len(parsed.MultipartParts) != 1 {
		t.Fatalf("parts=%d", len(parsed.MultipartParts))
	}
	fingerprint, complete := parsed.MultipartParts[0].ContentFingerprint()
	if complete || fingerprint != "" {
		t.Fatalf("truncated content must not receive a fingerprint: %q complete=%v", fingerprint, complete)
	}
	observations := BuildUploadFileObservations(parsed.MultipartParts)
	if len(observations) != 1 || observations[0].ContentSHA256 != "" {
		t.Fatalf("truncated observation must omit fingerprint: %+v", observations)
	}
}
