// redact_test.go 脱敏与截断回归（安全红线：凭据头值 [redacted]、样本截断、
// 敏感字段只落名不落值）。
package apiscan

import (
	"net/http"
	"strings"
	"testing"
)

// TestBuildRequestSampleRedaction 请求样本脱敏：凭据头值一律 [redacted]，普通头保留。
func TestBuildRequestSampleRedaction(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://target.local/v1/users?x=1", nil)
	req.Header.Set("Authorization", "Bearer secret-token-123")
	req.Header.Set("Cookie", "session=abc123")
	req.Header.Set("X-Api-Key", "key-xyz")
	req.Header.Set(ScanHeader, "jobid.sig")
	req.Header.Set("X-Normal", "keep-me")
	sample := buildRequestSample(req)
	for _, leaked := range []string{"secret-token-123", "abc123", "key-xyz", "jobid.sig"} {
		if strings.Contains(sample, leaked) {
			t.Fatalf("sample leaks credential %q: %s", leaked, sample)
		}
	}
	if !strings.Contains(sample, "keep-me") {
		t.Fatal("normal header should be kept")
	}
	if !strings.Contains(sample, Redacted) {
		t.Fatal("sample should contain redacted placeholder")
	}
	if !strings.Contains(sample, "GET /v1/users?x=1") {
		t.Fatalf("request line missing: %s", sample)
	}
}

// TestTruncateSample 截断：超长保留前缀 + 截断标记。
func TestTruncateSample(t *testing.T) {
	short := "abc"
	if got := truncateSample(short, 10); got != short {
		t.Fatalf("short sample changed: %q", got)
	}
	long := strings.Repeat("A", 5000)
	got := truncateSample(long, maxResponseSample)
	if len(got) <= maxResponseSample || !strings.Contains(got, "truncated") {
		t.Fatalf("truncation broken: len=%d", len(got))
	}
	if !strings.HasPrefix(got, strings.Repeat("A", 100)) {
		t.Fatal("truncated sample should keep prefix")
	}
}

// TestScanSensitiveFields 敏感字段名扫描：命中只落字段名，非 JSON 不命中，大小写归一。
func TestScanSensitiveFields(t *testing.T) {
	body := []byte(`{"user":{"Password":"x","EMAIL":"a@b.c"},"list":[{"bank_card":"1"}],"name":"ok"}`)
	got := scanSensitiveFields(body)
	want := map[string]bool{"password": true, "email": true, "bank_card": true}
	if len(got) != len(want) {
		t.Fatalf("fields=%v, want %v", got, want)
	}
	for _, f := range got {
		if !want[f] {
			t.Fatalf("unexpected field %q", f)
		}
		// 不落值
		if strings.Contains(f, "x") || strings.Contains(f, "a@b.c") {
			t.Fatalf("field output leaks value: %q", f)
		}
	}
	if got := scanSensitiveFields([]byte(`{"name":"ok","count":1}`)); len(got) != 0 {
		t.Fatalf("clean body should not hit: %v", got)
	}
	if got := scanSensitiveFields([]byte(`not json`)); got != nil {
		t.Fatalf("non-json should not hit: %v", got)
	}
}

// TestBodyDigest 响应体哈希证据稳定且不含原文。
func TestBodyDigest(t *testing.T) {
	body := []byte(`{"ssn":"123-45-6789"}`)
	d := bodyDigest(body)
	if len(d) != 16 {
		t.Fatalf("digest len=%d", len(d))
	}
	if strings.Contains(d, "123-45-6789") {
		t.Fatal("digest leaks body")
	}
	if d != bodyDigest(body) {
		t.Fatal("digest not stable")
	}
}
