package mirrorcap

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

// newPHP2ShellWAF 加载真实 cve-emergency.conf（DetectionOnly），验证规则语法与命中语义。
func newPHP2ShellWAF(t *testing.T) coraza.WAF {
	t.Helper()
	raw, err := os.ReadFile("../rules/contrib/CUSTOM_PACK/cve-emergency.conf")
	if err != nil {
		t.Fatalf("read cve-emergency.conf: %v", err)
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(
		"SecRuleEngine DetectionOnly\nSecRequestBodyAccess On\nSecRequestBodyLimit 134217728\n" + string(raw)))
	if err != nil {
		t.Fatalf("NewWAF cve-emergency: %v", err)
	}
	return waf
}

func runPHP2ShellRequest(t *testing.T, waf coraza.WAF, contentType string, body []byte, transferEncoding ...string) map[int]bool {
	t.Helper()
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection("203.0.113.10", 41000, "10.20.30.40", 8080)
	tx.ProcessURI("/upload.php", http.MethodPost, "HTTP/1.1")
	tx.AddRequestHeader("Host", "php.example.com")
	tx.AddRequestHeader("Content-Type", contentType)
	if len(transferEncoding) > 0 {
		tx.AddRequestHeader("Transfer-Encoding", transferEncoding[0])
	} else {
		tx.AddRequestHeader("Content-Length", fmt.Sprint(len(body)))
	}
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody(body); err != nil {
		t.Fatalf("WriteRequestBody: %v", err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("ProcessRequestBody: %v", err)
	}
	tx.ProcessLogging()
	got := map[int]bool{}
	for _, m := range tx.MatchedRules() {
		got[m.Rule().ID()] = true
	}
	return got
}

func requirePHP2ShellRules(t *testing.T, got map[int]bool, want ...int) {
	t.Helper()
	for _, id := range want {
		if !got[id] {
			t.Errorf("missing rule %d; matched=%v", id, got)
		}
	}
}

func TestPHP2ShellEmergencyRules(t *testing.T) {
	waf := newPHP2ShellWAF(t)
	boundary := "p2s-boundary"
	contentType := "multipart/form-data; boundary=" + boundary

	part := func(name, value string) string {
		return "--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + value + "\r\n"
	}
	closeBoundary := "--" + boundary + "--\r\n"

	t.Run("普通 multipart 不命中", func(t *testing.T) {
		body := []byte(part("file", "ordinary text") + closeBoundary)
		got := runPHP2ShellRequest(t, waf, contentType, body)
		for id := 1000043; id <= 1000047; id++ {
			if got[id] {
				t.Fatalf("benign multipart unexpectedly matched %d: %v", id, got)
			}
		}
	})

	t.Run("upload progress 字段命中入口规则", func(t *testing.T) {
		body := []byte(part("PHP_SESSION_UPLOAD_PROGRESS", "123") + closeBoundary)
		got := runPHP2ShellRequest(t, waf, contentType, body)
		requirePHP2ShellRules(t, got, 1000043)
	})

	t.Run("PHP 标签与 session 反序列化字段值命中", func(t *testing.T) {
		body := []byte(part("PHP_SESSION_UPLOAD_PROGRESS", "<?php echo 1; ?>") + closeBoundary)
		got := runPHP2ShellRequest(t, waf, contentType, body)
		requirePHP2ShellRules(t, got, 1000043, 1000044)

		body = []byte(part("PHP_SESSION_UPLOAD_PROGRESS", "|O:8:\"stdClass\":0:{}") + closeBoundary)
		got = runPHP2ShellRequest(t, waf, contentType, body)
		requirePHP2ShellRules(t, got, 1000043, 1000044)
	})

	t.Run("超长 part header 命中 OOM 探针", func(t *testing.T) {
		filename := strings.Repeat("a", 8300) + ".txt"
		body := []byte("--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\n\r\nx\r\n" + closeBoundary)
		got := runPHP2ShellRequest(t, waf, contentType, body)
		requirePHP2ShellRules(t, got, 1000045)
	})

	t.Run("chunked multipart 命中无可信长度 OOM 入口", func(t *testing.T) {
		body := []byte(part("file", "x") + closeBoundary)
		got := runPHP2ShellRequest(t, waf, contentType, body, "chunked")
		requirePHP2ShellRules(t, got, 1000046)
	})

	t.Run("深层嵌套字段名命中 OOM 放大弱特征", func(t *testing.T) {
		body := []byte(part("profile[a][b][c][d][e]", "x") + closeBoundary)
		got := runPHP2ShellRequest(t, waf, contentType, body)
		requirePHP2ShellRules(t, got, 1000047)
	})
}
