package notify

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestBuildMailMessageWithAttachment(t *testing.T) {
	cfg := SMTPConfig{Host: "smtp.example.com", Port: 465, From: "waf@example.com"}
	msg := string(buildMailMessage(cfg, []string{"a@x.com", "b@x.com"}, "安全报告（2026-08期）", "见附件。", "report-abc.pdf", []byte("%PDF-fake")))

	for _, want := range []string{
		"From: waf@example.com", "To: a@x.com, b@x.com",
		"multipart/mixed", "jz-mail-boundary-9f2c7e",
		"Content-Disposition: attachment; filename=\"report-abc.pdf\"",
		"Content-Type: text/plain; charset=\"utf-8\"",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("mail message missing %q", want)
		}
	}
	// 中文主题必须 QEncoding 编码（不出现裸中文）
	if strings.Contains(msg, "Subject: 安全报告") {
		t.Fatal("subject should be QEncoding encoded")
	}
	if !strings.Contains(msg, "Subject: =?utf-8?") {
		t.Fatal("subject should use RFC2047 encoding")
	}
	// 附件内容 base64 存在
	if !strings.Contains(msg, base64.StdEncoding.EncodeToString([]byte("%PDF-fake"))) {
		t.Fatal("attachment base64 missing")
	}
	// 边界正确闭合
	if !strings.HasSuffix(msg, "--jz-mail-boundary-9f2c7e--\r\n") {
		t.Fatal("multipart should close with boundary")
	}
}

func TestBuildMailMessageTextOnly(t *testing.T) {
	cfg := SMTPConfig{Host: "smtp.example.com", Port: 25, From: "waf@example.com"}
	msg := string(buildMailMessage(cfg, []string{"a@x.com"}, "test", "正文", "", nil))
	if strings.Contains(msg, "multipart/mixed") {
		t.Fatal("text-only mail should not be multipart")
	}
	if !strings.Contains(msg, `Content-Type: text/plain; charset="utf-8"`) {
		t.Fatal("text/plain content type missing")
	}
}

func TestSendMailValidation(t *testing.T) {
	if err := SendMail(SMTPConfig{}, []string{"a@x.com"}, "s", "t", "", nil); err == nil {
		t.Fatal("expect error for unconfigured smtp")
	}
	if err := SendMail(SMTPConfig{Host: "h", Port: 25}, nil, "s", "t", "", nil); err == nil {
		t.Fatal("expect error for empty recipients")
	}
}
