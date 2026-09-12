// mail.go 通用邮件发送（MIME multipart/mixed：文本正文 + 单个附件）。
// 报告系统定时报告邮件用；连接与认证复用 sendSMTPReal（纯标准库）。
package notify

import (
	"encoding/base64"
	"fmt"
	"mime"
	"strings"
	"time"
)

// SendMail 以邮件渠道配置发送一封邮件（可带单个附件）。
//   - to：收件人列表（覆盖渠道配置的默认收件人，报告计划按自有收件人发送）；
//   - subject：主题（中文经 RFC2047 QEncoding 编码）；
//   - text：纯文本正文（UTF-8，base64 传输）；
//   - attachName/attach：附件名与内容；attach 为 nil 时仅发正文（text/plain 单段）。
func SendMail(cfg SMTPConfig, to []string, subject, text, attachName string, attach []byte) error {
	if cfg.Host == "" || cfg.Port == 0 {
		return fmt.Errorf("SMTP 服务器未配置")
	}
	if len(to) == 0 {
		return fmt.Errorf("收件人为空")
	}
	msg := buildMailMessage(cfg, to, subject, text, attachName, attach)
	return sendSMTPReal(SMTPConfig{
		Host: cfg.Host, Port: cfg.Port, Security: cfg.Security,
		Username: cfg.Username, Password: cfg.Password,
		From: cfg.From, To: to,
	}, msg)
}

// buildMailMessage 构建 MIME 报文（multipart/mixed；无附件时退化为 text/plain）。
func buildMailMessage(cfg SMTPConfig, to []string, subject, text, attachName string, attach []byte) []byte {
	var b strings.Builder
	b.WriteString("From: " + cfg.From + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700") + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")

	writeBase64 := func(data []byte) {
		enc := base64.StdEncoding.EncodeToString(data)
		for i := 0; i < len(enc); i += 76 { // RFC2045 76 列折行
			end := i + 76
			if end > len(enc) {
				end = len(enc)
			}
			b.WriteString(enc[i:end] + "\r\n")
		}
	}

	if len(attach) == 0 {
		b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		writeBase64([]byte(text))
		return []byte(b.String())
	}

	const boundary = "jz-mail-boundary-9f2c7e"
	b.WriteString("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n\r\n")
	// 正文段
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	writeBase64([]byte(text))
	// 附件段（附件名按 RFC2047 编码，防中文名乱码；本系统报告文件名本身为 ASCII）
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: application/octet-stream; name=\"" + mime.QEncoding.Encode("utf-8", attachName) + "\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("Content-Disposition: attachment; filename=\"" + mime.QEncoding.Encode("utf-8", attachName) + "\"\r\n\r\n")
	writeBase64(attach)
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}
