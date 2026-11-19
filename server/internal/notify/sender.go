// sender.go 通知渠道发送实现：企业微信（markdown/text）、飞书（post 富文本 + 签名）、
// 邮件（net/smtp + STARTTLS/SSL）、短信（通用 HTTP 短信网关 + HMAC-SHA256 签名）。全部纯标准库。
// HTTP 出口统一经 outbound.go 的 SSRF 防护客户端（见 SEC-01 修复）。
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// sendTimeout 是单次外发 HTTP/SMTP 请求超时。
const sendTimeout = 10 * time.Second

// postJSON 发送 JSON POST 并检查 2xx；响应体限长丢弃（不读回业务数据）。
func postJSON(ctx context.Context, url string, body []byte) ([]byte, error) {
	return postJSONWithHeaders(ctx, url, body, nil)
}

// postJSONWithHeaders 同 postJSON，附带自定义请求头（短信网关签名用）。
// 出口经 outboundhttp 防护（SEC-01）：发送前目标地址校验 + 拨号重解析复检，
// 不跟随重定向；配置/目标不合规如实报错（进 spool 重试路径，不静默吞掉）。
func postJSONWithHeaders(ctx context.Context, url string, body []byte, headers map[string]string) ([]byte, error) {
	pol, err := outbound.policy()
	if err != nil {
		return nil, err
	}
	if _, err := pol.ValidateURL(ctx, url); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := pol.Client()
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("对端返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

// ---------- 企业微信 ----------

// WecomSender 是企业微信群机器人发送器。
type WecomSender struct{}

// wecomResp 是企业微信机器人响应（{"errcode":0,"errmsg":"ok"}）。
type wecomResp struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// Send 发送企业微信消息：默认 markdown；mention_all 时降级为 text + mentioned_list
// （企业微信机器人 markdown 消息不支持 @ 提及，见官方文档 msgtype 说明）。
func (WecomSender) Send(ctx context.Context, cfg WecomConfig, msg Message) error {
	var payload []byte
	var err error
	if cfg.MentionAll {
		payload, err = json.Marshal(map[string]interface{}{
			"msgtype": "text",
			"text": map[string]interface{}{
				"content":        msg.Subject + "\n" + msg.Text,
				"mentioned_list": []string{"@all"},
			},
		})
	} else {
		payload, err = json.Marshal(map[string]interface{}{
			"msgtype":  "markdown",
			"markdown": map[string]interface{}{"content": msg.Markdown},
		})
	}
	if err != nil {
		return fmt.Errorf("构造企业微信消息失败: %w", err)
	}
	respBody, err := postJSON(ctx, cfg.WebhookURL, payload)
	if err != nil {
		return fmt.Errorf("企业微信 Webhook %w", err)
	}
	var wr wecomResp
	if err := json.Unmarshal(respBody, &wr); err != nil {
		return fmt.Errorf("解析企业微信响应失败: %w", err)
	}
	if wr.ErrCode != 0 {
		return fmt.Errorf("企业微信返回错误 %d: %s", wr.ErrCode, wr.ErrMsg)
	}
	return nil
}

// ---------- 飞书 ----------

// FeishuSender 是飞书自定义机器人发送器。
type FeishuSender struct{}

// feishuResp 是飞书机器人响应（{"code":0,"msg":"success"}）。
type feishuResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

// feishuSign 按飞书机器人文档计算签名：以 "timestamp\nsecret" 为 HMAC-SHA256 的 key、
// 空串为消息，digest 做 base64。
func feishuSign(secret string, timestamp int64) string {
	stringToSign := fmt.Sprintf("%d\n%s", timestamp, secret)
	h := hmac.New(sha256.New, []byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Send 发送飞书富文本 post 消息（zh_cn）；Secret 非空时附带 timestamp/sign 签名校验。
func (FeishuSender) Send(ctx context.Context, cfg FeishuConfig, msg Message) error {
	lines := [][]map[string]string{}
	for _, line := range strings.Split(msg.Subject+"\n"+msg.Text, "\n") {
		lines = append(lines, []map[string]string{{"tag": "text", "text": line}})
	}
	body := map[string]interface{}{
		"msg_type": "post",
		"content": map[string]interface{}{
			"post": map[string]interface{}{
				"zh_cn": map[string]interface{}{"title": msg.Subject, "content": lines},
			},
		},
	}
	if cfg.Secret != "" {
		ts := time.Now().Unix()
		body["timestamp"] = strconv.FormatInt(ts, 10)
		body["sign"] = feishuSign(cfg.Secret, ts)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("构造飞书消息失败: %w", err)
	}
	respBody, err := postJSON(ctx, cfg.WebhookURL, payload)
	if err != nil {
		return fmt.Errorf("飞书 Webhook %w", err)
	}
	var fr feishuResp
	if err := json.Unmarshal(respBody, &fr); err != nil {
		return fmt.Errorf("解析飞书响应失败: %w", err)
	}
	if fr.Code != 0 {
		return fmt.Errorf("飞书返回错误 %d: %s", fr.Code, fr.Msg)
	}
	return nil
}

// ---------- 短信 ----------

// SMSSender 是短信渠道发送器（通用 HTTP 短信网关模板协议）。
//
// 协议约定（适配具体厂商网关时需按其协议调整本实现）：
//   - POST gateway_url，JSON 请求体：
//     {"app_key","template_id","phones":[...],"params":{"title","severity","component","message","time"}}
//   - app_secret 非空时附带请求头 X-App-Key: <app_key>、
//     X-Sign: hex(HMAC-SHA256(app_secret, rawBody))；
//   - 成功判定：HTTP 2xx 且（响应 JSON 无 code 字段 或 code ∈ {"0","SUCCESS","OK"}）。
type SMSSender struct{}

// smsRequest 是短信网关请求体。
type smsRequest struct {
	AppKey     string            `json:"app_key"`
	TemplateID string            `json:"template_id"`
	Phones     []string          `json:"phones"`
	Params     map[string]string `json:"params"`
}

// smsResp 是短信网关响应（仅关心业务 code 与可选 message/msg 描述）。
type smsResp struct {
	Code    json.RawMessage `json:"code"`
	Message string          `json:"message"`
	Msg     string          `json:"msg"`
}

// Send 发送短信：模板参数由告警事件渲染（time 为 Asia/Shanghai 的 2006-01-02 15:04:05）。
func (SMSSender) Send(ctx context.Context, cfg SMSConfig, ev Event) error {
	ts := ev.OccurredAt
	if ts.IsZero() {
		ts = time.Now()
	}
	payload, err := json.Marshal(smsRequest{
		AppKey:     cfg.AppKey,
		TemplateID: cfg.TemplateID,
		Phones:     cfg.Phones,
		Params: map[string]string{
			"title":     ev.Title,
			"severity":  ev.Severity,
			"component": ev.Component,
			"message":   ev.Message,
			"time":      ts.In(shanghai).Format("2006-01-02 15:04:05"),
		},
	})
	if err != nil {
		return fmt.Errorf("构造短信请求失败: %w", err)
	}
	var headers map[string]string
	if cfg.AppSecret != "" {
		mac := hmac.New(sha256.New, []byte(cfg.AppSecret))
		mac.Write(payload)
		headers = map[string]string{
			"X-App-Key": cfg.AppKey,
			"X-Sign":    hex.EncodeToString(mac.Sum(nil)),
		}
	}
	respBody, err := postJSONWithHeaders(ctx, cfg.GatewayURL, payload, headers)
	if err != nil {
		return fmt.Errorf("短信网关 %w", err)
	}
	var sr smsResp
	if err := json.Unmarshal(respBody, &sr); err != nil {
		// 2xx 但响应非 JSON：无法判定业务结果，按成功语义无法确认，如实报错进重试
		return fmt.Errorf("解析短信网关响应失败: %w", err)
	}
	if code := strings.Trim(string(sr.Code), `"`); code != "" && !smsCodeOK(code) {
		desc := sr.Message
		if desc == "" {
			desc = sr.Msg
		}
		return fmt.Errorf("短信网关返回错误 code=%s: %s", code, desc)
	}
	return nil
}

// smsCodeOK 判定业务 code 是否成功（"0"/"SUCCESS"/"OK"，大小写不敏感）。
func smsCodeOK(code string) bool {
	switch strings.ToUpper(code) {
	case "0", "SUCCESS", "OK":
		return true
	}
	return false
}

// ---------- 邮件 ----------

// SMTPSender 是邮件渠道发送器；send 可注入（单测替换为假实现/假服务器地址）。
type SMTPSender struct {
	send func(cfg SMTPConfig, msg []byte) error
}

// NewSMTPSender 创建邮件发送器（真实 SMTP 发送）。
func NewSMTPSender() *SMTPSender {
	return &SMTPSender{send: sendSMTPReal}
}

// Send 发送纯文本邮件（UTF-8，主题 Q 编码，正文 base64）。
func (s *SMTPSender) Send(_ context.Context, cfg SMTPConfig, msg Message) error {
	return s.send(cfg, buildMail(cfg, msg))
}

// buildMail 构造 RFC822 报文（头 ASCII 安全；正文 UTF-8 base64）。
func buildMail(cfg SMTPConfig, msg Message) []byte {
	var b strings.Builder
	b.WriteString("From: " + cfg.From + "\r\n")
	b.WriteString("To: " + strings.Join(cfg.To, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", msg.Subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700") + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("\r\n")
	body := base64.StdEncoding.EncodeToString([]byte(msg.Text))
	// base64 正文按 76 列折行（RFC2045）
	for i := 0; i < len(body); i += 76 {
		end := i + 76
		if end > len(body) {
			end = len(body)
		}
		b.WriteString(body[i:end] + "\r\n")
	}
	return []byte(b.String())
}

// sendSMTPReal 真实 SMTP 发送：none=明文，starttls=升级加密，ssl=直连 TLS；
// username 非空时进行 PLAIN 认证（net/smtp 仅在加密连接上发送凭据）。
func sendSMTPReal(cfg SMTPConfig, msg []byte) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Timeout: sendTimeout}
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}

	var client *smtp.Client
	if cfg.Security == "ssl" {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("连接 SMTP 服务器（SSL）失败: %w", err)
		}
		c, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("建立 SMTP 会话失败: %w", err)
		}
		client = c
	} else {
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("连接 SMTP 服务器失败: %w", err)
		}
		c, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("建立 SMTP 会话失败: %w", err)
		}
		client = c
		if cfg.Security == "starttls" {
			if ok, _ := client.Extension("STARTTLS"); !ok {
				_ = client.Close()
				return fmt.Errorf("SMTP 服务器不支持 STARTTLS")
			}
			if err := client.StartTLS(tlsCfg); err != nil {
				_ = client.Close()
				return fmt.Errorf("STARTTLS 握手失败: %w", err)
			}
		}
	}
	defer client.Close()

	if cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return fmt.Errorf("SMTP 认证失败: %w", err)
		}
	}
	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("SMTP MAIL FROM 失败: %w", err)
	}
	for _, to := range cfg.To {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("SMTP RCPT TO（%s）失败: %w", to, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA 失败: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("写入邮件内容失败: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("提交邮件内容失败: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("SMTP 会话结束失败: %w", err)
	}
	return nil
}
