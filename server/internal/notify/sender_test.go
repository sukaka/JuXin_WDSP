package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testEvent 构造一条测试事件。
func testEvent() Event {
	return Event{
		AlertType:  "GATEWAY_DOWN",
		Severity:   SeverityCritical,
		Component:  "GATEWAY",
		Title:      "防护网关不可用",
		Message:    "网关 Admin Socket 不可达",
		Status:     StatusOpen,
		OccurredAt: time.Date(2026, 8, 18, 7, 0, 0, 0, time.UTC),
	}
}

// webhookRecorder 是 httptest 接收端：记录请求体，按给定状态码/响应体回复。
type webhookRecorder struct {
	mu     sync.Mutex
	bodies [][]byte
}

func (r *webhookRecorder) handler(status int, respBody string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.bodies = append(r.bodies, body)
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}
}

func (r *webhookRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

// last 返回最后一条请求体并解析为 JSON。
func (r *webhookRecorder) last(t *testing.T) map[string]interface{} {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bodies) == 0 {
		t.Fatal("未收到任何请求")
	}
	var m map[string]interface{}
	if err := json.Unmarshal(r.bodies[len(r.bodies)-1], &m); err != nil {
		t.Fatalf("请求体非 JSON: %v, body=%s", err, r.bodies[len(r.bodies)-1])
	}
	return m
}

func newRecorderServer(t *testing.T, rec *webhookRecorder, status int, respBody string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(rec.handler(status, respBody))
	t.Cleanup(srv.Close)
	return srv
}

// TestWecomSendMarkdown 企业微信默认 markdown 消息结构与文案。
func TestWecomSendMarkdown(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	rec := &webhookRecorder{}
	srv := newRecorderServer(t, rec, http.StatusOK, `{"errcode":0,"errmsg":"ok"}`)
	msg := renderMessage(testEvent())
	if err := (WecomSender{}).Send(context.Background(), WecomConfig{WebhookURL: srv.URL}, msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	body := rec.last(t)
	if body["msgtype"] != "markdown" {
		t.Fatalf("msgtype = %v, want markdown", body["msgtype"])
	}
	content, _ := body["markdown"].(map[string]interface{})["content"].(string)
	for _, want := range []string{"【九章WAF告警】防护网关不可用", "CRITICAL", "网关离线（GATEWAY_DOWN）", "GATEWAY", "网关 Admin Socket 不可达"} {
		if !strings.Contains(content, want) {
			t.Errorf("markdown 内容缺少 %q\ncontent=%s", want, content)
		}
	}
	// CRITICAL 应为 warning 颜色
	if !strings.Contains(content, `<font color="warning">CRITICAL</font>`) {
		t.Errorf("CRITICAL 未用 warning 颜色: %s", content)
	}
	// 时间应为 Asia/Shanghai（UTC+8：07:00 UTC → 15:00）
	if !strings.Contains(content, "2026-08-18 15:00:00") {
		t.Errorf("时间未按 Asia/Shanghai 渲染: %s", content)
	}
}

// TestWecomMentionAllFallsBackToText mention_all 降级为 text + @all（markdown 不支持提及）。
func TestWecomMentionAllFallsBackToText(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	rec := &webhookRecorder{}
	srv := newRecorderServer(t, rec, http.StatusOK, `{"errcode":0,"errmsg":"ok"}`)
	msg := renderMessage(testEvent())
	if err := (WecomSender{}).Send(context.Background(), WecomConfig{WebhookURL: srv.URL, MentionAll: true}, msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	body := rec.last(t)
	if body["msgtype"] != "text" {
		t.Fatalf("mention_all 时 msgtype = %v, want text", body["msgtype"])
	}
	text, _ := body["text"].(map[string]interface{})
	if c, _ := text["content"].(string); !strings.Contains(c, "防护网关不可用") {
		t.Errorf("text 内容缺少标题: %s", c)
	}
	mentions, _ := text["mentioned_list"].([]interface{})
	if len(mentions) != 1 || mentions[0] != "@all" {
		t.Errorf("mentioned_list = %v, want [@all]", mentions)
	}
}

// TestWecomSendError 企业微信业务错误如实返回。
func TestWecomSendError(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	rec := &webhookRecorder{}
	srv := newRecorderServer(t, rec, http.StatusOK, `{"errcode":93000,"errmsg":"invalid webhook"}`)
	err := (WecomSender{}).Send(context.Background(), WecomConfig{WebhookURL: srv.URL}, renderMessage(testEvent()))
	if err == nil || !strings.Contains(err.Error(), "invalid webhook") {
		t.Fatalf("应返回企业微信错误, got %v", err)
	}
}

// TestFeishuSendWithSign 飞书 post 富文本结构与 timestamp+sign 签名。
func TestFeishuSendWithSign(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	rec := &webhookRecorder{}
	srv := newRecorderServer(t, rec, http.StatusOK, `{"code":0,"msg":"success"}`)
	secret := "test-secret"
	err := (FeishuSender{}).Send(context.Background(),
		FeishuConfig{WebhookURL: srv.URL, Secret: secret}, renderMessage(testEvent()))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	body := rec.last(t)
	if body["msg_type"] != "post" {
		t.Fatalf("msg_type = %v, want post", body["msg_type"])
	}
	tsStr, _ := body["timestamp"].(string)
	sign, _ := body["sign"].(string)
	if tsStr == "" || sign == "" {
		t.Fatalf("缺少 timestamp/sign: %v", body)
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		t.Fatalf("timestamp 非数字: %v", tsStr)
	}
	// 独立复算签名（飞书算法：HMAC-SHA256 key="ts\nsecret"，空消息，base64）
	h := hmac.New(sha256.New, []byte(tsStr+"\n"+secret))
	want := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if sign != want {
		t.Errorf("sign = %s, want %s（ts=%d）", sign, want, ts)
	}
	post := body["content"].(map[string]interface{})["post"].(map[string]interface{})["zh_cn"].(map[string]interface{})
	if title, _ := post["title"].(string); !strings.Contains(title, "防护网关不可用") {
		t.Errorf("post 标题错误: %s", title)
	}
	lines, _ := post["content"].([]interface{})
	if len(lines) < 3 {
		t.Fatalf("post 内容行数不足: %v", lines)
	}
	first, _ := lines[0].([]interface{})[0].(map[string]interface{})
	if first["tag"] != "text" {
		t.Errorf("首行 tag = %v, want text", first["tag"])
	}
}

// TestFeishuSendNoSecret 未配置签名密钥时不带 timestamp/sign。
func TestFeishuSendNoSecret(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	rec := &webhookRecorder{}
	srv := newRecorderServer(t, rec, http.StatusOK, `{"code":0,"msg":"success"}`)
	if err := (FeishuSender{}).Send(context.Background(), FeishuConfig{WebhookURL: srv.URL}, renderMessage(testEvent())); err != nil {
		t.Fatalf("Send: %v", err)
	}
	body := rec.last(t)
	if _, ok := body["timestamp"]; ok {
		t.Errorf("无签名密钥不应带 timestamp: %v", body)
	}
	if _, ok := body["sign"]; ok {
		t.Errorf("无签名密钥不应带 sign: %v", body)
	}
}

// TestFeishuSendError 飞书业务错误如实返回。
func TestFeishuSendError(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	rec := &webhookRecorder{}
	srv := newRecorderServer(t, rec, http.StatusOK, `{"code":19021,"msg":"sign match fail"}`)
	err := (FeishuSender{}).Send(context.Background(),
		FeishuConfig{WebhookURL: srv.URL, Secret: "wrong"}, renderMessage(testEvent()))
	if err == nil || !strings.Contains(err.Error(), "sign match fail") {
		t.Fatalf("应返回飞书错误, got %v", err)
	}
}

// TestSMTPBuildMail 邮件报文结构：Q 编码主题、base64 正文、收件人列表。
func TestSMTPBuildMail(t *testing.T) {
	cfg := SMTPConfig{Host: "smtp.example.com", Port: 25, Security: "none",
		From: "waf@example.com", To: []string{"a@example.com", "b@example.com"}}
	raw := buildMail(cfg, renderMessage(testEvent()))
	msg := string(raw)
	if !strings.Contains(msg, "From: waf@example.com\r\n") {
		t.Errorf("缺 From 头: %s", msg)
	}
	if !strings.Contains(msg, "To: a@example.com, b@example.com\r\n") {
		t.Errorf("缺 To 头: %s", msg)
	}
	if !strings.Contains(msg, "Subject: =?utf-8?q?") {
		t.Errorf("主题未 Q 编码: %s", msg)
	}
	parts := strings.SplitN(msg, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatalf("报文缺空行分隔: %s", msg)
	}
	body, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(parts[1], "\r\n", ""))
	if err != nil {
		t.Fatalf("正文 base64 解码失败: %v", err)
	}
	if !strings.Contains(string(body), "网关离线（GATEWAY_DOWN）") {
		t.Errorf("正文缺少类型中文名: %s", body)
	}
}

// TestSMTPSenderInjectedFailure 发送失败如实返回错误（注入失败 send 函数）。
func TestSMTPSenderInjectedFailure(t *testing.T) {
	s := &SMTPSender{send: func(cfg SMTPConfig, msg []byte) error {
		return errors.New("connection refused")
	}}
	err := s.Send(context.Background(), SMTPConfig{Host: "x", Port: 25, Security: "none",
		From: "a@b.c", To: []string{"d@e.f"}}, renderMessage(testEvent()))
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("应透传发送错误, got %v", err)
	}
}

// ---------- 短信 ----------

// smsRecorder 是短信网关 httptest 接收端：记录请求体与请求头。
type smsRecorder struct {
	mu      sync.Mutex
	bodies  [][]byte
	appKeys []string
	signs   []string
}

func (r *smsRecorder) handler(status int, respBody string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.bodies = append(r.bodies, body)
		r.appKeys = append(r.appKeys, req.Header.Get("X-App-Key"))
		r.signs = append(r.signs, req.Header.Get("X-Sign"))
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}
}

func (r *smsRecorder) last(t *testing.T) (body map[string]interface{}, appKey, sign string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bodies) == 0 {
		t.Fatal("未收到任何请求")
	}
	if err := json.Unmarshal(r.bodies[len(r.bodies)-1], &body); err != nil {
		t.Fatalf("请求体非 JSON: %v, body=%s", err, r.bodies[len(r.bodies)-1])
	}
	return body, r.appKeys[len(r.appKeys)-1], r.signs[len(r.signs)-1]
}

func testSMSConfig(url string) SMSConfig {
	return SMSConfig{
		GatewayURL: url,
		AppKey:     "ak-1",
		AppSecret:  "sk-secret",
		TemplateID: "SMS_TPL_001",
		Phones:     []string{"+8613800138000", "13900139000"},
	}
}

// TestSMSSendWithSign 短信请求体结构（模板参数）与 X-App-Key/X-Sign 签名头。
func TestSMSSendWithSign(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	rec := &smsRecorder{}
	srv := httptest.NewServer(rec.handler(http.StatusOK, `{"code":"0","message":"ok"}`))
	t.Cleanup(srv.Close)

	cfg := testSMSConfig(srv.URL)
	if err := (SMSSender{}).Send(context.Background(), cfg, testEvent()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	body, appKey, sign := rec.last(t)
	if appKey != "ak-1" {
		t.Errorf("X-App-Key = %q, want ak-1", appKey)
	}
	// 独立复算签名：hex(HMAC-SHA256(app_secret, rawBody))
	rec.mu.Lock()
	raw := rec.bodies[len(rec.bodies)-1]
	rec.mu.Unlock()
	mac := hmac.New(sha256.New, []byte("sk-secret"))
	mac.Write(raw)
	if want := hex.EncodeToString(mac.Sum(nil)); sign != want {
		t.Errorf("X-Sign = %s, want %s", sign, want)
	}
	// 请求体契约
	if body["app_key"] != "ak-1" || body["template_id"] != "SMS_TPL_001" {
		t.Errorf("app_key/template_id 错误: %v", body)
	}
	phones, _ := body["phones"].([]interface{})
	if len(phones) != 2 || phones[0] != "+8613800138000" {
		t.Errorf("phones = %v", body["phones"])
	}
	params, _ := body["params"].(map[string]interface{})
	if params == nil {
		t.Fatalf("缺 params: %v", body)
	}
	if params["title"] != "防护网关不可用" || params["severity"] != "CRITICAL" || params["component"] != "GATEWAY" {
		t.Errorf("params 标题/级别/组件错误: %v", params)
	}
	if msg, _ := params["message"].(string); !strings.Contains(msg, "网关 Admin Socket 不可达") {
		t.Errorf("params.message 错误: %v", params["message"])
	}
	// UTC 07:00 → Asia/Shanghai 15:00
	if params["time"] != "2026-08-18 15:00:00" {
		t.Errorf("params.time 未按 Asia/Shanghai 渲染: %v", params["time"])
	}
}

// TestSMSSendNoSecret 未配置 app_secret 时不带签名头。
func TestSMSSendNoSecret(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	rec := &smsRecorder{}
	srv := httptest.NewServer(rec.handler(http.StatusOK, `{"code":"SUCCESS"}`))
	t.Cleanup(srv.Close)

	cfg := testSMSConfig(srv.URL)
	cfg.AppSecret = ""
	if err := (SMSSender{}).Send(context.Background(), cfg, testEvent()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	_, appKey, sign := rec.last(t)
	if appKey != "" || sign != "" {
		t.Errorf("无 app_secret 不应带签名头: X-App-Key=%q X-Sign=%q", appKey, sign)
	}
}

// TestSMSSendBusinessCodeFailure 业务 code 非成功值视为失败（进 spool 重试）。
func TestSMSSendBusinessCodeFailure(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	for _, respBody := range []string{
		`{"code":"1001","message":"invalid sign"}`,
		`{"code":1001,"msg":"invalid sign"}`,
	} {
		rec := &smsRecorder{}
		srv := httptest.NewServer(rec.handler(http.StatusOK, respBody))
		err := (SMSSender{}).Send(context.Background(), testSMSConfig(srv.URL), testEvent())
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "invalid sign") {
			t.Fatalf("响应 %s 应返回业务错误, got %v", respBody, err)
		}
	}
}

// TestSMSSendSuccessCodeVariants 成功 code 变体（"0"/"SUCCESS"/"OK"/无 code 字段）均视为成功。
func TestSMSSendSuccessCodeVariants(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	for _, respBody := range []string{`{"code":"0"}`, `{"code":"SUCCESS"}`, `{"code":"ok"}`, `{"code":0}`, `{}`} {
		rec := &smsRecorder{}
		srv := httptest.NewServer(rec.handler(http.StatusOK, respBody))
		err := (SMSSender{}).Send(context.Background(), testSMSConfig(srv.URL), testEvent())
		srv.Close()
		if err != nil {
			t.Fatalf("响应 %s 应视为成功, got %v", respBody, err)
		}
	}
}

// TestSMSSendHTTPFailure 非 2xx 视为失败并带回对端信息。
func TestSMSSendHTTPFailure(t *testing.T) {
	useTestGuard(t, loopbackGuard())
	rec := &smsRecorder{}
	srv := httptest.NewServer(rec.handler(http.StatusBadGateway, `bad gateway`))
	t.Cleanup(srv.Close)
	err := (SMSSender{}).Send(context.Background(), testSMSConfig(srv.URL), testEvent())
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("非 2xx 应失败, got %v", err)
	}
}

// TestParseSMSConfig 配置校验：缺字段/非法手机号/未知字段/脱敏占位符。
func TestParseSMSConfig(t *testing.T) {
	good := map[string]interface{}{
		"gateway_url": "https://sms.example.com/send", "app_key": "ak",
		"app_secret": "sk", "template_id": "T1", "phones": []string{"13800138000"},
	}
	if _, err := ParseSMSConfig(good); err != nil {
		t.Fatalf("合法配置应通过: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{"空gateway", func(m map[string]interface{}) { m["gateway_url"] = "" }},
		{"脱敏占位符gateway", func(m map[string]interface{}) { m["gateway_url"] = MaskedValue }},
		{"空app_key", func(m map[string]interface{}) { m["app_key"] = "" }},
		{"空template_id", func(m map[string]interface{}) { m["template_id"] = " " }},
		{"空phones", func(m map[string]interface{}) { m["phones"] = []string{} }},
		{"非法手机号", func(m map[string]interface{}) { m["phones"] = []string{"abc"} }},
		{"未知字段", func(m map[string]interface{}) { m["bogus"] = 1 }},
	}
	for _, c := range cases {
		m := map[string]interface{}{}
		for k, v := range good {
			m[k] = v
		}
		c.mutate(m)
		if _, err := ParseSMSConfig(m); err == nil {
			t.Errorf("%s 应校验失败", c.name)
		}
	}
	// ValidateConfig 分发
	if err := ValidateConfig(TypeSMS, good); err != nil {
		t.Errorf("ValidateConfig(sms) 应通过: %v", err)
	}
}
