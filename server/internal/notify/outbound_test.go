package notify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/jiuzhang-waf/server/internal/outboundhttp"
)

// ---------- 出口防护测试装配 ----------

// useTestGuard 替换出口防护装配（t.Cleanup 恢复；本包测试不并行，包级替换安全）。
func useTestGuard(t *testing.T, g *outboundGuard) {
	t.Helper()
	old := outbound
	outbound = g
	t.Cleanup(func() { outbound = old })
}

// loopbackGuard 放行回环（httptest 接收端）、不锁官方域名的测试装配。
func loopbackGuard() *outboundGuard {
	return &outboundGuard{
		allowlist:         func() string { return "127.0.0.0/8, ::1/128" },
		lockOfficialHosts: false,
	}
}

// fakeDNS 是可编程的假 DNS 解析器。
type fakeDNS struct {
	mu     sync.Mutex
	calls  int
	lookup func(call int, host string) ([]net.IP, error)
}

func (f *fakeDNS) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.lookup(f.calls, host)
}

// staticDNS 返回按主机名映射的固定记录。
func staticDNS(records map[string]string) *fakeDNS {
	return &fakeDNS{lookup: func(_ int, host string) ([]net.IP, error) {
		raw, ok := records[host]
		if !ok {
			return nil, fmt.Errorf("no such host: %s", host)
		}
		var ips []net.IP
		for _, s := range strings.Split(raw, ",") {
			ips = append(ips, net.ParseIP(strings.TrimSpace(s)))
		}
		return ips, nil
	}}
}

// ---------- 校验层（保存配置阶段） ----------

// TestCheckWebhookURLOfficialLock 企业微信/飞书锁定官方域名（仅 https + 默认端口）。
func TestCheckWebhookURLOfficialLock(t *testing.T) {
	good := []struct{ typ, raw string }{
		{TypeWecom, "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc-123"},
		{TypeFeishu, "https://open.feishu.cn/open-apis/bot/v2/hook/abc"},
		{TypeFeishu, "https://open.larksuite.com/open-apis/bot/v2/hook/abc"},
	}
	for _, c := range good {
		if err := checkWebhookURL(c.typ, c.raw); err != nil {
			t.Errorf("%s %s 应通过: %v", c.typ, c.raw, err)
		}
	}
	bad := []struct{ typ, raw string }{
		{TypeWecom, "http://qyapi.weixin.qq.com/x"},           // 非 https
		{TypeWecom, "https://qyapi.weixin.qq.com.evil.com/x"}, // 后缀仿冒
		{TypeWecom, "https://weixin.qq.com/x"},                // 非机器人 API 域名
		{TypeWecom, "https://qyapi.weixin.qq.com:8443/x"},     // 非标端口
		{TypeFeishu, "http://open.feishu.cn/x"},
		{TypeFeishu, "https://open.feishu.cn.evil.com/x"},
		{TypeFeishu, "https://feishu.cn/x"},
	}
	for _, c := range bad {
		if err := checkWebhookURL(c.typ, c.raw); err == nil {
			t.Errorf("%s %s 应被拒绝", c.typ, c.raw)
		}
	}
}

// TestCheckWebhookURLPrivateTargets 短信网关/自定义目标默认拒绝内网与保留地址。
func TestCheckWebhookURLPrivateTargets(t *testing.T) {
	deny := []string{
		"http://127.0.0.1:8080/send",
		"http://10.0.0.1/send",
		"http://172.16.0.1/send",
		"http://192.168.1.1/send",
		"http://169.254.169.254/latest/meta-data", // 云元数据
		"http://[::1]/send",
		"http://[fe80::1]/send",
		"http://[fd00::1]/send",
		"http://[::ffff:127.0.0.1]/send", // IPv4-mapped IPv6
		"http://0.0.0.0/send",
		"http://user:pass@93.184.216.34/send", // 内嵌凭据
		"file:///etc/passwd",
		"http://93.184.216.34:99999/send", // 非法端口
	}
	for _, raw := range deny {
		if err := checkWebhookURL(TypeSMS, raw); err == nil {
			t.Errorf("%s 应被拒绝", raw)
		}
	}
	// 公网字面量 IP 与域名（域名解析在 ValidateChannelConfig/拨号阶段）放行
	for _, raw := range []string{"https://93.184.216.34/send", "https://sms.example.com/send"} {
		if err := checkWebhookURL(TypeSMS, raw); err != nil {
			t.Errorf("%s 应通过: %v", raw, err)
		}
	}
}

// TestCheckWebhookURLAllowlist 显式允许列表放行内网目标；列表外内网仍拒绝。
func TestCheckWebhookURLAllowlist(t *testing.T) {
	useTestGuard(t, &outboundGuard{
		allowlist:         func() string { return "10.0.0.0/8, ::1/128" },
		lockOfficialHosts: true,
	})
	if err := checkWebhookURL(TypeSMS, "http://10.1.2.3:8080/send"); err != nil {
		t.Errorf("允许列表内地址应放行: %v", err)
	}
	for _, raw := range []string{"http://192.168.1.1/send", "http://127.0.0.1/send", "http://169.254.169.254/x"} {
		if err := checkWebhookURL(TypeSMS, raw); err == nil {
			t.Errorf("%s 不在允许列表，应被拒绝", raw)
		}
	}
	// 允许列表不解除官方域名锁定
	if err := checkWebhookURL(TypeWecom, "https://10.1.2.3/x"); err == nil {
		t.Error("企业微信仍应锁定官方域名")
	}
}

// TestValidateChannelConfigDeep 保存时深度校验：域名解析全部记录，任一内网即拒绝。
func TestValidateChannelConfigDeep(t *testing.T) {
	dns := staticDNS(map[string]string{
		"sms.example.com":       "93.184.216.34",
		"mixed.test":            "93.184.216.34, 10.0.0.1", // 混合 A/AAAA
		"rebinding.example.com": "127.0.0.1",
	})
	useTestGuard(t, &outboundGuard{
		resolver:          dns,
		allowlist:         func() string { return "" },
		lockOfficialHosts: true,
	})
	d := &Dispatcher{}
	cfg := func(gw string) map[string]interface{} {
		return map[string]interface{}{
			"gateway_url": gw, "app_key": "ak", "template_id": "T1",
			"phones": []string{"13800138000"},
		}
	}
	if err := d.ValidateChannelConfig(context.Background(), TypeSMS, cfg("https://sms.example.com/send")); err != nil {
		t.Errorf("公网解析应通过: %v", err)
	}
	if err := d.ValidateChannelConfig(context.Background(), TypeSMS, cfg("http://mixed.test/send")); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Errorf("混合解析记录应拒绝, got %v", err)
	}
	if err := d.ValidateChannelConfig(context.Background(), TypeSMS, cfg("http://rebinding.example.com/send")); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Errorf("回环解析应拒绝, got %v", err)
	}
	if err := d.ValidateChannelConfig(context.Background(), TypeSMS, cfg("http://no-such-host.invalid/send")); !errors.Is(err, outboundhttp.ErrDenied) {
		t.Errorf("解析失败应拒绝, got %v", err)
	}
	// 语法层错误照常返回（未经地址校验）
	bad := cfg("https://sms.example.com/send")
	bad["phones"] = []string{"abc"}
	if err := d.ValidateChannelConfig(context.Background(), TypeSMS, bad); err == nil || errors.Is(err, outboundhttp.ErrDenied) {
		t.Errorf("非法手机号应返回参数校验错误, got %v", err)
	}
	// 官方域名锁定先于解析
	if err := d.ValidateChannelConfig(context.Background(), TypeWecom,
		map[string]interface{}{"webhook_url": "https://wecom.example.com/x"}); err == nil {
		t.Error("非官方企业微信域名应拒绝")
	}
}

// ---------- 发送阶段（拨号复检） ----------

// TestSMSSendDeniedLoopbackByDefault 默认装配（空允许列表）拒绝回环目标，
// 即使 httptest 服务真实可达。
func TestSMSSendDeniedLoopbackByDefault(t *testing.T) {
	rec := &smsRecorder{}
	srv := httptest.NewServer(rec.handler(http.StatusOK, `{"code":"0"}`))
	t.Cleanup(srv.Close)
	err := (SMSSender{}).Send(context.Background(), testSMSConfig(srv.URL), testEvent())
	if !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("回环目标应被拒绝, got %v", err)
	}
	if rec.count() != 0 {
		t.Fatal("请求不应到达接收端")
	}
}

func (r *smsRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

// TestSMSSendDNSRebinding DNS 重绑定：校验时解析为公网、拨号时变为回环，发送必须失败。
func TestSMSSendDNSRebinding(t *testing.T) {
	dns := &fakeDNS{lookup: func(call int, _ string) ([]net.IP, error) {
		if call == 1 {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil // 发送前校验：公网
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil // 拨号重解析：回环
	}}
	useTestGuard(t, &outboundGuard{
		resolver:          dns,
		allowlist:         func() string { return "" },
		lockOfficialHosts: true,
	})
	cfg := testSMSConfig("http://sms-gw.example.com/send")
	err := (SMSSender{}).Send(context.Background(), cfg, testEvent())
	if !errors.Is(err, outboundhttp.ErrDenied) {
		t.Fatalf("重绑定到回环应在拨号阶段被拒绝, got %v", err)
	}
}

// TestSMSSendAllowlistedInternal 允许列表内的内网短信网关可正常发送（签名头完整）。
func TestSMSSendAllowlistedInternal(t *testing.T) {
	dns := staticDNS(map[string]string{"sms.internal.example.com": "127.0.0.1"})
	rec := &smsRecorder{}
	srv := httptest.NewServer(rec.handler(http.StatusOK, `{"code":"0"}`))
	t.Cleanup(srv.Close)
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	useTestGuard(t, &outboundGuard{
		resolver:          dns,
		allowlist:         func() string { return "sms.internal.example.com" },
		lockOfficialHosts: true,
	})
	cfg := testSMSConfig("http://sms.internal.example.com:" + port + "/send")
	if err := (SMSSender{}).Send(context.Background(), cfg, testEvent()); err != nil {
		t.Fatalf("允许列表内的内网网关应发送成功: %v", err)
	}
	_, appKey, sign := rec.last(t)
	if appKey != "ak-1" || sign == "" {
		t.Errorf("签名头应完整送达: X-App-Key=%q X-Sign=%q", appKey, sign)
	}
}

// TestWecomSendViaOfficialDomainLocked 默认装配下非官方域名 webhook 不发出请求。
func TestWecomSendViaOfficialDomainLocked(t *testing.T) {
	rec := &webhookRecorder{}
	srv := newRecorderServer(t, rec, http.StatusOK, `{"errcode":0,"errmsg":"ok"}`)
	// 模拟完整发送路径（dispatcher.sendNow 同款）：先 Parse 校验再发送
	_, err := ParseWecomConfig(map[string]interface{}{"webhook_url": srv.URL})
	if err == nil {
		t.Fatal("非官方域名应在配置校验层被拒绝")
	}
	if rec.count() != 0 {
		t.Fatal("请求不应发出")
	}
}
