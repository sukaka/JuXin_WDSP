package botchallenge

import (
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
)

// 挑战页安全属性：CSP nonce 挂脚本/样式、connect-src 'self'（仅第一方连接）、
// frame-ancestors 'none' + X-Frame-Options DENY（禁止嵌入）、Cache-Control no-store、
// 无 eval、无外部 URL、无 innerHTML。
func TestRenderChallengeHeaders(t *testing.T) {
	svc, _ := newTestService(t, nil, nil, nil, testServiceOpts{})
	host := "shop.example.com"
	o := doOffer(t, svc, host, "203.0.113.7")
	if o.recorder.Code != http.StatusForbidden {
		t.Fatalf("offer: %d", o.recorder.Code)
	}
	h := o.recorder.Header()
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q: %s", want, csp)
		}
	}
	// script-src/style-src 仅 nonce（无 unsafe-inline/unsafe-eval/外部源）
	if !strings.Contains(csp, "script-src 'nonce-") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Fatalf("script-src must be nonce-only: %s", csp)
	}
	if h.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("X-Frame-Options: %q", h.Get("X-Frame-Options"))
	}
	if h.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control: %q", h.Get("Cache-Control"))
	}
	body := o.recorder.Body.String()
	for _, bad := range []string{"eval(", "innerHTML", "document.write", "http://cdn", "https://cdn", "src=\"http", "new Function"} {
		if strings.Contains(body, bad) {
			t.Errorf("challenge page must not contain %q", bad)
		}
	}
	// CSP nonce 出现在 CSP 头与脚本标签且一致
	m := strings.Index(body, `<script nonce="`)
	if m < 0 {
		t.Fatal("script nonce missing")
	}
	nonceVal := body[m+len(`<script nonce="`):]
	nonceVal = nonceVal[:strings.Index(nonceVal, `"`)]
	if !strings.Contains(csp, "'nonce-"+nonceVal+"'") {
		t.Fatalf("CSP nonce mismatch with script tag: %q vs %s", nonceVal, csp)
	}
}

// 动态文本转义：RequestID 含脚本注入串 → HTML 转义；题目参数 JSON 不含原始
// `</script>`（json.Marshal 默认 \u003c 转义）。
func TestRenderEscaping(t *testing.T) {
	svc, _ := newTestService(t, nil, nil, nil, testServiceOpts{})
	host := "shop.example.com"
	r := httptestRequestWithHost(host)
	rec := newOfferRecorder(t, svc, r, "rid-<script>alert(1)</script>-xss")
	body := rec.Body.String()
	if strings.Contains(body, "rid-<script>alert(1)</script>") {
		t.Fatal("request id must be HTML-escaped")
	}
	if !strings.Contains(body, html.EscapeString("rid-<script>alert(1)</script>-xss")) {
		t.Fatal("escaped request id expected")
	}
	// 参数块内容可解析为 JSON 且无原始闭合标签
	m := paramsRe.FindStringSubmatch(body)
	if len(m) != 2 {
		t.Fatal("params block missing")
	}
	if strings.Contains(m[1], "</script>") || strings.Contains(m[1], "</") {
		t.Fatalf("params json must not contain raw closing tags: %s", m[1])
	}
	var pj paramsJSON
	if err := json.Unmarshal([]byte(m[1]), &pj); err != nil {
		t.Fatalf("params must be valid json: %v", err)
	}
	if pj.Difficulty != svc.cfg.Difficulty || pj.VerifyPath != VerifyPath || pj.BudgetMS != computeBudgetMS {
		t.Fatalf("params: %+v", pj)
	}
}

// 两次签发 CSP nonce 不同（每响应随机）。
func TestRenderCSPNonceUnique(t *testing.T) {
	svc, _ := newTestService(t, nil, nil, nil, testServiceOpts{})
	host := "shop.example.com"
	o1 := doOffer(t, svc, host, "203.0.113.7")
	o2 := doOffer(t, svc, host, "203.0.113.8")
	n1 := o1.recorder.Header().Get("Content-Security-Policy")
	n2 := o2.recorder.Header().Get("Content-Security-Policy")
	if n1 == n2 {
		t.Fatal("CSP nonce must be per-response random")
	}
}

// 会话复用：第二次 Offer 携带有效会话 Cookie → 复用同一会话（不重发 Cookie）。
func TestSessionReuse(t *testing.T) {
	svc, _ := newTestService(t, nil, nil, nil, testServiceOpts{})
	host := "shop.example.com"
	o1 := doOffer(t, svc, host, "203.0.113.7")
	if o1.sessionC == nil {
		t.Fatal("first offer must set session cookie")
	}
	o2 := doOffer(t, svc, host, "203.0.113.7", o1.sessionC)
	if o2.recorder.Code != http.StatusForbidden {
		t.Fatalf("second offer: %d", o2.recorder.Code)
	}
	if o2.sessionC != nil {
		t.Fatal("valid session must be reused without re-setting cookie")
	}
	// 两挑战绑定同一会话摘要：用第一会话验证第二挑战成功
	sol := solveFor(t, svc, o2)
	rec := doVerify(t, svc, o2, sol, func(r *http.Request) {
		r.Header.Del("Cookie")
		r.AddCookie(o1.sessionC)
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("verify with reused session: %d", rec.Code)
	}
}

// OBSERVE 记录：LogObservedOffer 只发事件（action=OBSERVE），不写状态不挑战。
func TestLogObservedOffer(t *testing.T) {
	fk := newFakeBotValkey()
	sink := &captureSink{}
	svc, _ := newTestService(t, fk, nil, sink, testServiceOpts{mode: ModeObserve})
	r := httptestRequestWithHost("shop.example.com")
	svc.LogObservedOffer(r, CallContext{RequestID: "r-1", ClientIP: "203.0.113.7"}, "SIGNAL_RULE_HIT")
	if got := len(fk.keyDump()); got != 0 {
		t.Fatalf("observe must not write state: %d", got)
	}
	evs := sink.byType(events.BotChallengeOffered)
	if len(evs) != 1 || evs[0].Action != "OBSERVE" || evs[0].Bot.Mode != ModeObserve {
		t.Fatalf("observe event: %+v", evs)
	}
}

// 辅助：构造指定 Host 的 GET 请求。
func httptestRequestWithHost(host string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://"+host+"/products", nil)
	r.Host = host
	return r
}

// 辅助：自定义 RequestID 的签发。
func newOfferRecorder(t *testing.T, svc *Service, r *http.Request, requestID string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	svc.Offer(rec, r, CallContext{RequestID: requestID, ClientIP: "203.0.113.7", ConnectionIP: "10.0.0.1"}, "SIGNAL_RULE_HIT")
	return rec
}
