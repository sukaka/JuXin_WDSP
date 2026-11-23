package jiuzhang_guard

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
)

func TestL7RequestBodyKeywordBlocksBeforeUpstream(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", L7Rules: l7Config(l7rules.RuleJSON{
		ID: "request-body", Priority: 1, Enabled: true,
		Conditions: []l7rules.ConditionJSON{{Type: "request_body", Op: "contains", Value: "blocked-keyword"}},
		Action:     "block",
	})})
	r := l7Req("POST", "/api", "203.0.113.30:1")
	r.Body = io.NopCloser(strings.NewReader(`{"note":"blocked-keyword"}`))
	r.ContentLength = int64(len(`{"note":"blocked-keyword"}`))
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil || called {
		t.Fatalf("请求体关键字应在源站前阻断: err=%v called=%v", err, called)
	}
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "blocked-keyword") {
		t.Fatalf("阻断响应异常: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestL7RequestBodyIsRestoredForDownstream(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", L7Rules: l7Config(l7rules.RuleJSON{
		ID: "request-body", Priority: 1, Enabled: true,
		Conditions: []l7rules.ConditionJSON{{Type: "request_body", Op: "contains", Value: "absent"}},
		Action:     "block",
	})})
	const payload = `{"note":"ordinary-content"}`
	r := l7Req("POST", "/api", "203.0.113.31:1")
	r.Body = io.NopCloser(strings.NewReader(payload))
	r.ContentLength = int64(len(payload))
	var downstream string
	rec := httptest.NewRecorder()
	err := g.ServeHTTP(rec, r, nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		body, err := io.ReadAll(r.Body)
		downstream = string(body)
		return err
	}))
	if err != nil || downstream != payload {
		t.Fatalf("下游必须读到完整原请求体: err=%v body=%q", err, downstream)
	}
}

func TestL7ResponseBodyKeywordBlocksWithoutLeakingOrigin(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", L7Rules: l7Config(l7rules.RuleJSON{
		ID: "response-body", Priority: 1, Enabled: true,
		Conditions: []l7rules.ConditionJSON{
			{Type: "uri", Op: "prefix", Value: "/api"},
			{Type: "response_body", Op: "contains", Value: "response-secret"},
		},
		Action: "block", ActionConfig: l7rules.ActionConfigJSON{Status: 451, Message: "响应内容不合规"},
	})})
	rec := httptest.NewRecorder()
	err := g.ServeHTTP(rec, l7Req("GET", "/api/orders", "203.0.113.32:1"), nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("X-Origin", "private")
		_, _ = io.WriteString(w, "prefix response-secret suffix")
		return nil
	}))
	if err != nil || rec.Code != 451 {
		t.Fatalf("响应体关键字应阻断: err=%v code=%d", err, rec.Code)
	}
	if strings.Contains(rec.Body.String(), "response-secret") || rec.Header().Get("X-Origin") != "" {
		t.Fatalf("源站内容或响应头泄露: headers=%v body=%s", rec.Header(), rec.Body.String())
	}
	evs := g.readEvents(t)
	if len(evs) != 1 || evs[0].EventType != events.L7RuleBlock || evs[0].ResponseStatus != 451 {
		t.Fatalf("响应阻断事件异常: %+v", evs)
	}
}

func TestL7ResponseHeaderConditionAndOriginalPassThrough(t *testing.T) {
	t.Run("响应头命中自定义页面", func(t *testing.T) {
		g := newTestGuard(t, Guard{AppID: "app1", L7Rules: l7Config(l7rules.RuleJSON{
			ID: "response-header", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "response_header", Name: "X-Result", Op: "eq", Value: "private"}},
			Action:     "custom_page", ActionConfig: l7rules.ActionConfigJSON{Status: 403, ContentType: "text/plain", Body: "denied"},
		})})
		rec := httptest.NewRecorder()
		_ = g.ServeHTTP(rec, l7Req("GET", "/", "203.0.113.33:1"), nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("X-Result", "private")
			_, _ = io.WriteString(w, "origin-body")
			return nil
		}))
		if rec.Code != 403 || rec.Body.String() != "denied" {
			t.Fatalf("响应头条件未生效: code=%d body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("未命中保持原响应", func(t *testing.T) {
		g := newTestGuard(t, Guard{AppID: "app1", L7Rules: l7Config(l7rules.RuleJSON{
			ID: "response-body", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "response_body", Op: "contains", Value: "secret"}},
			Action:     "block",
		})})
		rec := httptest.NewRecorder()
		_ = g.ServeHTTP(rec, l7Req("GET", "/", "203.0.113.34:1"), nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("X-Origin", "public")
			w.WriteHeader(201)
			_, _ = io.WriteString(w, "public-body")
			return nil
		}))
		if rec.Code != 201 || rec.Body.String() != "public-body" || rec.Header().Get("X-Origin") != "public" {
			t.Fatalf("未命中响应被改变: code=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
		}
	})
	t.Run("响应头命中重定向保留路径与查询参数", func(t *testing.T) {
		g := newTestGuard(t, Guard{AppID: "app1", L7Rules: l7Config(l7rules.RuleJSON{
			ID: "response-redirect", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{
				{Type: "host", Op: "eq", Value: "jxdr.cn"},
				{Type: "response_header", Name: "X-Move", Op: "eq", Value: "1"},
			},
			Action: "redirect",
			ActionConfig: l7rules.ActionConfigJSON{
				RedirectURL: "https://www.jxdr.cn", RedirectStatus: 301, PreservePathQuery: true,
			},
		})})
		r := l7Req("GET", "/news?id=1", "203.0.113.34:1")
		r.Host = "JXDR.CN:443"
		rec := httptest.NewRecorder()
		_ = g.ServeHTTP(rec, r, nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("X-Move", "1")
			_, _ = io.WriteString(w, "origin-body")
			return nil
		}))
		if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "https://www.jxdr.cn/news?id=1" {
			t.Fatalf("响应阶段重定向异常: code=%d loc=%q", rec.Code, rec.Header().Get("Location"))
		}
	})
}

func TestL7ResponseInspectionDegradesWithoutTruncation(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), maxL7BodyInspectionBytes+1)
	g := newTestGuard(t, Guard{AppID: "app1", L7Rules: l7Config(l7rules.RuleJSON{
		ID: "response-body", Priority: 1, Enabled: true,
		Conditions: []l7rules.ConditionJSON{{Type: "response_body", Op: "contains", Value: "secret"}},
		Action:     "block",
	})})
	rec := httptest.NewRecorder()
	_ = g.ServeHTTP(rec, l7Req("GET", "/large", "203.0.113.35:1"), nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		_, _ = w.Write(payload)
		return nil
	}))
	if !bytes.Equal(rec.Body.Bytes(), payload) {
		t.Fatal("超限响应必须完整透传，不得截断")
	}
}

func TestL7ResponseSSEPassThrough(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", L7Rules: l7Config(l7rules.RuleJSON{
		ID: "response-body", Priority: 1, Enabled: true,
		Conditions: []l7rules.ConditionJSON{{Type: "response_body", Op: "contains", Value: "secret"}},
		Action:     "block",
	})})
	rec := httptest.NewRecorder()
	_ = g.ServeHTTP(rec, l7Req("GET", "/events", "203.0.113.36:1"), nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: secret\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		return nil
	}))
	if rec.Body.String() != "data: secret\n\n" {
		t.Fatalf("SSE 必须原样透传: %q", rec.Body.String())
	}
}

// N-01 回归：
// 1. response_header 阻断规则不得被 >1MiB 响应体或 Flush()/SSE 流式切直通绕过；
// 2. 网关本地终止响应（如 JWT 401 + WWW-Authenticate）不得被源站 L7 响应规则剥离头或覆写；
// 3. C-07 路径规范化防 L7 URI 规则 // 或 .. 绕过。
func TestN01L7ResponseHeaderNoBypassAndPreserveGatewayErrors(t *testing.T) {
	t.Run("response_header 阻断不得被 >1MiB 响应体绕过", func(t *testing.T) {
		payload := bytes.Repeat([]byte("A"), maxL7BodyInspectionBytes+64)
		g := newTestGuard(t, Guard{AppID: "app1", L7Rules: l7Config(l7rules.RuleJSON{
			ID: "hdr-block-large", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "response_header", Name: "X-Leak", Op: "eq", Value: "true"}},
			Action:     "block", ActionConfig: l7rules.ActionConfigJSON{Status: 403, Message: "header blocked"},
		})})
		rec := httptest.NewRecorder()
		_ = g.ServeHTTP(rec, l7Req("GET", "/download", "203.0.113.40:1"), nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("X-Leak", "true")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
			return nil
		}))
		if rec.Code != http.StatusForbidden {
			t.Fatalf(">1MiB 响应体不得绕过 response_header 阻断: code=%d", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "AAAA") || rec.Header().Get("X-Leak") != "" {
			t.Fatalf("阻断后不得泄露源站头或正文: headers=%v len=%d", rec.Header(), rec.Body.Len())
		}
	})

	t.Run("response_header 阻断不得被 Flush/SSE 流式响应绕过", func(t *testing.T) {
		g := newTestGuard(t, Guard{AppID: "app1", L7Rules: l7Config(l7rules.RuleJSON{
			ID: "hdr-block-stream", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "response_header", Name: "X-Sensitive", Op: "eq", Value: "1"}},
			Action:     "block", ActionConfig: l7rules.ActionConfigJSON{Status: 403, Message: "stream header blocked"},
		})})
		rec := httptest.NewRecorder()
		_ = g.ServeHTTP(rec, l7Req("GET", "/stream", "203.0.113.41:1"), nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("X-Sensitive", "1")
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			_, _ = io.WriteString(w, "data: leaked-token\n\n")
			return nil
		}))
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "leaked-token") {
			t.Fatalf("SSE/Flush 不得绕过 response_header 阻断: code=%d body=%q", rec.Code, rec.Body.String())
		}
	})

	t.Run("网关本地终止响应（JWT 401）不被 L7 响应规则覆写或剥离 WWW-Authenticate", func(t *testing.T) {
		key := jwtTestRSA(t)
		jwks := jwtTestJWKS(t, &key.PublicKey, "kid-l7")
		g := newJWTGuard(t, jwtStaticSection("PROTECT", true, jwks), func(g *Guard) {
			eng, errs := l7rules.Compile(l7Config(l7rules.RuleJSON{
				ID: "catch-all-json", Priority: 1, Enabled: true,
				Conditions: []l7rules.ConditionJSON{
					{Type: "response_header", Name: "Content-Type", Op: "contains", Value: "application/json"},
				},
				Action: "custom_page", ActionConfig: l7rules.ActionConfigJSON{Status: 200, ContentType: "text/plain", Body: "overwritten"},
			}))
			if len(errs) > 0 {
				t.Fatalf("compile l7: %+v", errs)
			}
			g.l7 = eng
		})
		rec := httptest.NewRecorder()
		called := false
		// 缺 Bearer token -> JWT PROTECT 本地返回 401 + WWW-Authenticate
		_ = g.ServeHTTP(rec, l7Req("GET", "/api/orders", "203.0.113.42:1"), nextHandler{&called})
		if called {
			t.Fatal("JWT 401 必须阻断上游")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("N-01: L7 响应规则不得覆写 JWT 401 状态码: code=%d body=%s", rec.Code, rec.Body.String())
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("N-01: L7 响应规则不得剥离 JWT 401 的 WWW-Authenticate 头: %v", rec.Header())
		}
		if strings.Contains(rec.Body.String(), "overwritten") {
			t.Fatalf("N-01: L7 custom_page 不得覆写网关本地响应: %s", rec.Body.String())
		}
	})

	t.Run("C-07 L7 URI 条件规范化拦截 // 和 ..", func(t *testing.T) {
		g := newTestGuard(t, Guard{AppID: "app1", L7Rules: l7Config(l7rules.RuleJSON{
			ID: "block-admin", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "uri", Op: "prefix", Value: "/admin"}},
			Action:     "block",
		})})
		for _, p := range []string{"//admin/panel", "/public/../admin/panel"} {
			called := false
			rec := httptest.NewRecorder()
			_ = g.ServeHTTP(rec, l7Req("GET", p, "203.0.113.43:1"), nextHandler{&called})
			if called || rec.Code != http.StatusForbidden {
				t.Fatalf("C-07: L7 URI 规则不得被 %q 绕过: called=%v code=%d", p, called, rec.Code)
			}
		}
	})
}
