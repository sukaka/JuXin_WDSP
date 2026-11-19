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
