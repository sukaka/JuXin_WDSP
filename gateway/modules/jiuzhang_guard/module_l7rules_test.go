package jiuzhang_guard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/temporaryblock"
)

// l7Req 构造 L7 测试请求（带 Request ID）。
func l7Req(method, target, remoteAddr string) *http.Request {
	r := httptest.NewRequest(method, "http://waf-test.local"+target, nil)
	r.RemoteAddr = remoteAddr
	r.Header.Set("X-Request-Id", "11111111-2222-3333-4444-555555555555")
	return r
}

// l7Config 单规则便捷配置。
func l7Config(rule l7rules.RuleJSON) *l7rules.Config {
	return &l7rules.Config{Rules: []l7rules.RuleJSON{rule}}
}

// TestL7BlockAction 阻止动作：可配状态码+文案，直接终结请求并写事件。
func TestL7BlockAction(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1", AppCode: "shop",
		L7Rules: l7Config(l7rules.RuleJSON{
			ID: "l7-block-1", Name: "后台拦截", Priority: 100, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "uri", Op: "prefix", Value: "/admin"}},
			Action:     "block",
			ActionConfig: l7rules.ActionConfigJSON{
				Status: 451, Message: "该页面不可访问",
			},
		}),
	})
	called := false
	rec := httptest.NewRecorder()
	err := g.ServeHTTP(rec, l7Req("GET", "/admin/panel", "203.0.113.10:1234"), nextHandler{&called})
	if err != nil || called {
		t.Fatalf("block 应直接终结请求: err=%v called=%v", err, called)
	}
	if rec.Code != 451 {
		t.Fatalf("状态码应为 451: %d", rec.Code)
	}
	body := rec.Body.String()
	if !contains(body, "该页面不可访问") || !contains(body, "451") {
		t.Fatalf("响应应含配置文案与状态码: %s", body)
	}
	if rec.Header().Get("X-Jiuzhang-Request-ID") == "" {
		t.Fatal("响应应携带 Request ID")
	}
	evs := g.readEvents(t)
	if len(evs) != 1 || evs[0].EventType != events.L7RuleBlock ||
		evs[0].AccessRuleID != "l7-block-1" || evs[0].Action != "BLOCK" ||
		evs[0].ResponseStatus != 451 || evs[0].ClientIP != "203.0.113.10" {
		t.Fatalf("block 事件字段: %+v", evs)
	}
}

// TestL7BlockDefaults 阻止默认值：403 + 默认文案；Accept: application/json 返回 JSON。
func TestL7BlockDefaults(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		L7Rules: l7Config(l7rules.RuleJSON{
			ID: "l7-block-2", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "uri", Op: "eq", Value: "/blocked"}},
			Action:     "block",
		}),
	})
	r := l7Req("GET", "/blocked", "203.0.113.11:1")
	r.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, r, nextHandler{new(bool)}); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("默认状态码应为 403: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("JSON Accept 应返回 JSON: %s", ct)
	}
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["message"] != "访问被拦截" || payload["error"] != "access_blocked" {
		t.Fatalf("默认文案: %+v", payload)
	}
}

// TestL7RedirectAction 重定向动作：301/302 + Location（URL 加载期已校验 http/https）。
func TestL7RedirectAction(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		L7Rules: l7Config(l7rules.RuleJSON{
			ID: "l7-redir-1", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "uri", Op: "eq", Value: "/old"}},
			Action:     "redirect",
			ActionConfig: l7rules.ActionConfigJSON{
				RedirectURL: "https://example.com/new", RedirectStatus: 301,
			},
		}),
	})
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, l7Req("GET", "/old", "203.0.113.12:1"), nextHandler{&called}); err != nil || called {
		t.Fatalf("redirect 应直接终结请求: called=%v", called)
	}
	if rec.Code != 301 || rec.Header().Get("Location") != "https://example.com/new" {
		t.Fatalf("redirect 响应: code=%d location=%s", rec.Code, rec.Header().Get("Location"))
	}
	evs := g.readEvents(t)
	if len(evs) != 1 || evs[0].EventType != events.L7RuleRedirect ||
		evs[0].AccessRuleID != "l7-redir-1" || evs[0].ResponseStatus != 301 {
		t.Fatalf("redirect 事件字段: %+v", evs)
	}
}

// TestL7CustomPageAction 自定义页面动作：状态码+Content-Type+内容。
func TestL7CustomPageAction(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		L7Rules: l7Config(l7rules.RuleJSON{
			ID: "l7-page-1", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "uri", Op: "prefix", Value: "/"}},
			Action:     "custom_page",
			ActionConfig: l7rules.ActionConfigJSON{
				Status: 200, ContentType: "text/html; charset=utf-8", Body: "<h1>系统维护中</h1>",
			},
		}),
	})
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, l7Req("GET", "/anything", "203.0.113.13:1"), nextHandler{&called}); err != nil || called {
		t.Fatalf("custom_page 应直接终结请求: called=%v", called)
	}
	if rec.Code != 200 || rec.Body.String() != "<h1>系统维护中</h1>" ||
		!strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("custom_page 响应: code=%d body=%s ct=%s", rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
	}
	evs := g.readEvents(t)
	if len(evs) != 1 || evs[0].EventType != events.L7RuleCustom || evs[0].AccessRuleID != "l7-page-1" {
		t.Fatalf("custom_page 事件字段: %+v", evs)
	}
}

// captureCtxHandler 记录下游收到的请求上下文（验证 allow 跳过标记随请求传递）。
type captureCtxHandler struct {
	called *bool
	ctx    *map[string]any
}

func (h captureCtxHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	*h.called = true
	*h.ctx = map[string]any{"l7skip": l7Skip(r.Context())}
	w.WriteHeader(200)
	return nil
}

// TestL7AllowSkipsCC 允许动作：放行并跳过 CC 与自动临时封禁（仍经 serveNext 进入下游/WAF）。
func TestL7AllowSkipsCC(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		L7Rules: l7Config(l7rules.RuleJSON{
			ID: "l7-allow-1", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "uri", Op: "prefix", Value: "/api"}},
			Action:     "allow",
		}),
		RateLimits: []policyJSON{{
			ID: "cc1", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60, BurstCapacity: 1,
			Action: "REJECT", Priority: 1,
		}},
	})
	// 该 IP 同时存在自动临时封禁（CC 产物）：allow 命中应一并跳过
	g.engine.blockCache.PutLocal(t.Context(), temporaryblock.Block{
		ID: "auto1", ClientIP: "203.0.113.14", AppID: "app1",
		ExpiresAt: time.Now().Add(time.Hour), Auto: true,
	})
	for i := 0; i < 3; i++ {
		called := false
		var ctx map[string]any
		rec := httptest.NewRecorder()
		if err := g.ServeHTTP(rec, l7Req("GET", "/api/data", "203.0.113.14:1"), captureCtxHandler{&called, &ctx}); err != nil || !called {
			t.Fatalf("第 %d 次请求应放行（CC limit=1 与自动封禁均被跳过）: err=%v", i, err)
		}
		if ctx["l7skip"] != true {
			t.Fatal("allow 命中应设置跳过标记并随请求传递")
		}
	}
	evs := g.readEvents(t)
	if len(evs) != 3 {
		t.Fatalf("每次 allow 命中均应写事件: %d 条", len(evs))
	}
	for _, e := range evs {
		if e.EventType != events.L7RuleAllow || e.AccessRuleID != "l7-allow-1" || e.Action != "ALLOW" {
			t.Fatalf("allow 事件字段: %+v", e)
		}
	}
}

// TestL7NoMatchFallsToCC 未命中任何规则：继续后续检查（CC 生效）。
func TestL7NoMatchFallsToCC(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		L7Rules: l7Config(l7rules.RuleJSON{
			ID: "l7-allow-2", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "uri", Op: "prefix", Value: "/api"}},
			Action:     "allow",
		}),
		RateLimits: []policyJSON{{
			ID: "cc1", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60, BurstCapacity: 1,
			Action: "REJECT", Priority: 1,
		}},
	})
	// 第一次（未命中 L7）：放行；第二次：CC 429
	rec1 := httptest.NewRecorder()
	if err := g.ServeHTTP(rec1, l7Req("GET", "/web", "203.0.113.15:1"), nextHandler{new(bool)}); err != nil {
		t.Fatal(err)
	}
	rec2 := httptest.NewRecorder()
	called := false
	if err := g.ServeHTTP(rec2, l7Req("GET", "/web", "203.0.113.15:1"), nextHandler{&called}); err != nil || called {
		t.Fatalf("第二次应被 CC 拦截: err=%v called=%v", err, called)
	}
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("应为 CC 429: %d", rec2.Code)
	}
}

// TestL7DoesNotBypassManualTempBlock 安全属性：人工临时封禁先于 L7，allow 不可绕过。
func TestL7DoesNotBypassManualTempBlock(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		L7Rules: l7Config(l7rules.RuleJSON{
			ID: "l7-allow-3", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "uri", Op: "prefix", Value: "/"}},
			Action:     "allow",
		}),
	})
	g.engine.blockCache.PutLocal(t.Context(), temporaryblock.Block{
		ID: "manual1", ClientIP: "203.0.113.16", AppID: "app1",
		ExpiresAt: time.Now().Add(time.Hour), Auto: false,
	})
	called := false
	err := g.ServeHTTP(httptest.NewRecorder(), l7Req("GET", "/api", "203.0.113.16:1"), nextHandler{&called})
	if err == nil || called {
		t.Fatal("人工封禁不得被 L7 allow 绕过")
	}
}

// TestL7AfterIPDeny 链序：IP 黑名单优先于 L7（deny 先终结，L7 不评估）。
func TestL7AfterIPDeny(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID:      "app1",
		GlobalDeny: []ruleJSON{{ID: "d1", Address: "203.0.113.17", Priority: 1}},
		L7Rules: l7Config(l7rules.RuleJSON{
			ID: "l7-allow-4", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "uri", Op: "prefix", Value: "/"}},
			Action:     "allow",
		}),
	})
	called := false
	err := g.ServeHTTP(httptest.NewRecorder(), l7Req("GET", "/api", "203.0.113.17:1"), nextHandler{&called})
	if err == nil || called {
		t.Fatal("IP 黑名单应先于 L7 拦截")
	}
	evs := g.readEvents(t)
	if len(evs) != 1 || evs[0].EventType != events.IPDenyMatch {
		t.Fatalf("应只有 IP 黑名单事件（L7 未评估）: %+v", evs)
	}
}

// TestL7FirstMatchStops 首中即停：高优先级 block 命中后不再评估后续 allow。
func TestL7FirstMatchStops(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		L7Rules: &l7rules.Config{Rules: []l7rules.RuleJSON{
			{
				ID: "l7-b", Priority: 50, Enabled: true,
				Conditions: []l7rules.ConditionJSON{{Type: "uri", Op: "prefix", Value: "/admin"}},
				Action:     "block",
			},
			{
				ID: "l7-a", Priority: 100, Enabled: true,
				Conditions: []l7rules.ConditionJSON{{Type: "uri", Op: "prefix", Value: "/"}},
				Action:     "allow",
			},
		}},
		RateLimits: []policyJSON{{
			ID: "cc1", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60, BurstCapacity: 1,
			Action: "REJECT", Priority: 1,
		}},
	})
	// /admin 命中 block（priority 50 先评估）
	rec := httptest.NewRecorder()
	called := false
	if err := g.ServeHTTP(rec, l7Req("GET", "/admin/x", "203.0.113.18:1"), nextHandler{&called}); err != nil || called {
		t.Fatal("首中 block 应终结请求")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("默认 block 状态码: %d", rec.Code)
	}
	// /other 命中 allow（priority 100），跳过 CC
	rec2 := httptest.NewRecorder()
	called = false
	if err := g.ServeHTTP(rec2, l7Req("GET", "/other", "203.0.113.18:1"), nextHandler{&called}); err != nil || !called {
		t.Fatal("后续规则 allow 应放行")
	}
	evs := g.readEvents(t)
	if len(evs) != 2 || evs[0].EventType != events.L7RuleBlock || evs[1].EventType != events.L7RuleAllow {
		t.Fatalf("两条命中事件: %+v", evs)
	}
}
