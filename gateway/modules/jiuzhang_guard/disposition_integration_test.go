// disposition.go 接线集成测试（WDSP P0-04 工作流 C）：
// 终止分支事件挂载 final_decision（内容完整——终止事实已记录后取 JSON）；放行/观察
// 事件不挂载（请求在途，Settled 门禁防提前 Finalize 锁死后续记录）。
package jiuzhang_guard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/temporaryblock"
)

// decodeEventFD 解析事件携带的 final_decision。
func decodeEventFD(t *testing.T, e events.Event) map[string]any {
	t.Helper()
	if len(e.FinalDecision) == 0 {
		t.Fatal("事件未携带 final_decision")
	}
	var m map[string]any
	if err := json.Unmarshal(e.FinalDecision, &m); err != nil {
		t.Fatalf("final_decision 非法 JSON: %v", err)
	}
	return m
}

func TestDispositionCCRejectEventCarriesFinalDecision(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		RateLimits: []policyJSON{{
			ID: "cc1", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60, BurstCapacity: 1,
			Action: "REJECT", Priority: 1,
		}},
	})
	ip := "203.0.113.88:1"
	called := false
	if err := g.ServeHTTP(httptest.NewRecorder(), req(ip, nil), nextHandler{&called}); err != nil || !called {
		t.Fatal("first request should pass")
	}
	called = false
	if err := g.ServeHTTP(httptest.NewRecorder(), req(ip, nil), nextHandler{&called}); err != nil || called {
		t.Fatal("second request should be 429")
	}
	for _, e := range g.readEvents(t) {
		if e.EventType != events.CCRequestRejected {
			continue
		}
		fd := decodeEventFD(t, e)
		if fd["completion_status"] != "ABORTED" || fd["security_action"] != "RATE_LIMIT" ||
			fd["executor_module"] != "CC" || fd["response_source"] != "GATEWAY" {
			t.Errorf("final_decision = %v", fd)
		}
		if fd["http_status"].(float64) != 429 || fd["response_committed"] != true {
			t.Errorf("status/committed = %v/%v", fd["http_status"], fd["response_committed"])
		}
		if fd["schema_version"].(float64) != 1 || fd["request_id"] != "11111111-2222-3333-4444-555555555555" {
			t.Errorf("标识字段 = %v", fd)
		}
		// 终止后模块补 SKIPPED（API/WAF 未到达）
		var apiSkipped bool
		for _, s := range fd["steps"].([]any) {
			sm := s.(map[string]any)
			if sm["module"] == "API" && sm["result"] == "SKIPPED" {
				apiSkipped = true
			}
		}
		if !apiSkipped {
			t.Errorf("终止后 API 应补 SKIPPED: %v", fd["steps"])
		}
		return
	}
	t.Fatal("CC_REQUEST_REJECTED event expected")
}

func TestDispositionManualBanEventCarriesFinalDecision(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1"})
	g.engine.blockCache.PutLocal(reqCtx(), temporaryblock.Block{
		ID: "mb1", ClientIP: "203.0.113.77", AppID: "app1",
		ExpiresAt: time.Now().Add(time.Hour), Auto: false,
	})
	called := false
	err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.77:1", nil), nextHandler{&called})
	if err == nil || called {
		t.Fatal("manual banned ip should be rejected")
	}
	for _, e := range g.readEvents(t) {
		if e.EventType != events.CCRequestRejected || e.Action != "TEMP_BLOCK" {
			continue
		}
		fd := decodeEventFD(t, e)
		if fd["executor_module"] != "MANUAL_BAN" || fd["security_action"] != "TEMP_BLOCK" {
			t.Errorf("final_decision = %v", fd)
		}
		// caddyhttp.Error 路径：记录时响应未提交
		if fd["response_committed"] != false {
			t.Errorf("committed = %v（caddyhttp.Error 路径应为 false）", fd["response_committed"])
		}
		reasons, _ := fd["reason_codes"].([]any)
		if len(reasons) != 1 || reasons[0] != "MANUAL_TEMP_BLOCK" {
			t.Errorf("reason_codes = %v", fd["reason_codes"])
		}
		return
	}
	t.Fatal("TEMP_BLOCK event expected")
}

func TestDispositionIPDenyEventCarriesFinalDecision(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1", AppCode: "shop",
		GlobalDeny: []ruleJSON{{ID: "d1", Address: "203.0.113.66", Priority: 1}},
	})
	called := false
	if err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.66:1", nil), nextHandler{&called}); err == nil || called {
		t.Fatal("deny should block")
	}
	for _, e := range g.readEvents(t) {
		if e.EventType != events.IPDenyMatch {
			continue
		}
		fd := decodeEventFD(t, e)
		if fd["executor_module"] != "IP_BLACKLIST" || fd["security_action"] != "BLOCK" ||
			fd["http_status"].(float64) != http.StatusForbidden {
			t.Errorf("final_decision = %v", fd)
		}
		return
	}
	t.Fatal("IP_DENY_MATCH event expected")
}

// 白名单放行：IP_ALLOW_MATCH 事件不挂 final_decision（放行非终止——请求仍过
// API 动态防护与 WAF，提前 Finalize 会落 UNKNOWN 并锁死后续记录）。
func TestDispositionAllowlistEventNoFinalDecision(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1", AppCode: "shop",
		GlobalAllow: []ruleJSON{{ID: "a1", Address: "203.0.113.67", Priority: 1}},
		GlobalDeny:  []ruleJSON{{ID: "d1", Address: "203.0.113.67", Priority: 2}},
	})
	called := false
	if err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.67:1", nil), nextHandler{&called}); err != nil || !called {
		t.Fatalf("allowlist should pass: %v", err)
	}
	for _, e := range g.readEvents(t) {
		if e.EventType == events.IPAllowMatch && len(e.FinalDecision) != 0 {
			t.Errorf("放行事件不应携带 final_decision: %s", e.FinalDecision)
		}
	}
}

// CC OBSERVE：观察事件不挂 final_decision（观察命中不进 security_action——契约 §2）。
func TestDispositionCCObserveEventNoFinalDecision(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID: "app1",
		RateLimits: []policyJSON{{
			ID: "cc-obs", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60, Action: "OBSERVE", Priority: 1,
		}},
	})
	for i := 0; i < 3; i++ {
		called := false
		if err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.91:1", nil), nextHandler{&called}); err != nil || !called {
			t.Fatalf("observe must not block: %v", err)
		}
	}
	for _, e := range g.readEvents(t) {
		if e.EventType == events.CCThresholdExceeded && len(e.FinalDecision) != 0 {
			t.Errorf("观察事件不应携带 final_decision: %s", e.FinalDecision)
		}
	}
}

// api_exceptions 装配（Provision 层 fail-closed）：段存在即严格解析，
// 与 api_dynamic_protection 开关无关；schema_version 不支持拒绝加载。
func TestAssembleAPIExceptions(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", AppCode: "shop"})
	if err := g.assembleAPIExceptions(); err != nil {
		t.Fatalf("缺省段装配应零行为变化: %v", err)
	}
	if g.apiExceptions != nil {
		t.Error("缺省段应不装配")
	}

	valid := `{"shop":[{"schema_version":1,"exception_id":"e1","version":2,"uri_prefix":"/api","methods":["POST"],"rule_refs":[{"detector_id":"api_schema","rule_id":"REQ-1"}]}]}`
	g2 := newTestGuard(t, Guard{AppID: "app1", AppCode: "shop", APIExceptions: json.RawMessage(valid)})
	if err := g2.assembleAPIExceptions(); err != nil {
		t.Fatalf("合法段装配失败: %v", err)
	}
	if len(g2.apiExceptions["shop"]) != 1 {
		t.Fatalf("装配结果 = %+v", g2.apiExceptions)
	}

	// schema_version 不支持 → 拒绝（fail-closed；不以 api_dynamic_protection 为前提）
	bad := `{"shop":[{"schema_version":99,"exception_id":"e1","version":1,"uri_prefix":"/api","methods":["POST"],"rule_refs":[{"detector_id":"api_schema","rule_id":"REQ-1"}]}]}`
	g3 := newTestGuard(t, Guard{AppID: "app1", AppCode: "shop", APIExceptions: json.RawMessage(bad)})
	if err := g3.assembleAPIExceptions(); err == nil {
		t.Error("不支持的 schema_version 应拒绝加载")
	}

	// Validate 预检同口径
	g4 := &Guard{EventsLog: t.TempDir() + "/events.log", APIExceptions: json.RawMessage(bad)}
	if err := g4.Validate(); err == nil {
		t.Error("Validate 应拒绝非法 api_exceptions 段")
	}
}
