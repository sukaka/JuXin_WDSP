package a2aguard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

func samplePolicyJSON() json.RawMessage {
	return json.RawMessage(`{
		"schema_version": 1,
		"application_id": "11111111-1111-1111-1111-111111111111",
		"mode": "PROTECT",
		"version": 3,
		"card_discovery_enabled": true,
		"a2a_path_prefixes": ["/a2a", "/.well-known/agent.json", "/.well-known/agent-card.json"],
		"allowed_caller_agents": ["agent-planner", "principal-allowed"],
		"max_delegation_depth": 2,
		"enforce_scope_attenuation": true,
		"loop_window_seconds": 60,
		"max_calls_per_task_window": 3,
		"lethal_trifecta_enabled": true,
		"confidential_read_patterns": ["/api/v1/secrets", "/api/v1/customers", "read_secret", "query_pii"],
		"external_egress_patterns": ["send_email", "webhook", "http_post", "upload_external"]
	}`)
}

func TestParseAndValidatePolicyStrict(t *testing.T) {
	pol, err := ParseAndValidatePolicy(samplePolicyJSON())
	if err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if pol.Mode != ModeProtect || pol.MaxDelegationDepth != 2 || pol.MaxCallsPerTaskWindow != 3 {
		t.Fatalf("unexpected parsed policy: %+v", pol)
	}

	// Minimal OFF policy succeeds with defaults.
	if _, err := ParseAndValidatePolicy(json.RawMessage(`{"schema_version":1,"application_id":"app-1","mode":"OFF","version":1}`)); err != nil {
		t.Fatalf("minimal OFF policy rejected: %v", err)
	}

	badCases := []struct {
		name string
		raw  string
	}{
		{"unknown field", `{"schema_version":1,"application_id":"a","mode":"OFF","version":1,"future_flag":true}`},
		{"trailing json", `{"schema_version":1,"application_id":"a","mode":"OFF","version":1}{}`},
		{"bad schema_version", `{"schema_version":2,"application_id":"a","mode":"OFF","version":1}`},
		{"bad mode", `{"schema_version":1,"application_id":"a","mode":"DENY","version":1}`},
		{"depth too small", `{"schema_version":1,"application_id":"a","mode":"PROTECT","version":1,"max_delegation_depth":0,"loop_window_seconds":60,"max_calls_per_task_window":20}`},
		{"depth too large", `{"schema_version":1,"application_id":"a","mode":"PROTECT","version":1,"max_delegation_depth":11,"loop_window_seconds":60,"max_calls_per_task_window":20}`},
		{"loop window too small", `{"schema_version":1,"application_id":"a","mode":"PROTECT","version":1,"max_delegation_depth":3,"loop_window_seconds":4,"max_calls_per_task_window":20}`},
		{"loop window too large", `{"schema_version":1,"application_id":"a","mode":"PROTECT","version":1,"max_delegation_depth":3,"loop_window_seconds":3601,"max_calls_per_task_window":20}`},
		{"max calls out of range", `{"schema_version":1,"application_id":"a","mode":"PROTECT","version":1,"max_delegation_depth":3,"loop_window_seconds":60,"max_calls_per_task_window":10001}`},
		{"prefix missing slash", `{"schema_version":1,"application_id":"a","mode":"PROTECT","version":1,"a2a_path_prefixes":["a2a"],"max_delegation_depth":3,"loop_window_seconds":60,"max_calls_per_task_window":20}`},
		{"prefix with query", `{"schema_version":1,"application_id":"a","mode":"PROTECT","version":1,"a2a_path_prefixes":["/a2a?x=1"],"max_delegation_depth":3,"loop_window_seconds":60,"max_calls_per_task_window":20}`},
		{"control char in agent", `{"schema_version":1,"application_id":"a","mode":"PROTECT","version":1,"allowed_caller_agents":["bad\nagent"],"max_delegation_depth":3,"loop_window_seconds":60,"max_calls_per_task_window":20}`},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseAndValidatePolicy(json.RawMessage(tc.raw)); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestAgentCardDiscoverySanitizeAndDedup(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	pol, err := ParseAndValidatePolicy(samplePolicyJSON())
	if err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(pol, EngineOptions{
		Now:          func() time.Time { return now },
		CardDedupTTL: 60 * time.Second,
		CardDedupMax: 3,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !eng.ShouldObserveAgentCard("GET", "/.well-known/agent.json") ||
		!eng.ShouldObserveAgentCard("GET", "//.well-known/agent-card.json") ||
		eng.ShouldObserveAgentCard("POST", "/.well-known/agent.json") {
		t.Fatal("ShouldObserveAgentCard path/method check failed")
	}

	cardJSON := []byte(`{
		"name": "Billing Agent\n",
		"url": "https://user:supersecret@billing.example.com/a2a?api_key=xyz#frag",
		"version": "2.1.0",
		"skills": [
			{"id": "invoice.read", "name": "Read Invoice"},
			{"name": "Pay Invoice"},
			{"id": "invoice.read"}
		],
		"authentication": {"schemes": ["Bearer", "OAuth2", "Bearer"]}
	}`)

	// Non-2xx, compressed, non-JSON, and oversized responses are ignored.
	if _, ok := eng.ObserveAgentCard("app-1", 404, "application/json", "", cardJSON, ""); ok {
		t.Fatal("non-2xx must be ignored")
	}
	if _, ok := eng.ObserveAgentCard("app-1", 200, "application/json", "gzip", cardJSON, ""); ok {
		t.Fatal("compressed response must be ignored")
	}
	if _, ok := eng.ObserveAgentCard("app-1", 200, "text/html", "", cardJSON, ""); ok {
		t.Fatal("non-JSON response must be ignored")
	}
	big := make([]byte, MaxAgentCardBytes+1)
	if _, ok := eng.ObserveAgentCard("app-1", 200, "application/json", "", big, ""); ok {
		t.Fatal("oversized >256KiB card must be ignored")
	}

	card, ok := eng.ObserveAgentCard("app-1", 200, "application/json; charset=utf-8", "", cardJSON, "")
	if !ok || card == nil {
		t.Fatal("expected valid card discovery")
	}
	if card.Name != "Billing Agent" || card.Version != "2.1.0" {
		t.Fatalf("card metadata = %+v", card)
	}
	if card.URL != "https://billing.example.com/a2a" {
		t.Fatalf("credentials/query/fragment not stripped: %q", card.URL)
	}
	if !reflect.DeepEqual(card.Skills, []string{"invoice.read", "Pay Invoice"}) {
		t.Fatalf("skills = %v", card.Skills)
	}
	if !reflect.DeepEqual(card.AuthSchemes, []string{"Bearer", "OAuth2"}) {
		t.Fatalf("auth_schemes = %v", card.AuthSchemes)
	}

	// Dedup within 60s TTL.
	if _, ok := eng.ObserveAgentCard("app-1", 200, "application/json", "", cardJSON, ""); ok {
		t.Fatal("duplicate card within TTL must be suppressed")
	}
	// After 61s TTL expires -> emits again.
	now = now.Add(61 * time.Second)
	if _, ok := eng.ObserveAgentCard("app-1", 200, "application/json", "", cardJSON, ""); !ok {
		t.Fatal("card after TTL expiry must emit again")
	}

	// Verify bounded LRU eviction (max 3).
	for i := 0; i < 10; i++ {
		c := []byte(fmt.Sprintf(`{"name":"Agent-%d","url":"https://a%d.example.com/a2a"}`, i, i))
		eng.ObserveAgentCard("app-1", 200, "application/json", "", c, "")
	}
	if eng.cardDedup.Len() > 3 {
		t.Fatalf("cardDedup exceeded cap: %d", eng.cardDedup.Len())
	}

	// Skills capped <= 32, auth_schemes capped <= 16.
	var manySkills []map[string]string
	for i := 0; i < 50; i++ {
		manySkills = append(manySkills, map[string]string{"id": fmt.Sprintf("skill-%d", i)})
	}
	var manyAuth []string
	for i := 0; i < 25; i++ {
		manyAuth = append(manyAuth, fmt.Sprintf("scheme-%d", i))
	}
	cappedRaw, _ := json.Marshal(map[string]any{
		"name":           "BigAgent",
		"url":            "javascript:alert(1)",
		"skills":         manySkills,
		"authentication": map[string]any{"schemes": manyAuth},
	})
	capped, ok := ParseAgentCard(cappedRaw, "https://user:pw@fallback.example.com/card?token=1")
	if !ok {
		t.Fatal("expected parse ok")
	}
	if len(capped.Skills) != MaxAgentSkills || len(capped.AuthSchemes) != MaxAgentAuthSchemes {
		t.Fatalf("caps not enforced: skills=%d auth=%d", len(capped.Skills), len(capped.AuthSchemes))
	}
	if capped.URL != "https://fallback.example.com/card" {
		t.Fatalf("javascript url must be rejected and fallback sanitized, got %q", capped.URL)
	}
}

func TestDelegationAllowlistDepthAndScopeAttenuation(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	pol, err := ParseAndValidatePolicy(samplePolicyJSON())
	if err != nil {
		t.Fatal(err)
	}
	eng, err := NewEngine(pol, EngineOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}

	rpcBody := []byte(`{"jsonrpc":"2.0","id":"req-1","method":"tasks/send","params":{"id":"task-42","message":{"text":"hello"}}}`)

	t.Run("unverified JWT cannot spoof X-A2A-Agent-ID", func(t *testing.T) {
		dec := eng.EvaluateRequest(EvalInput{
			AppID:         "app-1",
			Method:        http.MethodPost,
			Path:          "/a2a",
			Body:          rpcBody,
			HeaderAgentID: "agent-planner", // in allowlist, but JWT is NOT verified!
			CallerKey:     "ip:10.0.0.1",
			JWT:           &jwtverify.VerificationResult{Status: jwtverify.StatusInvalid},
		})
		if !dec.Matched || !dec.Block || dec.RuleID != RuleCallerAgentDenied || dec.HTTPStatus != 403 || dec.JSONRPCCode != CodeCallerAgentDenied {
			t.Fatalf("expected caller_agent_denied block, got %+v", dec)
		}
	})

	t.Run("verified JWT caller not in allowlist denied", func(t *testing.T) {
		dec := eng.EvaluateRequest(EvalInput{
			AppID:     "app-1",
			Method:    http.MethodPost,
			Path:      "/a2a",
			Body:      rpcBody,
			CallerKey: "jwt:other",
			JWT: &jwtverify.VerificationResult{
				Status:              jwtverify.StatusVerified,
				VerifiedPrincipalID: "other-principal",
				VerifiedAZP:         "rogue-agent",
			},
		})
		if !dec.Matched || !dec.Block || dec.RuleID != RuleCallerAgentDenied || dec.JSONRPCCode != -32022 {
			t.Fatalf("expected caller_agent_denied, got %+v", dec)
		}
	})

	t.Run("delegation depth exceeded blocked with -32023", func(t *testing.T) {
		dec := eng.EvaluateRequest(EvalInput{
			AppID:     "app-1",
			Method:    http.MethodPost,
			Path:      "/a2a",
			Body:      rpcBody,
			CallerKey: "jwt:depth",
			JWT: &jwtverify.VerificationResult{
				Status:              jwtverify.StatusVerified,
				VerifiedPrincipalID: "principal-allowed",
				DelegationChain:     []string{"agent-3", "agent-2", "agent-1"}, // depth 3 > max 2
			},
		})
		if !dec.Matched || !dec.Block || dec.RuleID != RuleDelegationDepthExceeded || dec.HTTPStatus != 403 || dec.JSONRPCCode != -32023 || dec.DelegationDepth != 3 {
			t.Fatalf("expected delegation_depth_exceeded, got %+v", dec)
		}
	})

	t.Run("scope escalation (child not subset of parent) blocked with -32024", func(t *testing.T) {
		dec := eng.EvaluateRequest(EvalInput{
			AppID:     "app-1",
			Method:    http.MethodPost,
			Path:      "/a2a",
			Body:      rpcBody,
			CallerKey: "jwt:esc1",
			JWT: &jwtverify.VerificationResult{
				Status:              jwtverify.StatusVerified,
				VerifiedPrincipalID: "principal-allowed",
				VerifiedScopes:      []string{"orders:read", "orders:delete"},
				DelegationChain:     []string{"agent-b", "agent-a"},
				DelegationScopes:    [][]string{{"orders:read"}, {"orders:read", "orders:write"}},
			},
		})
		if !dec.Matched || !dec.Block || dec.RuleID != RuleDelegationScopeEscalation || dec.HTTPStatus != 403 || dec.JSONRPCCode != -32024 {
			t.Fatalf("expected delegation_scope_escalation, got %+v", dec)
		}
	})

	t.Run("wildcard/admin scope on delegated chain (depth>=1) blocked with -32024", func(t *testing.T) {
		for _, badScope := range []string{"*", "admin:*", "root", "orders:*"} {
			dec := eng.EvaluateRequest(EvalInput{
				AppID:     "app-1",
				Method:    http.MethodPost,
				Path:      "/a2a",
				Body:      rpcBody,
				CallerKey: "jwt:wild-" + badScope,
				JWT: &jwtverify.VerificationResult{
					Status:              jwtverify.StatusVerified,
					VerifiedPrincipalID: "principal-allowed",
					VerifiedScopes:      []string{badScope},
					DelegationChain:     []string{"agent-b"},
				},
			})
			if !dec.Matched || !dec.Block || dec.RuleID != RuleDelegationScopeEscalation || dec.JSONRPCCode != -32024 {
				t.Fatalf("scope %q on delegated chain should block, got %+v", badScope, dec)
			}
		}
	})

	t.Run("valid attenuated delegation passes", func(t *testing.T) {
		dec := eng.EvaluateRequest(EvalInput{
			AppID:         "app-1",
			Method:        http.MethodPost,
			Path:          "/a2a",
			Body:          rpcBody,
			HeaderAgentID: "agent-planner",
			CallerKey:     "jwt:valid",
			JWT: &jwtverify.VerificationResult{
				Status:              jwtverify.StatusVerified,
				VerifiedPrincipalID: "some-fp",
				VerifiedScopes:      []string{"orders:read"},
				DelegationChain:     []string{"agent-b", "agent-a"},
				DelegationScopes:    [][]string{{"orders:read"}, {"orders:read", "orders:write"}},
			},
		})
		if dec.Matched || dec.Block {
			t.Fatalf("valid attenuated request should pass, got %+v", dec)
		}
	})

	t.Run("OBSERVE mode records without blocking", func(t *testing.T) {
		obsPol := clonePolicy(pol)
		obsPol.Mode = ModeObserve
		obsEng, err := NewEngine(&obsPol, EngineOptions{Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		dec := obsEng.EvaluateRequest(EvalInput{
			AppID:     "app-1",
			Method:    http.MethodPost,
			Path:      "/a2a",
			Body:      rpcBody,
			CallerKey: "jwt:obs",
			JWT: &jwtverify.VerificationResult{
				Status:              jwtverify.StatusVerified,
				VerifiedPrincipalID: "principal-allowed",
				DelegationChain:     []string{"a", "b", "c"},
			},
		})
		if !dec.Matched || dec.Block || dec.EventType != EventObserved || dec.RuleID != RuleDelegationDepthExceeded {
			t.Fatalf("OBSERVE should match without blocking, got %+v", dec)
		}
	})
}

func TestRecursiveLoopKillSwitchAndLethalTrifecta(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	pol, err := ParseAndValidatePolicy(samplePolicyJSON())
	if err != nil {
		t.Fatal(err)
	}
	pol.AllowedCallerAgents = nil
	eng, err := NewEngine(pol, EngineOptions{
		Now:          func() time.Time { return now },
		LoopMaxKeys:  8,
		TaintMaxKeys: 8,
		TaintTTL:     120 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	rpcBody := []byte(`{"jsonrpc":"2.0","id":7,"method":"message/send","params":{"taskId":"t-loop-1"}}`)
	for i := 1; i <= 3; i++ {
		dec := eng.EvaluateRequest(EvalInput{
			AppID: "app-1", Method: http.MethodPost, Path: "/a2a", Body: rpcBody, CallerKey: "jwt:u1",
		})
		if dec.Matched {
			t.Fatalf("call %d within limit 3 should pass: %+v", i, dec)
		}
	}
	// 4th call within 60s exceeds max_calls_per_task_window=3 -> 429 / -32020 / A2A_LOOP_KILLED.
	dec := eng.EvaluateRequest(EvalInput{
		AppID: "app-1", Method: http.MethodPost, Path: "/a2a", Body: rpcBody, CallerKey: "jwt:u1",
	})
	if !dec.Matched || !dec.Block || dec.RuleID != RuleRecursiveLoopDetected ||
		dec.HTTPStatus != 429 || dec.JSONRPCCode != -32020 || dec.EventType != EventLoopKilled {
		t.Fatalf("expected loop kill-switch, got %+v", dec)
	}
	// Different appID or different callerKey is strictly isolated.
	if decOther := eng.EvaluateRequest(EvalInput{
		AppID: "app-2", Method: http.MethodPost, Path: "/a2a", Body: rpcBody, CallerKey: "jwt:u1",
	}); decOther.Matched {
		t.Fatalf("different app must be isolated: %+v", decOther)
	}

	// After window elapses, calls succeed again.
	now = now.Add(61 * time.Second)
	if decAfter := eng.EvaluateRequest(EvalInput{
		AppID: "app-1", Method: http.MethodPost, Path: "/a2a", Body: rpcBody, CallerKey: "jwt:u1",
	}); decAfter.Matched {
		t.Fatalf("after loop window expiry calls should pass: %+v", decAfter)
	}

	// Lethal Trifecta: untainted egress passes.
	egressRPC := []byte(`{"jsonrpc":"2.0","id":9,"method":"tasks/send","params":{"action":"send_email","to":"ext@evil.test"}}`)
	if decClean := eng.EvaluateRequest(EvalInput{
		AppID: "app-1", Method: http.MethodPost, Path: "/a2a", Body: egressRPC, CallerKey: "jwt:trifecta",
	}); decClean.Matched {
		t.Fatalf("untainted egress should pass: %+v", decClean)
	}

	// Step 1: Confidential read taints (app-1, jwt:trifecta).
	if decRead := eng.EvaluateRequest(EvalInput{
		AppID: "app-1", Method: http.MethodGet, Path: "/api/v1/secrets/db-password", CallerKey: "jwt:trifecta",
	}); decRead.Matched {
		t.Fatalf("confidential read alone should pass: %+v", decRead)
	}

	// Step 2: Same app + principal invokes external egress -> 403 / -32021 / A2A_LETHAL_TRIFECTA.
	decTrifecta := eng.EvaluateRequest(EvalInput{
		AppID: "app-1", Method: http.MethodPost, Path: "/a2a", Body: egressRPC, CallerKey: "jwt:trifecta",
	})
	if !decTrifecta.Matched || !decTrifecta.Block || decTrifecta.RuleID != RuleLethalTrifectaBlocked ||
		decTrifecta.HTTPStatus != 403 || decTrifecta.JSONRPCCode != -32021 || decTrifecta.EventType != EventLethalTrifecta {
		t.Fatalf("expected lethal trifecta block, got %+v", decTrifecta)
	}
	if !strings.Contains(decTrifecta.Reason, "tainted(") || !strings.Contains(decTrifecta.Reason, "send_email") {
		t.Fatalf("unexpected reason: %q", decTrifecta.Reason)
	}

	// Different app/principal must NOT be tainted.
	if decIso := eng.EvaluateRequest(EvalInput{
		AppID: "app-2", Method: http.MethodPost, Path: "/a2a", Body: egressRPC, CallerKey: "jwt:trifecta",
	}); decIso.Matched {
		t.Fatalf("taint leaked across apps: %+v", decIso)
	}

	// MCP confidential tool taint hook + expiry after 120s.
	eng.RecordConfidentialTaint("app-1", "jwt:mcp-user", "mcp:confidential:read_customer_vault")
	if decMCP := eng.EvaluateRequest(EvalInput{
		AppID: "app-1", Method: http.MethodPost, Path: "/a2a", Body: egressRPC, CallerKey: "jwt:mcp-user",
	}); !decMCP.Matched || decMCP.RuleID != RuleLethalTrifectaBlocked {
		t.Fatalf("MCP confidential read must trigger A2A lethal trifecta: %+v", decMCP)
	}
	now = now.Add(121 * time.Second)
	if decExp := eng.EvaluateRequest(EvalInput{
		AppID: "app-1", Method: http.MethodPost, Path: "/a2a", Body: egressRPC, CallerKey: "jwt:mcp-user",
	}); decExp.Matched {
		t.Fatalf("expired taint (>120s) should not block: %+v", decExp)
	}

	// Verify bounded memory caps (max 8 keys) + concurrent race safety.
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				k := fmt.Sprintf("caller-%d-%d", gid, i)
				eng.RecordConfidentialTaint("app-1", k, "mcp:secret")
				eng.EvaluateRequest(EvalInput{
					AppID: "app-1", Method: http.MethodPost, Path: "/a2a", Body: rpcBody, CallerKey: k,
				})
			}
		}(g)
	}
	wg.Wait()
	if eng.loopTracker.Len() > 8 || eng.taintTracker.Len() > 8 {
		t.Fatalf("bounded memory cap violated: loop=%d taint=%d", eng.loopTracker.Len(), eng.taintTracker.Len())
	}
}
