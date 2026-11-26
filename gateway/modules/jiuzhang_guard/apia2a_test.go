package jiuzhang_guard

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/a2aguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/mcpguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"go.uber.org/zap"
)

func newA2ATestGuard(t *testing.T, policyJSON string) (*Guard, string) {
	t.Helper()
	dir := t.TempDir()
	evLog := filepath.Join(dir, "events.log")
	el, err := events.NewLogger(evLog, "gw-a2a-test")
	if err != nil {
		t.Fatalf("events.NewLogger: %v", err)
	}
	t.Cleanup(func() { _ = el.Close() })
	g := &Guard{
		AppID:        "app-a2a-1",
		AppCode:      "a2a-app",
		EventsLog:    evLog,
		GatewayNode:  "gw-a2a-test",
		IdentitySalt: "a2a-test-salt-not-a-real-secret-32b",
		APIA2APolicy: json.RawMessage(policyJSON),
		logger:       zap.NewNop(),
		events:       el,
	}
	if err := g.validateA2APolicy(); err != nil {
		t.Fatalf("validateA2APolicy: %v", err)
	}
	if err := g.assembleA2A(); err != nil {
		t.Fatalf("assembleA2A: %v", err)
	}
	return g, evLog
}

func readAccessControlEvents(t *testing.T, path string) []events.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("open events log: %v", err)
	}
	defer f.Close()
	var out []events.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev events.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal event: %v (line=%s)", err, line)
		}
		out = append(out, ev)
	}
	return out
}

func TestA2APolicyValidateAndAssembleFailClosed(t *testing.T) {
	g := &Guard{
		EventsLog:    filepath.Join(t.TempDir(), "events.log"),
		APIA2APolicy: json.RawMessage(`{"schema_version":1,"application_id":"app-1","mode":"PROTECT","unknown_field":1}`),
		logger:       zap.NewNop(),
	}
	if err := g.Validate(); err == nil {
		t.Fatal("Validate must reject unknown field in api_a2a_policy")
	}
	if err := g.assembleA2A(); err == nil {
		t.Fatal("assembleA2A must fail-closed on unknown field")
	}

	gOff := &Guard{
		EventsLog:    filepath.Join(t.TempDir(), "events.log"),
		APIA2APolicy: json.RawMessage(`{"schema_version":1,"application_id":"app-1","mode":"OFF","version":1}`),
		logger:       zap.NewNop(),
	}
	if err := gOff.Validate(); err != nil {
		t.Fatalf("OFF policy Validate failed: %v", err)
	}
	if err := gOff.assembleA2A(); err != nil {
		t.Fatalf("OFF policy assembleA2A failed: %v", err)
	}
	if gOff.apiA2A != nil {
		t.Fatal("OFF mode must leave g.apiA2A == nil for zero overhead")
	}
}

func TestA2AAgentCardDiscoveryE2E(t *testing.T) {
	g, evLog := newA2ATestGuard(t, `{
		"schema_version": 1,
		"application_id": "app-a2a-1",
		"mode": "OBSERVE",
		"version": 2,
		"card_discovery_enabled": true,
		"a2a_path_prefixes": ["/a2a", "/.well-known/agent.json", "/.well-known/agent-card.json"],
		"allowed_caller_agents": [],
		"max_delegation_depth": 3,
		"enforce_scope_attenuation": true,
		"loop_window_seconds": 60,
		"max_calls_per_task_window": 20,
		"lethal_trifecta_enabled": true,
		"confidential_read_patterns": [],
		"external_egress_patterns": []
	}`)

	cardBody := `{"name":"PlannerAgent","url":"https://user:pw@planner.example.com/a2a?key=secret","version":"1.2.3","skills":[{"id":"plan.create"},{"name":"plan.cancel"}],"authentication":{"schemes":["Bearer","OAuth2"]}}`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(cardBody))
		return nil
	})

	// First GET discovers and emits A2A_AGENT_CARD_DISCOVERED.
	req := httptest.NewRequest(http.MethodGet, "https://planner.example.com/.well-known/agent-card.json", nil)
	req.Header.Set("X-Request-Id", "req-card-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != cardBody {
		t.Fatalf("response altered: code=%d body=%q", rec.Code, rec.Body.String())
	}

	// Second immediate GET is deduplicated by bounded LRU (60s TTL).
	req2 := httptest.NewRequest(http.MethodGet, "https://planner.example.com/.well-known/agent-card.json", nil)
	req2.Header.Set("X-Request-Id", "req-card-2")
	rec2 := httptest.NewRecorder()
	if err := g.serveNext(rec2, req2, next); err != nil {
		t.Fatalf("serveNext #2: %v", err)
	}

	evs := readAccessControlEvents(t, evLog)
	if len(evs) != 1 {
		t.Fatalf("expected 1 deduped discovery event, got %d", len(evs))
	}
	if evs[0].EventType != events.A2AAgentCardDiscovered || evs[0].A2A == nil {
		t.Fatalf("unexpected event: %+v", evs[0])
	}
	if evs[0].A2A.AgentName != "PlannerAgent" || evs[0].A2A.AgentURL != "https://planner.example.com/a2a" ||
		evs[0].A2A.AgentVersion != "1.2.3" || len(evs[0].A2A.Skills) != 2 || len(evs[0].A2A.AuthSchemes) != 2 {
		t.Fatalf("unexpected A2A detail: %+v", evs[0].A2A)
	}
}

func TestA2ADelegationJWTAndLoopKillSwitchE2E(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: &privKey.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}
	jwksRaw, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})

	sign := func(claims map[string]any) string {
		payload, _ := json.Marshal(claims)
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		if err != nil {
			t.Fatal(err)
		}
		jws, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		s, err := jws.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	g, evLog := newA2ATestGuard(t, `{
		"schema_version": 1,
		"application_id": "app-a2a-1",
		"mode": "PROTECT",
		"version": 5,
		"card_discovery_enabled": true,
		"a2a_path_prefixes": ["/a2a"],
		"allowed_caller_agents": ["agent-b"],
		"max_delegation_depth": 2,
		"enforce_scope_attenuation": true,
		"loop_window_seconds": 60,
		"max_calls_per_task_window": 2,
		"lethal_trifecta_enabled": true,
		"confidential_read_patterns": ["/api/v1/secrets"],
		"external_egress_patterns": ["send_email"]
	}`)
	v, err := jwtverify.NewVerifier(jwtverify.VerifierConfig{
		Policy: jwtverify.Policy{
			ApplicationID: "app-a2a-1",
			Version:       "1",
			Mode:          jwtverify.ModeProtect,
			Selectors:     []jwtverify.Selector{{Methods: []string{"POST", "GET"}, PathPrefix: "/", TokenRequired: false}},
			Issuers: []jwtverify.IssuerConfig{{
				Issuer:     "https://idp.a2a.test",
				Audiences:  []string{"api://a2a"},
				Algorithms: []jwtverify.Algorithm{jwtverify.AlgRS256},
				KeySource:  jwtverify.KeySourceStaticJWKS,
				StaticJWKS: jwksRaw,
			}},
		},
		IdentitySecret: []byte(g.IdentitySalt),
	})
	if err != nil {
		t.Fatal(err)
	}
	g.jwtVerifier = v

	rpcBody := `{"jsonrpc":"2.0","id":11,"method":"tasks/send","params":{"id":"task-99","text":"ping"}}`
	var downstreamBody string
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		b, _ := io.ReadAll(r.Body)
		downstreamBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":11,"result":{"ok":true}}`))
		return nil
	})

	doReq := func(tok string, body string, reqID string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/a2a", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-Id", reqID)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		g.verifyJWTTrust(req)
		rec := httptest.NewRecorder()
		if err := g.serveNext(rec, req, next); err != nil {
			t.Fatalf("serveNext(%s): %v", reqID, err)
		}
		return rec
	}

	// 1. Valid attenuated delegation token passes (twice within max_calls_per_task_window=2) and preserves body!
	goodTok := sign(map[string]any{
		"iss": "https://idp.a2a.test", "sub": "user-1", "aud": "api://a2a",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"scope": "tasks:read",
		"act": map[string]any{
			"sub":   "agent-b",
			"scope": "tasks:read",
			"act":   map[string]any{"sub": "agent-a", "scope": "tasks:read tasks:write"},
		},
	})
	rec1 := doReq(goodTok, rpcBody, "req-good-1")
	if rec1.Code != http.StatusOK || downstreamBody != rpcBody {
		t.Fatalf("valid A2A call failed or mutated body: code=%d body=%q", rec1.Code, downstreamBody)
	}
	rec2 := doReq(goodTok, rpcBody, "req-good-2")
	if rec2.Code != http.StatusOK {
		t.Fatalf("2nd call within window should pass: code=%d", rec2.Code)
	}

	// 2. 3rd call on same task hits loop kill-switch -> 429 JSON-RPC -32020 + A2A_LOOP_KILLED.
	rec3 := doReq(goodTok, rpcBody, "req-loop-3")
	if rec3.Code != http.StatusTooManyRequests || !strings.Contains(rec3.Body.String(), `"code":-32020`) {
		t.Fatalf("expected 429 -32020 loop kill, got %d %s", rec3.Code, rec3.Body.String())
	}

	// 3. Scope escalation token -> 403 JSON-RPC -32024 + A2A_BLOCKED.
	escTok := sign(map[string]any{
		"iss": "https://idp.a2a.test", "sub": "user-1", "aud": "api://a2a",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"scope": "tasks:read admin:*",
		"act":   map[string]any{"sub": "agent-b"},
	})
	recEsc := doReq(escTok, rpcBody, "req-esc-1")
	if recEsc.Code != http.StatusForbidden || !strings.Contains(recEsc.Body.String(), `"code":-32024`) {
		t.Fatalf("expected 403 -32024 scope escalation, got %d %s", recEsc.Code, recEsc.Body.String())
	}

	// 4. Depth 3 > max 2 -> 403 JSON-RPC -32023 + A2A_BLOCKED.
	deepTok := sign(map[string]any{
		"iss": "https://idp.a2a.test", "sub": "user-1", "aud": "api://a2a",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"act": map[string]any{
			"sub": "agent-b",
			"act": map[string]any{
				"sub": "agent-a",
				"act": map[string]any{"sub": "agent-root"},
			},
		},
	})
	recDeep := doReq(deepTok, rpcBody, "req-deep-1")
	if recDeep.Code != http.StatusForbidden || !strings.Contains(recDeep.Body.String(), `"code":-32023`) {
		t.Fatalf("expected 403 -32023 depth exceeded, got %d %s", recDeep.Code, recDeep.Body.String())
	}

	evs := readAccessControlEvents(t, evLog)
	if len(evs) != 3 {
		t.Fatalf("expected 3 security events (loop, scope, depth), got %d: %+v", len(evs), evs)
	}
	if evs[0].EventType != events.A2ALoopKilled || evs[0].A2A.RuleID != a2aguard.RuleRecursiveLoopDetected {
		t.Fatalf("event 0 = %+v", evs[0])
	}
	if evs[1].EventType != events.A2ABlocked || evs[1].A2A.RuleID != a2aguard.RuleDelegationScopeEscalation {
		t.Fatalf("event 1 = %+v", evs[1])
	}
	if evs[2].EventType != events.A2ABlocked || evs[2].A2A.RuleID != a2aguard.RuleDelegationDepthExceeded {
		t.Fatalf("event 2 = %+v", evs[2])
	}
}

func TestA2ALethalTrifectaFromMCPConfidentialToolAndMCPOAuthSanitize(t *testing.T) {
	// Build a Guard with BOTH apiMCPGuard (CONFIDENTIAL tool + SANITIZE + OAuth2.1 metadata) AND apiA2A.
	hashes := []string{"mcp-tool-sha256:v1:read_vault", "mcp-tool-sha256:v1:echo"}
	sort.Strings(hashes)
	sum := sha256.Sum256([]byte(strings.Join(hashes, "")))
	catHash := "mcp-catalog-sha256:v1:" + hex.EncodeToString(sum[:])

	g, _ := newAPITestGuard(t, "PROTECT", nil)
	dir := t.TempDir()
	evLog := filepath.Join(dir, "ac-events.log")
	el, err := events.NewLogger(evLog, "gw-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = el.Close() })
	g.events = el
	g.AppID = "app-1"
	g.APIA2APolicy = json.RawMessage(`{
		"schema_version": 1,
		"application_id": "app-1",
		"mode": "PROTECT",
		"version": 1,
		"card_discovery_enabled": true,
		"a2a_path_prefixes": ["/a2a"],
		"allowed_caller_agents": [],
		"max_delegation_depth": 3,
		"enforce_scope_attenuation": true,
		"loop_window_seconds": 60,
		"max_calls_per_task_window": 20,
		"lethal_trifecta_enabled": true,
		"confidential_read_patterns": ["/api/v1/secrets"],
		"external_egress_patterns": ["send_email"]
	}`)
	if err := g.assembleA2A(); err != nil {
		t.Fatal(err)
	}

	g.apiMCPGuard = &mcpguard.Config{
		IdentitySalt: g.IdentitySalt,
		Apps: map[string]map[string]mcpguard.Endpoint{
			"app-1": {
				"/mcp": {
					Mode:                     mcpguard.ModeProtect,
					ResponseGuardMode:        mcpguard.ResponseGuardSanitize,
					OAuthResourceMetadataURL: "https://mcp.example.com/.well-known/oauth-protected-resource",
					Catalog: &mcpguard.Catalog{
						Name: "cat-1",
						Hash: catHash,
						Tools: map[string]*mcpguard.Tool{
							"read_vault": {
								Name:               "read_vault",
								Hash:               "mcp-tool-sha256:v1:read_vault",
								RiskLevel:          "LOW",
								DataClassification: mcpguard.ClassificationConfidential,
							},
							"echo": {
								Name:               "echo",
								Hash:               "mcp-tool-sha256:v1:echo",
								RiskLevel:          "LOW",
								DataClassification: "PUBLIC",
							},
						},
					},
				},
			},
		},
	}

	verified := jwtverify.VerificationResult{
		Status:              jwtverify.StatusVerified,
		VerifiedPrincipalID: "principal-mcp-a2a",
		VerifiedTenantID:    "tenant-1",
	}

	// 1. MCP SANITIZE response replacement: upstream returns invisible zero-width chars -> gateway strips them cleanly.
	nextSanitize := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"text\":\"hello\u200Bworld\"}}"))
		return nil
	})
	reqSan := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`))
	reqSan.Header.Set("Content-Type", "application/json")
	reqSan.Header.Set("X-Request-Id", "req-mcp-san-1")
	*reqSan = *reqSan.WithContext(context.WithValue(reqSan.Context(), jwtResultKey{}, verified))
	recSan := httptest.NewRecorder()
	if err := g.serveNext(recSan, reqSan, nextSanitize); err != nil {
		t.Fatalf("serveNext sanitize: %v", err)
	}
	if recSan.Code != http.StatusOK || strings.Contains(recSan.Body.String(), "\u200B") || !strings.Contains(recSan.Body.String(), "helloworld") {
		t.Fatalf("MCP sanitized response replacement failed: code=%d body=%q", recSan.Code, recSan.Body.String())
	}

	// 2. MCP OAuth 2.1 WWW-Authenticate header on 403 (-32010 unverified caller).
	reqOAuth := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`))
	reqOAuth.Header.Set("Content-Type", "application/json")
	reqOAuth.Header.Set("X-Request-Id", "req-mcp-oauth-1")
	unverified := jwtverify.VerificationResult{Status: jwtverify.StatusInvalid, ReasonCode: jwtverify.ReasonMissingToken}
	*reqOAuth = *reqOAuth.WithContext(context.WithValue(reqOAuth.Context(), jwtResultKey{}, unverified))
	recOAuth := httptest.NewRecorder()
	if err := g.serveNext(recOAuth, reqOAuth, nextSanitize); err != nil {
		t.Fatalf("serveNext oauth: %v", err)
	}
	wantChallenge := `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`
	if recOAuth.Code != http.StatusForbidden || recOAuth.Header().Get("WWW-Authenticate") != wantChallenge {
		t.Fatalf("expected 403 + WWW-Authenticate %q, got %d / %q", wantChallenge, recOAuth.Code, recOAuth.Header().Get("WWW-Authenticate"))
	}

	// 3. Cross-protocol Lethal Trifecta: CONFIDENTIAL MCP tool read -> A2A external egress blocked (403, -32021, A2A_LETHAL_TRIFECTA).
	nextOK := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":3,"result":{"secret":"ok"}}`))
		return nil
	})
	reqConf := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_vault","arguments":{}}}`))
	reqConf.Header.Set("Content-Type", "application/json")
	reqConf.Header.Set("X-Request-Id", "req-mcp-conf-1")
	*reqConf = *reqConf.WithContext(context.WithValue(reqConf.Context(), jwtResultKey{}, verified))
	recConf := httptest.NewRecorder()
	if err := g.serveNext(recConf, reqConf, nextOK); err != nil {
		t.Fatalf("serveNext confidential mcp: %v", err)
	}
	if recConf.Code != http.StatusOK {
		t.Fatalf("CONFIDENTIAL read tool should succeed and taint session, got %d", recConf.Code)
	}

	// Now same verified principal invokes A2A external egress -> blocked with -32021!
	reqA2A := httptest.NewRequest(http.MethodPost, "/a2a", strings.NewReader(`{"jsonrpc":"2.0","id":4,"method":"tasks/send","params":{"action":"send_email","to":"leak@evil.test"}}`))
	reqA2A.Header.Set("Content-Type", "application/json")
	reqA2A.Header.Set("X-Request-Id", "req-a2a-trifecta-1")
	*reqA2A = *reqA2A.WithContext(context.WithValue(reqA2A.Context(), jwtResultKey{}, verified))
	recA2A := httptest.NewRecorder()
	if err := g.serveNext(recA2A, reqA2A, nextOK); err != nil {
		t.Fatalf("serveNext a2a trifecta: %v", err)
	}
	if recA2A.Code != http.StatusForbidden || !strings.Contains(recA2A.Body.String(), `"code":-32021`) {
		t.Fatalf("expected 403 -32021 lethal trifecta block after MCP CONFIDENTIAL read, got %d %s", recA2A.Code, recA2A.Body.String())
	}
	evs := readAccessControlEvents(t, evLog)
	if len(evs) != 1 || evs[0].EventType != events.A2ALethalTrifecta || evs[0].A2A.RuleID != a2aguard.RuleLethalTrifectaBlocked {
		t.Fatalf("expected A2A_LETHAL_TRIFECTA event, got %+v", evs)
	}
}
