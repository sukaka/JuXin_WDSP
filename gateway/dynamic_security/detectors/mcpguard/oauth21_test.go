package mcpguard

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
)

func TestSessionBinderLifecycleAndLRU(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	b := NewSessionBinderWithLimits(3, 30*time.Minute)
	b.now = func() time.Time { return now }

	// Bind s1 -> p1
	if !b.BindOrVerify("app-1", "/mcp", "s1", "p1") {
		t.Fatal("initial bind must succeed")
	}
	// Same principal re-verifies
	now = now.Add(10 * time.Minute)
	if !b.BindOrVerify("app-1", "/mcp", "s1", "p1") {
		t.Fatal("same principal must succeed")
	}
	// Different principal rejected, original binding preserved
	if b.BindOrVerify("app-1", "/mcp", "s1", "p2") {
		t.Fatal("different principal must be rejected")
	}
	if !b.BindOrVerify("app-1", "/mcp", "s1", "p1") {
		t.Fatal("original owner must remain valid after rejected hijack attempt")
	}
	// Isolation across appID and endpointPath
	if !b.BindOrVerify("app-2", "/mcp", "s1", "p2") {
		t.Fatal("different app must be isolated")
	}
	if !b.BindOrVerify("app-1", "/mcp-v2", "s1", "p2") {
		t.Fatal("different endpoint must be isolated")
	}
	// LRU bound check: 4th distinct key evicts oldest (max=3)
	if !b.BindOrVerify("app-1", "/mcp", "s4", "p4") {
		t.Fatal("4th bind must succeed with eviction")
	}
	if b.Len() != 3 {
		t.Fatalf("Len() = %d, want <= 3", b.Len())
	}

	// TTL expiry allows new principal to re-bind
	now = now.Add(31 * time.Minute)
	if !b.BindOrVerify("app-1", "/mcp", "s4", "p-new") {
		t.Fatal("expired session should allow new principal")
	}
}

func TestSessionBinderConcurrentRace(t *testing.T) {
	b := NewSessionBinderWithLimits(64, time.Minute)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				sess := fmt.Sprintf("sess-%d", i%80)
				prin := fmt.Sprintf("p-%d", id%2)
				_ = b.BindOrVerify("app-1", "/mcp", sess, prin)
			}
		}(g)
	}
	wg.Wait()
	if b.Len() > 64 {
		t.Fatalf("Len() = %d exceeded max 64", b.Len())
	}
}

func TestEvaluateAndCheckSessionBinding(t *testing.T) {
	full := &Config{
		IdentitySalt:  "test-salt",
		SessionBinder: NewSessionBinder(),
		Apps: map[string]map[string]Endpoint{
			"app-1": {
				"/mcp": {
					Catalog:               testCatalog(),
					Mode:                  ModeProtect,
					RequireSessionBinding: true,
				},
			},
		},
	}

	const rawSess = "mcp-secret-session-token-12345"
	user1 := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-1", VerifiedTenantID: "t-1"}
	user2 := &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-2", VerifiedTenantID: "t-1"}

	// Request 1 (POST tools/call by user-1) binds the session
	ctx1 := newTestCtx()
	scoped1 := full.ForEndpoint("app-1", "/mcp")
	req1 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req1.Header.Set("Mcp-Session-Id", rawSess)
	NoteHeadObservations(ctx1, req1.Header.Get, scoped1)
	Evaluate(ctx1, callMsg(t, "echo", map[string]any{"text": "ok"}), scoped1, user1, "app-1", true)
	if findMatch(ctx1, "mcp.session_hijack_suspected") != nil {
		t.Fatal("first bind should not emit hijack")
	}

	// Request 2 (POST tools/list by user-2 reusing rawSess) -> BLOCK -32010
	ctx2 := newTestCtx()
	scoped2 := full.ForEndpoint("app-1", "/mcp")
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req2.Header.Set("Mcp-Session-Id", rawSess)
	NoteHeadObservations(ctx2, req2.Header.Get, scoped2)
	Evaluate(ctx2, otherMsg(t, "tools/list"), scoped2, user2, "app-1", true)
	m := findMatch(ctx2, "mcp.session_hijack_suspected")
	if m == nil || m.Severity != "HIGH" || m.Category != "BLOCK" || m.Evidence["mcp_error_code"] != "-32010" || m.Evidence["mcp_http_status"] != "403" {
		t.Fatalf("hijack match = %+v", m)
	}
	for k, v := range m.Evidence {
		if strings.Contains(v, rawSess) {
			t.Fatalf("evidence leaked raw Mcp-Session-Id: %s=%q", k, v)
		}
	}

	// Request 3 (GET Streamable HTTP by user-2 via CheckSessionBinding) -> shares same binder!
	ctx3 := newTestCtx()
	req3 := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req3.Header.Set("Mcp-Session-Id", rawSess)
	blocked := CheckSessionBinding(ctx3, req3, full, user2, "app-1", "/mcp", true)
	if !blocked {
		t.Fatal("GET reuse by user-2 must be blocked")
	}
	// Idempotent on same RequestContext
	if CheckSessionBinding(ctx3, req3, full, user2, "app-1", "/mcp", true) {
		t.Fatal("second CheckSessionBinding on same ctx should be idempotent no-op")
	}

	// Unauthenticated fallback uses tracking key (client IP / credential)
	ctxUnauth1 := newTestCtx()
	reqUnauth1 := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	reqUnauth1.RemoteAddr = "203.0.113.10:1234"
	reqUnauth1.Header.Set("Mcp-Session-Id", "anon-sess-1")
	if CheckSessionBinding(ctxUnauth1, reqUnauth1, full, nil, "app-1", "/mcp", true) {
		t.Fatal("initial unauth bind should pass")
	}
	ctxUnauth2 := newTestCtx()
	reqUnauth2 := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	reqUnauth2.RemoteAddr = "198.51.100.20:5678"
	reqUnauth2.Header.Set("Mcp-Session-Id", "anon-sess-1")
	if !CheckSessionBinding(ctxUnauth2, reqUnauth2, full, nil, "app-1", "/mcp", true) {
		t.Fatal("different unauth tracking key reusing session should block in PROTECT")
	}
}

func TestFormatOAuth21Challenge(t *testing.T) {
	valid := "https://mcp.example.com/.well-known/oauth-protected-resource"
	want := `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`
	if got := FormatOAuth21Challenge(valid); got != want {
		t.Fatalf("FormatOAuth21Challenge = %q, want %q", got, want)
	}

	invalidCases := []string{
		"",
		"http://mcp.example.com/.well-known/oauth-protected-resource",
		"javascript:alert(1)",
		"https://mcp.example.com/meta\r\nX-Evil: 1",
		"https://mcp.example.com/meta\nX-Evil: 1",
		`https://mcp.example.com/meta", realm="evil`,
		"https://user:pass@mcp.example.com/meta",
		"https://mcp.example.com/meta#frag",
		"https://",
		"https://mcp.example.com/" + strings.Repeat("a", 512),
	}
	for _, raw := range invalidCases {
		if got := FormatOAuth21Challenge(raw); got != "" {
			t.Errorf("FormatOAuth21Challenge(%q) = %q, want empty", raw, got)
		}
	}
}
