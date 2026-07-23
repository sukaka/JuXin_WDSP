package detectors

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func authTestCtx() *dsctx.RequestContext {
	return dsctx.New("t", dsctx.DefaultParseLimits())
}

func findMatch(ctx *dsctx.RequestContext, ruleID string) *dsctx.DetectorMatch {
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == ruleID {
			cp := m
			return &cp
		}
	}
	return nil
}

func TestAuthentication_UnauthenticatedAPI(t *testing.T) {
	ctx := authTestCtx()
	r := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	CheckAuthentication(ctx, r, true)
	m := findMatch(ctx, "auth.unauthenticated_api")
	if m == nil {
		t.Fatal("expected UNAUTHENTICATED_API match")
	}
	if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 10 {
		t.Fatalf("bad match attrs: %+v", m)
	}
}

func TestAuthentication_NonAPIWithoutCredentialNoMatch(t *testing.T) {
	// 负例：非 API 流量无凭据属正常（静态资源），不产生 match
	ctx := authTestCtx()
	r := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	CheckAuthentication(ctx, r, false)
	if ctx.MatchCount() != 0 {
		t.Fatalf("expected no match, got %+v", ctx.CopyMatches())
	}
}

func TestAuthentication_WeakCredentials(t *testing.T) {
	cases := []struct {
		name   string
		header string
		value  string
	}{
		{"bearer short token", "Authorization", "Bearer abc123"},
		{"bearer empty token", "Authorization", "Bearer  "},
		{"basic non base64ish", "Authorization", "Basic not a token!!"},
		{"api key too short", "X-API-Key", "k1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := authTestCtx()
			r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
			r.Header.Set(tc.header, tc.value)
			CheckAuthentication(ctx, r, true)
			m := findMatch(ctx, "auth.weak_credential")
			if m == nil {
				t.Fatalf("expected WEAK_CREDENTIAL, got %+v", ctx.CopyMatches())
			}
			if m.Category != "OBSERVE" || m.Severity != "LOW" || m.ScoreDelta != 5 {
				t.Fatalf("bad match attrs: %+v", m)
			}
			// 凭据值不得出现在证据中
			token := strings.TrimSpace(strings.TrimPrefix(tc.value, "Bearer "))
			if token != "" {
				for _, v := range m.Evidence {
					if strings.Contains(v, token) {
						t.Fatalf("credential value leaked into evidence: %+v", m.Evidence)
					}
				}
			}
		})
	}
}

func TestAuthentication_Malformed(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{"unsupported scheme", "Token abcdef123456"},
		{"missing credentials part", "Bearer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := authTestCtx()
			r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
			r.Header.Set("Authorization", tc.value)
			CheckAuthentication(ctx, r, true)
			m := findMatch(ctx, "auth.malformed_credential")
			if m == nil {
				t.Fatalf("expected MALFORMED_CREDENTIAL, got %+v", ctx.CopyMatches())
			}
			if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 10 {
				t.Fatalf("bad match attrs: %+v", m)
			}
		})
	}
}

func TestAuthentication_ValidCredentialNoMatch(t *testing.T) {
	// 负例：格式合法且强度足够的凭据不产生 match
	ctx := authTestCtx()
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig")
	r.Header.Set("X-API-Key", "0123456789abcdef")
	CheckAuthentication(ctx, r, true)
	if ctx.MatchCount() != 0 {
		t.Fatalf("expected no match, got %+v", ctx.CopyMatches())
	}
}

func TestAuthentication_Digest(t *testing.T) {
	// Digest 为 k=v 对结构，不走 Base64 判据
	ctx := authTestCtx()
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r.Header.Set("Authorization", `Digest username="u", realm="r", nonce="n", response="0123456789abcdef"`)
	CheckAuthentication(ctx, r, true)
	if ctx.MatchCount() != 0 {
		t.Fatalf("valid digest should not match, got %+v", ctx.CopyMatches())
	}

	ctx2 := authTestCtx()
	r2 := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r2.Header.Set("Authorization", "Digest abcdefghijklmnop")
	CheckAuthentication(ctx2, r2, true)
	if findMatch(ctx2, "auth.weak_credential") == nil {
		t.Fatalf("digest without k=v should be weak, got %+v", ctx2.CopyMatches())
	}
}

func TestIdentityKey(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r.Header.Set("Authorization", "Bearer some-token-value")
	k1 := IdentityKey(r)
	if !strings.HasPrefix(k1, "auth:") {
		t.Fatalf("want auth fingerprint key, got %q", k1)
	}
	if strings.Contains(k1, "some-token-value") {
		t.Fatal("identity key must not contain raw credential")
	}
	r2 := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	if !strings.HasPrefix(IdentityKey(r2), "ip:") {
		t.Fatalf("want ip fallback, got %q", IdentityKey(r2))
	}
}
