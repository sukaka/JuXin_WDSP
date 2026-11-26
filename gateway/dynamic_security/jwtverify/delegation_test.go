package jwtverify

import (
	"reflect"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestVerifyScopesAndDelegationChain(t *testing.T) {
	clock := newFakeClock()
	key := genRSA(t, 2048)
	jwks := jwksJSON(t, rsaJWK(key, "rsa-1"))
	v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwks)), clock)

	t.Run("scope string + scp array merged and deduplicated", func(t *testing.T) {
		claims := validClaims(clock, testIssuer)
		claims["scope"] = "orders:read  orders:write"
		claims["scp"] = []string{"orders:write", "inventory:read"}
		claims["azp"] = "planner-agent"

		tok := signToken(t, key, jose.RS256, "rsa-1", claims, nil)
		res := v.Verify(bearer(tok), "POST", "/api/a2a")
		if res.Status != StatusVerified {
			t.Fatalf("expected VERIFIED, got %s/%s", res.Status, res.ReasonCode)
		}
		wantScopes := []string{"orders:read", "orders:write", "inventory:read"}
		if !reflect.DeepEqual(res.VerifiedScopes, wantScopes) {
			t.Fatalf("VerifiedScopes = %v, want %v", res.VerifiedScopes, wantScopes)
		}
		if res.VerifiedAZP != "planner-agent" {
			t.Fatalf("VerifiedAZP = %q, want planner-agent", res.VerifiedAZP)
		}
		if len(res.DelegationChain) != 0 || len(res.DelegationScopes) != 0 {
			t.Fatalf("expected empty delegation chain, got %v / %v", res.DelegationChain, res.DelegationScopes)
		}
	})

	t.Run("RFC 8693 nested act chain with per-hop scopes", func(t *testing.T) {
		claims := validClaims(clock, testIssuer)
		claims["scope"] = "orders:read"
		claims["client_id"] = "worker-agent-c"
		claims["act"] = map[string]any{
			"sub":   "agent-b",
			"scope": "orders:read",
			"act": map[string]any{
				"sub":   "agent-a",
				"scope": "orders:read orders:write",
				"act": map[string]any{
					"sub": "orchestrator-root",
					"scp": []string{"orders:read", "orders:write", "orders:export"},
				},
			},
		}
		tok := signToken(t, key, jose.RS256, "rsa-1", claims, nil)
		res := v.Verify(bearer(tok), "POST", "/api/a2a")
		if res.Status != StatusVerified {
			t.Fatalf("expected VERIFIED, got %s/%s", res.Status, res.ReasonCode)
		}
		wantChain := []string{"agent-b", "agent-a", "orchestrator-root"}
		if !reflect.DeepEqual(res.DelegationChain, wantChain) {
			t.Fatalf("DelegationChain = %v, want %v", res.DelegationChain, wantChain)
		}
		wantHopScopes := [][]string{
			{"orders:read"},
			{"orders:read", "orders:write"},
			{"orders:read", "orders:write", "orders:export"},
		}
		if !reflect.DeepEqual(res.DelegationScopes, wantHopScopes) {
			t.Fatalf("DelegationScopes = %v, want %v", res.DelegationScopes, wantHopScopes)
		}
		if res.VerifiedAZP != "worker-agent-c" {
			t.Fatalf("VerifiedAZP = %q, want worker-agent-c", res.VerifiedAZP)
		}
	})

	t.Run("RFC 8693 nested act chain without per-hop scopes leaves DelegationScopes nil", func(t *testing.T) {
		claims := validClaims(clock, testIssuer)
		claims["scope"] = "tasks:send"
		claims["act"] = map[string]any{
			"sub": "agent-1",
			"act": map[string]any{
				"sub": "agent-0",
			},
		}
		tok := signToken(t, key, jose.RS256, "rsa-1", claims, nil)
		res := v.Verify(bearer(tok), "POST", "/api/a2a")
		if res.Status != StatusVerified {
			t.Fatalf("expected VERIFIED, got %s/%s", res.Status, res.ReasonCode)
		}
		wantChain := []string{"agent-1", "agent-0"}
		if !reflect.DeepEqual(res.DelegationChain, wantChain) {
			t.Fatalf("DelegationChain = %v, want %v", res.DelegationChain, wantChain)
		}
		if res.DelegationScopes != nil {
			t.Fatalf("DelegationScopes = %v, want nil when hops omit scope", res.DelegationScopes)
		}
	})

	t.Run("scopes capped at MaxVerifiedScopes and invalid claims ignored safely", func(t *testing.T) {
		claims := validClaims(clock, testIssuer)
		many := make([]string, 0, MaxVerifiedScopes+20)
		for i := 0; i < MaxVerifiedScopes+20; i++ {
			many = append(many, "scope_"+string(rune('a'+(i%26)))+"_"+strings.Repeat("x", i%5+1))
		}
		claims["scp"] = many
		claims["scope"] = 12345 // malformed type ignored
		claims["act"] = "not-an-object"
		claims["azp"] = "bad\ncontrol"

		tok := signToken(t, key, jose.RS256, "rsa-1", claims, nil)
		res := v.Verify(bearer(tok), "POST", "/api/a2a")
		if res.Status != StatusVerified {
			t.Fatalf("expected VERIFIED, got %s/%s", res.Status, res.ReasonCode)
		}
		if len(res.VerifiedScopes) > MaxVerifiedScopes || len(res.VerifiedScopes) == 0 {
			t.Fatalf("unexpected VerifiedScopes len=%d", len(res.VerifiedScopes))
		}
		if len(res.DelegationChain) != 0 {
			t.Fatalf("malformed act must yield empty chain, got %v", res.DelegationChain)
		}
		if res.VerifiedAZP != "" {
			t.Fatalf("control-char azp must be ignored, got %q", res.VerifiedAZP)
		}
	})
}

// Security invariant: NEVER populate VerifiedScopes, DelegationChain,
// DelegationScopes, or VerifiedAZP from unverified / invalid / failed-binding tokens.
func TestDelegationNeverPopulatedFromUnverifiedTokens(t *testing.T) {
	clock := newFakeClock()
	realKey := genRSA(t, 2048)
	attackerKey := genRSA(t, 2048)
	jwks := jwksJSON(t, rsaJWK(realKey, "rsa-1"))

	withDelegation := func(mut func(c map[string]any)) map[string]any {
		c := validClaims(clock, testIssuer)
		c["scope"] = "orders:read admin:*"
		c["azp"] = "evil-agent"
		c["act"] = map[string]any{
			"sub":   "agent-b",
			"scope": "orders:read",
			"act":   map[string]any{"sub": "agent-a", "scope": "orders:read orders:write"},
		}
		if mut != nil {
			mut(c)
		}
		return c
	}

	v := newTestVerifier(t, testPolicy(ModeProtect, staticIssuerCfg(jwks)), clock)

	assertEmpty := func(t *testing.T, label string, res VerificationResult) {
		t.Helper()
		if res.Status == StatusVerified {
			t.Fatalf("%s: expected non-VERIFIED, got VERIFIED", label)
		}
		if len(res.VerifiedScopes) != 0 || len(res.DelegationChain) != 0 ||
			len(res.DelegationScopes) != 0 || res.VerifiedAZP != "" {
			t.Fatalf("%s: unverified token leaked delegation/scopes: scopes=%v chain=%v hopScopes=%v azp=%q",
				label, res.VerifiedScopes, res.DelegationChain, res.DelegationScopes, res.VerifiedAZP)
		}
	}

	t.Run("forged signature", func(t *testing.T) {
		tok := signToken(t, attackerKey, jose.RS256, "rsa-1", withDelegation(nil), nil)
		assertEmpty(t, "forged", v.Verify(bearer(tok), "POST", "/api/a2a"))
	})

	t.Run("alg none", func(t *testing.T) {
		tok := manualToken(map[string]any{"alg": "none", "kid": "rsa-1"}, withDelegation(nil), "eA")
		assertEmpty(t, "alg=none", v.Verify(bearer(tok), "POST", "/api/a2a"))
	})

	t.Run("expired token", func(t *testing.T) {
		claims := withDelegation(func(c map[string]any) {
			c["exp"] = clock.Now().Add(-5 * time.Minute).Unix()
		})
		tok := signToken(t, realKey, jose.RS256, "rsa-1", claims, nil)
		assertEmpty(t, "expired", v.Verify(bearer(tok), "POST", "/api/a2a"))
	})

	t.Run("audience mismatch", func(t *testing.T) {
		claims := withDelegation(func(c map[string]any) {
			c["aud"] = "api://other"
		})
		tok := signToken(t, realKey, jose.RS256, "rsa-1", claims, nil)
		assertEmpty(t, "bad-aud", v.Verify(bearer(tok), "POST", "/api/a2a"))
	})

	t.Run("policy off", func(t *testing.T) {
		vOff := newTestVerifier(t, testPolicy(ModeOff, staticIssuerCfg(jwks)), clock)
		tok := signToken(t, realKey, jose.RS256, "rsa-1", withDelegation(nil), nil)
		assertEmpty(t, "policy-off", vOff.Verify(bearer(tok), "POST", "/api/a2a"))
	})

	t.Run("out of scope", func(t *testing.T) {
		tok := signToken(t, realKey, jose.RS256, "rsa-1", withDelegation(nil), nil)
		assertEmpty(t, "out-of-scope", v.Verify(bearer(tok), "POST", "/other/path"))
	})

	t.Run("DPoP binding failure clears verified delegation claims", func(t *testing.T) {
		iss := staticIssuerCfg(jwks)
		iss.TokenBinding = &TokenBindingConfig{Mode: TokenBindingDPoPRequired}
		vDPoP := newTestVerifier(t, testPolicy(ModeProtect, iss), clock)
		tok := signToken(t, realKey, jose.RS256, "rsa-1", withDelegation(nil), nil)
		assertEmpty(t, "dpop-missing", vDPoP.Verify(bearer(tok), "POST", "/api/a2a"))
	})
}
