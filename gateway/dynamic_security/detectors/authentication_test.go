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

// 统一指纹：HMAC-SHA256(key=salt) 截断 16 字节 hex（32 字符）；加盐确定性、异盐异指纹。
func TestFingerprint(t *testing.T) {
	fp := Fingerprint("s1", "Bearer token-value")
	if len(fp) != 32 {
		t.Fatalf("want 32-char hex, got %d chars: %q", len(fp), fp)
	}
	for _, c := range fp {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("non-hex char in fingerprint: %q", fp)
		}
	}
	if Fingerprint("s1", "Bearer token-value") != fp {
		t.Fatal("same salt+value must be deterministic")
	}
	if Fingerprint("s2", "Bearer token-value") == fp {
		t.Fatal("different salt must yield different fingerprint")
	}
	// 空盐走固定域分隔前缀：仍确定、仍 32 字符，且与任意显式盐不同
	unsalted := Fingerprint("", "Bearer token-value")
	if len(unsalted) != 32 || unsalted == fp {
		t.Fatalf("unsalted fingerprint unexpected: %q", unsalted)
	}
}

// 身份键仅凭据派生：auth > key > sess 优先级链；无凭据为空（匿名）。
func TestCredentialKey(t *testing.T) {
	const salt = "test-salt"
	// auth 优先于 key/sess
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r.Header.Set("Authorization", "Bearer some-token-value")
	r.Header.Set("X-API-Key", "0123456789abcdef")
	r.Header.Set("Cookie", "sid=abc")
	k := CredentialKey(r, salt)
	if !strings.HasPrefix(k, "auth:") {
		t.Fatalf("want auth: priority, got %q", k)
	}
	if strings.Contains(k, "some-token-value") {
		t.Fatal("credential key must not contain raw credential")
	}
	// key 优先于 sess
	r2 := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r2.Header.Set("X-API-Key", "0123456789abcdef")
	r2.Header.Set("Cookie", "sid=abc")
	if k := CredentialKey(r2, salt); !strings.HasPrefix(k, "key:") {
		t.Fatalf("want key: priority, got %q", k)
	}
	// 仅 cookie → sess:
	r3 := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r3.Header.Set("Cookie", "sid=abc")
	k3 := CredentialKey(r3, salt)
	if !strings.HasPrefix(k3, "sess:") {
		t.Fatalf("want sess: for cookie-only, got %q", k3)
	}
	if strings.Contains(k3, "sid=abc") {
		t.Fatal("cookie plaintext must not leave credential key")
	}
	// 无凭据 → 空串（匿名，不得以 IP 冒充身份）
	r4 := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	if k := CredentialKey(r4, salt); k != "" {
		t.Fatalf("anonymous credential key must be empty, got %q", k)
	}
	if k := CredentialKey(nil, salt); k != "" {
		t.Fatalf("nil request credential key must be empty, got %q", k)
	}
	// 指纹部分随盐变化
	r5 := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r5.Header.Set("Authorization", "Bearer some-token-value")
	if CredentialKey(r5, "s1") == CredentialKey(r5, "s2") {
		t.Fatal("credential key must vary with salt")
	}
}

// 追踪键：凭据指纹优先，无凭据回退 ip:（仅作滑窗计数维度，避免匿名流量并桶）。
func TestTrackingKey(t *testing.T) {
	const salt = "test-salt"
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r.Header.Set("Authorization", "Bearer some-token-value")
	r.Header.Set("Cookie", "sid=abc")
	k1 := TrackingKey(r, salt)
	if !strings.HasPrefix(k1, "auth:") {
		t.Fatalf("want auth fingerprint key, got %q", k1)
	}
	if strings.Contains(k1, "some-token-value") {
		t.Fatal("tracking key must not contain raw credential")
	}
	// cookie-only → sess:（第三级）
	r3 := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r3.Header.Set("Cookie", "sid=abc")
	if !strings.HasPrefix(TrackingKey(r3, salt), "sess:") {
		t.Fatalf("want sess: for cookie-only, got %q", TrackingKey(r3, salt))
	}
	// 无凭据 → ip: 回退
	r2 := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	if !strings.HasPrefix(TrackingKey(r2, salt), "ip:") {
		t.Fatalf("want ip fallback, got %q", TrackingKey(r2, salt))
	}
	// 完全无信号 → unknown
	if k := TrackingKey(nil, salt); k != "unknown" {
		t.Fatalf("want unknown for nil request, got %q", k)
	}
}

func TestAuthentication_JWTAlgNone(t *testing.T) {
	// header {"alg":"none","typ":"JWT"} payload {"sub":"1"} empty sig
	// eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.
	token := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."
	ctx := authTestCtx()
	r := httptest.NewRequest(http.MethodGet, "/v1/x", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	CheckAuthentication(ctx, r, true)
	if findMatch(ctx, "auth.jwt_alg_none") == nil {
		t.Fatalf("want jwt_alg_none, got %+v", ctx.CopyMatches())
	}
	if findMatch(ctx, "auth.jwt_empty_signature") == nil {
		t.Fatalf("want jwt_empty_signature, got %+v", ctx.CopyMatches())
	}
}
