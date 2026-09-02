package identitybehavior

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// makeUnsignedJWT 构造未验签 JWT（测试用；结构三段，payload 为给定 claims JSON）。
func makeUnsignedJWT(claims string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(claims))
	return hdr + "." + payload + ".fakesig"
}

func ibReq(t *testing.T, target string, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("GET", target, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestResolveIdentityJWTCredential(t *testing.T) {
	token := makeUnsignedJWT(`{"sub":"user-42","client_id":"web-console","exp":1893456000}`)
	r := ibReq(t, "http://waf-test.local/api", map[string]string{
		"Authorization": "Bearer " + token,
		"User-Agent":    "Mozilla/5.0 Chrome/120",
	})
	id := ResolveIdentity(r, "salt-1", "203.0.113.10")
	if len(id.Credentials) != 1 {
		t.Fatalf("credentials: %+v", id.Credentials)
	}
	c := id.Credentials[0]
	if c.Type != CredentialJWT || c.JWTSubject != "user-42" || c.OAuthClientID != "web-console" || c.AccountID != "user-42" {
		t.Fatalf("jwt credential: %+v", c)
	}
	if c.Hash != detectors.Fingerprint("salt-1", token) {
		t.Fatalf("hash must cover whole token: %q", c.Hash)
	}
	want := detectors.Fingerprint("salt-1", "cred:JWT:"+token)
	if id.Key != want {
		t.Fatalf("identity key: got %q want %q", id.Key, want)
	}
	// 稳定性：同凭据不同 IP 同 key
	r2 := ibReq(t, "http://waf-test.local/api", map[string]string{"Authorization": "Bearer " + token})
	id2 := ResolveIdentity(r2, "salt-1", "198.51.100.77")
	if id2.Key != id.Key {
		t.Fatalf("same credential across IPs must share key: %q vs %q", id2.Key, id.Key)
	}
	// 不同盐不同 key
	if ResolveIdentity(r, "salt-2", "203.0.113.10").Key == id.Key {
		t.Fatal("different salt must change key")
	}
	if id.Type != IdentityHuman {
		t.Fatalf("ua classification: %q", id.Type)
	}
}

func TestResolveIdentityOAuthClientCredential(t *testing.T) {
	// 仅 client_id 无 sub（client_credentials 形态）→ OAUTH
	token := makeUnsignedJWT(`{"client_id":"svc-bot","exp":1893456000}`)
	r := ibReq(t, "http://waf-test.local/api", map[string]string{"Authorization": "bearer " + token})
	id := ResolveIdentity(r, "s", "10.0.0.1")
	if len(id.Credentials) != 1 || id.Credentials[0].Type != CredentialOAuth || id.Credentials[0].OAuthClientID != "svc-bot" {
		t.Fatalf("oauth credential: %+v", id.Credentials)
	}
	if id.Key != detectors.Fingerprint("s", "cred:OAUTH:"+token) {
		t.Fatalf("oauth key: %q", id.Key)
	}
	if id.Type != IdentityApplication {
		t.Fatalf("oauth credential should remain APPLICATION for correlation: %q", id.Type)
	}
	if id.Confidence >= 70 {
		t.Fatalf("unverified oauth claims must not get high confidence: %d", id.Confidence)
	}
	if !containsSignal(id.Evidence, "credential:oauth_unverified") {
		t.Fatalf("oauth evidence must explain unverified source: %v", id.Evidence)
	}
	if containsSignal(id.Evidence, "credential:oauth") {
		t.Fatalf("oauth evidence must not imply verification: %v", id.Evidence)
	}
}

func TestResolveIdentityOpaqueBearerAndBasic(t *testing.T) {
	r := ibReq(t, "http://waf-test.local/", map[string]string{"Authorization": "Bearer opaque-token-123"})
	id := ResolveIdentity(r, "s", "10.0.0.1")
	if len(id.Credentials) != 1 || id.Credentials[0].Type != CredentialCustom {
		t.Fatalf("opaque bearer must be CUSTOM: %+v", id.Credentials)
	}
	if id.Key != detectors.Fingerprint("s", "cred:CUSTOM:bearer:opaque-token-123") {
		t.Fatalf("opaque key: %q", id.Key)
	}
	r2 := ibReq(t, "http://waf-test.local/", map[string]string{"Authorization": "Basic dXNlcjpwYXNz"})
	id2 := ResolveIdentity(r2, "s", "10.0.0.1")
	if len(id2.Credentials) != 1 || id2.Credentials[0].Type != CredentialCustom {
		t.Fatalf("basic auth must be CUSTOM: %+v", id2.Credentials)
	}
}

func TestResolveIdentityAPIKeyHeaders(t *testing.T) {
	for _, h := range []string{"X-API-Key", "Api-Key"} {
		r := ibReq(t, "http://waf-test.local/", map[string]string{h: "key-abc-123"})
		id := ResolveIdentity(r, "s", "10.0.0.1")
		if len(id.Credentials) != 1 || id.Credentials[0].Type != CredentialAPIKey {
			t.Fatalf("%s must extract API_KEY: %+v", h, id.Credentials)
		}
		if id.Key != detectors.Fingerprint("s", "cred:API_KEY:key-abc-123") {
			t.Fatalf("%s key: %q", h, id.Key)
		}
		if id.Type != IdentityApplication || id.Confidence >= 70 {
			t.Fatalf("%s identity classification: type=%q confidence=%d", h, id.Type, id.Confidence)
		}
		if !containsSignal(id.Evidence, "credential:api_key_observed") {
			t.Fatalf("%s identity evidence: %v", h, id.Evidence)
		}
	}
}

func TestResolveIdentityConfidenceEvidenceDoesNotContainSecrets(t *testing.T) {
	token := makeUnsignedJWT(`{"sub":"user-42"}`)
	r := ibReq(t, "http://waf-test.local/", map[string]string{
		"Authorization": "Bearer " + token,
		"User-Agent":    "Mozilla/5.0 Chrome/120",
	})
	id := ResolveIdentity(r, "s", "203.0.113.5")
	if id.Confidence == 0 || len(id.Evidence) == 0 {
		t.Fatalf("identity confidence/evidence missing: %+v", id)
	}
	for _, evidence := range id.Evidence {
		if strings.Contains(evidence, token) || strings.Contains(evidence, "user-42") {
			t.Fatalf("identity evidence must not contain credential values: %q", evidence)
		}
	}
	unknown := ResolveIdentity(ibReq(t, "http://waf-test.local/", map[string]string{
		"User-Agent": "autonomous-agent/1.0",
	}), "s", "203.0.113.5")
	if unknown.Type != IdentityUnknown || unknown.Confidence == 0 {
		t.Fatalf("agent UA alone must not classify as AGENT: %+v", unknown)
	}
}

func containsSignal(signals []string, want string) bool {
	for _, signal := range signals {
		if signal == want {
			return true
		}
	}
	return false
}

func TestResolveIdentitySessionCookieCaseInsensitive(t *testing.T) {
	r := ibReq(t, "http://waf-test.local/", map[string]string{
		"Cookie": "theme=dark; SessionID=abc123; other=1",
	})
	id := ResolveIdentity(r, "s", "10.0.0.1")
	if len(id.Credentials) != 1 || id.Credentials[0].Type != CredentialSession {
		t.Fatalf("session cookie: %+v", id.Credentials)
	}
	if id.Key != detectors.Fingerprint("s", "cred:SESSION:SessionID=abc123") {
		t.Fatalf("session key: %q", id.Key)
	}
}

func TestResolveIdentityGenericCookieFallback(t *testing.T) {
	r := ibReq(t, "http://waf-test.local/", map[string]string{"Cookie": "theme=dark; cart=9"})
	id := ResolveIdentity(r, "s", "10.0.0.1")
	if len(id.Credentials) != 1 || id.Credentials[0].Type != CredentialCookie {
		t.Fatalf("generic cookie must be COOKIE: %+v", id.Credentials)
	}
}

func TestIdentityKeyPriority(t *testing.T) {
	token := makeUnsignedJWT(`{"sub":"u1"}`)
	r := ibReq(t, "http://waf-test.local/", map[string]string{
		"Authorization": "Bearer " + token,
		"X-API-Key":     "key-1",
		"Cookie":        "sid=sess-1",
		"User-Agent":    "curl/8.0",
	})
	id := ResolveIdentity(r, "s", "10.0.0.1")
	if len(id.Credentials) != 3 {
		t.Fatalf("all credentials extracted: %+v", id.Credentials)
	}
	// JWT 优先于 API_KEY 与 SESSION
	if id.Key != detectors.Fingerprint("s", "cred:JWT:"+token) {
		t.Fatalf("priority key: %q", id.Key)
	}
	if id.Type != IdentityBot {
		t.Fatalf("curl must classify BOT: %q", id.Type)
	}
}

func TestIdentityAnonymousBrowserKey(t *testing.T) {
	mk := func(ip string) *Identity {
		r := ibReq(t, "http://waf-test.local/", map[string]string{
			"User-Agent":      "Mozilla/5.0 Safari/605",
			"Accept-Language": "zh-CN",
			"Accept-Encoding": "gzip",
			"Accept":          "text/html",
		})
		return ResolveIdentity(r, "s", ip)
	}
	a, b := mk("203.0.113.1"), mk("198.51.100.9")
	if a.Key != b.Key {
		t.Fatalf("same browser across IPs must share key: %q vs %q", a.Key, b.Key)
	}
	if a.BrowserFingerprint == "" {
		t.Fatal("browser fingerprint expected")
	}
	if a.Key != detectors.Fingerprint("s", "anon:"+a.BrowserFingerprint) {
		t.Fatalf("anon key: %q", a.Key)
	}
	// 不同 UA → 不同 key
	r := ibReq(t, "http://waf-test.local/", map[string]string{"User-Agent": "Mozilla/5.0 Chrome/120"})
	if ResolveIdentity(r, "s", "203.0.113.1").Key == a.Key {
		t.Fatal("different UA must change anon key")
	}
}

func TestIdentityIPFallback(t *testing.T) {
	r := ibReq(t, "http://waf-test.local/", nil)
	id := ResolveIdentity(r, "s", "203.0.113.5")
	if id.Key != detectors.Fingerprint("s", "ip:203.0.113.5") {
		t.Fatalf("ip fallback key: %q", id.Key)
	}
	if id.Type != IdentityUnknown || id.BrowserFingerprint != "" || len(id.Credentials) != 0 {
		t.Fatalf("ip fallback identity: %+v", id)
	}
}

func TestClassifyUA(t *testing.T) {
	cases := map[string]string{
		"curl/8.1":                      IdentityBot,
		"Wget/1.21":                     IdentityBot,
		"python-requests/2.31":          IdentityBot,
		"Go-http-client/2.0":            IdentityBot,
		"Mozilla/5.0 HeadlessChrome/99": IdentityBot, // bot 特征优先于浏览器特征
		"Googlebot/2.1":                 IdentityBot,
		"nmap-scanner":                  IdentityBot,
		"Mozilla/5.0 Chrome/120 Safari": IdentityHuman,
		"Mozilla/5.0 Safari/605":        IdentityHuman,
		"my-custom-agent":               IdentityUnknown,
		"":                              IdentityUnknown,
	}
	for ua, want := range cases {
		if got := classifyUA(ua); got != want {
			t.Fatalf("classifyUA(%q) = %q, want %q", ua, got, want)
		}
	}
}

func TestTLSFingerprint(t *testing.T) {
	r := ibReq(t, "http://waf-test.local/", map[string]string{"User-Agent": "x"})
	if id := ResolveIdentity(r, "s", "10.0.0.1"); id.TLSFingerprint != "" {
		t.Fatalf("no TLS must yield empty fingerprint: %q", id.TLSFingerprint)
	}
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256}
	id := ResolveIdentity(r, "s", "10.0.0.1")
	if id.TLSFingerprint == "" {
		t.Fatal("TLS fingerprint expected")
	}
	if again := ResolveIdentity(r, "s", "10.0.0.2"); again.TLSFingerprint != id.TLSFingerprint {
		t.Fatal("TLS fingerprint must be deterministic")
	}
	r2 := ibReq(t, "http://waf-test.local/", nil)
	r2.TLS = &tls.ConnectionState{Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	if ResolveIdentity(r2, "s", "10.0.0.1").TLSFingerprint == id.TLSFingerprint {
		t.Fatal("different TLS params must change fingerprint")
	}
}

func TestParamSignature(t *testing.T) {
	r := ibReq(t, "http://waf-test.local/p?b=2&a=&c=550e8400-e29b-41d4-a716-446655440000&a=xyz", nil)
	sig := ParamSignature(r.URL.Query())
	want := "a=empty&a=s:1-8&b=n&c=uuid"
	if sig != want {
		t.Fatalf("param signature: got %q want %q", sig, want)
	}
	// 顺序无关
	r2 := ibReq(t, "http://waf-test.local/p?c=550e8400-e29b-41d4-a716-446655440000&a=xyz&a=&b=2", nil)
	if ParamSignature(r2.URL.Query()) != sig {
		t.Fatal("param signature must be order-independent")
	}
	if ParamSignature(ibReq(t, "http://waf-test.local/p", nil).URL.Query()) != "" {
		t.Fatal("no params must yield empty signature")
	}
	// 长度桶
	cls := map[string]string{"1234567890": "n", "": "empty", "1234567a": "s:1-8", "12345678a": "s:9-64"}
	for v, want := range cls {
		if got := valueClass(v); got != want {
			t.Fatalf("valueClass(%q) = %q want %q", v, got, want)
		}
	}
}
