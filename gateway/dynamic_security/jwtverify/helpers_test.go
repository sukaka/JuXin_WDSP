package jwtverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// 测试密钥均为代码内临时生成，不引用任何真实凭据。

var testSecret = []byte("jwtverify-test-only-secret-not-a-real-credential")

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func genRSA(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("生成 RSA 测试密钥失败: %v", err)
	}
	return k
}

func genEC(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("生成 EC 测试密钥失败: %v", err)
	}
	return k
}

func rsaJWK(priv *rsa.PrivateKey, kid string) jose.JSONWebKey {
	return jose.JSONWebKey{Key: &priv.PublicKey, KeyID: kid, Algorithm: string(AlgRS256), Use: "sig"}
}

func ecJWK(priv *ecdsa.PrivateKey, kid string) jose.JSONWebKey {
	return jose.JSONWebKey{Key: &priv.PublicKey, KeyID: kid, Algorithm: string(AlgES256), Use: "sig"}
}

func jwksJSON(t *testing.T, keys ...jose.JSONWebKey) []byte {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatalf("序列化测试 JWKS 失败: %v", err)
	}
	return b
}

// signToken 用 go-jose 签发测试 Token；extraHeaders 可注入 jku/x5u/crit 等。
func signToken(t *testing.T, key any, alg jose.SignatureAlgorithm, kid string, claims map[string]any, extraHeaders map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("序列化测试 claims 失败: %v", err)
	}
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid)
	for k, v := range extraHeaders {
		opts = opts.WithHeader(jose.HeaderKey(k), v)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatalf("创建测试签名器失败: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("测试签名失败: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("测试序列化失败: %v", err)
	}
	return compact
}

// manualToken 手工拼接 compact 三段（none/HS 混淆/畸形用例）。
func manualToken(header, payload map[string]any, sigSegment string) string {
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(pb) + "." + sigSegment
}

func b64JSON(raw string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func validClaims(clock *fakeClock, issuer string) map[string]any {
	return map[string]any{
		"iss": issuer,
		"sub": "user-42",
		"aud": "api://orders",
		"exp": clock.Now().Add(5 * time.Minute).Unix(),
	}
}

const testIssuer = "https://idp.example.com"

func staticIssuerCfg(jwks []byte) IssuerConfig {
	return IssuerConfig{
		Issuer:     testIssuer,
		Audiences:  []string{"api://orders"},
		Algorithms: []Algorithm{AlgRS256, AlgES256},
		KeySource:  KeySourceStaticJWKS,
		StaticJWKS: jwks,
	}
}

func testPolicy(mode Mode, issuers ...IssuerConfig) Policy {
	return Policy{
		ApplicationID: "app-1",
		Version:       "pol-v1",
		Mode:          mode,
		Selectors: []Selector{{
			Methods:       []string{"GET", "POST"},
			PathPrefix:    "/api",
			TokenRequired: true,
		}},
		Issuers: issuers,
	}
}

func newTestVerifier(t *testing.T, policy Policy, clock *fakeClock) *Verifier {
	t.Helper()
	v, err := NewVerifier(VerifierConfig{
		Policy:         policy,
		IdentitySecret: testSecret,
		Clock:          clock,
	})
	if err != nil {
		t.Fatalf("构造验证器失败: %v", err)
	}
	return v
}

func bearer(token string) []string { return []string{"Bearer " + token} }
