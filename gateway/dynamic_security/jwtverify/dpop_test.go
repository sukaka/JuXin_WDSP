package jwtverify

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// ---------- 测试用 DPoP 防重放存储与签名工具 ----------

type memDPoPReplayStore struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	clock   Clock
	failErr error
	lastTTL time.Duration
	calls   atomic.Int64
}

func newMemDPoPReplayStore(clock Clock) *memDPoPReplayStore {
	return &memDPoPReplayStore{
		seen:  make(map[string]time.Time),
		clock: clock,
	}
}

func (s *memDPoPReplayStore) CheckAndSet(_ context.Context, jkt, jtiDigestHex32 string, ttl time.Duration) (bool, error) {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failErr != nil {
		return false, s.failErr
	}
	s.lastTTL = ttl
	now := time.Now()
	if s.clock != nil {
		now = s.clock.Now()
	}
	key := jkt + ":" + jtiDigestHex32
	if exp, ok := s.seen[key]; ok && now.Before(exp) {
		return true, nil
	}
	s.seen[key] = now.Add(ttl)
	return false, nil
}

type mockReplayEvaluator struct {
	mu       sync.Mutex
	fn       func(ctx context.Context, script string, keys []string, args []string) ([]interface{}, error)
	lastKeys []string
	lastArgs []string
}

func (m *mockReplayEvaluator) Eval(ctx context.Context, script string, keys []string, args []string) ([]interface{}, error) {
	m.mu.Lock()
	m.lastKeys = append([]string(nil), keys...)
	m.lastArgs = append([]string(nil), args...)
	fn := m.fn
	m.mu.Unlock()
	return fn(ctx, script, keys, args)
}

func genEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成 Ed25519 测试密钥失败: %v", err)
	}
	return pub, priv
}

func mustJKT(t *testing.T, pub any) string {
	t.Helper()
	jkt, err := ComputeJWKThumbprintSHA256(pub)
	if err != nil {
		t.Fatalf("计算 JWK Thumbprint 失败: %v", err)
	}
	return jkt
}

func computeATH(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func pubToJWKMap(t *testing.T, pub any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(jose.JSONWebKey{Key: pub})
	if err != nil {
		t.Fatalf("marshal public jwk: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal jwk map: %v", err)
	}
	return m
}

func signDPoPProof(
	t *testing.T,
	priv any,
	pub any,
	alg jose.SignatureAlgorithm,
	claims map[string]any,
	extraHeaders map[string]any,
) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal dpop claims: %v", err)
	}
	jwkObj := jose.JSONWebKey{Key: pub}
	opts := (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jwkObj)
	for k, v := range extraHeaders {
		opts = opts.WithHeader(jose.HeaderKey(k), v)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: priv}, opts)
	if err != nil {
		t.Fatalf("create dpop signer (%s): %v", alg, err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign dpop proof: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("compact serialize dpop: %v", err)
	}
	return compact
}

func makeDPoPClaims(clock *fakeClock, jti, htm, htu, accessToken string) map[string]any {
	return map[string]any{
		"jti": jti,
		"htm": htm,
		"htu": htu,
		"iat": clock.Now().Unix(),
		"ath": computeATH(accessToken),
	}
}

func newDPoPVerifier(
	t *testing.T,
	mode Mode,
	tb *TokenBindingConfig,
	idpKey *rsa.PrivateKey,
	clock *fakeClock,
	replay DPoPReplayStore,
) *Verifier {
	t.Helper()
	iss := staticIssuerCfg(jwksJSON(t, rsaJWK(idpKey, "rsa-1")))
	iss.TokenBinding = tb
	v, err := NewVerifier(VerifierConfig{
		Policy:         testPolicy(mode, iss),
		IdentitySecret: testSecret,
		Clock:          clock,
		DPoPReplay:     replay,
	})
	if err != nil {
		t.Fatalf("NewVerifier(DPoP) failed: %v", err)
	}
	return v
}

func signBoundAccessToken(t *testing.T, idpKey *rsa.PrivateKey, clock *fakeClock, jkt string) string {
	t.Helper()
	c := validClaims(clock, testIssuer)
	if jkt != "" {
		c["cnf"] = map[string]any{"jkt": jkt}
	}
	return signToken(t, idpKey, jose.RS256, "rsa-1", c, nil)
}

func dpopReq(token, proof, method, host, path string) RequestVerifyInput {
	in := RequestVerifyInput{
		AuthValues: []string{"DPoP " + token},
		Method:     method,
		Path:       path,
		RawPath:    path,
		Scheme:     "https",
		Host:       host,
	}
	if proof != "" {
		in.DPoPHeaders = []string{proof}
	}
	return in
}

// ---------- RFC 7638 Thumbprint 跨算法核验 ----------

func TestComputeJWKThumbprintSHA256_RFC7638Canonical(t *testing.T) {
	// EC P-256: {"crv":...,"kty":"EC","x":...,"y":...}
	ecKey := genEC(t, elliptic.P256())
	ecMap := pubToJWKMap(t, &ecKey.PublicKey)
	ecCanon := fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, ecMap["crv"], ecMap["x"], ecMap["y"])
	ecWantSum := sha256.Sum256([]byte(ecCanon))
	if got := mustJKT(t, &ecKey.PublicKey); got != base64.RawURLEncoding.EncodeToString(ecWantSum[:]) {
		t.Fatalf("EC JKT mismatch: got=%q", got)
	}

	// RSA: {"e":...,"kty":"RSA","n":...}
	rsaKey := genRSA(t, 2048)
	rsaMap := pubToJWKMap(t, &rsaKey.PublicKey)
	rsaCanon := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, rsaMap["e"], rsaMap["n"])
	rsaWantSum := sha256.Sum256([]byte(rsaCanon))
	if got := mustJKT(t, &rsaKey.PublicKey); got != base64.RawURLEncoding.EncodeToString(rsaWantSum[:]) {
		t.Fatalf("RSA JKT mismatch: got=%q", got)
	}

	// OKP Ed25519 (RFC 8037 §2): {"crv":"Ed25519","kty":"OKP","x":...}
	edPub, _ := genEd25519(t)
	edMap := pubToJWKMap(t, edPub)
	edCanon := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, edMap["x"])
	edWantSum := sha256.Sum256([]byte(edCanon))
	if got := mustJKT(t, edPub); got != base64.RawURLEncoding.EncodeToString(edWantSum[:]) {
		t.Fatalf("Ed25519 JKT mismatch: got=%q", got)
	}
}

// ---------- RFC 9449：ES256 / RS256 / EdDSA 正常通过 ----------

func TestDPoP_ValidES256RS256EdDSA(t *testing.T) {
	clock := newFakeClock()
	idpKey := genRSA(t, 2048)
	replay := newMemDPoPReplayStore(clock)
	v := newDPoPVerifier(t, ModeProtect, &TokenBindingConfig{Mode: TokenBindingDPoPRequired}, idpKey, clock, replay)

	ecKey := genEC(t, elliptic.P256())
	rsaKey := genRSA(t, 2048)
	edPub, edPriv := genEd25519(t)

	cases := []struct {
		name string
		alg  jose.SignatureAlgorithm
		priv any
		pub  any
	}{
		{"ES256", jose.ES256, ecKey, &ecKey.PublicKey},
		{"RS256", jose.RS256, rsaKey, &rsaKey.PublicKey},
		{"EdDSA", jose.EdDSA, edPriv, edPub},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jkt := mustJKT(t, tc.pub)
			tok := signBoundAccessToken(t, idpKey, clock, jkt)
			claims := makeDPoPClaims(clock, fmt.Sprintf("jti-%d", i), "POST", "https://api.example.com/api/orders", tok)
			proof := signDPoPProof(t, tc.priv, tc.pub, tc.alg, claims, nil)

			res := v.VerifyRequest(dpopReq(tok, proof, "POST", "api.example.com", "/api/orders"))
			if res.Status != StatusVerified || res.ReasonCode != ReasonValid {
				t.Fatalf("%s 应 VERIFIED/VALID，得到 %s/%s", tc.name, res.Status, res.ReasonCode)
			}
			if res.TokenBindingVerified != "DPOP" {
				t.Fatalf("TokenBindingVerified 应为 DPOP，得到 %q", res.TokenBindingVerified)
			}
			if res.TokenScheme != "DPoP" {
				t.Fatalf("TokenScheme 应为 DPoP，得到 %q", res.TokenScheme)
			}
			if res.VerifiedPrincipalID == "" {
				t.Fatal("VERIFIED 应产出可信主体指纹")
			}
		})
	}
}

// ---------- RFC 9449：缺失 / 畸形 / 算法拒绝 / 私钥 JWK 拒绝 / 验签失败 ----------

func TestDPoP_ProofRejectionMatrix(t *testing.T) {
	clock := newFakeClock()
	idpKey := genRSA(t, 2048)
	replay := newMemDPoPReplayStore(clock)
	v := newDPoPVerifier(t, ModeProtect, &TokenBindingConfig{
		Mode:            TokenBindingDPoPRequired,
		AllowedDPoPAlgs: []string{DPoPAlgES256, DPoPAlgRS256, DPoPAlgEdDSA},
	}, idpKey, clock, replay)

	ecKey := genEC(t, elliptic.P256())
	otherEC := genEC(t, elliptic.P256())
	jkt := mustJKT(t, &ecKey.PublicKey)
	tok := signBoundAccessToken(t, idpKey, clock, jkt)
	baseClaims := func(jti string) map[string]any {
		return makeDPoPClaims(clock, jti, "GET", "https://api.example.com/api/orders", tok)
	}

	assertInvalid := func(t *testing.T, res VerificationResult, want ReasonCode) {
		t.Helper()
		if res.Status != StatusInvalid || res.ReasonCode != want {
			t.Fatalf("期望 INVALID/%s，得到 %s/%s", want, res.Status, res.ReasonCode)
		}
		if res.VerifiedPrincipalID != "" || res.VerifiedTenantID != "" || len(res.VerifiedRoles) != 0 || res.TokenBindingVerified != "" {
			t.Fatalf("DPoP 失败不得泄露可信身份或绑定标记: %+v", res)
		}
	}

	t.Run("missing DPoP header", func(t *testing.T) {
		in := dpopReq(tok, "", "GET", "api.example.com", "/api/orders")
		assertInvalid(t, v.VerifyRequest(in), ReasonDPoPMissing)
	})

	t.Run("whitespace-only DPoP header", func(t *testing.T) {
		in := dpopReq(tok, "   ", "GET", "api.example.com", "/api/orders")
		assertInvalid(t, v.VerifyRequest(in), ReasonDPoPMissing)
	})

	t.Run("multiple DPoP headers rejected", func(t *testing.T) {
		proof := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, baseClaims("j-dup-hdr"), nil)
		in := dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")
		in.DPoPHeaders = []string{proof, proof}
		assertInvalid(t, v.VerifyRequest(in), ReasonDPoPMalformed)
	})

	t.Run("comma-separated DPoP headers rejected", func(t *testing.T) {
		proof := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, baseClaims("j-comma"), nil)
		in := dpopReq(tok, proof+","+proof, "GET", "api.example.com", "/api/orders")
		assertInvalid(t, v.VerifyRequest(in), ReasonDPoPMalformed)
	})

	t.Run("oversized DPoP proof rejected", func(t *testing.T) {
		big := strings.Repeat("a", MaxTokenBytes+1)
		in := dpopReq(tok, big, "GET", "api.example.com", "/api/orders")
		assertInvalid(t, v.VerifyRequest(in), ReasonDPoPMalformed)
	})

	t.Run("wrong typ rejected", func(t *testing.T) {
		proof := manualToken(
			map[string]any{"typ": "JWT", "alg": "ES256", "jwk": pubToJWKMap(t, &ecKey.PublicKey)},
			baseClaims("j-typ"), "c2ln",
		)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPMalformed)
	})

	t.Run("case-insensitive typ dpop+jwt accepted", func(t *testing.T) {
		jwkObj := jose.JSONWebKey{Key: &ecKey.PublicKey}
		opts := (&jose.SignerOptions{}).WithType("DPoP+JWT").WithHeader("jwk", jwkObj)
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: ecKey}, opts)
		if err != nil {
			t.Fatal(err)
		}
		pb, _ := json.Marshal(baseClaims("j-typ-case"))
		jws, err := signer.Sign(pb)
		if err != nil {
			t.Fatal(err)
		}
		proof, _ := jws.CompactSerialize()
		res := v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders"))
		if res.Status != StatusVerified {
			t.Fatalf("大小写不敏感 typ DPoP+JWT 应通过: %s/%s", res.Status, res.ReasonCode)
		}
	})

	t.Run("crit header rejected", func(t *testing.T) {
		proof := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, baseClaims("j-crit"), map[string]any{
			"crit": []string{"exp"},
		})
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPMalformed)
	})

	t.Run("duplicate json key in header rejected", func(t *testing.T) {
		jwkBytes, _ := json.Marshal(pubToJWKMap(t, &ecKey.PublicKey))
		hdr := fmt.Sprintf(`{"typ":"dpop+jwt","alg":"ES256","alg":"none","jwk":%s}`, string(jwkBytes))
		pb, _ := json.Marshal(baseClaims("j-duphdr"))
		proof := b64JSON(hdr) + "." + base64.RawURLEncoding.EncodeToString(pb) + ".c2ln"
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPMalformed)
	})

	t.Run("alg=none rejected", func(t *testing.T) {
		proof := manualToken(
			map[string]any{"typ": "dpop+jwt", "alg": "none", "jwk": pubToJWKMap(t, &ecKey.PublicKey)},
			baseClaims("j-none"), "eA",
		)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPAlgRejected)
	})

	t.Run("alg=HS256 rejected", func(t *testing.T) {
		proof := manualToken(
			map[string]any{"typ": "dpop+jwt", "alg": "HS256", "jwk": map[string]any{"kty": "oct", "k": "c2VjcmV0"}},
			baseClaims("j-hs256"), "c2ln",
		)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPAlgRejected)
	})

	t.Run("alg not in restricted allowed_dpop_algs subset rejected", func(t *testing.T) {
		vESOnly := newDPoPVerifier(t, ModeProtect, &TokenBindingConfig{
			Mode:            TokenBindingDPoPRequired,
			AllowedDPoPAlgs: []string{DPoPAlgES256},
		}, idpKey, clock, replay)
		edPub, edPriv := genEd25519(t)
		edTok := signBoundAccessToken(t, idpKey, clock, mustJKT(t, edPub))
		edProof := signDPoPProof(t, edPriv, edPub, jose.EdDSA, makeDPoPClaims(clock, "j-ed-blocked", "GET", "https://api.example.com/api/orders", edTok), nil)
		assertInvalid(t, vESOnly.VerifyRequest(dpopReq(edTok, edProof, "GET", "api.example.com", "/api/orders")), ReasonDPoPAlgRejected)
	})

	t.Run("private jwk params rejected", func(t *testing.T) {
		for _, privField := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			jwkMap := pubToJWKMap(t, &ecKey.PublicKey)
			jwkMap[privField] = "c2VjcmV0"
			proof := manualToken(
				map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwkMap},
				baseClaims("j-priv-"+privField), "c2ln",
			)
			assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPMalformed)
		}
	})

	t.Run("jwk kty=oct rejected", func(t *testing.T) {
		proof := manualToken(
			map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": map[string]any{"kty": "oct"}},
			baseClaims("j-oct"), "c2ln",
		)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPMalformed)
	})

	t.Run("jwk use=enc rejected", func(t *testing.T) {
		jwkMap := pubToJWKMap(t, &ecKey.PublicKey)
		jwkMap["use"] = "enc"
		proof := manualToken(
			map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwkMap},
			baseClaims("j-enc"), "c2ln",
		)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPMalformed)
	})

	t.Run("jwk alg mismatch rejected", func(t *testing.T) {
		jwkMap := pubToJWKMap(t, &ecKey.PublicKey)
		jwkMap["alg"] = "RS256"
		proof := manualToken(
			map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwkMap},
			baseClaims("j-jwkalg"), "c2ln",
		)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPAlgRejected)
	})

	t.Run("weak 1024-bit RSA key in DPoP rejected", func(t *testing.T) {
		weakRSA := genRSA(t, 1024)
		weakTok := signBoundAccessToken(t, idpKey, clock, mustJKT(t, &weakRSA.PublicKey))
		proof := signDPoPProof(t, weakRSA, &weakRSA.PublicKey, jose.RS256,
			makeDPoPClaims(clock, "j-weak-rsa", "GET", "https://api.example.com/api/orders", weakTok), nil)
		assertInvalid(t, v.VerifyRequest(dpopReq(weakTok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPAlgRejected)
	})

	t.Run("off-curve EC point in DPoP rejected", func(t *testing.T) {
		badX := big.NewInt(1)
		badY := big.NewInt(2)
		pad32 := func(n *big.Int) string {
			buf := make([]byte, 32)
			n.FillBytes(buf)
			return base64.RawURLEncoding.EncodeToString(buf)
		}
		proof := manualToken(
			map[string]any{
				"typ": "dpop+jwt",
				"alg": "ES256",
				"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": pad32(badX), "y": pad32(badY)},
			},
			baseClaims("j-offcurve"), "c2ln",
		)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPMalformed)
	})

	t.Run("forged DPoP signature rejected", func(t *testing.T) {
		// 用 otherEC 私钥签名但 header.jwk 放 ecKey 公钥 → 验签失败
		proof := signDPoPProof(t, otherEC, &ecKey.PublicKey, jose.ES256, baseClaims("j-forged"), nil)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPSigInvalid)
	})

	t.Run("JKT mismatch rejected", func(t *testing.T) {
		// 用 otherEC 完整自签，与 access token 的 cnf.jkt(ecKey) 不一致
		proof := signDPoPProof(t, otherEC, &otherEC.PublicKey, jose.ES256, baseClaims("j-jkt"), nil)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPJKTMismatch)
	})

	t.Run("htm mismatch rejected", func(t *testing.T) {
		c := makeDPoPClaims(clock, "j-htm", "POST", "https://api.example.com/api/orders", tok)
		proof := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, c, nil)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPHTMMismatch)
	})

	t.Run("htu mismatches rejected (scheme/host/path/query/fragment/empty-query)", func(t *testing.T) {
		badHTUs := []string{
			"http://api.example.com/api/orders",
			"https://evil.example.com/api/orders",
			"https://api.example.com/api/other",
			"https://api.example.com/api/orders?a=1",
			"https://api.example.com/api/orders?",
			"https://api.example.com/api/orders#frag",
			"https://api.example.com/api/orders#",
			"https://user@api.example.com/api/orders",
			"https://api.example.com:8443/api/orders",
		}
		for i, htu := range badHTUs {
			c := makeDPoPClaims(clock, fmt.Sprintf("j-htu-%d", i), "GET", htu, tok)
			proof := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, c, nil)
			assertInvalid(t, v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders")), ReasonDPoPHTUMismatch)
		}
	})

	t.Run("htu host case-insensitivity and default port normalization", func(t *testing.T) {
		c1 := makeDPoPClaims(clock, "j-htu-norm1", "GET", "HTTPS://API.EXAMPLE.COM:443/api/orders", tok)
		p1 := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, c1, nil)
		if res := v.VerifyRequest(dpopReq(tok, p1, "GET", "api.example.com", "/api/orders")); res.Status != StatusVerified {
			t.Fatalf("默认端口 :443 与大小写归一应通过: %s/%s", res.Status, res.ReasonCode)
		}

		c2 := makeDPoPClaims(clock, "j-htu-norm2", "GET", "https://[::1]/api/orders", tok)
		p2 := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, c2, nil)
		if res := v.VerifyRequest(dpopReq(tok, p2, "GET", "[::1]:443", "/api/orders")); res.Status != StatusVerified {
			t.Fatalf("IPv6 默认端口 :443 归一应通过: %s/%s", res.Status, res.ReasonCode)
		}
	})

	t.Run("ath mismatch and missing ath rejected", func(t *testing.T) {
		cWrong := baseClaims("j-ath-wrong")
		cWrong["ath"] = computeATH("different-access-token")
		pWrong := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, cWrong, nil)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, pWrong, "GET", "api.example.com", "/api/orders")), ReasonDPoPATHMismatch)

		cMiss := baseClaims("j-ath-miss")
		delete(cMiss, "ath")
		pMiss := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, cMiss, nil)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, pMiss, "GET", "api.example.com", "/api/orders")), ReasonDPoPATHMismatch)
	})

	t.Run("expired and future iat rejected", func(t *testing.T) {
		// Default maxAge=60s, leeway=30s → past by 91s rejected; future by 31s rejected
		cOld := baseClaims("j-iat-old")
		cOld["iat"] = clock.Now().Add(-(60 + DefaultClockSkewSeconds + 1) * time.Second).Unix()
		pOld := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, cOld, nil)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, pOld, "GET", "api.example.com", "/api/orders")), ReasonDPoPExpired)

		cFuture := baseClaims("j-iat-future")
		cFuture["iat"] = clock.Now().Add((DefaultClockSkewSeconds + 1) * time.Second).Unix()
		pFuture := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, cFuture, nil)
		assertInvalid(t, v.VerifyRequest(dpopReq(tok, pFuture, "GET", "api.example.com", "/api/orders")), ReasonDPoPExpired)

		// Boundary inside window (future by exactly leeway): passes AND replay TTL covers full validity window
		cEdge := baseClaims("j-iat-edge")
		cEdge["iat"] = clock.Now().Add(DefaultClockSkewSeconds * time.Second).Unix()
		pEdge := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, cEdge, nil)
		res := v.VerifyRequest(dpopReq(tok, pEdge, "GET", "api.example.com", "/api/orders"))
		if res.Status != StatusVerified {
			t.Fatalf("边界内 iat=+leeway 应通过: %s/%s", res.Status, res.ReasonCode)
		}
		if replay.lastTTL < time.Duration(60+2*DefaultClockSkewSeconds)*time.Second {
			t.Fatalf("replayTTL 必须覆盖 iat(+leeway)+maxAge+leeway，得到 %v", replay.lastTTL)
		}
	})

	t.Run("jku/x5u in DPoP header ignored without network", func(t *testing.T) {
		proof := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, baseClaims("j-jku"), map[string]any{
			"jku": "https://attacker.invalid/jwks.json",
			"x5u": "https://attacker.invalid/cert.pem",
		})
		res := v.VerifyRequest(dpopReq(tok, proof, "GET", "api.example.com", "/api/orders"))
		if res.Status != StatusVerified {
			t.Fatalf("DPoP header jku/x5u 应被忽略: %s/%s", res.Status, res.ReasonCode)
		}
	})
}

// ---------- RFC 9449 §9：DPoP-Nonce 挑战与桶切换 ----------

func TestDPoP_NonceChallengeAndAccept(t *testing.T) {
	clock := newFakeClock()
	idpKey := genRSA(t, 2048)
	replay := newMemDPoPReplayStore(clock)
	v := newDPoPVerifier(t, ModeProtect, &TokenBindingConfig{
		Mode:            TokenBindingDPoPRequired,
		RequireNonce:    true,
		NonceTTLSeconds: 60,
	}, idpKey, clock, replay)

	ecKey := genEC(t, elliptic.P256())
	jkt := mustJKT(t, &ecKey.PublicKey)
	tok := signBoundAccessToken(t, idpKey, clock, jkt)

	// 1. 缺 nonce → 401/DPOP_NONCE_REQUIRED + 签发 DPoPNonce（不消耗 replay）
	cNoNonce := makeDPoPClaims(clock, "j-nonce-1", "GET", "https://api.example.com/api/orders", tok)
	pNoNonce := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, cNoNonce, nil)
	res1 := v.VerifyRequest(dpopReq(tok, pNoNonce, "GET", "api.example.com", "/api/orders"))
	if res1.Status != StatusInvalid || res1.ReasonCode != ReasonDPoPNonceRequired || res1.DPoPNonce == "" {
		t.Fatalf("缺 nonce 应挑战: %+v", res1)
	}
	if replay.calls.Load() != 0 {
		t.Fatalf("缺 nonce 挑战阶段不应写入重放存储: calls=%d", replay.calls.Load())
	}

	// 2. 错误 nonce → 重新挑战
	cWrong := makeDPoPClaims(clock, "j-nonce-wrong", "GET", "https://api.example.com/api/orders", tok)
	cWrong["nonce"] = "wrong-nonce-value"
	pWrong := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, cWrong, nil)
	resWrong := v.VerifyRequest(dpopReq(tok, pWrong, "GET", "api.example.com", "/api/orders"))
	if resWrong.Status != StatusInvalid || resWrong.ReasonCode != ReasonDPoPNonceRequired || resWrong.DPoPNonce != res1.DPoPNonce {
		t.Fatalf("错误 nonce 应返回当前桶 nonce 挑战: %+v", resWrong)
	}

	// 3. 携带挑战返回的当前桶 nonce → VERIFIED
	cValid := makeDPoPClaims(clock, "j-nonce-ok1", "GET", "https://api.example.com/api/orders", tok)
	cValid["nonce"] = res1.DPoPNonce
	pValid := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, cValid, nil)
	res2 := v.VerifyRequest(dpopReq(tok, pValid, "GET", "api.example.com", "/api/orders"))
	if res2.Status != StatusVerified || res2.TokenBindingVerified != "DPOP" {
		t.Fatalf("当前桶 nonce 应通过: %+v", res2)
	}

	// 4. 时钟推进 1 个桶（60s）：上一桶 nonce 仍在容忍窗口内 → VERIFIED
	clock.Advance(60 * time.Second)
	cPrev := makeDPoPClaims(clock, "j-nonce-ok2", "GET", "https://api.example.com/api/orders", tok)
	cPrev["nonce"] = res1.DPoPNonce
	pPrev := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, cPrev, nil)
	res3 := v.VerifyRequest(dpopReq(tok, pPrev, "GET", "api.example.com", "/api/orders"))
	if res3.Status != StatusVerified {
		t.Fatalf("上一桶 nonce 应通过: %+v", res3)
	}

	// 5. 再推进 1 个桶（累计 120s，跨 2 桶）：旧 nonce 失效 → 重新挑战并返回新 nonce
	clock.Advance(60 * time.Second)
	cStale := makeDPoPClaims(clock, "j-nonce-stale", "GET", "https://api.example.com/api/orders", tok)
	cStale["nonce"] = res1.DPoPNonce
	pStale := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256, cStale, nil)
	res4 := v.VerifyRequest(dpopReq(tok, pStale, "GET", "api.example.com", "/api/orders"))
	if res4.Status != StatusInvalid || res4.ReasonCode != ReasonDPoPNonceRequired || res4.DPoPNonce == "" || res4.DPoPNonce == res1.DPoPNonce {
		t.Fatalf("跨 2 桶过期 nonce 应重新挑战并返回新 nonce: %+v", res4)
	}

	// 6. OBSERVE 空密钥 + RequireNonce → UNAVAILABLE/VERIFIER_ERROR（不以空密钥签发 nonce）
	iss := staticIssuerCfg(jwksJSON(t, rsaJWK(idpKey, "rsa-1")))
	iss.TokenBinding = &TokenBindingConfig{Mode: TokenBindingDPoPRequired, RequireNonce: true}
	vNoSecret, err := NewVerifier(VerifierConfig{
		Policy:     testPolicy(ModeObserve, iss),
		Clock:      clock,
		DPoPReplay: replay,
	})
	if err != nil {
		t.Fatalf("OBSERVE 空密钥应允许构造: %v", err)
	}
	resNoSec := vNoSecret.VerifyRequest(dpopReq(tok, pStale, "GET", "api.example.com", "/api/orders"))
	if resNoSec.Status != StatusUnavailable || resNoSec.ReasonCode != ReasonVerifierError {
		t.Fatalf("空密钥启用 RequireNonce 应返 UNAVAILABLE/VERIFIER_ERROR: %+v", resNoSec)
	}
}

// ---------- 重放检测 + Valkey nil/故障 → UNAVAILABLE ----------

func TestDPoP_ReplayAndStoreUnavailable(t *testing.T) {
	clock := newFakeClock()
	idpKey := genRSA(t, 2048)
	ecKey1 := genEC(t, elliptic.P256())
	ecKey2 := genEC(t, elliptic.P256())
	jkt1 := mustJKT(t, &ecKey1.PublicKey)
	jkt2 := mustJKT(t, &ecKey2.PublicKey)
	tok1 := signBoundAccessToken(t, idpKey, clock, jkt1)
	tok2 := signBoundAccessToken(t, idpKey, clock, jkt2)

	t.Run("replay rejected and isolated by jkt", func(t *testing.T) {
		replay := newMemDPoPReplayStore(clock)
		v := newDPoPVerifier(t, ModeProtect, &TokenBindingConfig{Mode: TokenBindingDPoPRequired}, idpKey, clock, replay)

		p1 := signDPoPProof(t, ecKey1, &ecKey1.PublicKey, jose.ES256,
			makeDPoPClaims(clock, "shared-jti", "GET", "https://api.example.com/api/orders", tok1), nil)
		if res := v.VerifyRequest(dpopReq(tok1, p1, "GET", "api.example.com", "/api/orders")); res.Status != StatusVerified {
			t.Fatalf("首次使用应通过: %+v", res)
		}
		// 重放同一 (jkt1, jti)
		if res := v.VerifyRequest(dpopReq(tok1, p1, "GET", "api.example.com", "/api/orders")); res.Status != StatusInvalid || res.ReasonCode != ReasonDPoPReplay {
			t.Fatalf("重放应 INVALID/DPOP_REPLAY: %+v", res)
		}
		// 不同密钥 (jkt2, 同一 jti) 互相隔离 → 通过
		p2 := signDPoPProof(t, ecKey2, &ecKey2.PublicKey, jose.ES256,
			makeDPoPClaims(clock, "shared-jti", "GET", "https://api.example.com/api/orders", tok2), nil)
		if res := v.VerifyRequest(dpopReq(tok2, p2, "GET", "api.example.com", "/api/orders")); res.Status != StatusVerified {
			t.Fatalf("不同 jkt 同 jti 应隔离通过: %+v", res)
		}
	})

	t.Run("nil replay store returns UNAVAILABLE", func(t *testing.T) {
		v := newDPoPVerifier(t, ModeProtect, &TokenBindingConfig{Mode: TokenBindingDPoPRequired}, idpKey, clock, nil)
		p1 := signDPoPProof(t, ecKey1, &ecKey1.PublicKey, jose.ES256,
			makeDPoPClaims(clock, "j-nil-store", "GET", "https://api.example.com/api/orders", tok1), nil)
		res := v.VerifyRequest(dpopReq(tok1, p1, "GET", "api.example.com", "/api/orders"))
		if res.Status != StatusUnavailable || res.ReasonCode != ReasonDPoPReplayUnavailable {
			t.Fatalf("DPoPReplay==nil 应 UNAVAILABLE/DPOP_REPLAY_UNAVAILABLE，得到 %s/%s", res.Status, res.ReasonCode)
		}
	})

	t.Run("replay store backend error returns UNAVAILABLE", func(t *testing.T) {
		replay := newMemDPoPReplayStore(clock)
		replay.failErr = errors.New("valkey connection refused")
		v := newDPoPVerifier(t, ModeProtect, &TokenBindingConfig{Mode: TokenBindingDPoPRequired}, idpKey, clock, replay)
		p1 := signDPoPProof(t, ecKey1, &ecKey1.PublicKey, jose.ES256,
			makeDPoPClaims(clock, "j-err-store", "GET", "https://api.example.com/api/orders", tok1), nil)
		res := v.VerifyRequest(dpopReq(tok1, p1, "GET", "api.example.com", "/api/orders"))
		if res.Status != StatusUnavailable || res.ReasonCode != ReasonDPoPReplayUnavailable {
			t.Fatalf("存储故障应 UNAVAILABLE/DPOP_REPLAY_UNAVAILABLE，得到 %s/%s", res.Status, res.ReasonCode)
		}
	})
}

func TestValkeyDPoPReplayStore(t *testing.T) {
	// nil store & nil client → unconfigured error
	var nilStore *ValkeyDPoPReplayStore
	if _, err := nilStore.CheckAndSet(context.Background(), "jkt", "abcd", time.Minute); !errors.Is(err, errDPoPStoreUnconfigured) {
		t.Fatalf("nil store 应报 unconfigured: %v", err)
	}
	if _, err := NewValkeyDPoPReplayStore(nil).CheckAndSet(context.Background(), "jkt", "abcd", time.Minute); !errors.Is(err, errDPoPStoreUnconfigured) {
		t.Fatalf("nil client 应报 unconfigured: %v", err)
	}

	// 正常 int64 {1}=first, {0}=replay，且 sub-second TTL 夹紧到 >=1000ms
	seen := map[string]bool{}
	eval := &mockReplayEvaluator{
		fn: func(_ context.Context, _ string, keys, args []string) ([]interface{}, error) {
			if len(keys) != 1 || len(args) != 2 {
				t.Fatalf("unexpected keys=%v args=%v", keys, args)
			}
			if !strings.HasPrefix(keys[0], dpopReplayKeyPrefix+"{") {
				t.Fatalf("key 应带前缀与 hash tag: %q", keys[0])
			}
			if seen[keys[0]] {
				return []interface{}{int64(0)}, nil
			}
			seen[keys[0]] = true
			return []interface{}{int64(1)}, nil
		},
	}
	store := NewValkeyDPoPReplayStore(eval)
	isReplay, err := store.CheckAndSet(context.Background(), "jkt-1", "deadbeef", 500*time.Microsecond)
	if err != nil || isReplay {
		t.Fatalf("首次登记应返回 (false, nil): isReplay=%v err=%v", isReplay, err)
	}
	if eval.lastArgs[1] != "1000" {
		t.Fatalf("亚秒 TTL 应夹紧到 1000ms 避免 Valkey PX 0 报错: got=%q", eval.lastArgs[1])
	}
	isReplay, err = store.CheckAndSet(context.Background(), "jkt-1", "deadbeef", 10*time.Second)
	if err != nil || !isReplay {
		t.Fatalf("第二次登记应返回 (true, nil): isReplay=%v err=%v", isReplay, err)
	}

	// 字符串回复 {"1"}/{"0"} 与异常回复
	for _, tc := range []struct {
		out        []interface{}
		wantReplay bool
		wantErr    bool
	}{
		{[]interface{}{"1"}, false, false},
		{[]interface{}{"0"}, true, false},
		{[]interface{}{"bad"}, false, true},
		{[]interface{}{}, false, true},
		{[]interface{}{true}, false, true},
	} {
		s := NewValkeyDPoPReplayStore(&mockReplayEvaluator{
			fn: func(context.Context, string, []string, []string) ([]interface{}, error) { return tc.out, nil },
		})
		r, e := s.CheckAndSet(context.Background(), "jkt", "jti", time.Second)
		if (e != nil) != tc.wantErr || (!tc.wantErr && r != tc.wantReplay) {
			t.Fatalf("out=%v: got (%v, %v), want (%v, err=%v)", tc.out, r, e, tc.wantReplay, tc.wantErr)
		}
	}
}

// ---------- 绑定模式矩阵 + 策略校验 ----------

func TestDPoP_BindingModesAndMultiIssuerIsolation(t *testing.T) {
	clock := newFakeClock()
	idpKey := genRSA(t, 2048)
	ecKey := genEC(t, elliptic.P256())
	jkt := mustJKT(t, &ecKey.PublicKey)
	replay := newMemDPoPReplayStore(clock)

	unboundTok := signBoundAccessToken(t, idpKey, clock, "")
	boundTok := signBoundAccessToken(t, idpKey, clock, jkt)

	t.Run("DPOP_OPTIONAL", func(t *testing.T) {
		v := newDPoPVerifier(t, ModeProtect, &TokenBindingConfig{Mode: TokenBindingDPoPOptional}, idpKey, clock, replay)

		// 普通 Bearer 无 cnf.jkt → 放行，TokenBindingVerified==""
		res := v.VerifyRequest(RequestVerifyInput{
			AuthValues: bearer(unboundTok), Method: "GET", Path: "/api/orders", RawPath: "/api/orders", Scheme: "https", Host: "api.example.com",
		})
		if res.Status != StatusVerified || res.TokenBindingVerified != "" {
			t.Fatalf("DPOP_OPTIONAL 普通 Bearer 应通过: %+v", res)
		}
		// 带 cnf.jkt 的令牌尝试降级为 Bearer → 拒绝（防降级）
		resDown := v.VerifyRequest(RequestVerifyInput{
			AuthValues: bearer(boundTok), Method: "GET", Path: "/api/orders", RawPath: "/api/orders", Scheme: "https", Host: "api.example.com",
		})
		if resDown.Status != StatusInvalid || resDown.ReasonCode != ReasonDPoPMalformed {
			t.Fatalf("DPOP_OPTIONAL 带 cnf.jkt 降级 Bearer 应拒绝: %+v", resDown)
		}
		// 无 cnf.jkt 却用 DPoP 方案 → TOKEN_BINDING_MISSING
		pUnbound := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256,
			makeDPoPClaims(clock, "j-opt-unb", "GET", "https://api.example.com/api/orders", unboundTok), nil)
		resUnb := v.VerifyRequest(dpopReq(unboundTok, pUnbound, "GET", "api.example.com", "/api/orders"))
		if resUnb.Status != StatusInvalid || resUnb.ReasonCode != ReasonBindingMissing {
			t.Fatalf("无 cnf.jkt 却用 DPoP 应 TOKEN_BINDING_MISSING: %+v", resUnb)
		}
		// 带 cnf.jkt + 合法 Proof → VERIFIED/DPOP
		pBound := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256,
			makeDPoPClaims(clock, "j-opt-ok", "GET", "https://api.example.com/api/orders", boundTok), nil)
		resOK := v.VerifyRequest(dpopReq(boundTok, pBound, "GET", "api.example.com", "/api/orders"))
		if resOK.Status != StatusVerified || resOK.TokenBindingVerified != "DPOP" {
			t.Fatalf("DPOP_OPTIONAL 合法 DPoP 应通过: %+v", resOK)
		}
	})

	t.Run("DPOP_REQUIRED rejects unbound Bearer", func(t *testing.T) {
		v := newDPoPVerifier(t, ModeProtect, &TokenBindingConfig{Mode: TokenBindingDPoPRequired}, idpKey, clock, replay)
		res := v.VerifyRequest(RequestVerifyInput{
			AuthValues: bearer(unboundTok), Method: "GET", Path: "/api/orders", RawPath: "/api/orders", Scheme: "https", Host: "api.example.com",
		})
		if res.Status != StatusInvalid || res.ReasonCode != ReasonBindingMissing {
			t.Fatalf("DPOP_REQUIRED 拒绝无 cnf.jkt 的 Bearer: %+v", res)
		}
	})

	t.Run("multi-issuer: NONE issuer rejects DPoP scheme even when sibling issuer enables DPoP", func(t *testing.T) {
		issA := staticIssuerCfg(jwksJSON(t, rsaJWK(idpKey, "rsa-1")))
		issA.Issuer = "https://idp-a.example.com"
		issA.TokenBinding = &TokenBindingConfig{Mode: TokenBindingDPoPRequired}

		issB := staticIssuerCfg(jwksJSON(t, rsaJWK(idpKey, "rsa-1")))
		issB.Issuer = "https://idp-b.example.com"
		issB.TokenBinding = nil // NONE

		v, err := NewVerifier(VerifierConfig{
			Policy:         testPolicy(ModeProtect, issA, issB),
			IdentitySecret: testSecret,
			Clock:          clock,
			DPoPReplay:     replay,
		})
		if err != nil {
			t.Fatal(err)
		}
		tokB := signToken(t, idpKey, jose.RS256, "rsa-1", validClaims(clock, issB.Issuer), nil)
		res := v.VerifyRequest(dpopReq(tokB, "", "GET", "api.example.com", "/api/orders"))
		if res.Status != StatusInvalid || res.ReasonCode != ReasonMalformedToken {
			t.Fatalf("未启用绑定的 issuer 必须拒绝 DPoP 方案: %+v", res)
		}
	})
}

func TestTokenBinding_PolicyValidationAndCloneSafety(t *testing.T) {
	idpKey := genRSA(t, 2048)
	jwks := jwksJSON(t, rsaJWK(idpKey, "rsa-1"))

	badConfigs := []*TokenBindingConfig{
		{Mode: "INVALID_MODE"},
		{Mode: TokenBindingDPoPRequired, MaxProofAgeSeconds: 4},
		{Mode: TokenBindingDPoPRequired, MaxProofAgeSeconds: 121},
		{Mode: TokenBindingDPoPRequired, NonceTTLSeconds: 9},
		{Mode: TokenBindingDPoPRequired, NonceTTLSeconds: 301},
		{Mode: TokenBindingDPoPRequired, AllowedDPoPAlgs: []string{"HS256"}},
		{Mode: TokenBindingDPoPRequired, AllowedDPoPAlgs: []string{"none"}},
		{Mode: TokenBindingDPoPRequired, AllowedDPoPAlgs: []string{"ES384"}},
	}
	for i, tb := range badConfigs {
		iss := staticIssuerCfg(jwks)
		iss.TokenBinding = tb
		if _, err := NewVerifier(VerifierConfig{
			Policy:         testPolicy(ModeProtect, iss),
			IdentitySecret: testSecret,
		}); err == nil {
			t.Fatalf("case %d: 非法 TokenBinding 配置应被拒绝: %+v", i, tb)
		}
	}

	// 验证 NewVerifier 不原地改写调用方的 *TokenBindingConfig
	callerTB := &TokenBindingConfig{Mode: " dpop_required "}
	iss := staticIssuerCfg(jwks)
	iss.TokenBinding = callerTB
	v, err := NewVerifier(VerifierConfig{
		Policy:         testPolicy(ModeProtect, iss),
		IdentitySecret: testSecret,
	})
	if err != nil {
		t.Fatalf("合法配置应构造成功: %v", err)
	}
	if callerTB.Mode != " dpop_required " || callerTB.MaxProofAgeSeconds != 0 || len(callerTB.AllowedDPoPAlgs) != 0 {
		t.Fatalf("NewVerifier 不得原地改写调用方 TokenBindingConfig: %+v", callerTB)
	}
	normTB := v.Policy().Issuers[0].TokenBinding
	if normTB.Mode != TokenBindingDPoPRequired || normTB.MaxProofAgeSeconds != 60 || normTB.NonceTTLSeconds != 60 || len(normTB.AllowedDPoPAlgs) != 3 {
		t.Fatalf("归一化默认值异常: %+v", normTB)
	}
}

// ---------- 并发 -race 测试：并发唯一验证 + 并发同 (jkt,jti) 重放竞争 ----------

func TestDPoP_ConcurrentRace(t *testing.T) {
	clock := newFakeClock()
	idpKey := genRSA(t, 2048)
	ecKey := genEC(t, elliptic.P256())
	jkt := mustJKT(t, &ecKey.PublicKey)
	tok := signBoundAccessToken(t, idpKey, clock, jkt)
	replay := newMemDPoPReplayStore(clock)
	v := newDPoPVerifier(t, ModeProtect, &TokenBindingConfig{Mode: TokenBindingDPoPRequired}, idpKey, clock, replay)

	// 1. 并发唯一 proof：全部通过
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				jti := fmt.Sprintf("uniq-%d-%d", g, i)
				p := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256,
					makeDPoPClaims(clock, jti, "GET", "https://api.example.com/api/orders", tok), nil)
				res := v.VerifyRequest(dpopReq(tok, p, "GET", "api.example.com", "/api/orders"))
				if res.Status != StatusVerified || res.TokenBindingVerified != "DPOP" {
					t.Errorf("并发唯一 DPoP 应通过: %s/%s", res.Status, res.ReasonCode)
				}
			}
		}(g)
	}
	wg.Wait()

	// 2. 并发重放同一 (jkt, jti)：有且仅有 1 次通过，其余全部 DPOP_REPLAY
	sharedProof := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256,
		makeDPoPClaims(clock, "race-replay-jti", "GET", "https://api.example.com/api/orders", tok), nil)
	var okCount, replayCount atomic.Int32
	const workers = 32
	start := make(chan struct{})
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res := v.VerifyRequest(dpopReq(tok, sharedProof, "GET", "api.example.com", "/api/orders"))
			switch {
			case res.Status == StatusVerified:
				okCount.Add(1)
			case res.Status == StatusInvalid && res.ReasonCode == ReasonDPoPReplay:
				replayCount.Add(1)
			default:
				t.Errorf("并发重放意外结果: %+v", res)
			}
		}()
	}
	close(start)
	wg.Wait()
	if okCount.Load() != 1 || replayCount.Load() != workers-1 {
		t.Fatalf("并发重放期望 1 成功 + %d 重放，实际 ok=%d replay=%d", workers-1, okCount.Load(), replayCount.Load())
	}
}
