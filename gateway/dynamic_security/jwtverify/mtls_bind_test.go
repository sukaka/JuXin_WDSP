package jwtverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func genTestClientCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate cert key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test cert: %v", err)
	}
	return der
}

func signMTLSBoundToken(t *testing.T, idpKey any, clock *fakeClock, x5t string) string {
	t.Helper()
	c := validClaims(clock, testIssuer)
	if x5t != "" {
		c["cnf"] = map[string]any{"x5t#S256": x5t}
	}
	return signToken(t, idpKey, jose.RS256, "rsa-1", c, nil)
}

func TestComputeCertThumbprintSHA256_RFC8705(t *testing.T) {
	der := genTestClientCertDER(t, "client-a")
	got := ComputeCertThumbprintSHA256(der)
	sum := sha256.Sum256(der)
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("x5t#S256 不一致: got=%q want=%q", got, want)
	}
	if len(got) != 43 || strings.ContainsAny(got, "=+/\r\n ") {
		t.Fatalf("x5t#S256 须为 43 字符无填充 base64url: %q", got)
	}
}

func TestMTLSBinding_RequiredAndFailures(t *testing.T) {
	clock := newFakeClock()
	idpKey := genRSA(t, 2048)
	certA := genTestClientCertDER(t, "client-a")
	certB := genTestClientCertDER(t, "client-b")
	x5tA := ComputeCertThumbprintSHA256(certA)

	v := newDPoPVerifier(t, ModeProtect, &TokenBindingConfig{Mode: TokenBindingMTLSRequired}, idpKey, clock, nil)
	boundTok := signMTLSBoundToken(t, idpKey, clock, x5tA)
	unboundTok := signMTLSBoundToken(t, idpKey, clock, "")

	t.Run("matching verified cert passes", func(t *testing.T) {
		res := v.VerifyRequest(RequestVerifyInput{
			AuthValues:  bearer(boundTok),
			Method:      "GET",
			Path:        "/api/orders",
			RawPath:     "/api/orders",
			Scheme:      "https",
			Host:        "api.example.com",
			PeerCertDER: certA,
		})
		if res.Status != StatusVerified || res.ReasonCode != ReasonValid {
			t.Fatalf("匹配 mTLS 证书应 VERIFIED/VALID: %+v", res)
		}
		if res.TokenBindingVerified != "MTLS" || res.VerifiedPrincipalID == "" {
			t.Fatalf("应设置 TokenBindingVerified=MTLS 与可信主体: %+v", res)
		}
	})

	t.Run("missing client cert rejected", func(t *testing.T) {
		res := v.VerifyRequest(RequestVerifyInput{
			AuthValues: bearer(boundTok),
			Method:     "GET",
			Path:       "/api/orders",
			Scheme:     "https",
			Host:       "api.example.com",
		})
		if res.Status != StatusInvalid || res.ReasonCode != ReasonMTLSNoCert {
			t.Fatalf("缺客户端证书应 INVALID/MTLS_CLIENT_CERT_MISSING: %+v", res)
		}
		if res.VerifiedPrincipalID != "" || res.TokenBindingVerified != "" {
			t.Fatalf("失败不得产出可信主体或绑定标记: %+v", res)
		}
	})

	t.Run("mismatched client cert rejected", func(t *testing.T) {
		res := v.VerifyRequest(RequestVerifyInput{
			AuthValues:  bearer(boundTok),
			Method:      "GET",
			Path:        "/api/orders",
			Scheme:      "https",
			Host:        "api.example.com",
			PeerCertDER: certB,
		})
		if res.Status != StatusInvalid || res.ReasonCode != ReasonMTLSCertMismatch {
			t.Fatalf("证书不匹配应 INVALID/MTLS_CERT_MISMATCH: %+v", res)
		}
		if res.VerifiedPrincipalID != "" || res.TokenBindingVerified != "" {
			t.Fatalf("失败不得产出可信主体或绑定标记: %+v", res)
		}
	})

	t.Run("missing cnf x5t#S256 rejected", func(t *testing.T) {
		res := v.VerifyRequest(RequestVerifyInput{
			AuthValues:  bearer(unboundTok),
			Method:      "GET",
			Path:        "/api/orders",
			Scheme:      "https",
			Host:        "api.example.com",
			PeerCertDER: certA,
		})
		if res.Status != StatusInvalid || res.ReasonCode != ReasonBindingMissing {
			t.Fatalf("缺 cnf.x5t#S256 应 TOKEN_BINDING_MISSING: %+v", res)
		}
	})

	t.Run("malformed cnf claim rejected", func(t *testing.T) {
		cBad := validClaims(clock, testIssuer)
		cBad["cnf"] = map[string]any{"x5t#S256": 12345}
		tokBad := signToken(t, idpKey, jose.RS256, "rsa-1", cBad, nil)
		res := v.VerifyRequest(RequestVerifyInput{
			AuthValues:  bearer(tokBad),
			Method:      "GET",
			Path:        "/api/orders",
			Scheme:      "https",
			Host:        "api.example.com",
			PeerCertDER: certA,
		})
		if res.Status != StatusInvalid || res.ReasonCode != ReasonClaimInvalid {
			t.Fatalf("非法 cnf 类型应 CLAIM_INVALID: %+v", res)
		}
	})

	t.Run("MTLS_REQUIRED rejects DPoP scheme", func(t *testing.T) {
		res := v.VerifyRequest(RequestVerifyInput{
			AuthValues:  []string{"DPoP " + boundTok},
			Method:      "GET",
			Path:        "/api/orders",
			Scheme:      "https",
			Host:        "api.example.com",
			PeerCertDER: certA,
		})
		if res.Status != StatusInvalid || res.ReasonCode != ReasonMalformedToken {
			t.Fatalf("MTLS_REQUIRED 不接受 DPoP 认证方案: %+v", res)
		}
	})
}

func TestDPoPOrMTLS_Mode(t *testing.T) {
	clock := newFakeClock()
	idpKey := genRSA(t, 2048)
	replay := newMemDPoPReplayStore(clock)
	v := newDPoPVerifier(t, ModeProtect, &TokenBindingConfig{Mode: TokenBindingDPoPOrMTLS}, idpKey, clock, replay)

	certA := genTestClientCertDER(t, "client-a")
	x5tA := ComputeCertThumbprintSHA256(certA)
	ecKey := genEC(t, elliptic.P256())
	jkt := mustJKT(t, &ecKey.PublicKey)

	// 1. mTLS-bound token passes with cert
	mtlsTok := signMTLSBoundToken(t, idpKey, clock, x5tA)
	resM := v.VerifyRequest(RequestVerifyInput{
		AuthValues: bearer(mtlsTok), Method: "GET", Path: "/api/orders", RawPath: "/api/orders",
		Scheme: "https", Host: "api.example.com", PeerCertDER: certA,
	})
	if resM.Status != StatusVerified || resM.TokenBindingVerified != "MTLS" {
		t.Fatalf("DPOP_OR_MTLS mTLS 令牌应通过: %+v", resM)
	}

	// 2. DPoP-bound token passes with DPoP proof
	dpopTok := signBoundAccessToken(t, idpKey, clock, jkt)
	proof := signDPoPProof(t, ecKey, &ecKey.PublicKey, jose.ES256,
		makeDPoPClaims(clock, "j-or-1", "GET", "https://api.example.com/api/orders", dpopTok), nil)
	resD := v.VerifyRequest(dpopReq(dpopTok, proof, "GET", "api.example.com", "/api/orders"))
	if resD.Status != StatusVerified || resD.TokenBindingVerified != "DPOP" {
		t.Fatalf("DPOP_OR_MTLS DPoP 令牌应通过: %+v", resD)
	}

	// 3. Unbound token rejected
	unboundTok := signMTLSBoundToken(t, idpKey, clock, "")
	resU := v.VerifyRequest(RequestVerifyInput{
		AuthValues: bearer(unboundTok), Method: "GET", Path: "/api/orders",
		Scheme: "https", Host: "api.example.com", PeerCertDER: certA,
	})
	if resU.Status != StatusInvalid || resU.ReasonCode != ReasonBindingMissing {
		t.Fatalf("DPOP_OR_MTLS 无绑定令牌应 TOKEN_BINDING_MISSING: %+v", resU)
	}

	// 4. Dual-claim token (cnf.jkt + cnf.x5t#S256) MUST NOT be accepted as plain Bearer (RFC 9449 §7.1)
	cBoth := validClaims(clock, testIssuer)
	cBoth["cnf"] = map[string]any{"jkt": jkt, "x5t#S256": x5tA}
	bothTok := signToken(t, idpKey, jose.RS256, "rsa-1", cBoth, nil)
	resBoth := v.VerifyRequest(RequestVerifyInput{
		AuthValues: bearer(bothTok), Method: "GET", Path: "/api/orders",
		Scheme: "https", Host: "api.example.com", PeerCertDER: certA,
	})
	if resBoth.Status != StatusInvalid || resBoth.ReasonCode != ReasonDPoPMalformed {
		t.Fatalf("含 cnf.jkt 令牌禁止按 Bearer 接受: %+v", resBoth)
	}
}

func TestMTLSBinding_ConcurrentRace(t *testing.T) {
	clock := newFakeClock()
	idpKey := genRSA(t, 2048)
	certA := genTestClientCertDER(t, "client-a")
	certB := genTestClientCertDER(t, "client-b")
	tok := signMTLSBoundToken(t, idpKey, clock, ComputeCertThumbprintSHA256(certA))
	v := newDPoPVerifier(t, ModeProtect, &TokenBindingConfig{Mode: TokenBindingMTLSRequired}, idpKey, clock, nil)

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if (g+i)%2 == 0 {
					res := v.VerifyRequest(RequestVerifyInput{
						AuthValues: bearer(tok), Method: "GET", Path: "/api/orders",
						Scheme: "https", Host: "api.example.com", PeerCertDER: certA,
					})
					if res.Status != StatusVerified || res.TokenBindingVerified != "MTLS" {
						t.Errorf("期望 VERIFIED/MTLS: %+v", res)
					}
				} else {
					res := v.VerifyRequest(RequestVerifyInput{
						AuthValues: bearer(tok), Method: "GET", Path: "/api/orders",
						Scheme: "https", Host: "api.example.com", PeerCertDER: certB,
					})
					if res.Status != StatusInvalid || res.ReasonCode != ReasonMTLSCertMismatch {
						t.Errorf("期望 INVALID/MTLS_CERT_MISMATCH: %+v", res)
					}
				}
			}
		}(g)
	}
	wg.Wait()
}
