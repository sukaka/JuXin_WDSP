package httpsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// signWebBotAuthRequest 构造真实 Web Bot Auth（RFC 9421）签名请求供测试使用。
func signWebBotAuthRequest(t *testing.T, k testKeys, alg, label, keyID, agent string, created, expires int64, components []string, includeAlgParam bool) (*http.Request, Key) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://example.com/articles/42?lang=zh", nil)
	if agent != "" {
		r.Header.Set("Signature-Agent", `"`+agent+`"`)
	}
	if len(components) == 0 {
		components = []string{"@authority"}
		if agent != "" {
			components = append(components, "signature-agent")
		}
	}
	if label == "" {
		label = "sig1"
	}
	var sb strings.Builder
	sb.WriteString(label)
	sb.WriteString("=(")
	for i, c := range components {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(`"` + c + `"`)
	}
	sb.WriteString(fmt.Sprintf(`);created=%d;expires=%d;keyid="%s";nonce="wba-nonce-01";tag="web-bot-auth"`, created, expires, keyID))
	if includeAlgParam {
		sb.WriteString(fmt.Sprintf(`;alg="%s"`, alg))
	}
	sigInput := sb.String()
	r.Header.Set("Signature-Input", sigInput)
	r.Header.Set("Signature", label+"=:AA==:")

	p, err := ParseWebBotAuth(r, Budgets{})
	if err != nil {
		t.Fatalf("ParseWebBotAuth placeholder failed: %v", err)
	}
	base, err := BuildWebBotAuthSignatureBase(r, p)
	if err != nil {
		t.Fatalf("BuildWebBotAuthSignatureBase failed: %v", err)
	}
	var sig []byte
	var pubPEM []byte
	switch alg {
	case AlgEd25519:
		sig = ed25519.Sign(k.edPriv, base)
		pubPEM = pemOfPublic(t, k.edPub)
	case AlgECDSAP256SHA256:
		sum := sha256.Sum256(base)
		rv, sv, err := ecdsa.Sign(rand.Reader, k.ecPriv, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = make([]byte, 64)
		rv.FillBytes(sig[:32])
		sv.FillBytes(sig[32:])
		pubPEM = pemOfPublic(t, k.ecPub)
	default:
		t.Fatalf("unsupported test alg %s", alg)
	}
	r.Header.Set("Signature", label+"=:"+base64.StdEncoding.EncodeToString(sig)+":")
	return r, Key{Kid: keyID, Alg: alg, PublicKeyPEM: pubPEM}
}

func TestVerifyWebBotAuth_Ed25519AndECDSAP256(t *testing.T) {
	k := genTestKeys(t)
	now := time.Unix(1750000100, 0)

	for _, tc := range []struct {
		name       string
		alg        string
		includeAlg bool
		agent      string
	}{
		{"ed25519_with_alg_and_agent", AlgEd25519, true, "https://crawler.openai.example"},
		{"ed25519_without_alg_param", AlgEd25519, false, "https://crawler.anthropic.example"},
		{"ecdsa_p256_with_alg", AlgECDSAP256SHA256, true, "https://bot.example.org"},
		{"ecdsa_p256_without_agent", AlgECDSAP256SHA256, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, key := signWebBotAuthRequest(t, k, tc.alg, "sig1", "kid-1", tc.agent, now.Unix()-10, now.Unix()+120, nil, tc.includeAlg)
			lookup := func(kid, sigAgent string) (Key, bool) {
				if kid == "kid-1" && NormalizeSignatureAgent(sigAgent) == NormalizeSignatureAgent(tc.agent) {
					return key, true
				}
				return Key{}, false
			}
			res, err := VerifyWebBotAuth(r, lookup, WebBotAuthOptions{Now: func() time.Time { return now }})
			if err != nil {
				t.Fatalf("VerifyWebBotAuth failed: %v", err)
			}
			if !res.Verified || res.KeyID != "kid-1" || res.Alg != tc.alg || res.SignatureAgent != tc.agent {
				t.Fatalf("unexpected result: %+v", res)
			}
		})
	}
}

func TestVerifyWebBotAuth_TimeBoundsAndSkew(t *testing.T) {
	k := genTestKeys(t)
	now := time.Unix(1750001000, 0)
	opts := WebBotAuthOptions{Now: func() time.Time { return now }}

	cases := []struct {
		name    string
		created int64
		expires int64
		wantOK  bool
	}{
		{"valid_within_300s", now.Unix() - 5, now.Unix() + 295, true},
		{"lifetime_exceeds_300s", now.Unix(), now.Unix() + 301, false},
		{"expired_within_30s_skew", now.Unix() - 100, now.Unix() - 25, true},
		{"expired_beyond_30s_skew", now.Unix() - 100, now.Unix() - 31, false},
		{"created_future_within_30s_skew", now.Unix() + 25, now.Unix() + 125, true},
		{"created_future_beyond_30s_skew", now.Unix() + 31, now.Unix() + 125, false},
		{"expires_le_created", now.Unix(), now.Unix(), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, key := signWebBotAuthRequest(t, k, AlgEd25519, "sig1", "kid-time", "https://bot.example", tc.created, tc.expires, nil, true)
			lookup := func(kid, _ string) (Key, bool) { return key, kid == "kid-time" }
			_, err := VerifyWebBotAuth(r, lookup, opts)
			if tc.wantOK && err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			if !tc.wantOK && !errors.Is(err, ErrWebBotAuthExpired) {
				t.Fatalf("expected ErrWebBotAuthExpired, got %v", err)
			}
		})
	}
}

func TestVerifyWebBotAuth_AuthorityAndTampering(t *testing.T) {
	k := genTestKeys(t)
	now := time.Unix(1750002000, 0)
	opts := WebBotAuthOptions{Now: func() time.Time { return now }}

	// 1. Missing @authority must be rejected as malformed.
	rMissingAuth := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	rMissingAuth.Header.Set("Signature-Input", fmt.Sprintf(`sig1=("@method" "@path");created=%d;expires=%d;keyid="k1";tag="web-bot-auth"`, now.Unix(), now.Unix()+60))
	rMissingAuth.Header.Set("Signature", `sig1=:AA==:`)
	if _, err := VerifyWebBotAuth(rMissingAuth, nil, opts); !errors.Is(err, ErrMalformed) {
		t.Fatalf("expected ErrMalformed for missing @authority, got %v", err)
	}

	// 2. Host tampering must fail cryptographic verification.
	r, key := signWebBotAuthRequest(t, k, AlgEd25519, "sig1", "kid-tamper", "https://bot.example", now.Unix()-5, now.Unix()+60, []string{"@authority", "signature-agent"}, true)
	r.Host = "evil.example.com"
	lookup := func(kid, _ string) (Key, bool) { return key, kid == "kid-tamper" }
	if _, err := VerifyWebBotAuth(r, lookup, opts); !errors.Is(err, ErrVerify) {
		t.Fatalf("expected ErrVerify on host tamper, got %v", err)
	}

	// 3. Signature-Agent tampering must fail cryptographic verification when covered.
	r2, key2 := signWebBotAuthRequest(t, k, AlgEd25519, "sig1", "kid-tamper2", "https://bot.example", now.Unix()-5, now.Unix()+60, []string{"@authority", "signature-agent"}, true)
	r2.Header.Set("Signature-Agent", `"https://spoofed.example"`)
	lookup2 := func(kid, _ string) (Key, bool) { return key2, kid == "kid-tamper2" }
	if _, err := VerifyWebBotAuth(r2, lookup2, opts); !errors.Is(err, ErrVerify) {
		t.Fatalf("expected ErrVerify on Signature-Agent tamper, got %v", err)
	}

	// 4. Case-insensitive @authority (RFC 9421 §2.2.3) passes.
	r3, key3 := signWebBotAuthRequest(t, k, AlgEd25519, "sig1", "kid-case", "", now.Unix()-5, now.Unix()+60, []string{"@authority"}, true)
	r3.Host = "EXAMPLE.COM"
	lookup3 := func(kid, _ string) (Key, bool) { return key3, kid == "kid-case" }
	if _, err := VerifyWebBotAuth(r3, lookup3, opts); err != nil {
		t.Fatalf("expected uppercase Host to normalize to lowercase @authority, got %v", err)
	}
}

func TestVerifyWebBotAuth_MultiLabelCoexistenceAndRejection(t *testing.T) {
	k := genTestKeys(t)
	now := time.Unix(1750003000, 0)
	opts := WebBotAuthOptions{Now: func() time.Time { return now }}

	// Non-web-bot-auth signature (e.g., machine identity) returns ErrWebBotAuthNotPresent.
	rOther := httptest.NewRequest(http.MethodGet, "https://example.com/api", nil)
	rOther.Header.Set("Signature-Input", fmt.Sprintf(`sig1=("@method" "@authority" "@path");created=%d;expires=%d;nonce="n1";keyid="m1";alg="ed25519"`, now.Unix(), now.Unix()+60))
	rOther.Header.Set("Signature", `sig1=:AAAA:`)
	if _, err := VerifyWebBotAuth(rOther, nil, opts); !errors.Is(err, ErrWebBotAuthNotPresent) {
		t.Fatalf("expected ErrWebBotAuthNotPresent for non-web-bot-auth sig, got %v", err)
	}

	// Coexistence: sig1 is another tag, sig2 is web-bot-auth.
	r, key := signWebBotAuthRequest(t, k, AlgEd25519, "sig2", "kid-multi", "https://agent.example", now.Unix()-5, now.Unix()+60, []string{"@authority", "signature-agent"}, true)
	r.Header.Set("Signature-Input", `sig1=("@method");created=1750002995;keyid="other";tag="custom", `+r.Header.Get("Signature-Input"))
	r.Header.Set("Signature", `sig1=:AAAA:, `+r.Header.Get("Signature"))
	lookup := func(kid, _ string) (Key, bool) { return key, kid == "kid-multi" }
	res, err := VerifyWebBotAuth(r, lookup, opts)
	if err != nil || !res.Verified || res.Label != "sig2" {
		t.Fatalf("multi-label verify failed: res=%+v err=%v", res, err)
	}

	// Reject unsupported algorithm (rsa-pss-sha512 / hmac-sha256).
	rBadAlg := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	rBadAlg.Header.Set("Signature-Input", fmt.Sprintf(`sig1=("@authority");created=%d;expires=%d;keyid="k1";alg="hmac-sha256";tag="web-bot-auth"`, now.Unix(), now.Unix()+60))
	rBadAlg.Header.Set("Signature", `sig1=:AAAA:`)
	if _, err := VerifyWebBotAuth(rBadAlg, lookup, opts); !errors.Is(err, ErrVerify) {
		t.Fatalf("expected ErrVerify for unsupported alg, got %v", err)
	}

	// Unknown key returns ErrWebBotAuthKeyNotFound.
	rUnknown, _ := signWebBotAuthRequest(t, k, AlgEd25519, "sig1", "unknown-kid", "", now.Unix()-5, now.Unix()+60, nil, true)
	if _, err := VerifyWebBotAuth(rUnknown, lookup, opts); !errors.Is(err, ErrWebBotAuthKeyNotFound) {
		t.Fatalf("expected ErrWebBotAuthKeyNotFound, got %v", err)
	}
}

func TestParseSignatureAgentVariants(t *testing.T) {
	if got := ParseSignatureAgent([]string{`"https://Crawler.Example.COM/"`}, "sig1"); got != "https://Crawler.Example.COM/" {
		t.Fatalf("sf string got %q", got)
	}
	if got := NormalizeSignatureAgent(`"https://Crawler.Example.COM/"`); got != "https://crawler.example.com" {
		t.Fatalf("normalize got %q", got)
	}
	if got := ParseSignatureAgent([]string{`sig1="https://a.example", sig2="https://b.example"`}, "sig2"); got != "https://b.example" {
		t.Fatalf("sf dict got %q", got)
	}
	if got := ParseSignatureAgent([]string{`https://plain.example/bot`}, "sig1"); got != "https://plain.example/bot" {
		t.Fatalf("plain got %q", got)
	}
}
