package aicrawl

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/httpsig"
)

func mustEd25519Pair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return pub, priv, string(p)
}

func mustECDSAP256Pair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return priv, string(p)
}

func signEd25519WebBotReq(t *testing.T, r *http.Request, priv ed25519.PrivateKey, kid, agent string, now time.Time) {
	t.Helper()
	comps := []string{"@authority"}
	if agent != "" {
		r.Header.Set("Signature-Agent", `"`+agent+`"`)
		comps = append(comps, "signature-agent")
	}
	var sb strings.Builder
	sb.WriteString(`sig1=(`)
	for i, c := range comps {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(`"` + c + `"`)
	}
	sb.WriteString(fmt.Sprintf(`);created=%d;expires=%d;keyid="%s";nonce="n1";tag="web-bot-auth"`, now.Unix()-5, now.Unix()+60, kid))
	r.Header.Set("Signature-Input", sb.String())
	r.Header.Set("Signature", "sig1=:AA==:")

	p, err := httpsig.ParseWebBotAuth(r, httpsig.Budgets{})
	if err != nil {
		t.Fatalf("ParseWebBotAuth: %v", err)
	}
	base, err := httpsig.BuildWebBotAuthSignatureBase(r, p)
	if err != nil {
		t.Fatalf("BuildWebBotAuthSignatureBase: %v", err)
	}
	sig := ed25519.Sign(priv, base)
	r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
}

func signECDSAWebBotReq(t *testing.T, r *http.Request, priv *ecdsa.PrivateKey, kid, agent string, now time.Time) {
	t.Helper()
	r.Header.Set("Signature-Agent", `"`+agent+`"`)
	sigInput := fmt.Sprintf(`sig1=("@authority" "signature-agent");created=%d;expires=%d;keyid="%s";alg="ecdsa-p256-sha256";tag="web-bot-auth"`, now.Unix()-5, now.Unix()+60, kid)
	r.Header.Set("Signature-Input", sigInput)
	r.Header.Set("Signature", "sig1=:AA==:")
	p, err := httpsig.ParseWebBotAuth(r, httpsig.Budgets{})
	if err != nil {
		t.Fatalf("ParseWebBotAuth: %v", err)
	}
	base, err := httpsig.BuildWebBotAuthSignatureBase(r, p)
	if err != nil {
		t.Fatalf("BuildWebBotAuthSignatureBase: %v", err)
	}
	sum := sha256.Sum256(base)
	rv, sv, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	rv.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	r.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
}

func TestParseAndValidatePolicy_StrictDecodingAndBounds(t *testing.T) {
	_, _, edPEM := mustEd25519Pair(t)
	valid := Policy{
		SchemaVersion:           1,
		ApplicationID:           "11111111-2222-3333-4444-555555555555",
		Mode:                    ModeProtect,
		Version:                 3,
		DefaultAIAction:         ActionHTTP402,
		ContentSignal:           "ai-train=no, search=yes, ai-input=no",
		VerifyWebBotAuth:        true,
		LabyrinthEnabled:        true,
		LabyrinthInjectLinks:    true,
		LabyrinthMaxDepth:       5,
		LabyrinthMaxConcurrency: 256,
		LabyrinthDelayMS:        150,
		LabyrinthKeyHex:         strings.Repeat("ab", 32),
		HTTP402: HTTP402Config{
			Message:       "Please license access",
			PriceHint:     "$0.001/req",
			ContactURL:    "https://licensing.example.com",
			ReceiptHeader: "X-AI-Receipt",
		},
		Rules: []Rule{
			{
				ID:                 "r-allow-search",
				Name:               "Allow Verified Search",
				Category:           CategorySearchEngine,
				RequireVerifiedSig: true,
				Action:             ActionAllow,
				ExemptBotChallenge: true,
				Priority:           10,
			},
		},
		Directories: []DirectorySpec{
			{
				ID:             "dir-1",
				Slug:           "search-bot",
				Name:           "Search Bot",
				Category:       CategorySearchEngine,
				SignatureAgent: "https://searchbot.example.com",
				Keys:           []KeySpec{{Kid: "k1", Alg: httpsig.AlgEd25519, PublicKeyPEM: edPEM}},
			},
		},
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAndValidatePolicy(raw)
	if err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if got.Mode != ModeProtect || got.LabyrinthMaxDepth != 5 || len(got.Rules) != 1 {
		t.Fatalf("unexpected parsed policy: %+v", got)
	}

	// Unknown field MUST fail closed.
	if _, err := ParseAndValidatePolicy(json.RawMessage(`{"schema_version":1,"mode":"OFF","unknown_flag":true}`)); err == nil {
		t.Fatal("expected unknown field to fail closed")
	}

	// Unsupported schema_version MUST fail closed.
	if _, err := ParseAndValidatePolicy(json.RawMessage(`{"schema_version":2,"mode":"OFF"}`)); err == nil {
		t.Fatal("expected unsupported schema_version to fail closed")
	}

	// PROTECT + labyrinth_enabled without key MUST fail closed.
	noKeyProtect := valid
	noKeyProtect.LabyrinthKeyHex = ""
	rawNoKey, _ := json.Marshal(noKeyProtect)
	if _, err := ParseAndValidatePolicy(rawNoKey); err == nil {
		t.Fatal("expected PROTECT + labyrinth_enabled without labyrinth_key_hex to fail closed")
	}

	// OBSERVE + labyrinth_enabled without key MUST succeed (ephemeral key generated in NewEngine).
	obsNoKey := valid
	obsNoKey.Mode = ModeObserve
	obsNoKey.LabyrinthKeyHex = ""
	rawObs, _ := json.Marshal(obsNoKey)
	obsPol, err := ParseAndValidatePolicy(rawObs)
	if err != nil {
		t.Fatalf("OBSERVE without labyrinth_key_hex should succeed: %v", err)
	}
	eng, err := NewEngine(obsPol, EngineOptions{})
	if err != nil {
		t.Fatalf("NewEngine OBSERVE ephemeral key failed: %v", err)
	}
	if eng.Labyrinth().SignPath("example.com", "0123456789abcdef", 0) == "" {
		t.Fatal("ephemeral labyrinth key should sign paths")
	}

	// Error message must NEVER leak labyrinth_key_hex value.
	badKey := valid
	badKey.LabyrinthKeyHex = "SUPER_SECRET_NOT_HEX_VALUE_999"
	rawBadKey, _ := json.Marshal(badKey)
	_, err = ParseAndValidatePolicy(rawBadKey)
	if err == nil {
		t.Fatal("expected bad hex key to fail")
	}
	if strings.Contains(err.Error(), "SUPER_SECRET") {
		t.Fatalf("secret leaked in error message: %v", err)
	}

	// SSRF directory_url rejected during validation.
	ssrfDir := valid
	ssrfDir.Directories = []DirectorySpec{{ID: "d1", Slug: "d1", DirectoryURL: "https://127.0.0.1/.well-known/http-message-signatures-directory"}}
	rawSSRF, _ := json.Marshal(ssrfDir)
	if _, err := ParseAndValidatePolicy(rawSSRF); err == nil {
		t.Fatal("expected loopback directory_url to fail validation")
	}
}

func TestEngineEvaluate_WebBotAuthAndRulePriority(t *testing.T) {
	_, edPriv, edPEM := mustEd25519Pair(t)
	ecPriv, ecPEM := mustECDSAP256Pair(t)
	now := time.Unix(1750010000, 0)

	pol := &Policy{
		SchemaVersion:        1,
		ApplicationID:        "app-1",
		Mode:                 ModeProtect,
		Version:              2,
		DefaultAIAction:      ActionHTTP402,
		ContentSignal:        "ai-train=no, search=yes, ai-input=no",
		VerifyWebBotAuth:     true,
		LabyrinthEnabled:     true,
		LabyrinthInjectLinks: true,
		LabyrinthKeyHex:      strings.Repeat("12", 32),
		Rules: []Rule{
			{
				ID:                 "r-low-prio-block-all-ai",
				Name:               "Block all AI training",
				Category:           CategoryAITraining,
				Action:             ActionBlock,
				Priority:           200,
			},
			{
				ID:                 "r-high-prio-verified-search",
				Name:               "Allow Verified Search + Exempt Bot",
				Category:           CategorySearchEngine,
				AgentID:            "trusted-search",
				RequireVerifiedSig: true,
				Action:             ActionAllow,
				ExemptBotChallenge: true,
				Priority:           10,
			},
			{
				ID:                 "r-verified-ai-rate-limit",
				Name:               "Rate limit verified AI agent",
				Category:           CategoryAIAgent,
				RequireVerifiedSig: true,
				Action:             ActionRateLimit,
				RateLimitRPM:       30,
				Priority:           50,
			},
			{
				ID:         "r-tarpit-scraper",
				Name:       "Tarpit custom scraper",
				UAPatterns: []string{"EvilScraper*"},
				Action:     ActionTarpit,
				Priority:   80,
			},
		},
		Directories: []DirectorySpec{
			{
				ID:             "dir-search",
				Slug:           "trusted-search",
				Name:           "Trusted Search",
				Category:       CategorySearchEngine,
				SignatureAgent: "https://search.trusted.example",
				Keys:           []KeySpec{{Kid: "search-k1", Alg: httpsig.AlgEd25519, PublicKeyPEM: edPEM}},
			},
			{
				ID:             "dir-agent",
				Slug:           "verified-agent",
				Name:           "Verified AI Agent",
				Category:       CategoryAIAgent,
				SignatureAgent: "https://agent.trusted.example",
				Keys:           []KeySpec{{Kid: "agent-k1", Alg: httpsig.AlgECDSAP256SHA256, PublicKeyPEM: ecPEM}},
			},
		},
	}

	eng, err := NewEngine(pol, EngineOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Verified Ed25519 search crawler -> matches r-high-prio-verified-search, ExemptBotChallenge=true, no trap link injection.
	r1 := httptest.NewRequest(http.MethodGet, "https://site.example/docs", nil)
	r1.Header.Set("User-Agent", "Mozilla/5.0 compatible SearchBot")
	signEd25519WebBotReq(t, r1, edPriv, "search-k1", "https://search.trusted.example", now)
	res1 := eng.Evaluate(r1)
	if !res1.Verified || res1.Action != ActionAllow || !res1.ExemptBotChallenge || res1.InjectTrapLink {
		t.Fatalf("verified search eval mismatch: %+v", res1)
	}

	// 2. Spoofed UA without valid Web Bot Auth MUST NOT match require_verified_sig or get ExemptBotChallenge.
	r2 := httptest.NewRequest(http.MethodGet, "https://site.example/docs", nil)
	r2.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GPTBot/1.2)")
	res2 := eng.Evaluate(r2)
	if res2.Verified || res2.ExemptBotChallenge || res2.Action != ActionBlock || res2.RuleID != "r-low-prio-block-all-ai" || !res2.InjectTrapLink {
		t.Fatalf("unverified GPTBot eval mismatch: %+v", res2)
	}

	// 3. Verified ECDSA P-256 AI agent -> RATE_LIMIT with RPM 30.
	r3 := httptest.NewRequest(http.MethodGet, "https://site.example/docs", nil)
	signECDSAWebBotReq(t, r3, ecPriv, "agent-k1", "https://agent.trusted.example", now)
	res3 := eng.Evaluate(r3)
	if !res3.Verified || res3.Action != ActionRateLimit || res3.RateLimitRPM != 30 || res3.ExemptBotChallenge {
		t.Fatalf("verified AI agent eval mismatch: %+v", res3)
	}

	// 4. Custom UA glob pattern -> TARPIT.
	r4 := httptest.NewRequest(http.MethodGet, "https://site.example/docs", nil)
	r4.Header.Set("User-Agent", "EvilScraper/9.9")
	res4 := eng.Evaluate(r4)
	if !res4.Matched || res4.Action != ActionTarpit || res4.RuleID != "r-tarpit-scraper" {
		t.Fatalf("custom UA glob eval mismatch: %+v", res4)
	}

	// 5. Unmatched AI_ASSISTANT falls back to default_ai_action (HTTP_402).
	r5 := httptest.NewRequest(http.MethodGet, "https://site.example/docs", nil)
	r5.Header.Set("User-Agent", "ChatGPT-User/1.0")
	res5 := eng.Evaluate(r5)
	if !res5.Matched || res5.Category != CategoryAIAssistant || res5.Action != ActionHTTP402 {
		t.Fatalf("default_ai_action fallback mismatch: %+v", res5)
	}

	// 6. Normal human browser is NOT matched and NOT injected with trap links.
	r6 := httptest.NewRequest(http.MethodGet, "https://site.example/docs", nil)
	r6.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	res6 := eng.Evaluate(r6)
	if res6.Matched || res6.IsSuspectedBot || res6.InjectTrapLink || res6.Verified {
		t.Fatalf("human browser should not be flagged: %+v", res6)
	}

	// 7. Invalid Web Bot Auth signature -> SigStatus=INVALID, falls back to default_ai_action (HTTP_402), IsSuspectedBot=true.
	r7 := httptest.NewRequest(http.MethodGet, "https://site.example/docs", nil)
	r7.Header.Set("Signature-Input", fmt.Sprintf(`sig1=("@authority");created=%d;expires=%d;keyid="search-k1";tag="web-bot-auth"`, now.Unix()-5, now.Unix()+60))
	r7.Header.Set("Signature", `sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:`)
	res7 := eng.Evaluate(r7)
	if res7.Verified || res7.SigStatus != "INVALID" || !res7.IsSuspectedBot || res7.Action != ActionHTTP402 {
		t.Fatalf("invalid web bot auth eval mismatch: %+v", res7)
	}
}
