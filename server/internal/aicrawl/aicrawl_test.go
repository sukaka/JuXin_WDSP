package aicrawl

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/outboundhttp"
)

func genEd25519PEM(t *testing.T) (ed25519.PublicKey, string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	return pub, pubPEM, privPEM
}

func genP256PEM(t *testing.T) (*ecdsa.PublicKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &priv.PublicKey, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}

func TestParseDirectoryJWKS(t *testing.T) {
	edPub, _, _ := genEd25519PEM(t)
	ecPub, _ := genP256PEM(t)

	xEd := base64.RawURLEncoding.EncodeToString(edPub)
	xEC := base64.RawURLEncoding.EncodeToString(ecPub.X.Bytes())
	yEC := base64.RawURLEncoding.EncodeToString(ecPub.Y.Bytes())

	// 1. 合法 Ed25519（显式 kid）+ ECDSA P-256（缺省 kid 自动派生 RFC 7638 thumbprint）+ 忽略不支持曲线
	raw := fmt.Sprintf(`{
		"keys": [
			{"kty":"OKP","crv":"Ed25519","kid":"ed-1","x":%q},
			{"kty":"EC","crv":"P-256","x":%q,"y":%q},
			{"kty":"RSA","kid":"rsa-skip","n":"AQAB","e":"AQAB"}
		]
	}`, xEd, xEC, yEC)
	keys, err := ParseDirectoryJWKS([]byte(raw))
	if err != nil {
		t.Fatalf("ParseDirectoryJWKS valid: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d: %+v", len(keys), keys)
	}
	if keys[0].KID != "ed-1" || keys[0].Alg != KeyAlgEd25519 {
		t.Fatalf("key[0] mismatch: %+v", keys[0])
	}
	if err := ValidatePublicKeyPEM(keys[0].Alg, keys[0].PublicKeyPEM); err != nil {
		t.Fatalf("key[0] PEM invalid: %v", err)
	}
	if keys[1].KID == "" || keys[1].Alg != KeyAlgECDSAP256 {
		t.Fatalf("key[1] mismatch: %+v", keys[1])
	}
	if err := ValidatePublicKeyPEM(keys[1].Alg, keys[1].PublicKeyPEM); err != nil {
		t.Fatalf("key[1] PEM invalid: %v", err)
	}

	// 2. 拒绝私钥参数 d / 对称密钥 oct / 重复 kid / 非法点
	badCases := []struct {
		name string
		raw  string
	}{
		{"含私钥参数d", fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":%q,"d":"secret"}]}`, xEd)},
		{"对称密钥oct", `{"keys":[{"kty":"oct","kid":"k1","k":"abc"}]}`},
		{"重复kid", fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"dup","x":%q},{"kty":"OKP","crv":"Ed25519","kid":"dup","x":%q}]}`, xEd, xEd)},
		{"空keys", `{"keys":[]}`},
		{"无受支持公钥", `{"keys":[{"kty":"RSA","kid":"r1","n":"AQAB","e":"AQAB"}]}`},
		{"EC点不在曲线上", `{"keys":[{"kty":"EC","crv":"P-256","kid":"bad","x":"AQ","y":"AQ"}]}`},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseDirectoryJWKS([]byte(tc.raw)); err == nil {
				t.Fatalf("%s should fail", tc.name)
			}
		})
	}
}

func TestValidatePublicKeyPEMRejectsPrivateAndMismatch(t *testing.T) {
	_, edPubPEM, edPrivPEM := genEd25519PEM(t)
	_, ecPubPEM := genP256PEM(t)

	if err := ValidatePublicKeyPEM(KeyAlgEd25519, edPubPEM); err != nil {
		t.Fatalf("valid ed25519 rejected: %v", err)
	}
	if err := ValidatePublicKeyPEM(KeyAlgECDSAP256, ecPubPEM); err != nil {
		t.Fatalf("valid p256 rejected: %v", err)
	}
	if err := ValidatePublicKeyPEM(KeyAlgEd25519, edPrivPEM); err == nil {
		t.Fatal("private key PEM must be rejected")
	}
	if err := ValidatePublicKeyPEM(KeyAlgEd25519, ecPubPEM); err == nil {
		t.Fatal("algorithm/key mismatch must be rejected")
	}
	if err := ValidatePublicKeyPEM(KeyAlgECDSAP256, edPubPEM); err == nil {
		t.Fatal("algorithm/key mismatch must be rejected")
	}
}

type fakeResolver struct {
	records map[string][]net.IP
}

func (f fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	if ips, ok := f.records[host]; ok {
		return ips, nil
	}
	return nil, fmt.Errorf("no such host: %s", host)
}

func TestValidateDirectoryAndSSRF(t *testing.T) {
	_, edPubPEM, edPrivPEM := genEd25519PEM(t)
	d := Directory{
		Slug:           " My-Bot ",
		Name:           "My AI Bot",
		Category:       "ai_agent",
		SignatureAgent: "https://bot.example.com",
		DirectoryURL:   "https://bot.example.com/.well-known/http-message-signatures-directory",
		Keys:           []CrawlerKey{{KID: "k1", Alg: "ED25519", PublicKeyPEM: edPubPEM}},
		Enabled:        true,
	}
	NormalizeDirectory(&d)
	if errs := ValidateDirectory(&d); len(errs) > 0 {
		t.Fatalf("valid directory rejected: %+v", errs)
	}

	// 私钥与非 HTTPS URL 必须拒绝
	badDir := d
	badDir.DirectoryURL = "http://bot.example.com/dir"
	badDir.Keys = []CrawlerKey{{KID: "k1", Alg: KeyAlgEd25519, PublicKeyPEM: edPrivPEM}}
	errs := ValidateDirectory(&badDir)
	if len(errs) < 2 {
		t.Fatalf("expected >=2 errors, got %+v", errs)
	}

	// SSRF 校验
	resolver := fakeResolver{records: map[string][]net.IP{
		"bot.example.com": {net.ParseIP("93.184.216.34")},
		"internal.corp":   {net.ParseIP("10.0.0.5")},
	}}
	pubPolicy, err := outboundhttp.NewPolicy(outboundhttp.Options{Resolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	if fe := ValidateDirectoryURLSSRF(context.Background(), "https://bot.example.com/.well-known/http-message-signatures-directory", pubPolicy); fe != nil {
		t.Fatalf("public https should pass: %+v", fe)
	}
	for _, blocked := range []string{
		"https://127.0.0.1/dir",
		"https://169.254.169.254/latest/meta-data",
		"https://internal.corp/dir",
		"http://bot.example.com/dir",
	} {
		if fe := ValidateDirectoryURLSSRF(context.Background(), blocked, pubPolicy); fe == nil {
			t.Errorf("%s should be blocked by SSRF check", blocked)
		}
	}
}

func TestValidatePolicyAndFrozenGuardContract(t *testing.T) {
	appID := uuid.MustParse("7b1a2c3d-0000-4000-8000-000000000099")
	p := DefaultPolicy(appID)
	p.Mode = ModeProtect
	p.Version = 2
	p.DefaultAIAction = ActionHTTP402
	p.ContentSignal = "ai-train=no, search=yes, ai-input=no"
	p.LabyrinthEnabled = true
	p.LabyrinthInjectLinks = true
	p.HTTP402 = HTTP402Config{
		Message:       "Licensed AI crawling required",
		PriceHint:     "0.001 USD/req",
		ContactURL:    "https://example.com/ai-license",
		ReceiptHeader: "X-AI-Payment-Receipt",
	}
	p.Rules = []Rule{
		{
			ID:                 "allow-search",
			Name:               "Allow verified search engines",
			Category:           CategorySearchEngine,
			RequireVerifiedSig: true,
			Action:             ActionAllow,
			ExemptBotChallenge: true,
			Priority:           10,
		},
		{
			ID:           "tarpit-trainers",
			Name:         "Tarpit AI trainers",
			Category:     CategoryAITraining,
			UAPatterns:   []string{"GPTBot", "ClaudeBot"},
			Action:       ActionTarpit,
			Priority:     20,
		},
	}
	NormalizePolicy(p)
	if errs := ValidatePolicy(p); len(errs) > 0 {
		t.Fatalf("valid policy rejected: %+v", errs)
	}

	// 验证冻结合同 JSON 键名
	_, edPubPEM, _ := genEd25519PEM(t)
	dirs := []Directory{
		{
			ID:             uuid.New(),
			Slug:           "openai-agent",
			Name:           "OpenAI Agent",
			Category:       CategoryAIAgent,
			SignatureAgent: "https://chatgpt.com",
			DirectoryURL:   "https://chatgpt.com/.well-known/http-message-signatures-directory",
			Keys:           []CrawlerKey{{KID: "k1", Alg: KeyAlgEd25519, PublicKeyPEM: edPubPEM}},
			Enabled:        true,
		},
		{
			ID:       uuid.New(),
			Slug:     "disabled-bot",
			Name:     "Disabled",
			Category: CategoryUnknownBot,
			Enabled:  false,
		},
	}
	gp := toGuardPolicy(p, dirs)
	raw, err := json.Marshal(gp)
	if err != nil {
		t.Fatalf("marshal guard policy: %v", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal guard policy: %v", err)
	}
	for _, key := range []string{
		"schema_version", "application_id", "mode", "version", "default_ai_action",
		"content_signal", "verify_web_bot_auth", "labyrinth_enabled", "labyrinth_inject_links",
		"labyrinth_max_depth", "labyrinth_max_concurrency", "labyrinth_delay_ms",
		"http_402", "rules", "directories",
	} {
		if _, ok := obj[key]; !ok {
			t.Errorf("frozen guard JSON missing key %q: %s", key, raw)
		}
	}
	if _, leaked := obj["labyrinth_key_hex"]; leaked {
		t.Errorf("toGuardPolicy must not emit labyrinth_key_hex: %s", raw)
	}
	if len(gp.Directories) != 1 || gp.Directories[0].Slug != "openai-agent" {
		t.Fatalf("only enabled directories should be published: %+v", gp.Directories)
	}

	// 校验矩阵：CRLF 注入、越界、RATE_LIMIT 缺 RPM
	fieldSet := func(errs []FieldError) map[string]bool {
		m := map[string]bool{}
		for _, e := range errs {
			m[e.Field] = true
		}
		return m
	}
	badCases := []struct {
		name   string
		mutate func(*Policy)
		field  string
	}{
		{"ContentSignal换行注入", func(x *Policy) { x.ContentSignal = "ai-train=no\r\nX-Evil: 1" }, "content_signal"},
		{"非法Mode", func(x *Policy) { x.Mode = "ENFORCE" }, "mode"},
		{"非法DefaultAction", func(x *Policy) { x.DefaultAIAction = "DROP" }, "default_ai_action"},
		{"深度越界", func(x *Policy) { x.LabyrinthMaxDepth = 99 }, "labyrinth_max_depth"},
		{"并发越界", func(x *Policy) { x.LabyrinthMaxConcurrency = 0 }, "labyrinth_max_concurrency"},
		{"延迟越界", func(x *Policy) { x.LabyrinthDelayMs = 9999 }, "labyrinth_delay_ms"},
		{"非法ContactURL", func(x *Policy) { x.HTTP402.ContactURL = "javascript:alert(1)" }, "http_402.contact_url"},
		{"非法ReceiptHeader", func(x *Policy) { x.HTTP402.ReceiptHeader = "Bad Header!" }, "http_402.receipt_header"},
		{"RATE_LIMIT缺RPM", func(x *Policy) {
			x.Rules = []Rule{{ID: "r1", Name: "limit", Category: CategoryAIAgent, Action: ActionRateLimit, RateLimitRPM: 0, Priority: 1}}
		}, "rules[0].rate_limit_rpm"},
		{"规则无匹配条件", func(x *Policy) {
			x.Rules = []Rule{{ID: "r1", Name: "empty", Action: ActionBlock, Priority: 1}}
		}, "rules[0]"},
		{"规则ID重复", func(x *Policy) {
			x.Rules = append(x.Rules, x.Rules[0])
		}, "rules[2].id"},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			cp := *p
			cp.Rules = append([]Rule(nil), p.Rules...)
			tc.mutate(&cp)
			errs := ValidatePolicy(&cp)
			if !fieldSet(errs)[tc.field] {
				t.Fatalf("expected error on %q, got %+v", tc.field, errs)
			}
		})
	}
}

func TestPutPolicyRequestDefaults(t *testing.T) {
	req := putPolicyRequest{
		Mode:   "observe",
		Reason: "init",
	}
	p := req.toPolicy(uuid.New())
	if p.Mode != ModeObserve || p.DefaultAIAction != ActionAllow || !p.VerifyWebBotAuth ||
		p.LabyrinthMaxDepth != DefaultLabyrinthMaxDepth || p.LabyrinthMaxConcurrency != DefaultLabyrinthMaxConcurrency ||
		p.LabyrinthDelayMs != DefaultLabyrinthDelayMs {
		t.Fatalf("defaults not applied properly: %+v", p)
	}
	if !strings.EqualFold(p.Mode, "OBSERVE") {
		t.Fatalf("mode = %q", p.Mode)
	}
}
