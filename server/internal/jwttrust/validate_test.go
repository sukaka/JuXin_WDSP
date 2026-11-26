// validate_test.go JWT 信任策略字段校验全矩阵单元测试（WDSP P0-03）。
package jwttrust

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/outboundhttp"
)

// validStaticJWKS 测试用合法静态公钥集（3072 位 RSA，本地生成）。
func validStaticJWKS(t *testing.T) string {
	t.Helper()
	return wrapKeys(rsaJWK(t, 2048, "k1"))
}

// basePolicy 合法 OBSERVE 策略基线（各用例在其上单点破坏）。
func basePolicy(t *testing.T) *Policy {
	t.Helper()
	return &Policy{
		ApplicationID: uuid.MustParse("7b1a2c3d-0000-4000-8000-000000000001"),
		Mode:          ModeObserve,
		Selectors: []Selector{
			{Methods: []string{"GET", "POST"}, PathPrefix: "/api", TokenRequired: true},
		},
		Issuers: []Issuer{
			{
				Issuer:           "https://idp.example.com/",
				Audiences:        []string{"shop-api"},
				Algorithms:       []string{AlgRS256},
				KeySource:        KeySource{Type: KeySourceStaticJWKS, JWKS: validStaticJWKS(t)},
				ClockSkewSeconds: DefaultClockSkew,
			},
		},
	}
}

func fieldSet(errs []FieldError) map[string]bool {
	out := map[string]bool{}
	for _, e := range errs {
		out[e.Field] = true
	}
	return out
}

// TestNormalize 方法大写去重、algorithms/audiences 去重去空白。
func TestNormalize(t *testing.T) {
	p := &Policy{
		Selectors: []Selector{{Methods: []string{"get", " Get ", "POST", "get", ""}}},
		Issuers: []Issuer{{
			Audiences:  []string{" a ", "a", "b"},
			Algorithms: []string{"rs256", "RS256", "es256"},
			RoleClaims: []string{" roles ", "groups", "roles"},
		}},
	}
	Normalize(p)
	got := p.Selectors[0].Methods
	if len(got) != 2 || got[0] != "GET" || got[1] != "POST" {
		t.Errorf("methods = %v, want [GET POST]", got)
	}
	if len(p.Issuers[0].Audiences) != 2 || p.Issuers[0].Audiences[0] != "a" {
		t.Errorf("audiences = %v", p.Issuers[0].Audiences)
	}
	if len(p.Issuers[0].Algorithms) != 2 || p.Issuers[0].Algorithms[1] != "ES256" {
		t.Errorf("algorithms = %v", p.Issuers[0].Algorithms)
	}
	if got := p.Issuers[0].RoleClaims; len(got) != 2 || got[0] != "roles" || got[1] != "groups" {
		t.Errorf("role claims = %v", got)
	}
}

// TestValidateStructureBaseline 合法策略通过。
func TestValidateStructureBaseline(t *testing.T) {
	if errs := ValidateStructure(basePolicy(t)); len(errs) > 0 {
		t.Fatalf("valid policy rejected: %+v", errs)
	}
}

// TestRoleClaimsJSONContract verifies that the management DTO/domain JSON and
// the publishable policy retain the explicit role declaration names end to end.
func TestRoleClaimsJSONContract(t *testing.T) {
	p := basePolicy(t)
	p.Issuers[0].RoleClaims = []string{"roles", "groups"}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	var roundTrip Policy
	if err := json.Unmarshal(b, &roundTrip); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}
	if got := roundTrip.Issuers[0].RoleClaims; len(got) != 2 || got[0] != "roles" || got[1] != "groups" {
		t.Fatalf("round-tripped role claims = %v", got)
	}

	req := putRequest{Issuers: []issuerRequest{{RoleClaims: []string{"roles", "groups"}}}}
	converted := req.toPolicy(uuid.New())
	if got := converted.Issuers[0].RoleClaims; len(got) != 2 || got[0] != "roles" || got[1] != "groups" {
		t.Fatalf("request role claims = %v", got)
	}
}

// TestValidateStructureMatrix 字段校验矩阵（每用例单点破坏基线）。
func TestValidateStructureMatrix(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(p *Policy)
		field  string
	}{
		{"非法mode", func(p *Policy) { p.Mode = "ENFORCE" }, "mode"},
		{"非OFF空selectors", func(p *Policy) { p.Selectors = nil }, "selectors"},
		{"非OFF空issuers", func(p *Policy) { p.Issuers = nil }, "issuers"},
		{"方法词形非法", func(p *Policy) { p.Selectors[0].Methods = []string{"g et"} }, "selectors[0].methods"},
		{"空方法集", func(p *Policy) { p.Selectors[0].Methods = nil }, "selectors[0].methods"},
		{"exact与prefix同给", func(p *Policy) { p.Selectors[0].PathExact = "/api/x" }, "selectors[0]"},
		{"exact与prefix均缺", func(p *Policy) { p.Selectors[0].PathPrefix = "" }, "selectors[0]"},
		{"路径不以/开头", func(p *Policy) { p.Selectors[0].PathPrefix = "api" }, "selectors[0].path_prefix"},
		{"路径含query", func(p *Policy) { p.Selectors[0].PathPrefix = "/api?x=1" }, "selectors[0].path_prefix"},
		{"prefix以/结尾", func(p *Policy) { p.Selectors[0].PathPrefix = "/api/" }, "selectors[0].path_prefix"},
		{"路径控制字符", func(p *Policy) { p.Selectors[0].PathPrefix = "/api/\x00" }, "selectors[0].path_prefix"},
		{"issuer重复", func(p *Policy) {
			p.Issuers = append(p.Issuers, p.Issuers[0])
		}, "issuers[1].issuer"},
		{"issuer为空", func(p *Policy) { p.Issuers[0].Issuer = "" }, "issuers[0].issuer"},
		{"audiences空", func(p *Policy) { p.Issuers[0].Audiences = nil }, "issuers[0].audiences"},
		{"audience含空串", func(p *Policy) { p.Issuers[0].Audiences = []string{"a", ""} }, "issuers[0].audiences"},
		{"算法越白名单", func(p *Policy) { p.Issuers[0].Algorithms = []string{"HS256"} }, "issuers[0].algorithms"},
		{"算法空", func(p *Policy) { p.Issuers[0].Algorithms = nil }, "issuers[0].algorithms"},
		{"时钟偏移越上限", func(p *Policy) { p.Issuers[0].ClockSkewSeconds = 121 }, "issuers[0].clock_skew_seconds"},
		{"时钟偏移负值", func(p *Policy) { p.Issuers[0].ClockSkewSeconds = -1 }, "issuers[0].clock_skew_seconds"},
		{"tenant_claim非法", func(p *Policy) { p.Issuers[0].TenantClaim = "1bad claim" }, "issuers[0].tenant_claim"},
		{"role_claim非法", func(p *Policy) { p.Issuers[0].RoleClaims = []string{"1bad"} }, "issuers[0].role_claims"},
		{"role_claim过多", func(p *Policy) {
			p.Issuers[0].RoleClaims = []string{"r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9"}
		}, "issuers[0].role_claims"},
		{"STATIC缺jwks", func(p *Policy) { p.Issuers[0].KeySource.JWKS = "" }, "issuers[0].key_source.jwks"},
		{"STATIC带url", func(p *Policy) { p.Issuers[0].KeySource.URL = "https://x.example.com/jwks" }, "issuers[0].key_source.url"},
		{"REMOTE缺url", func(p *Policy) {
			p.Issuers[0].KeySource = KeySource{Type: KeySourceRemoteJWKS}
		}, "issuers[0].key_source.url"},
		{"REMOTE非HTTPS", func(p *Policy) {
			p.Issuers[0].KeySource = KeySource{Type: KeySourceRemoteJWKS, URL: "http://idp.example.com/jwks"}
		}, "issuers[0].key_source.url"},
		{"REMOTE带内联jwks", func(p *Policy) {
			p.Issuers[0].KeySource = KeySource{Type: KeySourceRemoteJWKS, URL: "https://idp.example.com/jwks", JWKS: "{}"}
		}, "issuers[0].key_source.jwks"},
		{"key_source类型非法", func(p *Policy) { p.Issuers[0].KeySource.Type = "FILE" }, "issuers[0].key_source.type"},
		{"issuer超8项", func(p *Policy) {
			for i := 0; i < MaxIssuers; i++ {
				is := p.Issuers[0]
				is.Issuer = fmt.Sprintf("https://idp%d.example.com/", i)
				p.Issuers = append(p.Issuers, is)
			}
		}, "issuers"},
	}
	for _, tc := range cases {
		p := basePolicy(t)
		tc.mutate(p)
		errs := ValidateStructure(p)
		if len(errs) == 0 {
			t.Errorf("%s: 应被拒绝", tc.name)
			continue
		}
		if !fieldSet(errs)[tc.field] {
			t.Errorf("%s: 期望字段 %s 报错，实际 %+v", tc.name, tc.field, errs)
		}
	}
}

// TestValidateStructureOffEmpty OFF 模式 selectors/issuers 可空（默认空策略合法）。
func TestValidateStructureOffEmpty(t *testing.T) {
	p := DefaultPolicy(uuid.MustParse("7b1a2c3d-0000-4000-8000-000000000001"))
	if errs := ValidateStructure(p); len(errs) > 0 {
		t.Fatalf("default OFF policy rejected: %+v", errs)
	}
}

// fakeResolver 可编程假 DNS 解析器（outboundhttp.Resolver）。
type fakeResolver struct {
	records map[string][]net.IP
}

func (f fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	if ips, ok := f.records[host]; ok {
		return ips, nil
	}
	return nil, fmt.Errorf("no such host: %s", host)
}

// TestValidateRemoteURLsSSRF REMOTE_JWKS 地址 SSRF 矩阵：
// 公网 HTTPS 通过；私网/回环/元数据/解析失败拒绝；允许清单显式放行内网 IdP。
func TestValidateRemoteURLsSSRF(t *testing.T) {
	mkPolicy := func(rawURL string) *Policy {
		p := DefaultPolicy(uuid.MustParse("7b1a2c3d-0000-4000-8000-000000000001"))
		p.Mode = ModeObserve
		p.Issuers = []Issuer{{
			Issuer:     "https://idp.example.com/",
			Audiences:  []string{"a"},
			Algorithms: []string{AlgRS256},
			KeySource:  KeySource{Type: KeySourceRemoteJWKS, URL: rawURL},
		}}
		return p
	}
	resolver := fakeResolver{records: map[string][]net.IP{
		"idp.example.com":      {net.ParseIP("93.184.216.34")},
		"internal-idp.corp":    {net.ParseIP("10.1.2.3")},
		"rebind.example.com":   {net.ParseIP("192.168.1.1")},
		"unresolv.example.com": nil,
	}}

	public, err := outboundhttp.NewPolicy(outboundhttp.Options{Resolver: resolver})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	if errs := ValidateRemoteURLs(context.Background(), mkPolicy("https://idp.example.com/jwks"), public); len(errs) > 0 {
		t.Errorf("公网 HTTPS 应通过: %+v", errs)
	}
	for _, u := range []string{
		"https://127.0.0.1/jwks",                   // 回环字面量
		"https://10.0.0.9/jwks",                    // 私网字面量
		"https://169.254.169.254/latest/meta-data", // 云元数据
		"https://[::1]/jwks",                       // IPv6 回环
		"https://rebind.example.com/jwks",          // 域名解析到私网
		"https://unresolv.example.com/jwks",        // 解析失败
	} {
		if errs := ValidateRemoteURLs(context.Background(), mkPolicy(u), public); len(errs) == 0 {
			t.Errorf("%s 应被 SSRF 拒绝", u)
		}
	}

	// 企业内网 IdP 显式登记允许清单后放行（仍拒绝元数据字面量——登记主机命中才跳过地址校验）
	allowed, err := outboundhttp.NewPolicy(outboundhttp.Options{Resolver: resolver, Allowlist: "internal-idp.corp"})
	if err != nil {
		t.Fatalf("NewPolicy with allowlist: %v", err)
	}
	if errs := ValidateRemoteURLs(context.Background(), mkPolicy("https://internal-idp.corp/jwks"), allowed); len(errs) > 0 {
		t.Errorf("登记允许清单的内网 IdP 应通过: %+v", errs)
	}
	if errs := ValidateRemoteURLs(context.Background(), mkPolicy("https://rebind.example.com/jwks"), allowed); len(errs) == 0 {
		t.Error("未登记的私网解析目标仍应拒绝")
	}
}

// TestNodePublishGuard 发布门禁：已知同步失败的扇出节点阻断 PROTECT 发布。
func TestNodePublishGuard(t *testing.T) {
	guard := NodePublishGuard(fakeNodeLister{nodes: testNodes()})
	if err := guard(context.Background(), nil); err != nil {
		t.Errorf("无 PROTECT 应用时不应阻断: %v", err)
	}
	if err := guard(context.Background(), []string{"shop"}); err == nil {
		t.Error("存在同步失败节点时应拒绝发布")
	} else if !strings.Contains(err.Error(), "gw-bad") {
		t.Errorf("错误应含节点名: %v", err)
	}
	okGuard := NodePublishGuard(fakeNodeLister{nodes: testNodesHealthy()})
	if err := okGuard(context.Background(), []string{"shop"}); err != nil {
		t.Errorf("健康节点不应阻断: %v", err)
	}
	errGuard := NodePublishGuard(fakeNodeLister{err: fmt.Errorf("db down")})
	if err := errGuard(context.Background(), []string{"shop"}); err == nil {
		t.Error("节点读取失败应中止发布（不静默跳过）")
	}
}

// TestTokenBindingNormalizeAndValidate 9A-1 令牌持有证明绑定归一化与字段级校验矩阵。
func TestTokenBindingNormalizeAndValidate(t *testing.T) {
	base := basePolicy(t)
	cloneBase := func() *Policy {
		cp := *base
		cp.Selectors = append([]Selector(nil), base.Selectors...)
		cp.Issuers = append([]Issuer(nil), base.Issuers...)
		return &cp
	}

	// 1. NONE 归一化为 nil（不污染旧节点 schema）
	p := cloneBase()
	p.Issuers[0].TokenBinding = &TokenBindingConfig{Mode: " none "}
	Normalize(p)
	if p.Issuers[0].TokenBinding != nil {
		t.Fatalf("NONE mode should normalize to nil, got %+v", p.Issuers[0].TokenBinding)
	}

	// 2. EdDSA 混合大小写保留、算法去重
	p = cloneBase()
	p.Issuers[0].TokenBinding = &TokenBindingConfig{
		Mode:               " dpop_required ",
		RequireNonce:       true,
		MaxProofAgeSeconds: 45,
		NonceTTLSeconds:    90,
		AllowedDPoPAlgs:    []string{"es256", "eddsa", "RS256", "EdDSA"},
	}
	Normalize(p)
	tb := p.Issuers[0].TokenBinding
	if tb.Mode != TokenBindingDPoPRequired {
		t.Fatalf("mode = %q, want %q", tb.Mode, TokenBindingDPoPRequired)
	}
	if len(tb.AllowedDPoPAlgs) != 3 || tb.AllowedDPoPAlgs[0] != "ES256" || tb.AllowedDPoPAlgs[1] != "EdDSA" || tb.AllowedDPoPAlgs[2] != "RS256" {
		t.Fatalf("allowed_dpop_algs = %v, want [ES256 EdDSA RS256]", tb.AllowedDPoPAlgs)
	}
	if errs := ValidateStructure(p); len(errs) > 0 {
		t.Fatalf("valid DPoP token_binding rejected: %+v", errs)
	}

	// 3. 字段级错误矩阵
	cases := []struct {
		name  string
		tb    *TokenBindingConfig
		field string
	}{
		{"非法mode", &TokenBindingConfig{Mode: "BEARER_ONLY", MaxProofAgeSeconds: 60, NonceTTLSeconds: 60}, "issuers[0].token_binding.mode"},
		{"max_proof_age过小", &TokenBindingConfig{Mode: TokenBindingDPoPRequired, MaxProofAgeSeconds: 4, NonceTTLSeconds: 60}, "issuers[0].token_binding.max_proof_age_seconds"},
		{"max_proof_age过大", &TokenBindingConfig{Mode: TokenBindingDPoPRequired, MaxProofAgeSeconds: 121, NonceTTLSeconds: 60}, "issuers[0].token_binding.max_proof_age_seconds"},
		{"nonce_ttl过小", &TokenBindingConfig{Mode: TokenBindingDPoPRequired, MaxProofAgeSeconds: 60, NonceTTLSeconds: 9}, "issuers[0].token_binding.nonce_ttl_seconds"},
		{"nonce_ttl过大", &TokenBindingConfig{Mode: TokenBindingDPoPRequired, MaxProofAgeSeconds: 60, NonceTTLSeconds: 301}, "issuers[0].token_binding.nonce_ttl_seconds"},
		{"禁止HS256", &TokenBindingConfig{Mode: TokenBindingDPoPOptional, MaxProofAgeSeconds: 60, NonceTTLSeconds: 60, AllowedDPoPAlgs: []string{"HS256"}}, "issuers[0].token_binding.allowed_dpop_algs"},
		{"禁止none", &TokenBindingConfig{Mode: TokenBindingDPoPOrMTLS, MaxProofAgeSeconds: 60, NonceTTLSeconds: 60, AllowedDPoPAlgs: []string{"none"}}, "issuers[0].token_binding.allowed_dpop_algs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := cloneBase()
			cp.Issuers[0].TokenBinding = tc.tb
			Normalize(cp)
			errs := ValidateStructure(cp)
			if !fieldSet(errs)[tc.field] {
				t.Fatalf("expected field %q error, got %+v", tc.field, errs)
			}
		})
	}
}

// TestPutRequestTokenBindingDefaults PUT 请求缺省值回填与 NONE 忽略语义。
func TestPutRequestTokenBindingDefaults(t *testing.T) {
	req := putRequest{
		Mode: ModeProtect,
		Issuers: []issuerRequest{
			{
				Issuer:       "https://idp.example.com/",
				TokenBinding: &tokenBindingRequest{Mode: "DPOP_REQUIRED", RequireNonce: true},
			},
			{
				Issuer:       "https://idp2.example.com/",
				TokenBinding: &tokenBindingRequest{Mode: "NONE"},
			},
		},
	}
	p := req.toPolicy(uuid.New())
	if p.Issuers[0].TokenBinding == nil {
		t.Fatal("active token_binding lost")
	}
	if p.Issuers[0].TokenBinding.MaxProofAgeSeconds != DefaultDPoPMaxProofAgeSeconds ||
		p.Issuers[0].TokenBinding.NonceTTLSeconds != DefaultDPoPNonceTTLSeconds {
		t.Fatalf("defaults not applied: %+v", p.Issuers[0].TokenBinding)
	}
	if p.Issuers[1].TokenBinding != nil {
		t.Fatalf("NONE mode should become nil, got %+v", p.Issuers[1].TokenBinding)
	}
}

// TestToGuardPolicySchemaVersion 仅启用活跃 TokenBinding 时升 schema_version=2，否则保持 1 向后兼容。
func TestToGuardPolicySchemaVersion(t *testing.T) {
	base := basePolicy(t)
	cloneBase := func() *Policy {
		cp := *base
		cp.Selectors = append([]Selector(nil), base.Selectors...)
		cp.Issuers = append([]Issuer(nil), base.Issuers...)
		return &cp
	}

	p := cloneBase()
	gp1, err := toGuardPolicy(p.ApplicationID, "shop", ModeProtect, 1, p.Selectors, p.Issuers)
	if err != nil {
		t.Fatalf("toGuardPolicy v1: %v", err)
	}
	if gp1.SchemaVersion != SchemaVersion || gp1.Issuers[0].TokenBinding != nil {
		t.Fatalf("without active binding expected schema_version=1 & nil binding, got v=%d tb=%+v",
			gp1.SchemaVersion, gp1.Issuers[0].TokenBinding)
	}

	// 显式 NONE 同样保持 schema_version=1 且不下发 token_binding（防旧节点 fail-closed 拒载）
	pNone := cloneBase()
	pNone.Issuers[0].TokenBinding = &TokenBindingConfig{Mode: TokenBindingNone}
	gpNone, err := toGuardPolicy(pNone.ApplicationID, "shop", ModeProtect, 1, pNone.Selectors, pNone.Issuers)
	if err != nil {
		t.Fatalf("toGuardPolicy NONE: %v", err)
	}
	if gpNone.SchemaVersion != SchemaVersion || gpNone.Issuers[0].TokenBinding != nil {
		t.Fatalf("NONE binding must keep schema_version=1 & nil binding, got v=%d tb=%+v",
			gpNone.SchemaVersion, gpNone.Issuers[0].TokenBinding)
	}

	// 启用 DPoP / mTLS 绑定 → schema_version=2 且仅活跃 issuer 携带 token_binding
	p2 := cloneBase()
	second := p2.Issuers[0]
	second.Issuer = "https://idp2.example.com/"
	p2.Issuers[0].TokenBinding = &TokenBindingConfig{
		Mode:               TokenBindingDPoPOrMTLS,
		RequireNonce:       true,
		MaxProofAgeSeconds: 30,
		NonceTTLSeconds:    120,
		AllowedDPoPAlgs:    []string{DPoPAlgES256, DPoPAlgEdDSA},
	}
	p2.Issuers = append(p2.Issuers, second)
	gp2, err := toGuardPolicy(p2.ApplicationID, "shop", ModeProtect, 2, p2.Selectors, p2.Issuers)
	if err != nil {
		t.Fatalf("toGuardPolicy v2: %v", err)
	}
	if gp2.SchemaVersion != SchemaVersionV2 {
		t.Fatalf("active binding expected schema_version=2, got %d", gp2.SchemaVersion)
	}
	if gp2.Issuers[0].TokenBinding == nil || gp2.Issuers[0].TokenBinding.Mode != TokenBindingDPoPOrMTLS ||
		!gp2.Issuers[0].TokenBinding.RequireNonce || gp2.Issuers[0].TokenBinding.MaxProofAgeSeconds != 30 {
		t.Fatalf("issuer[0] token_binding mismatch: %+v", gp2.Issuers[0].TokenBinding)
	}
	if gp2.Issuers[1].TokenBinding != nil {
		t.Fatalf("inactive issuer[1] token_binding should be nil, got %+v", gp2.Issuers[1].TokenBinding)
	}
}
