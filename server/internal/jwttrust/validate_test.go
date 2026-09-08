// validate_test.go JWT 信任策略字段校验全矩阵单元测试（WDSP P0-03）。
package jwttrust

import (
	"context"
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
}

// TestValidateStructureBaseline 合法策略通过。
func TestValidateStructureBaseline(t *testing.T) {
	if errs := ValidateStructure(basePolicy(t)); len(errs) > 0 {
		t.Fatalf("valid policy rejected: %+v", errs)
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
