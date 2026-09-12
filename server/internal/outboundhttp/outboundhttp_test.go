package outboundhttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeResolver 是可编程的假 DNS 解析器（lookup 返回错误时视为解析失败）。
type fakeResolver struct {
	lookup func(host string) ([]net.IP, error)
}

func (f fakeResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	return f.lookup(host)
}

// staticResolver 返回按主机名映射的固定记录。
func staticResolver(records map[string][]net.IP) fakeResolver {
	return fakeResolver{lookup: func(host string) ([]net.IP, error) {
		ips, ok := records[host]
		if !ok {
			return nil, fmt.Errorf("no such host: %s", host)
		}
		return ips, nil
	}}
}

func mustPolicy(t *testing.T, opts Options) *Policy {
	t.Helper()
	p, err := NewPolicy(opts)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return p
}

// TestCheckIPMatrix 回环/RFC1918/链路本地/云元数据/保留网段/IPv4-mapped IPv6 一律拒绝。
func TestCheckIPMatrix(t *testing.T) {
	p := mustPolicy(t, Options{})
	deny := []string{
		"127.0.0.1", "127.0.0.53", // IPv4 回环
		"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.1", // RFC1918
		"169.254.1.1", "169.254.169.254", // 链路本地 + 云元数据
		"0.0.0.0", "100.64.0.1", "198.18.0.1", "240.0.0.1", // 保留网段
		"224.0.0.1", "255.255.255.255", // 组播/广播
		"::1", "fe80::1", "fc00::1", "fd00::1", // IPv6 回环/链路本地/ULA
		"fd00:ec2::254",                       // AWS IPv6 元数据
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", // IPv4-mapped IPv6
	}
	for _, s := range deny {
		if err := p.CheckIP(net.ParseIP(s)); !errors.Is(err, ErrDenied) {
			t.Errorf("%s 应被拒绝, got %v", s, err)
		}
	}
	allow := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8"}
	for _, s := range allow {
		if err := p.CheckIP(net.ParseIP(s)); err != nil {
			t.Errorf("%s 应放行: %v", s, err)
		}
	}
	if err := p.CheckIP(nil); !errors.Is(err, ErrDenied) {
		t.Errorf("空地址应被拒绝, got %v", err)
	}
}

// TestCheckIPAllowlist allowlist CIDR 显式放行内网目标，其余内网仍拒绝。
func TestCheckIPAllowlist(t *testing.T) {
	p := mustPolicy(t, Options{Allowlist: "10.0.0.0/8, fd00::/8"})
	if err := p.CheckIP(net.ParseIP("10.1.2.3")); err != nil {
		t.Errorf("allowlist 内的 10.1.2.3 应放行: %v", err)
	}
	if err := p.CheckIP(net.ParseIP("fd00::1")); err != nil {
		t.Errorf("allowlist 内的 fd00::1 应放行: %v", err)
	}
	for _, s := range []string{"192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.169.254"} {
		if err := p.CheckIP(net.ParseIP(s)); !errors.Is(err, ErrDenied) {
			t.Errorf("%s 不在 allowlist，应被拒绝, got %v", s, err)
		}
	}
}

// TestNewPolicyBadAllowlist 非法 allowlist 项如实报错（不静默跳过）。
func TestNewPolicyBadAllowlist(t *testing.T) {
	for _, raw := range []string{"10.0.0.0/33", "not-a-host/", "8.8.8.8"} {
		if _, err := NewPolicy(Options{Allowlist: raw}); err == nil {
			t.Errorf("allowlist %q 应报错", raw)
		}
	}
	if _, err := NewPolicy(Options{Allowlist: "10.0.0.0/8, sms.internal.example.com ; 192.168.0.0/16"}); err != nil {
		t.Errorf("合法 allowlist 不应报错: %v", err)
	}
}

func TestAllowlistCannotAuthorizeMetadataAddress(t *testing.T) {
	p := mustPolicy(t, Options{Allowlist: "169.254.0.0/16"})
	if err := p.CheckIP(net.ParseIP("169.254.169.254")); !errors.Is(err, ErrDenied) {
		t.Fatalf("metadata IP must remain denied through CIDR allowlist, err=%v", err)
	}

	resolver := staticResolver(map[string][]net.IP{
		"provider.internal": {net.ParseIP("169.254.169.254")},
	})
	p = mustPolicy(t, Options{Resolver: resolver, Allowlist: "provider.internal"})
	if _, err := p.ValidateURL(context.Background(), "http://provider.internal/v1"); !errors.Is(err, ErrDenied) {
		t.Fatalf("metadata IP must remain denied through hostname allowlist, err=%v", err)
	}
}

// TestParseURLMatrix scheme/host/端口/内嵌凭据校验。
func TestParseURLMatrix(t *testing.T) {
	deny := []string{
		"", "not-a-url", "file:///etc/passwd", "ftp://example.com/x", "gopher://example.com/",
		"http://", "http://:8080/x", // 缺主机
		"http://user:pass@93.184.216.34/x", // 内嵌凭据
		"http://93.184.216.34:0/x", "http://93.184.216.34:99999/x", "http://93.184.216.34:abc/x",
	}
	for _, raw := range deny {
		if _, err := ParseURL(raw); !errors.Is(err, ErrDenied) {
			t.Errorf("%q 应被拒绝, got %v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://93.184.216.34/x", "https://example.com/x", " https://example.com:8443/x ",
	} {
		if _, err := ParseURL(raw); err != nil {
			t.Errorf("%q 应通过: %v", raw, err)
		}
	}
}

// TestValidateURLResolveMatrix 域名解析全部 A/AAAA 逐一校验：混合记录/IPv4-mapped/解析失败均拒绝。
func TestValidateURLResolveMatrix(t *testing.T) {
	res := staticResolver(map[string][]net.IP{
		"public.test":   {net.ParseIP("93.184.216.34"), net.ParseIP("2606:4700:4700::1111")},
		"mixed.test":    {net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.1")}, // 混合 A/AAAA
		"v6mapped.test": {net.ParseIP("::ffff:127.0.0.1")},
		"meta.test":     {net.ParseIP("169.254.169.254")},
		"empty.test":    {},
		"internal.test": {net.ParseIP("10.9.9.9")},
	})
	p := mustPolicy(t, Options{Resolver: res})
	if _, err := p.ValidateURL(context.Background(), "http://public.test/x"); err != nil {
		t.Errorf("全公网记录应放行: %v", err)
	}
	for _, host := range []string{"mixed.test", "v6mapped.test", "meta.test", "empty.test", "unknown.test"} {
		if _, err := p.ValidateURL(context.Background(), "http://"+host+"/x"); !errors.Is(err, ErrDenied) {
			t.Errorf("%s 应被拒绝, got %v", host, err)
		}
	}
	// 字面量 IP 不经解析器
	if _, err := p.ValidateURL(context.Background(), "http://127.0.0.1/x"); !errors.Is(err, ErrDenied) {
		t.Errorf("回环字面量应被拒绝, got %v", err)
	}
	if _, err := p.ValidateURL(context.Background(), "http://[::ffff:10.0.0.1]/x"); !errors.Is(err, ErrDenied) {
		t.Errorf("IPv4-mapped IPv6 私网字面量应被拒绝, got %v", err)
	}
	// allowlist 精确主机名放行内网解析结果
	p2 := mustPolicy(t, Options{Resolver: res, Allowlist: "internal.test"})
	if _, err := p2.ValidateURL(context.Background(), "http://internal.test/x"); err != nil {
		t.Errorf("allowlist 主机名应放行: %v", err)
	}
	if _, err := p2.ValidateURL(context.Background(), "http://mixed.test/x"); !errors.Is(err, ErrDenied) {
		t.Errorf("非 allowlist 主机仍应校验, got %v", err)
	}
}

// TestClientDeniesLoopback httptest 服务真实存在，但防护必须拒绝回环目标。
func TestClientDeniesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	p := mustPolicy(t, Options{})
	if _, err := p.ValidateURL(context.Background(), srv.URL); !errors.Is(err, ErrDenied) {
		t.Fatalf("ValidateURL 应拒绝回环: %v", err)
	}
	resp, err := p.Client().Get(srv.URL)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("拨号阶段也应拒绝回环: resp=%v err=%v", resp, err)
	}
}

// TestDialRebinding DNS 重绑定：校验时解析为公网，拨号时重解析变为回环，必须拒绝。
func TestDialRebinding(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	res := fakeResolver{lookup: func(host string) ([]net.IP, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil // 校验阶段：公网
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil // 拨号阶段：重绑定到回环
	}}
	p := mustPolicy(t, Options{Resolver: res})
	if _, err := p.ValidateURL(context.Background(), "http://rebind.test/"); err != nil {
		t.Fatalf("首次校验（公网记录）应通过: %v", err)
	}
	resp, err := p.Client().Get("http://rebind.test/")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("拨号重解析为回环应被拒绝: resp=%v err=%v", resp, err)
	}
}

// redirectFixture 是重定向测试场景：a.test 跳转 b.test，均经假解析器指向 127.0.0.1 上的
// httptest 服务（allowlist 放行回环，模拟"公网"目标）。
type redirectFixture struct {
	policy *Policy
	aURL   string
	bSrv   *httptest.Server
	bHost  string
}

func newRedirectFixture(t *testing.T, maxRedirects int, bHandler http.HandlerFunc) *redirectFixture {
	t.Helper()
	bSrv := httptest.NewServer(bHandler)
	t.Cleanup(bSrv.Close)
	bURL, _ := ParseURL(bSrv.URL)
	bHost := fmt.Sprintf("b.test:%s", bURL.Port())

	var aSrv *httptest.Server
	aSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("http://%s/", bHost), http.StatusFound)
	}))
	t.Cleanup(aSrv.Close)
	aURL, _ := ParseURL(aSrv.URL)

	res := staticResolver(map[string][]net.IP{
		"a.test": {net.ParseIP("127.0.0.1")},
		"b.test": {net.ParseIP("127.0.0.1")},
	})
	p := mustPolicy(t, Options{
		Resolver:     res,
		Allowlist:    "127.0.0.0/8",
		MaxRedirects: maxRedirects,
	})
	return &redirectFixture{policy: p, aURL: fmt.Sprintf("http://a.test:%s/", aURL.Port()), bSrv: bSrv, bHost: bHost}
}

// TestRedirectCrossHostStripsHeaders 跟随重定向时每跳复检，跨 Host 剥离认证/签名头。
func TestRedirectCrossHostStripsHeaders(t *testing.T) {
	type seen struct{ appKey, sign, auth string }
	var bSeen seen
	fx := newRedirectFixture(t, 5, func(w http.ResponseWriter, r *http.Request) {
		bSeen = seen{appKey: r.Header.Get("X-App-Key"), sign: r.Header.Get("X-Sign"), auth: r.Header.Get("Authorization")}
		_, _ = w.Write([]byte("ok"))
	})
	req, err := http.NewRequest(http.MethodGet, fx.aURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-App-Key", "ak-1")
	req.Header.Set("X-Sign", "sig-1")
	req.Header.Set("Authorization", "Bearer token-1")
	resp, err := fx.policy.Client().Do(req)
	if err != nil {
		t.Fatalf("同策略内重定向应成功: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("最终状态码 = %d", resp.StatusCode)
	}
	if bSeen.appKey != "" || bSeen.sign != "" || bSeen.auth != "" {
		t.Errorf("跨 Host 重定向应剥离敏感头, got %+v", bSeen)
	}
}

// TestRedirectToPrivateDenied 重定向目标解析为私网地址时每跳复检必须拦截。
func TestRedirectToPrivateDenied(t *testing.T) {
	fx := newRedirectFixture(t, 5, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	// 换用把 b.test 解析到私网的解析器
	fx.policy = mustPolicy(t, Options{
		Resolver: staticResolver(map[string][]net.IP{
			"a.test": {net.ParseIP("127.0.0.1")},
			"b.test": {net.ParseIP("10.1.2.3")},
		}),
		Allowlist:    "127.0.0.0/8",
		MaxRedirects: 5,
	})
	resp, err := fx.policy.Client().Get(fx.aURL)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("重定向到私网应被拒绝: resp=%v err=%v", resp, err)
	}
}

// TestRedirectDisabled 默认策略（MaxRedirects<=0）不跟随重定向，如实报错。
func TestRedirectDisabled(t *testing.T) {
	fx := newRedirectFixture(t, 0, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	resp, err := fx.policy.Client().Get(fx.aURL)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("禁止重定向时应报错: resp=%v err=%v", resp, err)
	}
	if !strings.Contains(err.Error(), "不跟随重定向") {
		t.Errorf("错误应说明不跟随重定向: %v", err)
	}
}

// TestRedirectLimit 超过重定向次数上限报错（自跳转循环）。
func TestRedirectLimit(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://a.test:"+mustPort(t, srv.URL)+"/", http.StatusFound)
	}))
	defer srv.Close()
	p := mustPolicy(t, Options{
		Resolver:     staticResolver(map[string][]net.IP{"a.test": {net.ParseIP("127.0.0.1")}}),
		Allowlist:    "127.0.0.0/8",
		MaxRedirects: 3,
	})
	resp, err := p.Client().Get("http://a.test:" + mustPort(t, srv.URL) + "/")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("重定向循环应触发次数上限: resp=%v err=%v", resp, err)
	}
	if !strings.Contains(err.Error(), "重定向次数过多") {
		t.Errorf("错误应说明次数过多: %v", err)
	}
}

func mustPort(t *testing.T, raw string) string {
	t.Helper()
	u, err := ParseURL(raw)
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", raw, err)
	}
	return u.Port()
}
