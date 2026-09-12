package jwtverify

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubResolver 可编程 DNS 解析桩（不访问真实 DNS）。
type stubResolver struct {
	ips  []net.IPAddr
	err  error
	hook func() // 每次解析调用回调
}

func (r *stubResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if r.hook != nil {
		r.hook()
	}
	return r.ips, r.err
}

func ipAddrs(ss ...string) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(ss))
	for _, s := range ss {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out
}

func loopbackAllow(t *testing.T) []netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	return []netip.Prefix{p}
}

// newTLSTestFetcher 面向 httptest TLS 服务器的获取器（回环经显式允许 CIDR 登记，
// CA 为该服务器证书），并返回拨号计数器。
func newTLSTestFetcher(t *testing.T, srv *httptest.Server) (*Fetcher, *atomic.Int32) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	var dialCount atomic.Int32
	base := &net.Dialer{}
	f := NewFetcher(FetcherConfig{
		RootCAs: pool,
		DialTCP: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialCount.Add(1)
			return base.DialContext(ctx, network, address)
		},
	})
	return f, &dialCount
}

// JWT-09：正常受限获取（回环需显式允许 CIDR + 受控 CA）。
func TestFetcherSuccess(t *testing.T) {
	body := `{"keys":[]}`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	f, dialCount := newTLSTestFetcher(t, srv)

	got, err := f.Fetch(context.Background(), RemoteTarget{URL: srv.URL, AllowCIDRs: loopbackAllow(t)})
	if err != nil {
		t.Fatalf("受限获取失败: %v", err)
	}
	if string(got) != body {
		t.Fatalf("响应内容不符: %q", got)
	}
	if dialCount.Load() == 0 {
		t.Fatalf("应发生受控拨号")
	}
}

func TestFetcherRejectsNonHTTPS(t *testing.T) {
	f := NewFetcher(FetcherConfig{})
	if _, err := f.Fetch(context.Background(), RemoteTarget{URL: "http://idp.example.com/jwks"}); err == nil {
		t.Fatalf("非 HTTPS 应拒绝")
	}
}

func TestFetcherRejectsMetadataHostname(t *testing.T) {
	f := NewFetcher(FetcherConfig{Resolver: &stubResolver{ips: ipAddrs("203.0.113.1")}})
	for _, host := range []string{"metadata.google.internal", "metadata"} {
		if _, err := f.Fetch(context.Background(), RemoteTarget{URL: "https://" + host + "/jwks"}); !errors.Is(err, errAddressBlocked) {
			t.Fatalf("元数据主机名应拒绝: %s: %v", host, err)
		}
	}
}

// JWT-09：跳转不跟随。
func TestFetcherRedirectNotFollowed(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/jwks" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	f, _ := newTLSTestFetcher(t, srv)
	_, err := f.Fetch(context.Background(), RemoteTarget{URL: srv.URL + "/jwks", AllowCIDRs: loopbackAllow(t)})
	if err == nil {
		t.Fatalf("3xx 应视为失败")
	}
	if hits.Load() != 1 {
		t.Fatalf("不得跟随跳转，命中次数 %d", hits.Load())
	}
}

// JWT-09：响应大小限制。
func TestFetcherResponseSizeLimit(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.Repeat("x", MaxJWKSBytes+100)))
	}))
	defer srv.Close()
	f, _ := newTLSTestFetcher(t, srv)
	if _, err := f.Fetch(context.Background(), RemoteTarget{URL: srv.URL, AllowCIDRs: loopbackAllow(t)}); err == nil {
		t.Fatalf("超限响应应拒绝")
	}
}

// JWT-09：SSRF 地址校验（回环/私网/链路本地/组播/元数据/IPv6）。
func TestFetcherAddressPolicy(t *testing.T) {
	cases := []struct {
		name    string
		ips     []net.IPAddr
		allow   []string
		blocked bool
	}{
		{"回环默认拒绝", ipAddrs("127.0.0.1"), nil, true},
		{"回环显式允许", ipAddrs("127.0.0.1"), []string{"127.0.0.0/8"}, false},
		{"私网默认拒绝", ipAddrs("10.1.2.3"), nil, true},
		{"私网显式允许", ipAddrs("10.1.2.3"), []string{"10.0.0.0/8"}, false},
		{"IPv6 回环默认拒绝", ipAddrs("::1"), nil, true},
		{"IPv6 ULA 默认拒绝", ipAddrs("fd00::1"), nil, true},
		{"IPv4-mapped 私网拒绝", ipAddrs("::ffff:10.1.2.3"), nil, true},
		{"链路本地永远拒绝", ipAddrs("169.254.1.1"), []string{"169.254.0.0/16"}, true},
		{"IPv6 链路本地永远拒绝", ipAddrs("fe80::1"), []string{"fe80::/10"}, true},
		{"云元数据永远拒绝", ipAddrs("169.254.169.254"), []string{"0.0.0.0/0"}, true},
		{"阿里云元数据永远拒绝", ipAddrs("100.100.100.200"), []string{"0.0.0.0/0"}, true},
		{"组播默认拒绝", ipAddrs("239.1.1.1"), nil, true},
		{"保留段默认拒绝", ipAddrs("240.1.1.1"), nil, true},
		{"混合候选 fail-closed", ipAddrs("203.0.113.1", "169.254.169.254"), nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allow, err := parseAllowCIDRs(tc.allow)
			if err != nil {
				t.Fatal(err)
			}
			f := NewFetcher(FetcherConfig{
				Resolver: &stubResolver{ips: tc.ips},
				DialTCP: func(ctx context.Context, network, address string) (net.Conn, error) {
					return nil, errors.New("禁止真实拨号")
				},
			})
			_, err = f.Fetch(context.Background(), RemoteTarget{URL: "https://idp.example.com/jwks", AllowCIDRs: allow})
			if tc.blocked && !errors.Is(err, errAddressBlocked) {
				t.Fatalf("应被 SSRF 策略拒绝: %v", err)
			}
			if !tc.blocked && errors.Is(err, errAddressBlocked) {
				t.Fatalf("允许的地址不应被拒: %v", err)
			}
		})
	}
}

// JWT-09：DNS 重绑定 —— 配置期解析为合法地址，拨号时重解析变为元数据地址，
// 必须在拨号时再次校验并拒绝。
func TestFetcherDNSRebinding(t *testing.T) {
	var resolveCount atomic.Int32
	resolver := &stubResolver{
		ips: ipAddrs("203.0.113.1"), // “配置期”观察到的合法地址
		hook: func() {
			if resolveCount.Add(1) > 0 {
				// 拨号时重解析已被攻击者替换为元数据地址
			}
		},
	}
	f := NewFetcher(FetcherConfig{
		Resolver: resolver,
		DialTCP: func(ctx context.Context, network, address string) (net.Conn, error) {
			t.Fatalf("重绑定场景不得拨号: %s", address)
			return nil, nil
		},
	})
	// 配置期主机校验通过（域名本身合法）。
	if err := ValidateRemoteHost("idp.example.com", nil); err != nil {
		t.Fatalf("域名配置期校验应通过: %v", err)
	}
	// 拨号时重解析返回恶意地址。
	resolver.ips = ipAddrs("169.254.169.254")
	_, err := f.Fetch(context.Background(), RemoteTarget{URL: "https://idp.example.com/jwks"})
	if !errors.Is(err, errAddressBlocked) {
		t.Fatalf("DNS 重绑定应在拨号时被拒: %v", err)
	}
}

// JWT-09：不继承环境代理（HTTPS_PROXY 指向无效代理仍直连成功）。
func TestFetcherIgnoresEnvProxy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	f, _ := newTLSTestFetcher(t, srv)
	if _, err := f.Fetch(context.Background(), RemoteTarget{URL: srv.URL, AllowCIDRs: loopbackAllow(t)}); err != nil {
		t.Fatalf("环境代理不应被继承（直连应成功）: %v", err)
	}
}

// TLS ServerName 保持配置主机：解析到回环 + 允许 CIDR，但 ServerName 为配置域名，
// 证书不匹配时应握手失败（证明未用拨号 IP 做 ServerName）。
func TestFetcherTLSServerNamePinned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	f := NewFetcher(FetcherConfig{
		RootCAs:  pool,
		Resolver: &stubResolver{ips: ipAddrs("127.0.0.1")},
	})
	// 服务器证书 SAN 为 127.0.0.1/localhost，不含 idp.example.com → 握手必须失败。
	_, err := f.Fetch(context.Background(), RemoteTarget{URL: "https://idp.example.com/jwks", AllowCIDRs: loopbackAllow(t)})
	if err == nil {
		t.Fatalf("ServerName 应固定为配置主机，证书不匹配须失败")
	}
	if errors.Is(err, errAddressBlocked) {
		t.Fatalf("失败原因应为 TLS 校验而非地址策略: %v", err)
	}
}

// 并发获取受信号量限制（有界并发）。
func TestFetcherConcurrencyLimit(t *testing.T) {
	var inFlight atomic.Int32
	var maxSeen atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := inFlight.Add(1)
		for {
			old := maxSeen.Load()
			if cur <= old || maxSeen.CompareAndSwap(old, cur) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		inFlight.Add(-1)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()
	f, _ := newTLSTestFetcher(t, srv)
	f.sem = make(chan struct{}, 2) // 收窄以便观察上限

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = f.Fetch(context.Background(), RemoteTarget{URL: srv.URL, AllowCIDRs: loopbackAllow(t)})
		}()
	}
	wg.Wait()
	if got := maxSeen.Load(); got > 2 {
		t.Fatalf("并发获取超过信号量上限: %d", got)
	}
	if got := maxSeen.Load(); got == 0 {
		t.Fatalf("应实际发生获取")
	}
}
