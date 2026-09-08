package jwtverify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

// JWKS 远程获取边界（§6.1）：仅配置中的 HTTPS URL；禁跳转、禁环境代理继承、
// 受控 CA、禁 insecureSkipVerify；超时/字节/并发受限；拨号时重解析并校验全部
// 候选地址、绑定已验证地址拨号；TLS ServerName 保持配置主机（防 DNS 重绑定）。
const (
	DefaultFetchTimeout    = 2 * time.Second
	DefaultMaxResponseByte = MaxJWKSBytes
	DefaultMaxConcurrent   = 4
)

// Resolver DNS 解析接口（可注入以便测试，默认 net.DefaultResolver）。
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// FetcherConfig JWKS 获取器配置。
type FetcherConfig struct {
	Timeout          time.Duration  // 默认 2s
	MaxResponseBytes int64          // 默认 256KiB（DisableCompression，直接限制原始字节）
	MaxConcurrent    int            // 默认 4
	RootCAs          *x509.CertPool // nil = 系统受控 CA
	Resolver         Resolver       // nil = net.DefaultResolver
	// DialTCP 底层拨号钩子（测试用计数/拦截）；nil = net.Dialer。
	DialTCP func(ctx context.Context, network, address string) (net.Conn, error)
}

// RemoteTarget 单个远程 JWKS 目标：预配置 HTTPS URL + 管理员登记的允许 CIDR。
type RemoteTarget struct {
	URL        string
	AllowCIDRs []netip.Prefix
}

// Fetcher 受限 JWKS 获取器。仅在后台/异步刷新路径使用，热路径不得调用。
type Fetcher struct {
	timeout  time.Duration
	maxBytes int64
	rootCAs  *x509.CertPool
	resolver Resolver
	dialTCP  func(ctx context.Context, network, address string) (net.Conn, error)
	sem      chan struct{}
}

// NewFetcher 构造获取器。
func NewFetcher(cfg FetcherConfig) *Fetcher {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	maxBytes := cfg.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxResponseByte
	}
	maxConc := cfg.MaxConcurrent
	if maxConc <= 0 {
		maxConc = DefaultMaxConcurrent
	}
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dial := cfg.DialTCP
	if dial == nil {
		d := &net.Dialer{Timeout: timeout}
		dial = d.DialContext
	}
	return &Fetcher{
		timeout:  timeout,
		maxBytes: maxBytes,
		rootCAs:  cfg.RootCAs,
		resolver: resolver,
		dialTCP:  dial,
		sem:      make(chan struct{}, maxConc),
	}
}

// Fetch 获取一份远程 JWKS 原始字节。不跟随跳转（3xx 视为失败）、不继承
// 环境代理、不读取 Token 自带地址（调用方只传配置 URL）。
func (f *Fetcher) Fetch(ctx context.Context, target RemoteTarget) ([]byte, error) {
	host, port, err := parseHTTPSAuthority(target.URL)
	if err != nil {
		return nil, err
	}
	if err := ValidateRemoteHost(host, target.AllowCIDRs); err != nil {
		return nil, err
	}
	select {
	case f.sem <- struct{}{}:
		defer func() { <-f.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	transport := &http.Transport{
		Proxy:                 nil, // 显式禁环境代理继承
		DisableCompression:    true,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   f.timeout,
		ResponseHeaderTimeout: f.timeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host, // ServerName 固定为配置主机，与拨号 IP 解耦
			RootCAs:    f.rootCAs,
		},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return f.dialValidated(ctx, host, port, target.AllowCIDRs)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   f.timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // 禁跳转
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Del("Accept-Encoding")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwtverify: JWKS 获取失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwtverify: JWKS 响应状态非 200: %d", resp.StatusCode)
	}
	if resp.ContentLength > f.maxBytes {
		return nil, fmt.Errorf("jwtverify: JWKS 响应超过 %d 字节上限", f.maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("jwtverify: JWKS 读取失败: %w", err)
	}
	if int64(len(body)) > f.maxBytes {
		return nil, fmt.Errorf("jwtverify: JWKS 响应超过 %d 字节上限", f.maxBytes)
	}
	return body, nil
}

func parseHTTPSAuthority(raw string) (host, port string, err error) {
	if err := validateRemoteURL(raw); err != nil {
		return "", "", err
	}
	u, err := url.Parse(raw) // validateRemoteURL 已保证合法
	if err != nil {
		return "", "", err
	}
	host = u.Hostname()
	port = u.Port()
	if port == "" {
		port = "443"
	}
	return host, port, nil
}

// dialValidated 拨号时重解析并校验全部候选地址（fail-closed：任一候选被拒
// 即整体失败），然后绑定已验证地址拨号，TLS ServerName 仍由 Transport 保持为
// 配置主机，防 DNS 重绑定。
func (f *Fetcher) dialValidated(ctx context.Context, host, port string, allow []netip.Prefix) (net.Conn, error) {
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		ips, err := f.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("jwtverify: JWKS 主机解析失败: %w", err)
		}
		for _, ipa := range ips {
			if addr, ok := netip.AddrFromSlice(ipa.IP); ok {
				addrs = append(addrs, addr.Unmap())
			}
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("jwtverify: JWKS 主机解析无结果")
	}
	for _, a := range addrs {
		if err := ValidateDialAddress(a, allow); err != nil {
			return nil, err
		}
	}
	var lastErr error
	for _, a := range addrs {
		conn, err := f.dialTCP(ctx, "tcp", net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("jwtverify: JWKS 拨号失败: %w", lastErr)
}
