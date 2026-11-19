// Package outboundhttp 提供带 SSRF 防护的出站 HTTP 客户端构造：
// URL 校验（scheme/host/端口/内嵌凭据）、公网地址校验（拒绝回环/私网/链路本地/
// 组播/未指定/IPv4-mapped IPv6/云元数据网段）、拨号时 DNS 重解析复检（防校验与
// 连接之间的 DNS 重绑定）、重定向每跳复检且跨 Host 剥离认证/签名头。
//
// 防护语义与 apisecurity 规范 URL 拉取（spec_version.go）一致，此处抽取为公共实现，
// 并增加显式允许列表（CIDR / 精确主机名）以支持确有需要的内网目标。默认策略最严格：
// 空允许列表、不跟随重定向。
package outboundhttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrDenied 是出站目标被安全策略拒绝的哨兵错误（errors.Is 判定）。
var ErrDenied = errors.New("出站目标被安全策略拒绝")

// defaultTimeout 是未配置时的整体超时。
const defaultTimeout = 10 * time.Second

// Resolver 是可注入的 DNS 解析接口（*net.Resolver 实现；测试注入假解析器）。
type Resolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// Options 是 Policy 构建参数。
type Options struct {
	Timeout      time.Duration // 0 → defaultTimeout
	MaxRedirects int           // <=0 不跟随重定向；>0 时每跳重新校验目标
	Resolver     Resolver      // nil → net.DefaultResolver
	Allowlist    string        // 逗号/分号/空白分隔的 CIDR 或精确主机名，命中即跳过公网校验
	StripHeaders []string      // 跨 Host 重定向时额外剥离的请求头（默认已含认证/Cookie/签名头）
}

// Policy 是出站安全策略（NewPolicy 后不可变，可并发使用）。
type Policy struct {
	timeout      time.Duration
	maxRedirects int
	resolver     Resolver
	allowHosts   map[string]bool
	allowCIDRs   []*net.IPNet
	stripHeaders []string
}

// defaultStripHeaders 是跨 Host 重定向时默认剥离的敏感请求头
// （短信网关签名头 X-App-Key/X-Sign 在此列，防重定向泄露凭据）。
var defaultStripHeaders = []string{"Authorization", "Proxy-Authorization", "Cookie", "X-App-Key", "X-Sign"}

// deniedCIDRs 是 net.IP 内置判定之外的保留网段补充（云元数据地址虽已被链路本地/ULA
// 判定覆盖，仍显式列出以便审计对照）。
var deniedCIDRs = mustParseCIDRs([]string{
	"0.0.0.0/8",          // 本网络
	"100.64.0.0/10",      // 运营商级 NAT
	"198.18.0.0/15",      // 基准测试
	"240.0.0.0/4",        // 保留
	"169.254.169.254/32", // 云元数据（AWS/GCP/Azure IPv4）
	"169.254.170.2/32",   // AWS ECS 任务元数据
	"100.100.100.200/32", // 阿里云元数据
	"fd00:ec2::254/128",  // 云元数据（AWS IPv6，ULA 内）
})

// hardDeniedCIDRs remain blocked even when an administrator allowlists a
// private range or hostname. Cloud instance metadata is never a valid
// application-level outbound destination.
var hardDeniedCIDRs = mustParseCIDRs([]string{
	"169.254.169.254/32",
	"169.254.170.2/32",
	"100.100.100.200/32",
	"fd00:ec2::254/128",
})

func mustParseCIDRs(list []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, s := range list {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic("invalid CIDR: " + s)
		}
		out = append(out, n)
	}
	return out
}

// NewPolicy 构建策略；Allowlist 中的非法项如实报错（不静默跳过，防配置拼写错误削弱防护）。
func NewPolicy(opts Options) (*Policy, error) {
	p := &Policy{
		timeout:      opts.Timeout,
		maxRedirects: opts.MaxRedirects,
		resolver:     opts.Resolver,
		allowHosts:   map[string]bool{},
	}
	if p.timeout <= 0 {
		p.timeout = defaultTimeout
	}
	if p.resolver == nil {
		p.resolver = net.DefaultResolver
	}
	for _, tok := range strings.FieldsFunc(opts.Allowlist, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if _, n, err := net.ParseCIDR(tok); err == nil {
			p.allowCIDRs = append(p.allowCIDRs, n)
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(tok, "."))
		if strings.Contains(tok, "/") || net.ParseIP(host) != nil || host == "" || len(host) > 253 {
			return nil, fmt.Errorf("allowlist 项非法（须为 CIDR 或主机名）: %q", tok)
		}
		p.allowHosts[host] = true
	}
	p.stripHeaders = append(append([]string{}, defaultStripHeaders...), opts.StripHeaders...)
	return p, nil
}

// CheckIP 校验目标 IP：allowlist CIDR 命中放行；否则须为公网地址——拒绝回环/私网/
// 链路本地/组播/未指定及 deniedCIDRs 网段（IPv4-mapped IPv6 先归一为 IPv4 再判定）。
func (p *Policy) CheckIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("%w: 空地址", ErrDenied)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if hardDenyIP(ip) {
		return fmt.Errorf("%w: 敏感基础设施地址 %s", ErrDenied, ip)
	}
	for _, n := range p.allowCIDRs {
		if n.Contains(ip) {
			return nil
		}
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return fmt.Errorf("%w: 内网/保留地址 %s", ErrDenied, ip)
	}
	for _, n := range deniedCIDRs {
		if n.Contains(ip) {
			return fmt.Errorf("%w: 保留网段 %s", ErrDenied, ip)
		}
	}
	return nil
}

// hostAllowed 判断主机名是否命中 allowlist 精确主机名（大小写不敏感，容忍末尾根点）。
func (p *Policy) hostAllowed(host string) bool {
	return p.allowHosts[strings.ToLower(strings.TrimSuffix(host, "."))]
}

// ParseURL 校验并解析目标 URL：仅 http/https、主机非空、无内嵌凭据（防 userinfo
// 混淆）、端口须在 1~65535。不做地址校验（见 ValidateURL / CheckIP）。
func ParseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return nil, fmt.Errorf("%w: URL 解析失败", ErrDenied)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: 仅支持 http/https", ErrDenied)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: 不允许内嵌凭据", ErrDenied)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("%w: 缺少主机名", ErrDenied)
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%w: 非法端口 %q", ErrDenied, port)
		}
	}
	return u, nil
}

// ValidateURL 完整校验目标 URL：ParseURL + 地址公网校验（域名解析全部 A/AAAA 记录
// 逐一校验，任一内网地址即拒绝；allowlist 主机名命中跳过地址校验）。
func (p *Policy) ValidateURL(ctx context.Context, raw string) (*url.URL, error) {
	u, err := ParseURL(raw)
	if err != nil {
		return nil, err
	}
	if err := p.checkHost(ctx, u.Hostname()); err != nil {
		return nil, err
	}
	return u, nil
}

// checkHost 校验主机地址：字面量 IP 直接 CheckIP；域名解析全部记录逐一校验。
func (p *Policy) checkHost(ctx context.Context, host string) error {
	if p.hostAllowed(host) {
		ips, err := p.resolver.LookupIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return fmt.Errorf("%w: 主机名 %s 解析失败", ErrDenied, host)
		}
		for _, ip := range ips {
			if hardDenyIP(ip) {
				return fmt.Errorf("%w: 主机名 %s 解析到敏感基础设施地址", ErrDenied, host)
			}
		}
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return p.CheckIP(ip)
	}
	ips, err := p.resolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("%w: 主机名 %s 解析失败", ErrDenied, host)
	}
	for _, ip := range ips {
		if err := p.CheckIP(ip); err != nil {
			return err
		}
	}
	return nil
}

// Transport 构造带 SSRF 防护的 Transport：拨号时重新解析并复检目标 IP（规避校验与
// 连接之间的 DNS 重绑定），直接连接已校验的地址（TLS SNI 仍取 URL 主机名，不受影响）。
func (p *Policy) Transport() *http.Transport {
	dialer := &net.Dialer{Timeout: p.timeout}
	return &http.Transport{
		DisableKeepAlives:   true,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: p.timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: 地址解析失败", ErrDenied)
			}
			if p.hostAllowed(host) {
				// allowlist 主机名跳过地址校验，但仍经配置解析器解析（与校验语义一致）
				ips, err := p.resolver.LookupIP(ctx, "ip", host)
				if err != nil || len(ips) == 0 {
					return nil, fmt.Errorf("%w: 主机名 %s 解析失败", ErrDenied, host)
				}
				for _, ip := range ips {
					if hardDenyIP(ip) {
						return nil, fmt.Errorf("%w: 主机名 %s 解析到敏感基础设施地址", ErrDenied, host)
					}
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
			}
			if ip := net.ParseIP(host); ip != nil {
				if err := p.CheckIP(ip); err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, addr)
			}
			ips, err := p.resolver.LookupIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("%w: 主机名 %s 解析失败", ErrDenied, host)
			}
			for _, ip := range ips {
				if err := p.CheckIP(ip); err != nil {
					return nil, err
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
	}
}

func hardDenyIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, network := range hardDeniedCIDRs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Client 构造防护 HTTP 客户端：防护 Transport + 整体超时 + 重定向策略
// （MaxRedirects<=0 时拒绝跟随；>0 时每跳重新校验目标，且跨 Host 重定向剥离敏感头）。
func (p *Policy) Client() *http.Client {
	return &http.Client{
		Transport: p.Transport(),
		Timeout:   p.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if p.maxRedirects <= 0 {
				return fmt.Errorf("%w: 不跟随重定向（%s → %s）",
					ErrDenied, via[len(via)-1].URL.Redacted(), req.URL.Redacted())
			}
			if len(via) >= p.maxRedirects {
				return fmt.Errorf("%w: 重定向次数过多", ErrDenied)
			}
			if _, err := p.ValidateURL(req.Context(), req.URL.String()); err != nil {
				return err
			}
			if !sameRedirectOrigin(req.URL, via[0].URL) {
				for _, h := range p.stripHeaders {
					req.Header.Del(h)
				}
			}
			return nil
		},
	}
}

func sameRedirectOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		normalizedSchemePort(a) == normalizedSchemePort(b)
}

func normalizedSchemePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}
