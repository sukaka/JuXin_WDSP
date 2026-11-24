package nodesync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ErrSyncAgentAddrDenied indicates an invalid or forbidden sync agent address (SSRF / policy block).
var ErrSyncAgentAddrDenied = errors.New("invalid sync agent address")

// IPResolver abstracts hostname resolution for SSRF validation and dial-time DNS rebinding checks.
type IPResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// deniedSyncPrefixes blocks cloud metadata endpoints and link-local ranges before IsPrivate checks
// (mirroring server/internal/gatewayconfig/caddyclient.go).
var deniedSyncPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.169.254/32"),
	netip.MustParsePrefix("169.254.170.2/32"),
	netip.MustParsePrefix("100.100.100.200/32"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
}

// ValidateSyncAgentAddr validates a node's hasyncd endpoint URL:
//   - Only http:// or https://
//   - No userinfo, non-root path, query, or fragment
//   - Valid optional port (1..65535)
//   - Only RFC1918 private, IPv6 ULA, or loopback IP (denying cloud metadata & link-local)
//   - Hostnames must resolve and ALL resolved IPs must satisfy the internal IP check
func ValidateSyncAgentAddr(addr string) error {
	_, err := parseSyncAgentAddr(context.Background(), addr, net.DefaultResolver)
	return err
}

// ValidateSyncAgentAddrWithResolver validates addr using a custom IPResolver (for tests or scoped contexts).
func ValidateSyncAgentAddrWithResolver(ctx context.Context, addr string, resolver IPResolver) error {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	_, err := parseSyncAgentAddr(ctx, addr, resolver)
	return err
}

func parseSyncAgentAddr(ctx context.Context, addr string, resolver IPResolver) (*url.URL, error) {
	for i := 0; i < len(addr); i++ {
		if addr[i] < 0x20 || addr[i] == 0x7f {
			return nil, fmt.Errorf("%w: 地址包含控制字符", ErrSyncAgentAddrDenied)
		}
	}
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, fmt.Errorf("%w: 地址为空", ErrSyncAgentAddrDenied)
	}
	if len(addr) > 255 {
		return nil, fmt.Errorf("%w: 地址过长", ErrSyncAgentAddrDenied)
	}
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: URL 解析失败", ErrSyncAgentAddrDenied)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: 仅支持 http:// 或 https://", ErrSyncAgentAddrDenied)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: 不允许携带用户信息", ErrSyncAgentAddrDenied)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("%w: 不允许携带路径", ErrSyncAgentAddrDenied)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: 不允许携带查询或片段", ErrSyncAgentAddrDenied)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: 缺少主机名", ErrSyncAgentAddrDenied)
	}
	if portStr := u.Port(); portStr != "" {
		p, perr := strconv.Atoi(portStr)
		if perr != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("%w: 端口非法", ErrSyncAgentAddrDenied)
		}
	}

	if ip := net.ParseIP(host); ip != nil {
		if err := checkInternalSyncIP(ip); err != nil {
			return nil, err
		}
		warnPlaintextSyncScheme(u)
		return u, nil
	}

	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("%w: 主机名解析失败", ErrSyncAgentAddrDenied)
	}
	for _, ip := range ips {
		if err := checkInternalSyncIP(ip); err != nil {
			return nil, err
		}
	}
	warnPlaintextSyncScheme(u)
	return u, nil
}

func warnPlaintextSyncScheme(u *url.URL) {
	if u.Scheme != "http" {
		return
	}
	slog.Warn("node sync agent address uses plaintext http: prefer https with TLS CA or certificate fingerprint pinning in production",
		"sync_agent_addr", u.Host)
}

func checkInternalSyncIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("%w: 空地址", ErrSyncAgentAddrDenied)
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("%w: 非法地址 %s", ErrSyncAgentAddrDenied, ip)
	}
	addr = addr.Unmap()
	for _, prefix := range deniedSyncPrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("%w: 禁止访问元数据或链路本地地址 %s", ErrSyncAgentAddrDenied, addr)
		}
	}
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return fmt.Errorf("%w: 禁止访问链路本地/组播/未指定地址 %s", ErrSyncAgentAddrDenied, addr)
	}
	if addr.IsLoopback() || addr.IsPrivate() {
		return nil
	}
	return fmt.Errorf("%w: 非内网管理面地址 %s", ErrSyncAgentAddrDenied, addr)
}

func safeDialContext(dialer *net.Dialer, resolver IPResolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("%w: 地址解析失败", ErrSyncAgentAddrDenied)
		}
		if ip := net.ParseIP(host); ip != nil {
			if err := checkInternalSyncIP(ip); err != nil {
				return nil, err
			}
			parsed, ok := netip.AddrFromSlice(ip)
			if !ok {
				return nil, fmt.Errorf("%w: 地址解析失败", ErrSyncAgentAddrDenied)
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(parsed.Unmap().String(), port))
		}
		// Dial-time DNS re-resolution & verification to defeat DNS rebinding attacks.
		ips, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("%w: 主机名解析失败", ErrSyncAgentAddrDenied)
		}
		verified := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			if err := checkInternalSyncIP(ip); err != nil {
				return nil, err
			}
			parsed, ok := netip.AddrFromSlice(ip)
			if !ok {
				return nil, fmt.Errorf("%w: 地址解析失败", ErrSyncAgentAddrDenied)
			}
			verified = append(verified, parsed.Unmap())
		}
		var lastErr error
		for _, targetIP := range verified {
			conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(targetIP.String(), port))
			if derr == nil {
				return conn, nil
			}
			lastErr = derr
		}
		return nil, lastErr
	}
}
