// dns.go 公网视角 DNS 解析判定：按 system_settings exposure_engine.public_dns_servers
// 配置的公网 DNS 服务器逐一查询（不经系统默认解析——管理面所在内网解析口径不代表
// 公网视角）。查询函数可注入（outboundhttp.Resolver 同一可注入模式），单测不做真实
// 网络调用。
//
// 诚实语义：全部服务器查询失败 → ERROR（证据如实记录，不伪造结论）；
// NXDOMAIN 或无地址记录（NODATA）→ NXDOMAIN；含公网 IP → PUBLIC；仅内网 → PRIVATE_ONLY。
package apiexposure

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/apigeo"
)

// DNS 公网视角判定结果词表（EvidenceInput.DNSResult 取值）。
const (
	DNSPublic      = "PUBLIC"       // 可解析到公网 IP
	DNSPrivateOnly = "PRIVATE_ONLY" // 仅解析到内网/保留地址
	DNSNXDomain    = "NXDOMAIN"     // 域名不存在或无地址记录（NODATA）
	DNSError       = "ERROR"        // 全部配置服务器查询失败
)

// dnsQueryTimeout 单台服务器单次查询超时（防慢服务器拖垮评估轮）。
const dnsQueryTimeout = 3 * time.Second

// LookupFunc 单服务器查询函数（生产为 dialServerLookup；测试注入假实现）。
type LookupFunc func(ctx context.Context, server, host string) ([]net.IP, error)

// PublicResolver 公网视角 DNS 判定器（无内部状态，并发安全）。
type PublicResolver struct {
	lookup LookupFunc // nil 时构造默认拨号实现（NewPublicResolver 已填充）
}

// NewPublicResolver 创建公网视角判定器（真实拨号配置服务器，UDP 53）。
func NewPublicResolver() *PublicResolver {
	return &PublicResolver{lookup: dialServerLookup}
}

// newTestResolver 测试构造（包内单测注入假查询函数，不做真实网络调用）。
func newTestResolver(lookup LookupFunc) *PublicResolver {
	return &PublicResolver{lookup: lookup}
}

// ResolvePublicView 公网视角解析判定：按配置服务器顺序查询，首个成功应答为准
// （NXDOMAIN 视为确定结论直接返回；传输级错误换下一台）。servers 为空或域名
// 为空时返回空串（不产 DNS 证据，与「未解析」区分于「查询失败」）。
func (r *PublicResolver) ResolvePublicView(ctx context.Context, hostname string, servers []string) string {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if host == "" || len(servers) == 0 || r == nil || r.lookup == nil {
		return ""
	}
	for _, server := range servers {
		ips, err := r.lookup(ctx, server, host)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				return DNSNXDomain
			}
			continue // 传输级错误：换下一台服务器
		}
		if len(ips) == 0 {
			return DNSNXDomain // NODATA：域名存在但无地址记录
		}
		for _, ip := range ips {
			if apigeo.ClassifyIPScope(ip.String()) == apigeo.IPScopePublic {
				return DNSPublic
			}
		}
		return DNSPrivateOnly
	}
	return DNSError
}

// dialServerLookup 真实查询：绕过系统默认解析，直接向配置服务器拨号（UDP，缺省 53 端口；
// 服务器带端口时尊重原文）。单次查询 dnsQueryTimeout 超时。
func dialServerLookup(ctx context.Context, server, host string) ([]net.IP, error) {
	addr := strings.TrimSpace(server)
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: dnsQueryTimeout}
			return d.DialContext(ctx, "udp", addr)
		},
	}
	qctx, cancel := context.WithTimeout(ctx, dnsQueryTimeout)
	defer cancel()
	return resolver.LookupIP(qctx, "ip", host)
}
