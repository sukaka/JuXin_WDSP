// Package clientip 真实客户端IP识别。
// 安全原则：仅当 TCP 连接来源为可信代理时才解析代理头，否则一律使用连接源IP。
package clientip

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/trustedproxy"
)

// Source 客户端IP来源。
type Source string

const (
	SourceConnection    Source = "CONNECTION"
	SourceXForwardedFor Source = "X_FORWARDED_FOR"
	SourceXRealIP       Source = "X_REAL_IP"
	SourceForwarded     Source = "FORWARDED"
	SourceCustomHeader  Source = "CUSTOM_HEADER"
)

// DefaultMaxChain 默认最大代理链长度。
const DefaultMaxChain = 16

// maxHeaderValueLen 代理头值长度上限（防资源耗尽）。
const maxHeaderValueLen = 2048

// Result 解析结果。
type Result struct {
	ClientIP         netip.Addr
	ConnectionIP     netip.Addr
	Source           Source
	TrustedProxyUsed string // 命中的可信代理名（未命中为空）
	ChainSummary     string // 截断的代理链摘要（日志用）
	HeaderInvalid    bool   // 代理头非法（触发 FORWARDED_HEADER_INVALID 事件）
	ChainTooLong     bool   // 代理链超限（触发 FORWARDED_CHAIN_TOO_LONG 事件）
}

// Resolver 真实IP解析器。
type Resolver struct {
	MaxChain int
}

// NewResolver 构造解析器（MaxChain<=0 取默认 16）。
func NewResolver(maxChain int) Resolver {
	if maxChain <= 0 {
		maxChain = DefaultMaxChain
	}
	return Resolver{MaxChain: maxChain}
}

// ConnectionIP 提取 TCP 连接源 IP（RemoteAddr 去端口）。
func ConnectionIP(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return cidr.ParseIP(strings.TrimSpace(host))
}

// hasControl 是否含控制字符（禁止换行/控制符，防日志与响应注入）。
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// Resolve 解析真实客户端 IP。
// 连接源不可信 → 直接使用连接源 IP，完全忽略代理头（防伪造）。
func (rs Resolver) Resolve(r *http.Request, proxies *trustedproxy.Set) Result {
	res := Result{Source: SourceConnection}
	conn, err := ConnectionIP(r)
	if err != nil {
		// 连接源不可解析：交由调用方处理（此处返回零值）
		res.HeaderInvalid = true
		return res
	}
	res.ConnectionIP = conn
	res.ClientIP = conn

	proxy := proxies.Match(conn)
	if proxy == nil {
		return res
	}
	res.TrustedProxyUsed = proxy.Name

	// 按可信代理配置的头类型取值（自定义头仅对显式配置 CUSTOM 的代理生效）
	var values []netip.Addr
	var headerName string
	switch proxy.HeaderType {
	case trustedproxy.HeaderXForwardedFor:
		headerName = "X-Forwarded-For"
		values, err = parseIPList(r.Header.Get(headerName))
		res.Source = SourceXForwardedFor
	case trustedproxy.HeaderXRealIP:
		headerName = "X-Real-IP"
		var ip netip.Addr
		ip, err = parseSingleIP(r.Header.Get(headerName))
		if err == nil {
			values = []netip.Addr{ip}
		}
		res.Source = SourceXRealIP
	case trustedproxy.HeaderForwarded:
		headerName = "Forwarded"
		values, err = parseForwarded(r.Header.Get(headerName))
		res.Source = SourceForwarded
	case trustedproxy.HeaderCustom:
		headerName = proxy.CustomHeaderName
		values, err = parseIPList(r.Header.Get(headerName))
		res.Source = SourceCustomHeader
	}

	if headerName == "" {
		return res
	}
	raw := r.Header.Get(headerName)
	if raw == "" {
		// 可信代理未携带对应头：回退连接源
		res.Source = SourceConnection
		return res
	}
	if err != nil || len(values) == 0 {
		// 非法地址：回退连接源 IP 并标记
		res.HeaderInvalid = true
		res.Source = SourceConnection
		res.ChainSummary = truncate(raw, 128)
		return res
	}
	if len(values) > rs.MaxChain {
		res.ChainTooLong = true
		res.Source = SourceConnection
		res.ChainSummary = truncate(raw, 128)
		return res
	}

	res.ChainSummary = truncate(joinAddrs(values), 128)
	res.ClientIP = rs.walkChain(values, proxies)
	return res
}

// walkChain 从右向左跳过连续可信代理，第一个非可信地址为客户端；
// 全链可信时取最左端声明。
func (rs Resolver) walkChain(values []netip.Addr, proxies *trustedproxy.Set) netip.Addr {
	for i := len(values) - 1; i >= 0; i-- {
		if !proxies.Trusted(values[i]) {
			return values[i]
		}
	}
	return values[0]
}

// parseIPList 解析逗号分隔 IP 列表（X-Forwarded-For 语义）。
// 固定规则：取首个同名头；任一元素非法则整体非法。
func parseIPList(v string) ([]netip.Addr, error) {
	if v == "" || len(v) > maxHeaderValueLen || hasControl(v) {
		return nil, errInvalid
	}
	parts := strings.Split(v, ",")
	out := make([]netip.Addr, 0, len(parts))
	for _, p := range parts {
		ip, err := cidr.ParseIP(strings.TrimSpace(p))
		if err != nil {
			return nil, errInvalid
		}
		out = append(out, ip)
	}
	return out, nil
}

// parseSingleIP 解析单 IP 头（X-Real-IP 语义）。
func parseSingleIP(v string) (netip.Addr, error) {
	if v == "" || len(v) > maxHeaderValueLen || hasControl(v) {
		return netip.Addr{}, errInvalid
	}
	return cidr.ParseIP(strings.TrimSpace(v))
}

// parseForwarded 解析 RFC 7239 Forwarded 头的 for= 链。
// 规则：按 ";" 取 for= 参数；去引号、去端口、去 IPv6 方括号；
// "unknown" 与 "_" 开头混淆标识跳过；非法地址整体非法。
func parseForwarded(v string) ([]netip.Addr, error) {
	if v == "" || len(v) > maxHeaderValueLen || hasControl(v) {
		return nil, errInvalid
	}
	var out []netip.Addr
	elements := strings.Split(v, ",")
	for _, el := range elements {
		for _, pair := range strings.Split(el, ";") {
			kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(kv) != 2 || !strings.EqualFold(strings.TrimSpace(kv[0]), "for") {
				continue
			}
			val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
			if val == "" {
				continue
			}
			lower := strings.ToLower(val)
			if lower == "unknown" || strings.HasPrefix(val, "_") {
				continue
			}
			val = stripPort(val)
			ip, err := cidr.ParseIP(val)
			if err != nil {
				return nil, errInvalid
			}
			out = append(out, ip)
		}
	}
	return out, nil
}

// stripPort 去掉 for= 值的端口与 IPv6 方括号。
func stripPort(v string) string {
	if strings.HasPrefix(v, "[") {
		if i := strings.Index(v, "]"); i >= 0 {
			return v[1:i]
		}
		return v
	}
	// IPv4:port
	if strings.Count(v, ":") == 1 {
		if i := strings.LastIndex(v, ":"); i > 0 {
			return v[:i]
		}
	}
	return v
}

func joinAddrs(addrs []netip.Addr) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	return strings.Join(parts, ", ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

type errInvalidT struct{}

func (errInvalidT) Error() string { return "invalid forwarded header" }

var errInvalid error = errInvalidT{}
