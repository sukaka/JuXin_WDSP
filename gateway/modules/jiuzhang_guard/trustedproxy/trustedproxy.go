// Package trustedproxy 可信代理集合与匹配。
// 核心安全原则：只有 TCP 连接来源属于可信代理时，才可信任其代理头。
package trustedproxy

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
)

// HeaderType 可信代理使用的真实IP头类型。
type HeaderType string

const (
	HeaderXForwardedFor HeaderType = "X_FORWARDED_FOR"
	HeaderXRealIP       HeaderType = "X_REAL_IP"
	HeaderForwarded     HeaderType = "FORWARDED"
	HeaderCustom        HeaderType = "CUSTOM"
)

// Proxy 一条可信代理配置。
type Proxy struct {
	Name             string
	Prefix           netip.Prefix // 单个 IP 视为 /32、/128
	HeaderType       HeaderType
	CustomHeaderName string // HeaderType=CUSTOM 时必填
	Priority         int    // 数值小者优先
}

// Set 可信代理匹配集合。
type Set struct {
	proxies []Proxy       // 按 Priority 升序
	matcher *cidr.Matcher // 索引对应 proxies 下标
}

// NewSet 构建可信代理集合（校验并排序）。
func NewSet(proxies []Proxy) (*Set, error) {
	if len(proxies) > 1024 {
		return nil, fmt.Errorf("too many trusted proxies: %d", len(proxies))
	}
	cp := make([]Proxy, len(proxies))
	copy(cp, proxies)
	for i := range cp {
		if !cp[i].Prefix.IsValid() {
			return nil, fmt.Errorf("trusted proxy %q: invalid prefix", cp[i].Name)
		}
		switch cp[i].HeaderType {
		case HeaderXForwardedFor, HeaderXRealIP, HeaderForwarded:
		case HeaderCustom:
			if !validHeaderName(cp[i].CustomHeaderName) {
				return nil, fmt.Errorf("trusted proxy %q: invalid custom header name", cp[i].Name)
			}
		default:
			return nil, fmt.Errorf("trusted proxy %q: unknown header type %q", cp[i].Name, cp[i].HeaderType)
		}
	}
	sort.SliceStable(cp, func(i, j int) bool { return cp[i].Priority < cp[j].Priority })
	entries := make([]cidr.Entry, len(cp))
	for i, p := range cp {
		entries[i] = cidr.Entry{Prefix: p.Prefix, Meta: p.Name}
	}
	return &Set{proxies: cp, matcher: cidr.NewMatcher(entries)}, nil
}

// validHeaderName 校验 HTTP 头名（RFC token，防响应拆分）。
func validHeaderName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.'
		if !ok {
			return false
		}
	}
	return true
}

// Match 返回命中的可信代理（按优先级取第一个），未命中返回 nil。
func (s *Set) Match(ip netip.Addr) *Proxy {
	if s == nil {
		return nil
	}
	idx := s.matcher.Match(ip)
	if len(idx) == 0 {
		return nil
	}
	// matcher 输出顺序不保证优先级，取最小下标（proxies 已按优先级排序）
	best := idx[0]
	for _, i := range idx[1:] {
		if i < best {
			best = i
		}
	}
	p := s.proxies[best]
	return &p
}

// Trusted 连接来源是否可信代理。
func (s *Set) Trusted(ip netip.Addr) bool {
	return s.Match(ip) != nil
}
