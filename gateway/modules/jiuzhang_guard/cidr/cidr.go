// Package cidr 提供 IP/CIDR 解析、规范化与匹配（IPv4/IPv6/CIDR）。
// 安全约束：禁止域名、带协议、带端口、通配字符串、控制字符；
// IPv4 映射 IPv6 统一规范化为 IPv4。
package cidr

import (
	"fmt"
	"net/netip"
	"strings"
)

// MaxPrefixLenV4 / MaxPrefixLenV6 限制合法掩码范围。
const (
	MaxPrefixLenV4 = 32
	MaxPrefixLenV6 = 128
)

// containsControl 检查控制字符与空白（防止日志注入与畸形输入）。
func containsControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// ParseIP 解析并规范化单个 IP（IPv4 映射 IPv6 归一为 IPv4）。
// 拒绝：空串、控制字符、域名、带端口、带 zone、带协议。
func ParseIP(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, fmt.Errorf("empty address")
	}
	if len(s) > 64 {
		return netip.Addr{}, fmt.Errorf("address too long")
	}
	if containsControl(s) {
		return netip.Addr{}, fmt.Errorf("address contains control characters")
	}
	if strings.ContainsAny(s, "/: ") && !strings.Contains(s, ":") {
		return netip.Addr{}, fmt.Errorf("invalid address %q", s)
	}
	// 含 "/" 视为 CIDR，不允许当作单 IP
	if strings.Contains(s, "/") {
		return netip.Addr{}, fmt.Errorf("address must not contain '/': use ParseCIDR")
	}
	// 带端口形式（IPv4:port 或 [v6]:port）拒绝
	if strings.Contains(s, "]") {
		return netip.Addr{}, fmt.Errorf("address must not contain port")
	}
	if strings.Count(s, ":") == 1 {
		return netip.Addr{}, fmt.Errorf("address must not contain port")
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP %q", s)
	}
	if addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("zone not allowed")
	}
	return addr.Unmap(), nil
}

// ParseCIDR 解析并规范化 CIDR（掩码化、IPv4 映射归一）。
func ParseCIDR(s string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("empty cidr")
	}
	if len(s) > 80 || containsControl(s) {
		return netip.Prefix{}, fmt.Errorf("invalid cidr")
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid cidr %q", s)
	}
	addr := p.Addr()
	bits := p.Bits()
	// IPv4 映射 IPv6：仅当掩码覆盖映射段（bits>=96）时归一为 IPv4（如 ::ffff:10.0.0.0/104 → 10.0.0.0/8）
	if addr.Is4In6() && bits >= 96 {
		addr = addr.Unmap()
		bits -= 96
	}
	if addr.Is4() && bits > MaxPrefixLenV4 {
		return netip.Prefix{}, fmt.Errorf("invalid v4 prefix bits")
	}
	if addr.Is6() && bits > MaxPrefixLenV6 {
		return netip.Prefix{}, fmt.Errorf("invalid v6 prefix bits")
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

// ParseAddress 解析单 IP 或 CIDR，统一返回 Prefix（单 IP 视为 /32、/128）。
func ParseAddress(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return ParseCIDR(s)
	}
	addr, err := ParseIP(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := MaxPrefixLenV6
	if addr.Is4() {
		bits = MaxPrefixLenV4
	}
	return netip.PrefixFrom(addr, bits), nil
}

// Entry 是一条地址匹配项。
type Entry struct {
	Prefix netip.Prefix
	Meta   string // 关联元数据（如规则 ID），便于命中回查
}

// Matcher 地址匹配器：精确地址走 map，CIDR 走线性扫描（万级规则下仍为微秒级）。
type Matcher struct {
	exact4  map[netip.Addr][]int // v4 单 IP -> entry 索引
	exact6  map[netip.Addr][]int
	prefix4 []int // v4 CIDR entry 索引
	prefix6 []int
	entries []Entry
}

// NewMatcher 构建匹配器（索引为 entries 下标）。
func NewMatcher(entries []Entry) *Matcher {
	m := &Matcher{
		exact4:  map[netip.Addr][]int{},
		exact6:  map[netip.Addr][]int{},
		entries: entries,
	}
	for i, e := range entries {
		p := e.Prefix
		if p.Addr().Is4() {
			if p.Bits() == MaxPrefixLenV4 {
				m.exact4[p.Addr()] = append(m.exact4[p.Addr()], i)
			} else {
				m.prefix4 = append(m.prefix4, i)
			}
		} else {
			if p.Bits() == MaxPrefixLenV6 {
				m.exact6[p.Addr()] = append(m.exact6[p.Addr()], i)
			} else {
				m.prefix6 = append(m.prefix6, i)
			}
		}
	}
	return m
}

// Match 返回命中条目索引（先精确后 CIDR，可能多个）。
func (m *Matcher) Match(ip netip.Addr) []int {
	ip = ip.Unmap()
	var out []int
	if ip.Is4() {
		out = append(out, m.exact4[ip]...)
		for _, i := range m.prefix4 {
			if m.entries[i].Prefix.Contains(ip) {
				out = append(out, i)
			}
		}
		return out
	}
	out = append(out, m.exact6[ip]...)
	for _, i := range m.prefix6 {
		if m.entries[i].Prefix.Contains(ip) {
			out = append(out, i)
		}
	}
	return out
}

// Contains 是否命中任一条目。
func (m *Matcher) Contains(ip netip.Addr) bool {
	return len(m.Match(ip)) > 0
}
