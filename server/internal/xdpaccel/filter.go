// filter.go 控制面保护地址隔离过滤器：
// 在下发至 xdpguard 前独立执行第一道防护——将全部全局黑名单/全局临时封禁与保护地址规范化为
// netip.Prefix，剔除与 protected_addresses 或环回/链路本地/未指定/组播/广播段存在任何重叠（Overlaps）
// 的候选前缀，防止宽 CIDR（如 0.0.0.0/0、10.0.0.0/8）误封管理面或核心资产。
package xdpaccel

import (
	"net/netip"
	"sort"
	"strings"
)

// hardcodedUnbannablePrefixes 永不可写入 XDP 丢包表的系统保留地址段。
var hardcodedUnbannablePrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),       // IPv4 loopback
	netip.MustParsePrefix("::1/128"),           // IPv6 loopback
	netip.MustParsePrefix("169.254.0.0/16"),    // IPv4 link-local
	netip.MustParsePrefix("fe80::/10"),         // IPv6 link-local
	netip.MustParsePrefix("0.0.0.0/32"),        // IPv4 unspecified
	netip.MustParsePrefix("::/128"),            // IPv6 unspecified
	netip.MustParsePrefix("224.0.0.0/4"),       // IPv4 multicast
	netip.MustParsePrefix("ff00::/8"),          // IPv6 multicast
	netip.MustParsePrefix("255.255.255.255/32"), // IPv4 broadcast
}

// ParseNormalizedPrefix 将单 IP 或 CIDR 规范化为掩码化后的 netip.Prefix：
//   - 拒绝空串、带区域（zone）地址与非法前缀；
//   - 将 IPv4-in-IPv6 映射地址（::ffff:a.b.c.d 及 /96+ 前缀）还原为纯 IPv4 前缀。
func ParseNormalizedPrefix(raw string) (netip.Prefix, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		addr := p.Addr()
		if addr.Zone() != "" {
			return netip.Prefix{}, false
		}
		bits := p.Bits()
		if addr.Is4In6() {
			if bits < 96 {
				return netip.Prefix{}, false
			}
			addr = addr.Unmap()
			bits -= 96
		}
		return netip.PrefixFrom(addr, bits).Masked(), true
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || addr.Zone() != "" {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()).Masked(), true
}

// FilterBlocklist 对控制面收集的全局黑名单（blacklistAddrs）与全局临时封禁（tempBlockIPs）
// 执行规范化、去重、受保护地址重叠排除与确定性排序：
//   - blockedCIDRs：最终允许下发给 xdpguard 的安全丢包前缀列表（保证非 nil）；
//   - protectedCIDRs：规范化去重后的保护地址前缀列表（透传给 xdpguard 执行第二道隔离，保证非 nil）；
//   - excludedCount：因与保护地址或系统不可封禁段重叠而被控制面剔除的唯一候选前缀数量。
func FilterBlocklist(blacklistAddrs, tempBlockIPs, protectedAddrs []string) (blockedCIDRs []string, protectedCIDRs []string, excludedCount int) {
	protSet := make(map[netip.Prefix]struct{}, len(protectedAddrs))
	for _, raw := range protectedAddrs {
		if p, ok := ParseNormalizedPrefix(raw); ok {
			protSet[p] = struct{}{}
		}
	}
	protList := sortedPrefixes(protSet)
	protectedCIDRs = make([]string, len(protList))
	for i, p := range protList {
		protectedCIDRs[i] = p.String()
	}

	allProtected := make([]netip.Prefix, 0, len(hardcodedUnbannablePrefixes)+len(protList))
	allProtected = append(allProtected, hardcodedUnbannablePrefixes...)
	allProtected = append(allProtected, protList...)

	candSet := make(map[netip.Prefix]struct{}, len(blacklistAddrs)+len(tempBlockIPs))
	for _, raw := range blacklistAddrs {
		if p, ok := ParseNormalizedPrefix(raw); ok {
			candSet[p] = struct{}{}
		}
	}
	for _, raw := range tempBlockIPs {
		if p, ok := ParseNormalizedPrefix(raw); ok {
			candSet[p] = struct{}{}
		}
	}

	allowed := make([]netip.Prefix, 0, len(candSet))
	for _, cand := range sortedPrefixes(candSet) {
		if overlapsAny(cand, allProtected) {
			excludedCount++
			continue
		}
		allowed = append(allowed, cand)
	}

	blockedCIDRs = make([]string, len(allowed))
	for i, p := range allowed {
		blockedCIDRs[i] = p.String()
	}
	return blockedCIDRs, protectedCIDRs, excludedCount
}

func overlapsAny(cand netip.Prefix, protected []netip.Prefix) bool {
	for _, p := range protected {
		if cand.Overlaps(p) {
			return true
		}
	}
	return false
}

func sortedPrefixes(set map[netip.Prefix]struct{}) []netip.Prefix {
	if len(set) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		ai, aj := out[i].Addr(), out[j].Addr()
		if ai.Is4() != aj.Is4() {
			return ai.Is4()
		}
		if cmp := ai.Compare(aj); cmp != 0 {
			return cmp < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}
