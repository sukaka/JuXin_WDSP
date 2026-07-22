package protectedaddresses

import (
	"net/netip"
	"strings"
)

// MatchProtected 判断 ip 是否命中任一启用中的保护地址（单IP或CIDR）。
// 返回是否命中与首个命中条目的名称；非法 IP 输入一律不命中。
// 纯函数，不依赖数据库。
func MatchProtected(addrs []ProtectedAddress, ip string) (bool, string) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false, ""
	}
	addr = addr.Unmap()
	for i := range addrs {
		a := &addrs[i]
		if a.Status != StatusEnabled {
			continue
		}
		if a.Address != "" {
			if single, err := netip.ParseAddr(a.Address); err == nil && single.Unmap() == addr {
				return true, a.Name
			}
			continue
		}
		if a.CIDR != "" {
			prefix, err := netip.ParsePrefix(a.CIDR)
			if err != nil {
				continue
			}
			pa := prefix.Addr()
			bits := prefix.Bits()
			if pa.Is4In6() {
				pa = pa.Unmap()
				bits -= 96
				if bits < 0 {
					continue
				}
			}
			if netip.PrefixFrom(pa, bits).Masked().Contains(addr) {
				return true, a.Name
			}
		}
	}
	return false, ""
}
