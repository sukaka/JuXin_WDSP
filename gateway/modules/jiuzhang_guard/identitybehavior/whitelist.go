package identitybehavior

import (
	"net/netip"
	"strings"
)

// Whitelisted 白名单判定：客户端 IP 命中 whitelist_ips（CIDR）或 UA 命中
// whitelist_uas（子串，小写匹配）→ 完全跳过身份行为观测与信号（放行不受影响）。
func (c *Config) Whitelisted(ip netip.Addr, ua string) bool {
	if c == nil {
		return false
	}
	if ip.IsValid() {
		for _, p := range c.whitelistIPs {
			if p.Contains(ip) {
				return true
			}
		}
	}
	if ua != "" {
		l := strings.ToLower(ua)
		for _, s := range c.whitelistUAs {
			if strings.Contains(l, s) {
				return true
			}
		}
	}
	return false
}

// SensitivePathPrefix 敏感路径前缀匹配（大小写不敏感；返回命中的前缀，空串 = 未命中）。
func (c *Config) SensitivePathPrefix(path string) string {
	if c == nil || path == "" {
		return ""
	}
	l := strings.ToLower(path)
	for _, p := range c.SensitivePaths {
		if p != "" && strings.HasPrefix(l, p) {
			return p
		}
	}
	return ""
}
