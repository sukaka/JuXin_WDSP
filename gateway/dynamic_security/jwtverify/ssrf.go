package jwtverify

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// JWKS 获取的 SSRF 网段表（§6.1）。与 server/internal/validation/domain.go
// 口径等价，但因 Go module 边界不能跨模块 import，在本包内独立实现。
//
// restrictedPrefixes：默认拒绝（回环/私有/组播/保留等），可被管理员显式
// 登记的允许 CIDR 覆盖；alwaysBlockedPrefixes：元数据与链路本地，永不可覆盖。
var (
	restrictedPrefixes = mustParsePrefixes([]string{
		"0.0.0.0/8",      // 本网络
		"10.0.0.0/8",     // 私有
		"100.64.0.0/10",  // CGNAT
		"127.0.0.0/8",    // 回环
		"172.16.0.0/12",  // 私有
		"192.168.0.0/16", // 私有
		"198.18.0.0/15",  // 基准测试
		"224.0.0.0/4",    // 组播
		"240.0.0.0/4",    // 保留（含 255.255.255.255）
		"::/128",         // 未指定
		"::1/128",        // IPv6 回环
		"fc00::/7",       // ULA
		"ff00::/8",       // IPv6 组播
	})
	alwaysBlockedPrefixes = mustParsePrefixes([]string{
		"169.254.0.0/16",     // IPv4 链路本地（含 169.254.169.254 云元数据）
		"fe80::/10",          // IPv6 链路本地
		"100.100.100.200/32", // 阿里云元数据
	})
	// blockedHosts 元数据主机名黑名单（大小写不敏感）。
	blockedHosts = []string{"metadata", "metadata.google.internal"}
)

var errAddressBlocked = errors.New("jwtverify: 目标地址被 SSRF 策略拒绝")

func mustParsePrefixes(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			panic(fmt.Sprintf("jwtverify: 内置网段表非法 %q: %v", c, err))
		}
		out = append(out, p)
	}
	return out
}

// ValidateDialAddress 校验单个拨号候选地址：元数据/链路本地绝对拒绝；
// 其余受限网段须被 allow CIDR 显式覆盖。IPv4-mapped IPv6 先 Unmap。
func ValidateDialAddress(addr netip.Addr, allow []netip.Prefix) error {
	addr = addr.Unmap()
	for _, p := range alwaysBlockedPrefixes {
		if p.Contains(addr) {
			return fmt.Errorf("%w: %s 为元数据/链路本地地址", errAddressBlocked, addr)
		}
	}
	for _, p := range restrictedPrefixes {
		if p.Contains(addr) {
			for _, ap := range allow {
				if ap.Contains(addr) {
					return nil
				}
			}
			return fmt.Errorf("%w: %s 属默认拒绝网段且未被允许 CIDR 覆盖", errAddressBlocked, addr)
		}
	}
	return nil
}

// ValidateRemoteHost 配置期主机校验：元数据主机名黑名单；IP 字面量立即按
// 拨号规则校验（域名留待拨号时重解析复检，防 DNS 重绑定）。
func ValidateRemoteHost(host string, allow []netip.Prefix) error {
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, bh := range blockedHosts {
		if lower == bh {
			return fmt.Errorf("%w: 元数据主机名 %q", errAddressBlocked, host)
		}
	}
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return ValidateDialAddress(addr, allow)
	}
	return nil
}

func parseAllowCIDRs(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("jwtverify: 允许 CIDR 非法 %q: %w", c, err)
		}
		out = append(out, p)
	}
	return out, nil
}
