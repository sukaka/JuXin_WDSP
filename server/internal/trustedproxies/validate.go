package trustedproxies

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// customHeaderRe 自定义代理头名仅允许字母、数字、点、下划线、连字符。
var customHeaderRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// NormalizeCIDR 将输入规范化为单 IP 或掩码化 CIDR，并派生 IP 版本。
// 支持：单 IPv4、IPv4 CIDR、单 IPv6、IPv6 CIDR。
// 规则：
//   - 拒绝域名、带协议（http://）、带端口、通配符、控制字符与带区域（%zone）的地址；
//   - IPv4 映射 IPv6 归一为 IPv4（::ffff:1.2.3.4 → 1.2.3.4）；
//   - CIDR 掩码化（192.168.1.77/24 → 192.168.1.0/24）。
func NormalizeCIDR(input string) (normalized string, ipVersion string, err error) {
	if input == "" {
		return "", "", fmt.Errorf("%w: 地址不能为空", ErrInvalidInput)
	}
	if len(input) > 64 {
		return "", "", fmt.Errorf("%w: 地址长度超过64字符", ErrInvalidInput)
	}
	for _, c := range input {
		if c < 0x20 || c == 0x7f {
			return "", "", fmt.Errorf("%w: 地址包含非法控制字符", ErrInvalidInput)
		}
	}
	if strings.Contains(input, "/") {
		prefix, perr := netip.ParsePrefix(input)
		if perr != nil {
			return "", "", fmt.Errorf("%w: 无效的CIDR: %s", ErrInvalidInput, input)
		}
		addr := prefix.Addr()
		bits := prefix.Bits()
		if addr.Zone() != "" {
			return "", "", fmt.Errorf("%w: 不允许带区域的地址", ErrInvalidInput)
		}
		if addr.Is4In6() {
			addr = addr.Unmap()
			bits -= 96
			if bits < 0 {
				return "", "", fmt.Errorf("%w: 无效的IPv4映射前缀: %s", ErrInvalidInput, input)
			}
		}
		masked := netip.PrefixFrom(addr, bits).Masked()
		return masked.String(), ipVersionOf(addr), nil
	}
	addr, aerr := netip.ParseAddr(input)
	if aerr != nil {
		return "", "", fmt.Errorf("%w: 无效的IP地址: %s", ErrInvalidInput, input)
	}
	if addr.Zone() != "" {
		return "", "", fmt.Errorf("%w: 不允许带区域的地址", ErrInvalidInput)
	}
	addr = addr.Unmap()
	return addr.String(), ipVersionOf(addr), nil
}

// MatchCIDR 判断 ip 是否被 cidr（规范单IP或CIDR）命中。
// 两侧均做 IPv4 映射归一；非法输入一律不命中。
func MatchCIDR(cidr, ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if single, err := netip.ParseAddr(cidr); err == nil {
		return single.Unmap() == addr
	}
	if prefix, err := netip.ParsePrefix(cidr); err == nil {
		pa := prefix.Addr()
		bits := prefix.Bits()
		if pa.Is4In6() {
			pa = pa.Unmap()
			bits -= 96
			if bits < 0 {
				return false
			}
		}
		return netip.PrefixFrom(pa, bits).Masked().Contains(addr)
	}
	return false
}

// isValidIPLiteral 判断输入是否为合法 IP 字面量（仅单IP，不含CIDR）。
func isValidIPLiteral(ip string) bool {
	_, err := netip.ParseAddr(strings.TrimSpace(ip))
	return err == nil
}

// ValidateInput 校验可信代理输入，并规范化 CIDR、派生 IP 版本（原地修改）。
func ValidateInput(p *TrustedProxy) error {
	if p.Name == "" || len(p.Name) > 100 {
		return fmt.Errorf("%w: 名称不能为空且不超过100字符", ErrInvalidInput)
	}
	normalized, version, err := NormalizeCIDR(p.CIDR)
	if err != nil {
		return err
	}
	p.CIDR = normalized
	p.IPVersion = version
	if err := validateHeader(p.HeaderType, p.CustomHeaderName); err != nil {
		return err
	}
	if p.Priority < 0 || p.Priority > 10000 {
		return fmt.Errorf("%w: 优先级必须在0-10000之间", ErrInvalidInput)
	}
	switch p.Scope {
	case ScopeGlobal:
		if p.NodeName != "" {
			return fmt.Errorf("%w: 全局可信代理不能指定节点", ErrInvalidInput)
		}
	case ScopeNode:
		if p.NodeName == "" || len(p.NodeName) > 100 {
			return fmt.Errorf("%w: 节点级可信代理必须指定节点名称（不超过100字符）", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: 无效的生效范围: %s", ErrInvalidInput, p.Scope)
	}
	if len(p.Description) > 500 {
		return fmt.Errorf("%w: 描述不能超过500字符", ErrInvalidInput)
	}
	return nil
}

// validateHeader 校验代理头类型与自定义头名的组合。
func validateHeader(headerType, customName string) error {
	switch headerType {
	case HeaderXForwardedFor, HeaderXRealIP, HeaderForwarded:
		if customName != "" {
			return fmt.Errorf("%w: 非自定义头类型不能填写自定义头名", ErrInvalidInput)
		}
	case HeaderCustom:
		if customName == "" {
			return fmt.Errorf("%w: 自定义头类型必须填写自定义头名", ErrInvalidInput)
		}
		if len(customName) > 64 || !customHeaderRe.MatchString(customName) {
			return fmt.Errorf("%w: 自定义头名仅允许字母、数字、点、下划线、连字符（不超过64字符）", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: 无效的代理头类型: %s", ErrInvalidInput, headerType)
	}
	return nil
}

func ipVersionOf(addr netip.Addr) string {
	if addr.Is4() {
		return IPVersion4
	}
	return IPVersion6
}
