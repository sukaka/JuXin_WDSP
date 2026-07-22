package protectedaddresses

import (
	"fmt"
	"net/netip"
)

// normalizeIP 规范化单 IP 字面量：拒绝控制字符与带区域地址，
// IPv4 映射 IPv6 归一为 IPv4（::ffff:1.2.3.4 → 1.2.3.4）。
func normalizeIP(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("%w: 地址不能为空", ErrInvalidInput)
	}
	if len(input) > 64 {
		return "", fmt.Errorf("%w: 地址长度超过64字符", ErrInvalidInput)
	}
	for _, c := range input {
		if c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("%w: 地址包含非法控制字符", ErrInvalidInput)
		}
	}
	addr, err := netip.ParseAddr(input)
	if err != nil {
		return "", fmt.Errorf("%w: 无效的IP地址: %s", ErrInvalidInput, input)
	}
	if addr.Zone() != "" {
		return "", fmt.Errorf("%w: 不允许带区域的地址", ErrInvalidInput)
	}
	return addr.Unmap().String(), nil
}

// normalizePrefix 规范化 CIDR：掩码化（192.168.1.77/24 → 192.168.1.0/24），
// IPv4 映射前缀归一为 IPv4 前缀。
func normalizePrefix(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("%w: CIDR不能为空", ErrInvalidInput)
	}
	if len(input) > 64 {
		return "", fmt.Errorf("%w: CIDR长度超过64字符", ErrInvalidInput)
	}
	for _, c := range input {
		if c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("%w: CIDR包含非法控制字符", ErrInvalidInput)
		}
	}
	prefix, err := netip.ParsePrefix(input)
	if err != nil {
		return "", fmt.Errorf("%w: 无效的CIDR: %s", ErrInvalidInput, input)
	}
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Zone() != "" {
		return "", fmt.Errorf("%w: 不允许带区域的地址", ErrInvalidInput)
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
		bits -= 96
		if bits < 0 {
			return "", fmt.Errorf("%w: 无效的IPv4映射前缀: %s", ErrInvalidInput, input)
		}
	}
	return netip.PrefixFrom(addr, bits).Masked().String(), nil
}

// ValidateInput 校验保护地址输入，并规范化地址（原地修改）。
// address 与 cidr 必须且只能填写一个。
func ValidateInput(a *ProtectedAddress) error {
	if a.Name == "" || len(a.Name) > 100 {
		return fmt.Errorf("%w: 名称不能为空且不超过100字符", ErrInvalidInput)
	}
	if (a.Address == "") == (a.CIDR == "") {
		return fmt.Errorf("%w: 地址与CIDR必须且只能填写一个", ErrInvalidInput)
	}
	if a.Address != "" {
		normalized, err := normalizeIP(a.Address)
		if err != nil {
			return err
		}
		a.Address = normalized
	}
	if a.CIDR != "" {
		normalized, err := normalizePrefix(a.CIDR)
		if err != nil {
			return err
		}
		a.CIDR = normalized
	}
	if !validAddressType(a.AddressType) {
		return fmt.Errorf("%w: 无效的地址类型: %s", ErrInvalidInput, a.AddressType)
	}
	if a.SourceType != SourceSystem && a.SourceType != SourceManual {
		return fmt.Errorf("%w: 无效的来源类型: %s", ErrInvalidInput, a.SourceType)
	}
	if len(a.Description) > 500 {
		return fmt.Errorf("%w: 描述不能超过500字符", ErrInvalidInput)
	}
	return nil
}

func validAddressType(t string) bool {
	switch t {
	case TypeGateway, TypeManagement, TypeUpstream, TypeDatabase, TypeCache,
		TypeTrustedProxy, TypeLoopback, TypeLinkLocal, TypeCustom:
		return true
	}
	return false
}
