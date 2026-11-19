// validate.go 控制台输入校验：所有参数在进入任何外部命令前必须过白名单校验。
package sysconsole

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// 接口名：字母开头，字母数字及 _. - :，最长 32（覆盖 eth0/enp3s0f0/br0/vlan 子接口 eth0.100）。
var reIfName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.\-:]{0,31}$`)

// 主机名/域名：标签级校验（ping 目标用），拒绝一切 shell 元字符。
var reHostname = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

// ValidIfName 校验网口名。
func ValidIfName(s string) bool { return reIfName.MatchString(s) }

// ValidHost 校验 ping 目标：IP（拒绝 zone 标识）或合法主机名。
func ValidHost(s string) bool {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Zone() == ""
	}
	return len(s) <= 253 && reHostname.MatchString(s)
}

// ParsePrefix 校验 CIDR（如 192.168.1.10/24 或 0.0.0.0/0）。
func ParsePrefix(s string) (netip.Prefix, error) { return netip.ParsePrefix(s) }

// ParseAddr 校验单个 IP（网关 / DNS；拒绝 zone 标识）。
func ParseAddr(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("IP 地址不允许包含 zone 标识")
	}
	return addr, nil
}

// ParseHostList 解析逗号分隔的主机列表（DNS/NTP 服务器等系统设置与下发配置共用）：
// 各项去首尾空白并丢弃空项；每项必须为 IP 或合法主机名（ValidHost 语义，拒绝
// 一切 shell 元字符）；项数不超过 maxItems。原始串为空/全空白返回 nil（不视为错误，
// 调用方按「不下发」处理）。
func ParseHostList(raw string, maxItems int) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !ValidHost(p) {
			return nil, fmt.Errorf("列表项 %q 不是合法 IP 或主机名", p)
		}
		out = append(out, p)
	}
	if len(out) > maxItems {
		return nil, fmt.Errorf("列表项数 %d 超出上限（%d）", len(out), maxItems)
	}
	return out, nil
}
