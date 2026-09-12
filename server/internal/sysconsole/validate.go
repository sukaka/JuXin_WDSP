// validate.go 控制台输入校验：所有参数在进入任何外部命令前必须过白名单校验。
package sysconsole

import (
	"net/netip"
	"regexp"
)

// 接口名：字母开头，字母数字及 _. - :，最长 32（覆盖 eth0/enp3s0f0/br0/vlan 子接口 eth0.100）。
var reIfName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.\-:]{0,31}$`)

// 主机名/域名：标签级校验（ping 目标用），拒绝一切 shell 元字符。
var reHostname = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

// ValidIfName 校验网口名。
func ValidIfName(s string) bool { return reIfName.MatchString(s) }

// ValidHost 校验 ping 目标：IP 或合法主机名。
func ValidHost(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return len(s) <= 253 && reHostname.MatchString(s)
}

// ParsePrefix 校验 CIDR（如 192.168.1.10/24 或 0.0.0.0/0）。
func ParsePrefix(s string) (netip.Prefix, error) { return netip.ParsePrefix(s) }

// ParseAddr 校验单个 IP（网关 / DNS）。
func ParseAddr(s string) (netip.Addr, error) { return netip.ParseAddr(s) }
