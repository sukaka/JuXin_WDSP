// Package netif Linux 网卡发现（TASK-003）。
//
// 采集 name/mac/ipv4/ipv6/mtu，排除 loopback 与未 UP 的接口；
// speed_mbps 尽力从 /sys/class/net/<name>/speed 读取（不可读时为 0）。
package netif

import (
	"net"
	"os"
	"strconv"
	"strings"
)

// Interface 网卡信息（契约 §3.1 interfaces 数组元素）。
type Interface struct {
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	IPv4      string `json:"ipv4"`
	IPv6      string `json:"ipv6"`
	MTU       int    `json:"mtu"`
	SpeedMbps int    `json:"speed_mbps"`
}

// Discover 枚举本机非 loopback 且 UP 的网卡。
func Discover() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		entry := Interface{
			Name:      ifi.Name,
			MTU:       ifi.MTU,
			SpeedMbps: readSpeed(ifi.Name),
		}
		if ifi.HardwareAddr != nil {
			entry.MAC = ifi.HardwareAddr.String()
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue // 单接口地址读取失败不致命
		}
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				if entry.IPv4 == "" {
					entry.IPv4 = ip4.String()
				}
			} else if ip.IsGlobalUnicast() && entry.IPv6 == "" {
				entry.IPv6 = ip.String()
			}
		}
		out = append(out, entry)
	}
	return out, nil
}

// readSpeed /sys/class/net/<name>/speed（Mb/s）；虚拟接口/无权限时返回 0。
func readSpeed(name string) int {
	data, err := os.ReadFile("/sys/class/net/" + name + "/speed")
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || n < 0 {
		return 0
	}
	return n
}
