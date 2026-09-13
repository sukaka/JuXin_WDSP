// Package netdiag 网络诊断工具（ping/端口探测/路由追踪/DNS 查询/抓包）。
// 管理面不直接执行诊断命令：校验通过后写共享卷 <SidecarDir>/diag/ 下的请求文件，
// 由网关侧 netmgrd 消费执行并回写结果文件（契约见 docs/NETWORK_MODES_DESIGN.md 边车契约），
// 服务端 Worker 轮询消费结果落库、搬移抓包产物并收割超时任务。
package netdiag

import (
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

// 诊断动作
const (
	ActionPing       = "ping"
	ActionTCPProbe   = "tcp_probe"
	ActionTraceroute = "traceroute"
	ActionDNSQuery   = "dns_query"
	ActionCapture    = "capture"
)

// 任务状态
const (
	StatusPending = "PENDING"
	StatusRunning = "RUNNING"
	StatusSuccess = "SUCCESS"
	StatusFailed  = "FAILED"
	StatusStopped = "STOPPED"
	StatusTimeout = "TIMEOUT"
)

// 参数边界
const (
	defaultPingCount     = 4
	maxPingCount         = 20
	defaultMaxHops       = 30
	maxMaxHops           = 30
	defaultCaptureDurSec = 10
	minCaptureDurSec     = 5
	maxCaptureDurSec     = 300
	// maxResultTextBytes 结果文本入库上限（stdout+stderr 合并截断）。
	maxResultTextBytes = 128 * 1024
)

// 主机名：标签内仅字母数字与 -/.，总长 ≤253，不以 - 开头，拒绝一切 shell 元字符。
var reHostname = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)

// 抓包网口名：字母数字及 ._-，最长 32。
var reIface = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,32}$`)

// ValidAction 校验诊断动作枚举。
func ValidAction(a string) bool {
	switch a {
	case ActionPing, ActionTCPProbe, ActionTraceroute, ActionDNSQuery, ActionCapture:
		return true
	}
	return false
}

// ValidHost 校验诊断目标：IPv4/IPv6 字面量或合法主机名
// （不以 - 开头、拒绝一切 shell 元字符；对齐 sysconsole.ValidHost 语义）。
func ValidHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return reHostname.MatchString(s)
}

// ValidIface 校验抓包网口名。
func ValidIface(s string) bool { return reIface.MatchString(s) }

// Params 动作参数（与共享卷请求文件 params 字段一致；未使用字段为 0/空）。
type Params struct {
	Count       int    `json:"count,omitempty"`
	Port        int    `json:"port,omitempty"`
	MaxHops     int    `json:"max_hops,omitempty"`
	DurationSec int    `json:"duration_sec,omitempty"`
	Iface       string `json:"iface,omitempty"`
	FilterProto string `json:"filter_proto,omitempty"`
	FilterPort  int    `json:"filter_port,omitempty"`
	FilterHost  string `json:"filter_host,omitempty"`
}

// actionTimeout 返回动作级超时上限（收割 TIMEOUT 的 deadline）。
func actionTimeout(action string, p Params) time.Duration {
	switch action {
	case ActionPing:
		return 40 * time.Second
	case ActionTraceroute:
		return 70 * time.Second
	case ActionTCPProbe, ActionDNSQuery:
		return 15 * time.Second
	case ActionCapture:
		d := p.DurationSec
		if d <= 0 {
			d = defaultCaptureDurSec
		}
		return time.Duration(d)*time.Second + 30*time.Second
	}
	return 30 * time.Second
}

// Validate 校验动作与参数组合；返回规范化后的参数（缺省值补齐）。
func Validate(action, target string, p *Params) error {
	if !ValidAction(action) {
		return fmt.Errorf("action 必须是 ping/tcp_probe/traceroute/dns_query/capture 之一")
	}
	if !ValidHost(target) {
		return fmt.Errorf("target 必须是合法的 IP 或主机名（不含非法字符）")
	}
	switch action {
	case ActionPing:
		if p.Count == 0 {
			p.Count = defaultPingCount
		}
		if p.Count < 1 || p.Count > maxPingCount {
			return fmt.Errorf("count 必须在 1-%d 之间", maxPingCount)
		}
	case ActionTCPProbe:
		if p.Port < 1 || p.Port > 65535 {
			return fmt.Errorf("port 必须在 1-65535 之间")
		}
	case ActionTraceroute:
		if p.MaxHops == 0 {
			p.MaxHops = defaultMaxHops
		}
		if p.MaxHops < 1 || p.MaxHops > maxMaxHops {
			return fmt.Errorf("max_hops 必须在 1-%d 之间", maxMaxHops)
		}
	case ActionDNSQuery:
		// 无额外参数
	case ActionCapture:
		if p.Iface == "" {
			return fmt.Errorf("capture 必须指定 iface")
		}
		if !ValidIface(p.Iface) {
			return fmt.Errorf("iface 含非法字符（仅允许字母数字及 ._-，最长 32）")
		}
		if p.DurationSec == 0 {
			p.DurationSec = defaultCaptureDurSec
		}
		if p.DurationSec < minCaptureDurSec || p.DurationSec > maxCaptureDurSec {
			return fmt.Errorf("duration_sec 必须在 %d-%d 之间", minCaptureDurSec, maxCaptureDurSec)
		}
		if p.FilterProto != "" && p.FilterProto != "tcp" && p.FilterProto != "udp" && p.FilterProto != "icmp" {
			return fmt.Errorf("filter_proto 仅允许 tcp/udp/icmp 或留空")
		}
		if p.FilterPort < 0 || p.FilterPort > 65535 {
			return fmt.Errorf("filter_port 必须在 0-65535 之间")
		}
		if p.FilterHost != "" && !ValidHost(p.FilterHost) {
			return fmt.Errorf("filter_host 必须是合法的 IP 或主机名")
		}
	}
	return nil
}
