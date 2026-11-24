// Package netif 宿主机物理网口清单采集（WDSP 阶段A 网口管理，docs/NETWORK_MODES_DESIGN.md §2.3）。
//
// 数据源：sysfs（/sys/class/net，容器只读挂载即可枚举）+ 尽力而为的 ethtool
// （容器内常无二进制或权限：缺省时 media_type=UNKNOWN、driver 回退 sysfs 驱动符号链接）。
// 采集绝不阻断网关主流程：单点失败一律降级为空值，非致命探测错误由调用方汇总告警。
package netif

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// 介质类型（与 server 侧 gateway_node_interfaces.media_type 约定一致）。
const (
	MediaTP      = "TP"
	MediaFibre   = "FIBRE"
	MediaUnknown = "UNKNOWN"
)

// Interface 一个物理网口的采集结果。
type Interface struct {
	IfName      string
	MAC         string
	IPAddresses []string // 当前绑定的全局单播 IPv4/IPv6（CIDR 形式，IPv4 优先）；nil=地址探测失败，空切片=无 IP
	PCIPath     string   // PCI BDF（如 0000:03:00.0）；非 PCI 设备或不可解析为空
	Driver      string   // ethtool -i 优先，sysfs device/driver 符号链接兜底
	MediaType   string   // TP / FIBRE / UNKNOWN
	LinkSpeed   int      // Mb/s；DOWN 或不可读为 0
	OperState   string   // up / down / unknown …（内核原值）
}

// Inventory 一次全量采集结果。
type Inventory struct {
	Interfaces []Interface
	// ProbeErrors 尽力而为探测（ethtool 等）的非致命错误；清单仍有效，调用方负责告警。
	ProbeErrors []error
}

// maxProbeErrors 单次采集保留的探测错误上限（防异常环境下错误无限堆积）。
const maxProbeErrors = 32

func (inv *Inventory) appendProbeErr(err error) {
	if len(inv.ProbeErrors) >= maxProbeErrors {
		return
	}
	inv.ProbeErrors = append(inv.ProbeErrors, err)
}

// Prober 介质/驱动增强探测（ethtool 实现见 ethtool.go；测试可注入假实现）。
type Prober interface {
	// DriverAndBus 返回驱动名与 PCI bus-info；失败返回 error（值无效）。
	DriverAndBus(ifname string) (driver string, busInfo string, err error)
	// Media 返回介质 TP/FIBRE；无法判定返回 error。
	Media(ifname string) (string, error)
}

// virtualNamePrefixes 虚拟口名称前缀（lo/docker*/veth*/br-* 等；名称过滤优先于 device 判定）。
var virtualNamePrefixes = []string{
	"lo", "docker", "veth", "br-", "virbr", "tun", "tap", "wg",
	"gre", "gretap", "erspan", "ip6tnl", "ip6gre", "sit", "dummy", "bond", "nlmon",
}

func isVirtualName(name string) bool {
	for _, p := range virtualNamePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// pciBDFRe PCI BDF 格式（domain:bus:slot.func，如 0000:03:00.0）；
// device 符号链接解析到 USB 等非 PCI 路径时 pci_path 置空（不作为 PCI 口上报）。
var pciBDFRe = regexp.MustCompile(`^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$`)

// maxInterfaceAddrs 单接口保留的 IP 地址上限（防御性边界）。
const maxInterfaceAddrs = 64

// interfaceAddrsLookup 按接口名返回其全局单播 IP/CIDR 列表（包级变量供单测注入，避免依赖宿主真实网卡）。
// failed 返回单接口 Addrs() 失败的错误映射（对应接口 IPAddresses 置 nil，供服务端保留既有值）；
// fatalErr 表示整体 net.Interfaces() 枚举失败。
var interfaceAddrsLookup = systemInterfaceAddrs

// Collect 枚举 sysfsDir（/sys/class/net 风格目录树）下的物理网口。
// 仅目录枚举失败返回 error；单接口字段读取失败按空值降级。
func Collect(sysfsDir string, prober Prober) (*Inventory, error) {
	entries, err := os.ReadDir(sysfsDir)
	if err != nil {
		return nil, fmt.Errorf("read sysfs net dir: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names) // 输出确定性（同清单多次快照可比对）

	inv := &Inventory{}
	addrByName, failedAddrs, addrFatalErr := interfaceAddrsLookup()
	if addrFatalErr != nil {
		inv.appendProbeErr(addrFatalErr)
	}

	for _, name := range names {
		if isVirtualName(name) {
			continue
		}
		ifDir := filepath.Join(sysfsDir, name)
		device := filepath.Join(ifDir, "device")
		if _, err := os.Lstat(device); err != nil {
			continue // 无 device 符号链接：虚拟口（lo/隧道等）
		}
		var ipAddrs []string
		if addrFatalErr == nil {
			if aerr, bad := failedAddrs[name]; bad {
				inv.appendProbeErr(aerr)
			} else if addrs, ok := addrByName[name]; ok && len(addrs) > 0 {
				ipAddrs = append([]string(nil), addrs...)
			} else {
				ipAddrs = []string{}
			}
		}
		ifi := Interface{
			IfName:      name,
			MAC:         readTrimmed(filepath.Join(ifDir, "address")),
			IPAddresses: ipAddrs,
			OperState:   readTrimmed(filepath.Join(ifDir, "operstate")),
			LinkSpeed:   readSpeed(filepath.Join(ifDir, "speed")),
			MediaType:   MediaUnknown,
			PCIPath:     resolvePCIPath(device),
			Driver:      resolveDriver(device),
		}
		if prober != nil {
			// ethtool 的 driver/bus-info 优先于 sysfs 兜底值
			if d, bus, perr := prober.DriverAndBus(name); perr != nil {
				inv.appendProbeErr(fmt.Errorf("ethtool -i %s: %w", name, perr))
			} else {
				if d != "" {
					ifi.Driver = d
				}
				if bus != "" {
					ifi.PCIPath = bus
				}
			}
			if m, perr := prober.Media(name); perr != nil {
				inv.appendProbeErr(fmt.Errorf("ethtool %s: %w", name, perr))
			} else if m == MediaTP || m == MediaFibre {
				ifi.MediaType = m
			}
		}
		inv.Interfaces = append(inv.Interfaces, ifi)
	}
	return inv, nil
}

// systemInterfaceAddrs 从当前网络命名空间枚举全部非虚拟网卡的全局单播 IPv4/IPv6 地址（CIDR 形式）。
// 排除 loopback、unspecified、multicast 与 link-local（含 fe80::/10、169.254.0.0/16）。
func systemInterfaceAddrs() (map[string][]string, map[string]error, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("list net interfaces: %w", err)
	}
	byName := make(map[string][]string, len(ifaces))
	var failed map[string]error
	for _, ifi := range ifaces {
		if isVirtualName(ifi.Name) {
			continue
		}
		addrs, aerr := ifi.Addrs()
		if aerr != nil {
			if failed == nil {
				failed = map[string]error{}
			}
			failed[ifi.Name] = fmt.Errorf("net addrs %s: %w", ifi.Name, aerr)
			continue
		}
		byName[ifi.Name] = normalizeNetAddrs(addrs)
	}
	return byName, failed, nil
}

// normalizeNetAddrs 提取、过滤并确定性排序接口地址（IPv4 优先，其次 IPv6；保留 CIDR 掩码）。
func normalizeNetAddrs(addrs []net.Addr) []string {
	type parsed struct {
		isV4 bool
		addr netip.Addr
		text string
	}
	seen := make(map[string]struct{}, len(addrs))
	items := make([]parsed, 0, len(addrs))
	for _, a := range addrs {
		if a == nil {
			continue
		}
		addr, text, ok := formatGlobalUnicastAddr(a)
		if !ok {
			continue
		}
		if _, dup := seen[text]; dup {
			continue
		}
		seen[text] = struct{}{}
		items = append(items, parsed{isV4: addr.Is4(), addr: addr, text: text})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].isV4 != items[j].isV4 {
			return items[i].isV4
		}
		if cmp := items[i].addr.Compare(items[j].addr); cmp != 0 {
			return cmp < 0
		}
		return items[i].text < items[j].text
	})
	if len(items) > maxInterfaceAddrs {
		items = items[:maxInterfaceAddrs]
	}
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.text
	}
	return out
}

// formatGlobalUnicastAddr 把单个 net.Addr 归一化为全局单播 IP 或 CIDR 字符串；
// loopback/link-local/multicast/unspecified 及非法值返回 ok=false。
func formatGlobalUnicastAddr(a net.Addr) (netip.Addr, string, bool) {
	switch v := a.(type) {
	case *net.IPNet:
		addr, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.Addr{}, "", false
		}
		addr = addr.Unmap()
		if !addr.IsGlobalUnicast() {
			return netip.Addr{}, "", false
		}
		ones, bits := v.Mask.Size()
		if bits > 0 {
			if addr.Is4() && bits == 128 && ones >= 96 {
				ones -= 96
			}
			if (addr.Is4() && ones >= 0 && ones <= 32) || (addr.Is6() && ones >= 0 && ones <= 128) {
				return addr, fmt.Sprintf("%s/%d", addr.String(), ones), true
			}
		}
		return addr, addr.String(), true
	case *net.IPAddr:
		addr, ok := netip.AddrFromSlice(v.IP)
		if !ok {
			return netip.Addr{}, "", false
		}
		addr = addr.Unmap()
		if !addr.IsGlobalUnicast() {
			return netip.Addr{}, "", false
		}
		return addr, addr.String(), true
	default:
		s := strings.TrimSpace(a.String())
		if p, err := netip.ParsePrefix(s); err == nil {
			addr := p.Addr().Unmap()
			if !addr.IsGlobalUnicast() {
				return netip.Addr{}, "", false
			}
			bits := p.Bits()
			if p.Addr().Is4In6() && bits >= 96 {
				bits -= 96
			}
			return addr, fmt.Sprintf("%s/%d", addr.String(), bits), true
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			addr = addr.Unmap()
			if !addr.IsGlobalUnicast() {
				return netip.Addr{}, "", false
			}
			return addr, addr.String(), true
		}
		return netip.Addr{}, "", false
	}
}

// resolvePCIPath 解析 device 符号链接末段为 PCI BDF；解析失败或非 PCI 拓扑返回空。
func resolvePCIPath(device string) string {
	target, err := filepath.EvalSymlinks(device)
	if err != nil {
		return ""
	}
	base := filepath.Base(target)
	if !pciBDFRe.MatchString(base) {
		return ""
	}
	return base
}

// resolveDriver 从 device/driver 符号链接末段取驱动名（ethtool 不可用时的兜底）。
func resolveDriver(device string) string {
	target, err := filepath.EvalSymlinks(filepath.Join(device, "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readSpeed 读取链路速率（Mb/s）；接口 DOWN 时内核返回 EINVAL，按 0 处理。
func readSpeed(path string) int {
	s := readTrimmed(path)
	if s == "" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return 0
	}
	return v
}
