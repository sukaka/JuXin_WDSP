// Package netif 宿主机物理网口清单采集（WDSP 阶段A 网口管理，docs/NETWORK_MODES_DESIGN.md §2.3）。
//
// 数据源：sysfs（/sys/class/net，容器只读挂载即可枚举）+ 尽力而为的 ethtool
// （容器内常无二进制或权限：缺省时 media_type=UNKNOWN、driver 回退 sysfs 驱动符号链接）。
// 采集绝不阻断网关主流程：单点失败一律降级为空值，非致命探测错误由调用方汇总告警。
package netif

import (
	"fmt"
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
	IfName    string
	MAC       string
	PCIPath   string // PCI BDF（如 0000:03:00.0）；非 PCI 设备或不可解析为空
	Driver    string // ethtool -i 优先，sysfs device/driver 符号链接兜底
	MediaType string // TP / FIBRE / UNKNOWN
	LinkSpeed int    // Mb/s；DOWN 或不可读为 0
	OperState string // up / down / unknown …（内核原值）
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
	for _, name := range names {
		if isVirtualName(name) {
			continue
		}
		ifDir := filepath.Join(sysfsDir, name)
		device := filepath.Join(ifDir, "device")
		if _, err := os.Lstat(device); err != nil {
			continue // 无 device 符号链接：虚拟口（lo/隧道等）
		}
		ifi := Interface{
			IfName:    name,
			MAC:       readTrimmed(filepath.Join(ifDir, "address")),
			OperState: readTrimmed(filepath.Join(ifDir, "operstate")),
			LinkSpeed: readSpeed(filepath.Join(ifDir, "speed")),
			MediaType: MediaUnknown,
			PCIPath:   resolvePCIPath(device),
			Driver:    resolveDriver(device),
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
