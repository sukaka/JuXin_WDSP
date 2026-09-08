// Package netconfig 页面配置网桥与路由牵引（docs/NETWORK_MODES_DESIGN.md §七）：
// 管理端维护节点网络期望配置（网桥/ip_forward/路由牵引），保存时整体替换入库
// node_network_configs 并原子写共享卷 sidecars/network.json（网关节点 netmgrd
// 读取执行）；netmgrd 回写同目录 network-status.json，本包只读透传给前端。
//
// 网络配置属高危操作，校验与安全约束必须严格执行：
//   - 桥名必须匹配 br\d{1,2} 且唯一；
//   - 桥成员口 ≥2，且全部存在于该节点网口清单（gateway_node_interfaces）并 present；
//   - role=MANAGEMENT 的管理口禁止加入桥（防止锁死管理通道）；
//   - 同一接口不得出现在两个桥（同一桥内也不得重复）；
//   - 路由 dst 必须为合法 CIDR、via 必须为合法 IP，dst 不得重复；
//   - 当前仅支持配置本网关节点（sidecar 卷属于默认节点，写错节点即错配执行端）。
package netconfig

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/nodeinterfaces"
)

// 防御性上限（防大包/误操作；与网口管理 items 上限 128 同量级）。
const (
	maxBridges     = 32
	maxBridgePorts = 32
	maxRoutes      = 128
)

// bridgeNameRe 桥名词表：br0 - br99。
var bridgeNameRe = regexp.MustCompile(`^br\d{1,2}$`)

// LinkPair 端口联动（Link-Pair）配置：网桥两个成员口互为配对，任一口链路故障
// 持续 hold_down_ms 后配对口被联动 down（上游设备感知链路中断后切换路径），
// 故障口恢复持续 hold_up_ms 后配对口回 up。设计见 docs/HA_ACTIVE_STANDBY_DESIGN.md §6。
type LinkPair struct {
	Enabled         bool `json:"enabled"`
	HoldDownMs      int  `json:"hold_down_ms"`       // 0 取默认 1000；合法区间 [200,10000]
	HoldUpMs        int  `json:"hold_up_ms"`         // 0 取默认 5000；合法区间 [1000,60000]
	MaxFlapsPerHour int  `json:"max_flaps_per_hour"` // 0 取默认 20；合法区间 [1,200]
}

// 联动参数缺省值与合法区间（与 gateway/netmgrd 保持一致，勿单方面变更）。
const (
	defaultLinkPairHoldDownMs = 1000
	defaultLinkPairHoldUpMs   = 5000
	defaultLinkPairMaxFlaps   = 20

	minLinkPairHoldDownMs = 200
	maxLinkPairHoldDownMs = 10000
	minLinkPairHoldUpMs   = 1000
	maxLinkPairHoldUpMs   = 60000
	maxLinkPairFlapsCap   = 200
)

// Bridge 是一座二层桥及其成员口。
type Bridge struct {
	Name  string   `json:"name"`
	Ports []string `json:"ports"`
	// LinkPair 端口联动配置（可选；nil 或 Enabled=false = 不启用）。
	LinkPair *LinkPair `json:"link_pair,omitempty"`
}

// Route 是一条牵引路由（目的网段经下一跳转发）。
type Route struct {
	Dst string `json:"dst"`
	Via string `json:"via"`
}

// Config 是节点网络期望配置（node_network_configs.config 与 sidecars/network.json
// 的配置段契约；Bridges/Routes 恒为数组，空数组而非 null）。
type Config struct {
	Bridges   []Bridge `json:"bridges"`
	IPForward bool     `json:"ip_forward"`
	Routes    []Route  `json:"routes"`
}

// DefaultConfig 返回空期望配置（节点无记录时的展示态）。
func DefaultConfig() Config {
	return Config{Bridges: []Bridge{}, Routes: []Route{}}
}

// normalize 归一化：nil 切片置空数组（契约恒为数组），各字段去首尾空白。
func (c *Config) normalize() {
	if c.Bridges == nil {
		c.Bridges = []Bridge{}
	}
	if c.Routes == nil {
		c.Routes = []Route{}
	}
	for i := range c.Bridges {
		b := &c.Bridges[i]
		b.Name = strings.TrimSpace(b.Name)
		if b.Ports == nil {
			b.Ports = []string{}
		}
		for j := range b.Ports {
			b.Ports[j] = strings.TrimSpace(b.Ports[j])
		}
	}
	for i := range c.Routes {
		c.Routes[i].Dst = strings.TrimSpace(c.Routes[i].Dst)
		c.Routes[i].Via = strings.TrimSpace(c.Routes[i].Via)
	}
}

// Validate 校验期望配置（先归一化；ifaces 为该节点网口清单，作为成员口
// 存在性/present/角色的校验数据源）。所有非法输入返回具体中文错误。
func Validate(cfg *Config, ifaces []nodeinterfaces.Interface) error {
	cfg.normalize()

	known := make(map[string]nodeinterfaces.Interface, len(ifaces))
	for _, it := range ifaces {
		known[it.Ifname] = it
	}

	if len(cfg.Bridges) > maxBridges {
		return fmt.Errorf("bridges 数量超出上限（%d）", maxBridges)
	}
	seenBridge := make(map[string]bool, len(cfg.Bridges))
	usedPort := make(map[string]string) // ifname -> 所属桥名（跨桥唯一）
	for i := range cfg.Bridges {
		b := &cfg.Bridges[i]
		if !bridgeNameRe.MatchString(b.Name) {
			return fmt.Errorf("桥名非法（允许 br0-br99）: %q", b.Name)
		}
		if seenBridge[b.Name] {
			return fmt.Errorf("桥名重复: %s", b.Name)
		}
		seenBridge[b.Name] = true
		if len(b.Ports) < 2 {
			return fmt.Errorf("桥 %s 成员口至少需要 2 个", b.Name)
		}
		if len(b.Ports) > maxBridgePorts {
			return fmt.Errorf("桥 %s 成员口数量超出上限（%d）", b.Name, maxBridgePorts)
		}
		if err := validateLinkPair(b); err != nil {
			return err
		}
		for _, p := range b.Ports {
			if p == "" {
				return fmt.Errorf("桥 %s 存在空成员口名", b.Name)
			}
			it, ok := known[p]
			if !ok {
				return fmt.Errorf("接口不存在于该节点: %s", p)
			}
			if !it.Present {
				return fmt.Errorf("接口 %s 已从最新快照中消失（present=false），不得入桥", p)
			}
			if it.Role == nodeinterfaces.RoleManagement {
				return fmt.Errorf("接口 %s 为管理口（role=MANAGEMENT），禁止加入桥", p)
			}
			if prev, dup := usedPort[p]; dup {
				if prev == b.Name {
					return fmt.Errorf("桥 %s 成员口重复: %s", b.Name, p)
				}
				return fmt.Errorf("接口 %s 不得同时出现在桥 %s 与桥 %s", p, prev, b.Name)
			}
			usedPort[p] = b.Name
		}
	}

	if len(cfg.Routes) > maxRoutes {
		return fmt.Errorf("routes 数量超出上限（%d）", maxRoutes)
	}
	seenDst := make(map[string]bool, len(cfg.Routes))
	for _, rt := range cfg.Routes {
		if _, _, err := net.ParseCIDR(rt.Dst); err != nil {
			return fmt.Errorf("路由 dst 不是合法 CIDR: %q", rt.Dst)
		}
		if ip := net.ParseIP(rt.Via); ip == nil {
			return fmt.Errorf("路由 via 不是合法 IP: %q", rt.Via)
		}
		if seenDst[rt.Dst] {
			return fmt.Errorf("路由 dst 重复: %s", rt.Dst)
		}
		seenDst[rt.Dst] = true
	}
	return nil
}

// validateLinkPair 校验并归一化端口联动配置：Enabled=true 要求成员口恰好 2 个
// （联动语义成对）；0 值参数落缺省，越界拒绝。Enabled=false/nil 不校验（等价未配置）。
func validateLinkPair(b *Bridge) error {
	lp := b.LinkPair
	if lp == nil || !lp.Enabled {
		return nil
	}
	if len(b.Ports) != 2 {
		return fmt.Errorf("桥 %s 启用端口联动（link_pair）要求成员口恰好 2 个，当前 %d 个", b.Name, len(b.Ports))
	}
	if lp.HoldDownMs == 0 {
		lp.HoldDownMs = defaultLinkPairHoldDownMs
	} else if lp.HoldDownMs < minLinkPairHoldDownMs || lp.HoldDownMs > maxLinkPairHoldDownMs {
		return fmt.Errorf("桥 %s link_pair.hold_down_ms 越界（%d~%d）: %d", b.Name, minLinkPairHoldDownMs, maxLinkPairHoldDownMs, lp.HoldDownMs)
	}
	if lp.HoldUpMs == 0 {
		lp.HoldUpMs = defaultLinkPairHoldUpMs
	} else if lp.HoldUpMs < minLinkPairHoldUpMs || lp.HoldUpMs > maxLinkPairHoldUpMs {
		return fmt.Errorf("桥 %s link_pair.hold_up_ms 越界（%d~%d）: %d", b.Name, minLinkPairHoldUpMs, maxLinkPairHoldUpMs, lp.HoldUpMs)
	}
	if lp.MaxFlapsPerHour == 0 {
		lp.MaxFlapsPerHour = defaultLinkPairMaxFlaps
	} else if lp.MaxFlapsPerHour < 1 || lp.MaxFlapsPerHour > maxLinkPairFlapsCap {
		return fmt.Errorf("桥 %s link_pair.max_flaps_per_hour 越界（1~%d）: %d", b.Name, maxLinkPairFlapsCap, lp.MaxFlapsPerHour)
	}
	return nil
}

// InterfaceLister 提供节点网口清单（nodeinterfaces.Store/MemStore 实现），
// 作为 PUT 校验的数据源。
type InterfaceLister interface {
	ListGrouped(ctx context.Context, nodeName string) ([]nodeinterfaces.NodeInterfaces, error)
}

// Repository 期望配置仓储接口（*Store 与 *MemStore 实现）。
type Repository interface {
	// Get 读取节点期望配置；无记录时 found=false（不视为错误）。
	Get(ctx context.Context, nodeName string) (cfg Config, updatedAt time.Time, found bool, err error)
	// Save 整体替换节点期望配置（UPSERT）。
	Save(ctx context.Context, nodeName string, cfg Config) error
}
