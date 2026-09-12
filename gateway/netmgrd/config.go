// 期望网络配置（network.json）解析与校验。
//
// 发布链路将本文件写入共享卷，容器内固定路径 DefaultConfigPath；本组件以
// 轮询（默认 15s，避免 fsnotify 依赖，与 tproxyd 同一约定）感知变化。
//
// 失败语义（注释即契约）：
//   - 文件不存在 → 等待下发（曾生效后被删除 = 发布方收回；不拆除已下发网络
//     状态，拆除属高危变更，由运维显式处理）；
//   - 解析/校验失败 → 整份配置拒绝，保留上一份生效配置（last-good），显式
//     告警并写 status，不做任何部分应用。
package netmgrd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	// DefaultConfigPath 发布链路写入共享卷的固定容器内路径（期望网络配置）。
	DefaultConfigPath = "/var/run/caddy/sidecars/network.json"
	// DefaultStatusPath 执行状态回写路径（与配置同目录）。
	DefaultStatusPath = "/var/run/caddy/sidecars/network-status.json"
	// DefaultPollInterval 配置文件轮询周期。
	DefaultPollInterval = 15 * time.Second
	// DefaultCmdTimeout 单个 ip/sysctl 动作超时。
	DefaultCmdTimeout = 5 * time.Second
)

// ifNameRE 接口/网桥名白名单（内核 IFNAMSIZ 上限 15 字符；仅安全字符集，
// 杜绝路径/参数注入面——本组件虽以参数数组 exec 不经 shell，高危操作仍从严）。
var ifNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)

// RouteSpec 静态路由期望（仅 IPv4，见 doc.go 已知边界）。
type RouteSpec struct {
	// Dst 目的网段（CIDR；加载时归一化为掩码后的网络地址）。
	Dst string `json:"dst"`
	// Via 下一跳 IPv4 地址。
	Via string `json:"via"`
}

// LinkPairSpec 端口联动（Link-Pair）期望：网桥两个成员口互为配对——任一口
// 链路故障（掉 carrier）持续 hold_down_ms 后，配对口被联动 set down（上游设备
// 感知整条链路中断后切换路径）；故障口恢复持续 hold_up_ms 后配对口回 up。
// 设计见 docs/HA_ACTIVE_STANDBY_DESIGN.md §6。
type LinkPairSpec struct {
	// Enabled 是否启用联动（false/未配置 = 不启用，行为与既有完全一致）。
	Enabled bool `json:"enabled"`
	// HoldDownMs carrier 持续丢失认定故障的时长（毫秒；0 取默认
	// DefaultLinkPairHoldDownMs，合法区间 [200, 10000]）。
	HoldDownMs int `json:"hold_down_ms"`
	// HoldUpMs carrier 持续恢复认定故障消除的时长（毫秒；0 取默认
	// DefaultLinkPairHoldUpMs，合法区间 [1000, 60000]）。
	HoldUpMs int `json:"hold_up_ms"`
	// MaxFlapsPerHour 单桥每小时联动 down 次数上限（0 取默认
	// DefaultLinkPairMaxFlaps，合法区间 [1, 200]；超限进入 SUPPRESSED 抑制态）。
	MaxFlapsPerHour int `json:"max_flaps_per_hour"`
}

// 联动参数缺省值与合法区间（0 值取默认；超出区间整份配置拒绝）。
const (
	DefaultLinkPairHoldDownMs = 1000
	DefaultLinkPairHoldUpMs   = 5000
	DefaultLinkPairMaxFlaps   = 20

	minLinkPairHoldDownMs = 200
	maxLinkPairHoldDownMs = 10000
	minLinkPairHoldUpMs   = 1000
	maxLinkPairHoldUpMs   = 60000
	maxLinkPairFlapsCap   = 200
)

// BridgeSpec 网桥期望。
type BridgeSpec struct {
	// Name 网桥名（如 br0）。
	Name string `json:"name"`
	// Ports 成员口集合（物理口/虚拟口；带 IP 的口在 apply 期安全拒绝）。
	Ports []string `json:"ports"`
	// LinkPair 端口联动期望（可选；nil 或 Enabled=false = 不启用）。
	LinkPair *LinkPairSpec `json:"link_pair,omitempty"`
}

// Config network.json 下发契约：
// {"bridges":[{"name":"br0","ports":["eth2","eth3"]}],"ip_forward":true,
//
//	"routes":[{"dst":"10.9.0.0/24","via":"192.168.50.1"}],"updated_at":"..."}
type Config struct {
	// Bridges 期望网桥集合（顺序保留，status 按同序输出）。
	Bridges []BridgeSpec `json:"bridges"`
	// IPForward 期望开启内核 IPv4 转发；false 表示「不触碰」（skipped，
	// 不主动关闭——同一主机可能有容器网络/NAT 等其他组件依赖转发）。
	IPForward bool `json:"ip_forward"`
	// Routes 期望静态路由集合（只增不删，最小实现）。
	Routes []RouteSpec `json:"routes"`
	// UpdatedAt 发布方时间戳（信息性字段，不参与指纹与执行）。
	UpdatedAt string `json:"updated_at"`
}

// LoadConfig 读取并校验下发文件。文件不存在返回可用 errors.Is(err, os.ErrNotExist)
// 判别的错误；解析/校验失败返回明确错误（调用方保留上一份有效配置，不静默降级）。
// 未知字段容忍（前向兼容：发布端先行新增字段时旧进程仍可解析）。
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("解析 %s: %w", path, err)
	}
	if err := cfg.normalize(); err != nil {
		return Config{}, fmt.Errorf("校验 %s: %w", path, err)
	}
	return cfg, nil
}

// normalize 去空白/去重/归一化并做合法性校验（任一违规整份拒绝）。
func (c *Config) normalize() error {
	owner := map[string]string{} // port → bridge：同一口不得出现在两个桥
	for bi := range c.Bridges {
		b := &c.Bridges[bi]
		b.Name = strings.TrimSpace(b.Name)
		if !ifNameRE.MatchString(b.Name) {
			return fmt.Errorf("bridges[%d] 网桥名非法（需 1-15 位字母数字开头，仅含 ._-）: %q", bi, b.Name)
		}
		seen := map[string]struct{}{}
		ports := make([]string, 0, len(b.Ports))
		for pi, p := range b.Ports {
			p = strings.TrimSpace(p)
			if !ifNameRE.MatchString(p) {
				return fmt.Errorf("bridges[%d].ports[%d] 接口名非法: %q", bi, pi, p)
			}
			if p == b.Name {
				return fmt.Errorf("bridges[%d] 网桥 %q 不能把自身列为成员口", bi, b.Name)
			}
			if _, dup := seen[p]; dup {
				continue // 幂等去重（保序）
			}
			seen[p] = struct{}{}
			if prev, taken := owner[p]; taken && prev != b.Name {
				return fmt.Errorf("接口 %q 同时出现在网桥 %q 与 %q 的成员中", p, prev, b.Name)
			}
			owner[p] = b.Name
			ports = append(ports, p)
		}
		b.Ports = ports
		if err := normalizeLinkPair(bi, b); err != nil {
			return err
		}
	}
	for ri := range c.Routes {
		r := &c.Routes[ri]
		r.Dst = strings.TrimSpace(r.Dst)
		r.Via = strings.TrimSpace(r.Via)
		_, ipnet, err := net.ParseCIDR(r.Dst)
		if err != nil || ipnet.IP.To4() == nil {
			return fmt.Errorf("routes[%d].dst 非法（需 IPv4 CIDR，仅支持 IPv4）: %q", ri, r.Dst)
		}
		r.Dst = ipnet.String() // 归一化为掩码后网络地址（如 10.9.0.1/24 → 10.9.0.0/24）
		via := net.ParseIP(r.Via)
		if via == nil || via.To4() == nil {
			return fmt.Errorf("routes[%d].via 非法（需 IPv4 地址）: %q", ri, r.Via)
		}
	}
	return nil
}

// normalizeLinkPair 校验并归一化端口联动配置：Enabled=false 等价未配置；
// Enabled=true 要求成员口恰好 2 个（联动语义成对）；0 值参数落缺省，越界整份拒绝。
func normalizeLinkPair(bi int, b *BridgeSpec) error {
	lp := b.LinkPair
	if lp == nil || !lp.Enabled {
		return nil
	}
	if len(b.Ports) != 2 {
		return fmt.Errorf("bridges[%d] 启用端口联动（link_pair）要求成员口恰好 2 个，当前 %d 个", bi, len(b.Ports))
	}
	if lp.HoldDownMs == 0 {
		lp.HoldDownMs = DefaultLinkPairHoldDownMs
	} else if lp.HoldDownMs < minLinkPairHoldDownMs || lp.HoldDownMs > maxLinkPairHoldDownMs {
		return fmt.Errorf("bridges[%d].link_pair.hold_down_ms 越界（%d~%d）: %d", bi, minLinkPairHoldDownMs, maxLinkPairHoldDownMs, lp.HoldDownMs)
	}
	if lp.HoldUpMs == 0 {
		lp.HoldUpMs = DefaultLinkPairHoldUpMs
	} else if lp.HoldUpMs < minLinkPairHoldUpMs || lp.HoldUpMs > maxLinkPairHoldUpMs {
		return fmt.Errorf("bridges[%d].link_pair.hold_up_ms 越界（%d~%d）: %d", bi, minLinkPairHoldUpMs, maxLinkPairHoldUpMs, lp.HoldUpMs)
	}
	if lp.MaxFlapsPerHour == 0 {
		lp.MaxFlapsPerHour = DefaultLinkPairMaxFlaps
	} else if lp.MaxFlapsPerHour < 1 || lp.MaxFlapsPerHour > maxLinkPairFlapsCap {
		return fmt.Errorf("bridges[%d].link_pair.max_flaps_per_hour 越界（1~%d）: %d", bi, maxLinkPairFlapsCap, lp.MaxFlapsPerHour)
	}
	return nil
}

// fingerprint 配置指纹：仅覆盖执行相关字段（bridges/ip_forward/routes），
// updated_at 等信息性字段不参与——同一期望重复发布不触发重复执行。
func (c Config) fingerprint() string {
	data, _ := json.Marshal(struct {
		Bridges   []BridgeSpec `json:"bridges"`
		IPForward bool         `json:"ip_forward"`
		Routes    []RouteSpec  `json:"routes"`
	}{c.Bridges, c.IPForward, c.Routes})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
