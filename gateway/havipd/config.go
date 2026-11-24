// 期望主备配置（ha-vip.json）解析与校验。
//
// 发布链路将本文件写入共享卷，容器内固定路径 DefaultConfigPath；本组件以
// 轮询（默认 15s，与 netmgrd 同一约定）感知变化。
//
// 失败语义（注释即契约）：
//   - 文件不存在 → 等待下发（STOPPED；曾生效后被删除或重启发现残留 pidfile =
//     发布方收回，停止本组件管理的 keepalived 释放 VIP——VIP 残留比停机更危险，
//     此处与 netmgrd「不拆除」纪律刻意不同，见 design §8 keepalived 停机即释放 VIP 的语义）；
//   - 解析/校验失败 → 整份配置拒绝，保留上一份生效配置（last-good），显式
//     告警并写 status，不做任何部分应用。
package havipd

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
	// DefaultConfigPath 发布链路写入共享卷的固定容器内路径（期望主备配置）。
	DefaultConfigPath = "/var/run/caddy/sidecars/ha-vip.json"
	// DefaultStatusPath 状态回写路径（与配置同目录）。
	DefaultStatusPath = "/var/run/caddy/sidecars/ha-vip-status.json"
	// DefaultPollInterval 配置文件轮询周期。
	DefaultPollInterval = 15 * time.Second
	// DefaultStateInterval VRRP 状态采集周期（VIP 漂移检测）。
	DefaultStateInterval = 1 * time.Second
	// DefaultCmdTimeout 单个外部命令超时。
	DefaultCmdTimeout = 5 * time.Second

	// ConfigEnabled / ConfigDisabled 配置启停取值（与运行态 StateDisabled 区分）。
	ConfigEnabled  = "ENABLED"
	ConfigDisabled = "DISABLED"

	maxTrackInterfaces = 16
)

// 配置名/节点名/接口名/认证串白名单（仅安全字符集，与管理面 hagroups 完全一致，杜绝配置/参数注入面）。
var (
	groupNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	nodeNameRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	ifNameRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
	authPassRE  = regexp.MustCompile(`^[A-Za-z0-9._:@+-]{1,8}$`)
)

// MemberSpec 主备组成员（恰 2 个；priority 大者倾向 MASTER）。
type MemberSpec struct {
	Node     string `json:"node"`
	Priority int    `json:"priority"`
}

// VRRPSpec VRRP 实例参数（keepalived vrrp_instance 映射）。
type VRRPSpec struct {
	// VRID 虚拟路由 ID（1-255；同一二层域内唯一）。
	VRID int `json:"vrid"`
	// VIPs 虚拟 IP 列表（IPv4 CIDR；至少 1 个）。
	VIPs []string `json:"vips"`
	// Iface VIP 承载网卡（校验：不得为桥成员口——本组件无法枚举网桥，
	// 该红线由发布端校验，本组件仅做名称合法性校验）。
	Iface string `json:"iface"`
	// Preempt 是否允许抢占（false = nopreempt：主恢复后不自动回切，默认 false）。
	Preempt bool `json:"preempt"`
	// AdvertIntMs VRRP 通告间隔毫秒（0 取默认 1000；合法区间 [1000,10000] 且为 1000 整数倍）。
	AdvertIntMs int `json:"advert_int_ms"`
	// AuthPass VRRPv2 认证串（可选；keepalived 上限 8 字符，仅允许安全字符集；敏感——禁日志）。
	AuthPass string `json:"auth_pass,omitempty"`
	// UnicastPeers 单播 VRRP 对端地址（可选；非空 = 单播模式，云上禁组播环境用）。
	UnicastPeers []string `json:"unicast_peers,omitempty"`
	// TrackInterfaces 需要由 keepalived 监控的关联接口列表（可选，如透明网桥成员口 eth2/eth3；
	// 渲染为 vrrp_instance 内的 track_interface 块，链路故障时自动触发主备让位）。
	TrackInterfaces []string `json:"track_interfaces,omitempty"`
}

// Config ha-vip.json 下发契约。
type Config struct {
	// Group 主备组名（同一主机一个组一个 VRRP 实例）。
	Group string `json:"group"`
	// State ENABLED/DISABLED（DISABLED = 停止 keepalived、释放 VIP，配置保留）。
	State string `json:"state"`
	// Members 组成员（恰 2；本组件按本机节点名选取自身优先级）。
	Members []MemberSpec `json:"members"`
	// VRRP VRRP 实例参数。
	VRRP VRRPSpec `json:"vrrp"`
	// UpdatedAt 发布方时间戳（信息性字段，不参与指纹与执行）。
	UpdatedAt string `json:"updated_at"`
}

// LoadConfig 读取并校验下发文件（未知字段容忍，前向兼容）。
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

// normalize 去空白/归一化并做合法性校验（任一违规整份拒绝）。
func (c *Config) normalize() error {
	c.Group = strings.TrimSpace(c.Group)
	if !groupNameRE.MatchString(c.Group) {
		return fmt.Errorf("group 组名非法（需 1-64 位字母数字开头，仅含 ._-）: %q", c.Group)
	}
	c.State = strings.ToUpper(strings.TrimSpace(c.State))
	if c.State != ConfigEnabled && c.State != ConfigDisabled {
		return fmt.Errorf("state 取值非法（ENABLED/DISABLED）: %q", c.State)
	}
	if len(c.Members) != 2 {
		return fmt.Errorf("members 必须恰好 2 个节点，当前 %d 个", len(c.Members))
	}
	seenPrio := map[int]bool{}
	seenNode := map[string]bool{}
	for i, m := range c.Members {
		m.Node = strings.TrimSpace(m.Node)
		if !nodeNameRE.MatchString(m.Node) {
			return fmt.Errorf("members[%d].node 节点名非法: %q", i, m.Node)
		}
		if m.Priority < 1 || m.Priority > 254 {
			return fmt.Errorf("members[%d].priority 越界（1~254）: %d", i, m.Priority)
		}
		if seenPrio[m.Priority] {
			return fmt.Errorf("members 优先级重复: %d", m.Priority)
		}
		if seenNode[m.Node] {
			return fmt.Errorf("members 节点重复: %s", m.Node)
		}
		seenPrio[m.Priority], seenNode[m.Node] = true, true
		c.Members[i] = m
	}

	v := &c.VRRP
	if v.VRID < 1 || v.VRID > 255 {
		return fmt.Errorf("vrrp.vrid 越界（1~255）: %d", v.VRID)
	}
	if len(v.VIPs) == 0 {
		return fmt.Errorf("vrrp.vips 至少 1 个")
	}
	for i, vip := range v.VIPs {
		vip = strings.TrimSpace(vip)
		ip, _, err := net.ParseCIDR(vip)
		if err != nil || ip.To4() == nil {
			return fmt.Errorf("vrrp.vips[%d] 非法（需 IPv4 CIDR）: %q", i, vip)
		}
		// 保持原始 CIDR 不归一化：VIP 是主机地址（192.168.31.100/24），
		// 归一到网络地址（192.168.31.0/24）会导致漂移判定与 keepalived 上址全错。
		v.VIPs[i] = vip
	}
	v.Iface = strings.TrimSpace(v.Iface)
	if !ifNameRE.MatchString(v.Iface) {
		return fmt.Errorf("vrrp.iface 接口名非法: %q", v.Iface)
	}
	if v.AdvertIntMs == 0 {
		v.AdvertIntMs = 1000
	} else if v.AdvertIntMs < 1000 || v.AdvertIntMs > 10000 || v.AdvertIntMs%1000 != 0 {
		return fmt.Errorf("vrrp.advert_int_ms 非法（需 1000~10000 且为 1000 的整数倍）: %d", v.AdvertIntMs)
	}
	if v.AuthPass != "" {
		if len(v.AuthPass) > 8 {
			return fmt.Errorf("vrrp.auth_pass 超长（VRRPv2 上限 8 字符）")
		}
		// 严格字符白名单，杜绝空格、控制字符及 {} # ! " ' \ 注入 keepalived 配置语法。
		if !authPassRE.MatchString(v.AuthPass) {
			return fmt.Errorf("vrrp.auth_pass 含非法字符（仅允许 1~8 位字母、数字及 . _ : @ + -）")
		}
	}
	for i, p := range v.UnicastPeers {
		p = strings.TrimSpace(p)
		if net.ParseIP(p) == nil {
			return fmt.Errorf("vrrp.unicast_peers[%d] 非法 IP: %q", i, p)
		}
		v.UnicastPeers[i] = p
	}
	if len(v.TrackInterfaces) > maxTrackInterfaces {
		return fmt.Errorf("vrrp.track_interfaces 数量超出上限（%d）", maxTrackInterfaces)
	}
	if len(v.TrackInterfaces) > 0 {
		seenTrack := map[string]bool{}
		tracks := make([]string, 0, len(v.TrackInterfaces))
		for i, tif := range v.TrackInterfaces {
			tif = strings.TrimSpace(tif)
			if !ifNameRE.MatchString(tif) {
				return fmt.Errorf("vrrp.track_interfaces[%d] 接口名非法: %q", i, tif)
			}
			if tif == v.Iface {
				return fmt.Errorf("vrrp.track_interfaces[%d] 不得与承载网卡 iface(%s) 相同", i, v.Iface)
			}
			if seenTrack[tif] {
				continue
			}
			seenTrack[tif] = true
			tracks = append(tracks, tif)
		}
		v.TrackInterfaces = tracks
	}
	return nil
}

// selfMember 取本机在组成员中的条目（第二个返回值=false 表示本机不在组内——
// 该配置不是发给本节点的，按 STOPPED 处理并显式报错）。
func (c Config) selfMember(node string) (MemberSpec, bool) {
	for _, m := range c.Members {
		if m.Node == node {
			return m, true
		}
	}
	return MemberSpec{}, false
}

// fingerprint 配置指纹：覆盖执行相关字段（group/state/members/vrrp，不含 auth_pass
// 明文本身——认证串变更也要重载，故以其长度+哈希参与指纹，同时避免敏感串进入
// 任何日志/诊断输出）。
func (c Config) fingerprint() string {
	authSum := sha256.Sum256([]byte(c.VRRP.AuthPass))
	data, _ := json.Marshal(struct {
		Group   string       `json:"group"`
		State   string       `json:"state"`
		Members []MemberSpec `json:"members"`
		VRRP    VRRPSpec     `json:"vrrp"`
		Auth    string       `json:"auth"`
	}{c.Group, c.State, c.Members, c.VRRP, hex.EncodeToString(authSum[:8])})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
