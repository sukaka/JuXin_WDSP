// Package hagroups 主备高可用（HA Active-Standby）管理：主备组配置
// （ha_groups/ha_group_members）+ 保存时原子写共享卷 sidecars/ha-vip.json
// （havipd 读取执行，并经可选 RemoteSyncer 同步远端成员），havipd 回写同目录
// ha-vip-status.json 只读透传并与远端状态汇聚。
//
// 设计：docs/HA_ACTIVE_STANDBY_DESIGN.md §8（M2）。高危操作纪律同 netconfig：
// 严格校验、CSRF、操作审计；VRRP 认证串加密落库（encSvc），下发文件 0640（同组 1000 可读，other 无权限）。
package hagroups

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// 防御性上限。
const (
	maxVIPs            = 8
	maxUnicastPeers    = 8
	maxTrackInterfaces = 16
	maxGroupNameLen    = 64
)

var (
	groupNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	ifNameRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
	authPassRE  = regexp.MustCompile(`^[A-Za-z0-9._:@+-]{1,8}$`)
)

// Member 主备组成员（恰 2 个；priority 大者倾向 MASTER）。
type Member struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	Priority int    `json:"priority"`
}

// Group 主备组（ha_groups + members）。
type Group struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	State           string   `json:"state"` // ENABLED/DISABLED
	VRID            int      `json:"vrid"`
	Iface           string   `json:"iface"`
	VIPs            []string `json:"vips"`
	Preempt         bool     `json:"preempt"`
	AdvertIntMs     int      `json:"advert_int_ms"`
	Unicast         bool     `json:"unicast"`
	UnicastPeers    []string `json:"unicast_peers"`    // 单播 VRRP 对端地址（unicast=true 时生效）
	TrackInterfaces []string `json:"track_interfaces"` // Keepalived track_interface 关联接口列表
	// AuthPass 仅写路径使用（提交/下发）；读路径永不返回（HasAuthPass 代替）。
	AuthPass    string   `json:"-"`
	HasAuthPass bool     `json:"has_auth_pass"`
	Members     []Member `json:"members"`
	Version     int      `json:"version"`
	CreatedAt   string   `json:"created_at,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
}

// UpsertInput 创建/修改请求体（AuthPass nil = 不变更；指向空串 = 清除；其他 = 设置）。
type UpsertInput struct {
	Name            string   `json:"name"`
	State           string   `json:"state"`
	VRID            int      `json:"vrid"`
	Iface           string   `json:"iface"`
	VIPs            []string `json:"vips"`
	Preempt         bool     `json:"preempt"`
	AdvertIntMs     int      `json:"advert_int_ms"`
	Unicast         bool     `json:"unicast"`
	UnicastPeers    []string `json:"unicast_peers"`
	TrackInterfaces []string `json:"track_interfaces"`
	AuthPass        *string  `json:"auth_pass"`
	Members         []Member `json:"members"`
	Version         int      `json:"version"` // 修改时乐观锁；创建忽略
}

// ValidateInput 校验创建/修改输入（nodeKnown 判定成员节点是否已登记）。
// 返回归一化后的 Group（VIPs/TrackInterfaces/UnicastPeers 均为非 nil 切片、state 大写）。
func ValidateInput(in *UpsertInput, nodeKnown func(nodeID string) bool) (*Group, error) {
	g := &Group{
		Name:            strings.TrimSpace(in.Name),
		State:           strings.ToUpper(strings.TrimSpace(in.State)),
		VRID:            in.VRID,
		Iface:           strings.TrimSpace(in.Iface),
		VIPs:            []string{},
		Preempt:         in.Preempt,
		AdvertIntMs:     in.AdvertIntMs,
		Unicast:         in.Unicast,
		UnicastPeers:    []string{},
		TrackInterfaces: []string{},
		Members:         make([]Member, 0, len(in.Members)),
	}
	if !groupNameRE.MatchString(g.Name) {
		return nil, fmt.Errorf("组名非法（1~64 位字母数字开头，仅含 ._-）: %q", g.Name)
	}
	if g.State == "" {
		g.State = "ENABLED"
	}
	if g.State != "ENABLED" && g.State != "DISABLED" {
		return nil, fmt.Errorf("state 取值非法（ENABLED/DISABLED）: %q", g.State)
	}
	if g.VRID < 1 || g.VRID > 255 {
		return nil, fmt.Errorf("vrid 越界（1~255）: %d", g.VRID)
	}
	if !ifNameRE.MatchString(g.Iface) {
		return nil, fmt.Errorf("iface 接口名非法: %q", g.Iface)
	}
	if len(in.VIPs) == 0 {
		return nil, fmt.Errorf("vips 至少 1 个")
	}
	if len(in.VIPs) > maxVIPs {
		return nil, fmt.Errorf("vips 数量超出上限（%d）", maxVIPs)
	}
	for i, vip := range in.VIPs {
		vip = strings.TrimSpace(vip)
		ip, _, err := net.ParseCIDR(vip)
		if err != nil || ip.To4() == nil {
			return nil, fmt.Errorf("vips[%d] 非法（需 IPv4 CIDR，如 192.168.31.100/24）: %q", i, vip)
		}
		g.VIPs = append(g.VIPs, vip)
	}
	if g.AdvertIntMs == 0 {
		g.AdvertIntMs = 1000
	} else if g.AdvertIntMs < 1000 || g.AdvertIntMs > 10000 || g.AdvertIntMs%1000 != 0 {
		return nil, fmt.Errorf("advert_int_ms 非法（需 1000~10000 且为 1000 的整数倍）: %d", g.AdvertIntMs)
	}
	if in.AuthPass != nil && *in.AuthPass != "" {
		if len(*in.AuthPass) > 8 {
			return nil, fmt.Errorf("auth_pass 超长（VRRPv2 上限 8 字符）")
		}
		if !authPassRE.MatchString(*in.AuthPass) {
			return nil, fmt.Errorf("auth_pass 含非法字符（仅允许 1~8 位字母、数字及 . _ : @ + -）")
		}
	}
	if len(in.UnicastPeers) > maxUnicastPeers {
		return nil, fmt.Errorf("unicast_peers 数量超出上限（%d）", maxUnicastPeers)
	}
	for i, p := range in.UnicastPeers {
		p = strings.TrimSpace(p)
		if net.ParseIP(p) == nil {
			return nil, fmt.Errorf("unicast_peers[%d] 非法 IP: %q", i, p)
		}
		g.UnicastPeers = append(g.UnicastPeers, p)
	}
	if g.Unicast && len(g.UnicastPeers) == 0 {
		return nil, fmt.Errorf("unicast=true 时必须提供 unicast_peers（单播对端地址）")
	}
	if len(in.TrackInterfaces) > maxTrackInterfaces {
		return nil, fmt.Errorf("track_interfaces 数量超出上限（%d）", maxTrackInterfaces)
	}
	seenTrack := map[string]bool{}
	for i, tif := range in.TrackInterfaces {
		tif = strings.TrimSpace(tif)
		if !ifNameRE.MatchString(tif) {
			return nil, fmt.Errorf("track_interfaces[%d] 接口名非法: %q", i, tif)
		}
		if tif == g.Iface {
			return nil, fmt.Errorf("track_interfaces[%d] 不得与承载网卡 iface(%s) 相同", i, g.Iface)
		}
		if seenTrack[tif] {
			continue
		}
		seenTrack[tif] = true
		g.TrackInterfaces = append(g.TrackInterfaces, tif)
	}
	if len(in.Members) != 2 {
		return nil, fmt.Errorf("members 必须恰好 2 个节点，当前 %d 个", len(in.Members))
	}
	seenPrio, seenNode := map[int]bool{}, map[string]bool{}
	for i, m := range in.Members {
		if !nodeKnown(m.NodeID) {
			return nil, fmt.Errorf("members[%d] 节点未登记为网关节点: %s", i, m.NodeID)
		}
		if m.Priority < 1 || m.Priority > 254 {
			return nil, fmt.Errorf("members[%d].priority 越界（1~254）: %d", i, m.Priority)
		}
		if seenPrio[m.Priority] {
			return nil, fmt.Errorf("members 优先级重复: %d", m.Priority)
		}
		if seenNode[m.NodeID] {
			return nil, fmt.Errorf("members 节点重复: %s", m.NodeID)
		}
		seenPrio[m.Priority], seenNode[m.NodeID] = true, true
		g.Members = append(g.Members, m)
	}
	return g, nil
}
