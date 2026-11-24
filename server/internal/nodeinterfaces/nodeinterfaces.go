// Package nodeinterfaces WDSP 阶段A 网口管理（docs/NETWORK_MODES_DESIGN.md §2）：
// 采集网关 node-interfaces.jsonl 全量快照入库 gateway_node_interfaces，
// 并提供按节点分组的清单查询与用户排序/角色保存接口。
//
// 快照合并语义（reconcile，SQL 与内存仓储共用）：
//   - 快照中的已有口：保留用户设定的 sort_order/role/first_seen_at，仅刷新采集字段；
//     其中已有明确 media_type（非空且非 UNKNOWN）时，不因新快照上报 UNKNOWN/空值而降级覆盖；
//   - 新发现的口：按快照先后顺序排在该节点 sort_order 末尾；
//   - 快照中消失的口：记录保留，仅置 present=false（便于界面感知拔卡/改名）。
package nodeinterfaces

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 介质类型（与网关 media_type 输出一致）。
const (
	MediaTP      = "TP"
	MediaFibre   = "FIBRE"
	MediaUnknown = "UNKNOWN"
)

// 角色词表（大写；空串 = 未分配）。与前端保存提交体契约一致：role 恒传，整体替换。
const (
	RoleManagement = "MANAGEMENT"
	RoleTraffic    = "TRAFFIC"
	RoleMirror     = "MIRROR"
)

// ValidRole 校验角色取值（空串合法，表示未分配/清除）。
func ValidRole(s string) bool {
	switch s {
	case "", RoleManagement, RoleTraffic, RoleMirror:
		return true
	}
	return false
}

// ErrUnknownInterface 排序请求引用了节点下不存在的接口。
var ErrUnknownInterface = errors.New("unknown interface")

// Interface 是一条节点网口清单记录。
type Interface struct {
	ID          uuid.UUID `json:"id"`
	NodeName    string    `json:"node_name"`
	Ifname      string    `json:"ifname"`
	MAC         string    `json:"mac"`
	IPAddresses []string  `json:"ip_addresses"`
	PCIPath     string    `json:"pci_path"`
	Driver      string    `json:"driver"`
	MediaType   string    `json:"media_type"`
	LinkSpeed   int64     `json:"link_speed"` // Mb/s，DOWN 为 0
	Operstate   string    `json:"operstate"`
	SortOrder   int       `json:"sort_order"`
	Role        string    `json:"role"`
	Present     bool      `json:"present"` // 最近一次快照中是否存在（false = 已消失/拔卡）
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

// NodeInterfaces 是按节点分组的网口清单（GET 响应单元）。
type NodeInterfaces struct {
	NodeName   string      `json:"node_name"`
	Interfaces []Interface `json:"interfaces"`
}

// SnapshotItem 是网关 node-interfaces.jsonl 快照中的一行（字段名与网关输出一致）。
type SnapshotItem struct {
	NodeName    string    `json:"node_name"`
	Ifname      string    `json:"ifname"`
	MAC         string    `json:"mac"`
	IPAddresses []string  `json:"ip_addresses"`
	PCIPath     string    `json:"pci_path"`
	Driver      string    `json:"driver"`
	MediaType   string    `json:"media_type"`
	LinkSpeed   int64     `json:"link_speed"`
	Operstate   string    `json:"operstate"`
	CollectedAt time.Time `json:"collected_at"`
}

// OrderItem 是排序保存请求中的一项；Role 恒传（空串 = 清除角色/未分配），整体替换语义。
type OrderItem struct {
	Ifname    string `json:"ifname"`
	SortOrder int    `json:"sort_order"`
	Role      string `json:"role"`
}

// Repository 清单仓储接口（*Store 与 *MemStore 实现）。
type Repository interface {
	ListGrouped(ctx context.Context, nodeName string) ([]NodeInterfaces, error)
	ApplySnapshot(ctx context.Context, nodeName string, items []SnapshotItem, seenAt time.Time) error
	ReplaceOrder(ctx context.Context, nodeName string, items []OrderItem) error
}

// normalizeMedia 归一化介质类型，无法识别一律 UNKNOWN（不静默吞掉：采集侧另记原值日志）。
func normalizeMedia(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case MediaTP:
		return MediaTP
	case MediaFibre:
		return MediaFibre
	default:
		return MediaUnknown
	}
}

// mergeMediaType 合并介质类型：新快照给出明确介质时刷新；若新快照为 UNKNOWN/空值
// 而已有记录具备明确介质（非空且非 UNKNOWN），则保留已有值，避免混合部署下无 ethtool 的
// gateway 容器与带 ethtool 的 mirrorcap 交替覆写导致前端介质类型抖动。
func mergeMediaType(existing, incoming string) string {
	next := normalizeMedia(incoming)
	if next != MediaUnknown {
		return next
	}
	cur := strings.TrimSpace(existing)
	if cur != "" && !strings.EqualFold(cur, MediaUnknown) {
		return cur
	}
	return MediaUnknown
}

// maxIPAddresses 单接口保留的 IP 地址上限（防御性边界）。
const maxIPAddresses = 64

// cloneIPAddresses 返回非 nil 的副本（空值统一为 []string{}，避免 JSON 输出 null）。
func cloneIPAddresses(src []string) []string {
	if len(src) == 0 {
		return []string{}
	}
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}

// normalizeIPAddresses 清洗、去重并确定性排序接口 IP/CIDR 列表（IPv4 优先，其次 IPv6）。
func normalizeIPAddresses(raw []string) []string {
	if len(raw) == 0 {
		return []string{}
	}
	type parsed struct {
		isV4 bool
		addr netip.Addr
		text string
	}
	seen := make(map[string]struct{}, len(raw))
	items := make([]parsed, 0, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		var addr netip.Addr
		var text string
		if p, err := netip.ParsePrefix(s); err == nil {
			addr = p.Addr().Unmap()
			bits := p.Bits()
			if p.Addr().Is4In6() && bits >= 96 {
				bits -= 96
			}
			text = fmt.Sprintf("%s/%d", addr.String(), bits)
		} else if a, err := netip.ParseAddr(s); err == nil {
			addr = a.Unmap()
			text = addr.String()
		} else {
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
	if len(items) > maxIPAddresses {
		items = items[:maxIPAddresses]
	}
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.text
	}
	return out
}

// mergeIPAddresses 合并网口 IP 列表：
//   - 新快照显式携带 ip_addresses（非 nil，含空数组 []）：清洗后覆盖；
//   - 新快照未携带该字段或为 null（旧版上报端或瞬时探测失败）：保留已有 IP 列表。
func mergeIPAddresses(existing, incoming []string) []string {
	if incoming == nil {
		return cloneIPAddresses(existing)
	}
	return normalizeIPAddresses(incoming)
}

// reconcile 把一次全量快照合并进已有清单（纯函数，双仓储共用同一语义）。
// existing 为节点当前全部记录；返回合并后的目标行集（含 present=false 的消失口）。
func reconcile(nodeName string, existing []Interface, items []SnapshotItem, seenAt time.Time) []Interface {
	idx := make(map[string]int, len(existing))
	maxOrder := 0
	out := make([]Interface, len(existing))
	for i, e := range existing {
		e.Present = false // 默认本轮消失，命中快照再置回
		e.IPAddresses = cloneIPAddresses(e.IPAddresses)
		out[i] = e
		idx[e.Ifname] = i
		if e.SortOrder > maxOrder {
			maxOrder = e.SortOrder
		}
	}
	for _, it := range items {
		if i, ok := idx[it.Ifname]; ok {
			row := &out[i]
			row.MAC = it.MAC
			row.IPAddresses = mergeIPAddresses(row.IPAddresses, it.IPAddresses)
			row.PCIPath = it.PCIPath
			row.Driver = it.Driver
			row.MediaType = mergeMediaType(row.MediaType, it.MediaType)
			row.LinkSpeed = it.LinkSpeed
			row.Operstate = it.Operstate
			row.Present = true
			row.LastSeenAt = seenAt
			continue
		}
		// 新发现的口排末尾（sort_order 从 1 起）
		maxOrder++
		out = append(out, Interface{
			NodeName:    nodeName,
			Ifname:      it.Ifname,
			MAC:         it.MAC,
			IPAddresses: mergeIPAddresses(nil, it.IPAddresses),
			PCIPath:     it.PCIPath,
			Driver:      it.Driver,
			MediaType:   normalizeMedia(it.MediaType),
			LinkSpeed:   it.LinkSpeed,
			Operstate:   it.Operstate,
			SortOrder:   maxOrder,
			Present:     true,
			FirstSeenAt: seenAt,
			LastSeenAt:  seenAt,
		})
		// 快照内同名重复行按刷新处理（防唯一键冲突）
		idx[it.Ifname] = len(out) - 1
	}
	return out
}
