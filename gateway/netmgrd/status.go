// 执行状态（network-status.json）模型与原子写。
package netmgrd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ItemState 单项执行状态。
type ItemState string

const (
	StateOK      ItemState = "ok"
	StateError   ItemState = "error"
	StateSkipped ItemState = "skipped" // 仅 ip_forward=false 使用（不主动关闭）
)

// BridgeStatus 单桥执行状态。
type BridgeStatus struct {
	Name    string    `json:"name"`
	State   ItemState `json:"state"`
	Message string    `json:"message,omitempty"`
}

// RouteStatus 单条路由执行状态。
type RouteStatus struct {
	Dst     string    `json:"dst"`
	Via     string    `json:"via"`
	State   ItemState `json:"state"`
	Message string    `json:"message,omitempty"`
}

// DNS/NTP 落地状态取值（network-status.json dns_status/ntp_status.state）。
const (
	// StateApplied 已落地到主机。
	StateApplied = "APPLIED"
	// StateUnsupported 主机环境无可用落地路径（如无 systemctl 且 resolv.conf
	// 只读的容器环境）——属预期情形，不计入整体失败。
	StateUnsupported = "UNSUPPORTED"
	// StateFailed 存在落地路径但执行失败（计入整体失败，按周期重试自愈）。
	StateFailed = "FAILED"
)

// ServiceStatus DNS/NTP 落地状态（字段存在即回报；omitempty 保持旧消费方兼容）。
type ServiceStatus struct {
	// State 落地状态（APPLIED/UNSUPPORTED/FAILED）。
	State string `json:"state"`
	// Message 落地方式或失败原因说明。
	Message string `json:"message,omitempty"`
}

// 端口联动（Link-Pair）运行状态机取值（network-status.json link_pairs[].state）。
const (
	// LinkPairBothUp 双口正常（无故障或已恢复）。
	LinkPairBothUp = "BOTH_UP"
	// LinkPairPropagatedDown 故障口掉 carrier，配对口已被本组件联动 down。
	LinkPairPropagatedDown = "PROPAGATED_DOWN"
	// LinkPairSuppressed 联动频率超限，进入抑制态（冻结动作，待配置变更/重启复位）。
	LinkPairSuppressed = "SUPPRESSED"
)

// LinkPairStatus 单桥端口联动运行状态（由联动监控器维护，重启后可据此对齐）。
type LinkPairStatus struct {
	// Bridge 所属网桥名。
	Bridge string `json:"bridge"`
	// State 状态机取值（BOTH_UP/PROPAGATED_DOWN/SUPPRESSED）。
	State string `json:"state"`
	// DownPort 故障口（carrier 丢失的一方；BOTH_UP 时为空）。
	DownPort string `json:"down_port,omitempty"`
	// PropagatedPort 被联动 down 的配对口（BOTH_UP 时为空）。
	PropagatedPort string `json:"propagated_port,omitempty"`
	// PropagatedByLinkpair 联动标记：配对口系本组件联动 down（恢复判定的唯一依据，
	// 运维手工 down 的口不带此标记，本组件绝不动）。
	PropagatedByLinkpair bool `json:"propagated_by_linkpair"`
	// FlapCountHour 近 1 小时联动 down 动作次数（防抖/抑制判定窗口）。
	FlapCountHour int `json:"flap_count_hour"`
	// LastEventAt 最近一次状态迁移时间（UTC RFC3339；无迁移为空）。
	LastEventAt string `json:"last_event_at,omitempty"`
	// Message 最近一次动作/异常说明（如安全红线拒绝、命令失败、抑制原因）。
	Message string `json:"message,omitempty"`
}

// 透明牵引（Transparent REDIRECT + Fail-Open）运行态取值（network-status.json transparent.state）。
const (
	// TransparentStateInactive 未启用或无可用网桥/牵引端口。
	TransparentStateInactive = "INACTIVE"
	// TransparentStateActive nat/PREROUTING 牵引规则已生效且 tproxyd/Caddy 探测健康。
	TransparentStateActive = "ACTIVE"
	// TransparentStateDegraded 触发 fail-open、bridge-nf-call-iptables 不可用或依赖探活失败。
	TransparentStateDegraded = "DEGRADED"
)

// TransparentStatus 透明网桥 netfilter 牵引与 fail-open 看门狗运行状态。
type TransparentStatus struct {
	State          string   `json:"state"`
	Enabled        bool     `json:"enabled"`
	RedirectActive bool     `json:"redirect_active"`
	ListenPort     uint16   `json:"listen_port,omitempty"`
	Ports          []uint16 `json:"ports,omitempty"`
	Bridges        []string `json:"bridges,omitempty"`
	TproxydHealthy bool     `json:"tproxyd_healthy"`
	CaddyHealthy   bool     `json:"caddy_healthy"`
	BridgeNFReady  bool     `json:"bridge_nf_ready"`
	Message        string   `json:"message,omitempty"`
	UpdatedAt      string   `json:"updated_at,omitempty"`
}

// Status network-status.json 回写契约：
// {"applied_at":"...","ok":bool,"bridges":[...],"ip_forward":"ok|error|skipped",
//
//	"routes":[...],"link_pairs":[...],"dns_status":{...},"ntp_status":{...},
//	"transparent":{...},"managed_bridges":[...],"message":"..."}
type Status struct {
	// AppliedAt 本次执行完成时间（UTC RFC3339）。
	AppliedAt string `json:"applied_at"`
	// OK 全部项成功（ip_forward=skipped 不算失败）。
	OK bool `json:"ok"`
	// Bridges 各桥状态（与期望配置同序；空为非 null 空数组）。
	Bridges []BridgeStatus `json:"bridges"`
	// IPForward 转发项状态（错误详情在 Message 中说明——契约中本字段为纯字符串）。
	IPForward ItemState `json:"ip_forward"`
	// Routes 各路由状态（与期望配置同序；空为非 null 空数组）。
	Routes []RouteStatus `json:"routes"`
	// LinkPairs 启用端口联动的桥的运行状态（由联动监控器独立维护；
	// 未启用任何联动时省略——omitempty 保持旧消费方兼容）。
	LinkPairs []LinkPairStatus `json:"link_pairs,omitempty"`
	// DNS DNS 服务器落地状态（仅当配置下发 dns_servers 字段时回报）。
	DNS *ServiceStatus `json:"dns_status,omitempty"`
	// NTP NTP 服务器落地状态（仅当配置下发 ntp_servers 字段时回报）。
	NTP *ServiceStatus `json:"ntp_status,omitempty"`
	// Transparent 透明牵引规则与 fail-open 看门狗状态（可选，omitempty 保持向后兼容）。
	Transparent *TransparentStatus `json:"transparent,omitempty"`
	// ManagedBridges 由 netmgrd 创建/纳管的网桥名列表（重启后用于识别被从配置移除的托管桥）。
	ManagedBridges []string `json:"managed_bridges,omitempty"`
	// Message 汇总信息（失败原因拼接 / 只增不删提示）。
	Message string `json:"message"`
}

// StatusWriter 跨子系统共享的互斥状态写入器：串行化 Supervisor（Apply）、
// LinkPairMonitor（link_pairs）与 TransparentManager（transparent）的合并回写，
// 防止互相覆盖或并发原子替换竞态。
type StatusWriter struct {
	mu      sync.Mutex
	path    string
	getPath func() string
}

// NewStatusWriter 创建指向固定路径的状态写入器。
func NewStatusWriter(path string) *StatusWriter {
	return &StatusWriter{path: path}
}

// NewDynamicStatusWriter 创建路径可动态读取的状态写入器（供 Supervisor 兼容字段修改）。
func NewDynamicStatusWriter(getPath func() string) *StatusWriter {
	return &StatusWriter{getPath: getPath}
}

func (w *StatusWriter) targetPath() string {
	if w.getPath != nil {
		return w.getPath()
	}
	return w.path
}

// Read 在互斥锁下读取当前状态文件（不存在或解析失败返回 nil）。
func (w *StatusWriter) Read() *Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	return loadStatusFile(w.targetPath())
}

// WriteApply 写入 Apply 侧状态，同时保留已持久化的 link_pairs 与 transparent 段。
// preserveManaged=true 用于配置解析失败等场景，避免丢失托管桥清单。
func (w *StatusWriter) WriteApply(st Status, preserveManaged bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	path := w.targetPath()
	if cur := loadStatusFile(path); cur != nil {
		if st.LinkPairs == nil && len(cur.LinkPairs) > 0 {
			st.LinkPairs = cur.LinkPairs
		}
		if st.Transparent == nil && cur.Transparent != nil {
			st.Transparent = cur.Transparent
		}
		if preserveManaged && len(cur.ManagedBridges) > 0 {
			st.ManagedBridges = cur.ManagedBridges
		}
	}
	return WriteStatusAtomic(path, st)
}

// WriteLinkPairs 合并更新 link_pairs 段并原子落盘（保留 Apply 与 transparent 段）。
func (w *StatusWriter) WriteLinkPairs(pairs []LinkPairStatus) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	path := w.targetPath()
	st := loadStatusFile(path)
	if st == nil {
		st = &Status{OK: true, Bridges: []BridgeStatus{}, Routes: []RouteStatus{}, Message: ""}
	}
	if len(pairs) == 0 {
		st.LinkPairs = nil
	} else {
		st.LinkPairs = pairs
	}
	return WriteStatusAtomic(path, *st)
}

// WriteTransparent 合并更新 transparent 段并原子落盘（保留 Apply 与 link_pairs 段）。
func (w *StatusWriter) WriteTransparent(ts *TransparentStatus) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	path := w.targetPath()
	st := loadStatusFile(path)
	if st == nil {
		st = &Status{OK: true, Bridges: []BridgeStatus{}, Routes: []RouteStatus{}, Message: ""}
	}
	st.Transparent = ts
	return WriteStatusAtomic(path, *st)
}

// WriteStatusAtomic 原子写状态文件：同目录临时文件 + rename，
// 消费方任意时刻读到的都是完整 JSON（不存在半截文件）。
func WriteStatusAtomic(path string, st Status) error {
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("序列化状态: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".network-status-*.tmp")
	if err != nil {
		return fmt.Errorf("创建状态临时文件（目录 %s 需可写）: %w", dir, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("写状态临时文件: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("设置状态文件权限: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("关闭状态临时文件: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("原子替换状态文件: %w", err)
	}
	return nil
}
