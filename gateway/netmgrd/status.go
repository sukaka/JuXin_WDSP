// 执行状态（network-status.json）模型与原子写。
package netmgrd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// Status network-status.json 回写契约：
// {"applied_at":"...","ok":bool,"bridges":[...],"ip_forward":"ok|error|skipped",
//
//	"routes":[...],"link_pairs":[...],"message":"..."}
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
	// Message 汇总信息（失败原因拼接 / 只增不删提示）。
	Message string `json:"message"`
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
