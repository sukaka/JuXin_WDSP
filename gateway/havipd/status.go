// 执行状态（ha-vip-status.json）模型与原子写。
package havipd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// VRRP 运行状态取值（ha-vip-status.json state）。
const (
	// StateMaster 本机持有 VIP（MASTER）。
	StateMaster = "MASTER"
	// StateBackup keepalived 存活但未持有 VIP（BACKUP）。
	StateBackup = "BACKUP"
	// StateFault 配置启用但 keepalived 不存活（FAULT）。
	StateFault = "FAULT"
	// StateDisabled 配置 DISABLED（实例已停，VIP 已释放）。
	StateDisabled = "DISABLED"
	// StateStopped 无有效配置（等待下发）。
	StateStopped = "STOPPED"
)

// Event 一次状态迁移（漂移/故障/启停）。
type Event struct {
	At     string `json:"at"`
	From   string `json:"from"`
	To     string `json:"to"`
	Detail string `json:"detail,omitempty"`
}

// maxEvents 事件滚动上限（超出丢弃最旧）。
const maxEvents = 100

// Status ha-vip-status.json 回写契约。
type Status struct {
	// Group 主备组名（无有效配置时为空）。
	Group string `json:"group"`
	// Node 本机节点名。
	Node string `json:"node"`
	// State VRRP 运行状态（MASTER/BACKUP/FAULT/DISABLED/STOPPED）。
	State string `json:"state"`
	// KeepalivedRunning keepalived 进程存活。
	KeepalivedRunning bool `json:"keepalived_running"`
	// VIPsPresent 本机当前持有的 VIP（空数组非 null）。
	VIPsPresent []string `json:"vips_present"`
	// Priority 本机 VRRP 优先级（无配置为 0）。
	Priority int `json:"priority"`
	// LastTransitionAt 最近一次状态迁移时间（UTC RFC3339；无迁移为空）。
	LastTransitionAt string `json:"last_transition_at,omitempty"`
	// AppliedAt 最近一次配置应用时间（UTC RFC3339；未应用为空）。
	AppliedAt string `json:"applied_at,omitempty"`
	// Message 最近一次动作/异常说明。
	Message string `json:"message"`
	// Events 漂移/状态迁移历史（新→旧滚动，上限 maxEvents）。
	Events []Event `json:"events"`
}

// WriteStatusAtomic 原子写状态文件：同目录临时文件 + rename。
// 0644：状态内容无敏感信息（认证串绝不落 status）。
func WriteStatusAtomic(path string, st Status) error {
	if st.VIPsPresent == nil {
		st.VIPsPresent = []string{}
	}
	if st.Events == nil {
		st.Events = []Event{}
	}
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("序列化状态: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return fmt.Errorf("创建状态文件目录 %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".ha-vip-status-*.tmp")
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
