// sidecar.go 主备配置边车通道（docs/HA_ACTIVE_STANDBY_DESIGN.md §8）：
// server 把期望主备配置原子写共享卷 sidecars/ha-vip.json（api 容器该目录可写，
// 网关节点 havipd 读取执行）；havipd 回写同目录 ha-vip-status.json，
// server 只读透传给前端。与 network.json 边车同一共享卷、同一原子写纪律。
package hagroups

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// DefaultSidecarDir 边车配置目录（与 netconfig.DefaultSidecarDir 同一目录）。
const DefaultSidecarDir = "/var/run/caddy/sidecars"

const (
	haVipFileName       = "ha-vip.json"
	haVipStatusFileName = "ha-vip-status.json"
)

// memberFile ha-vip.json 成员条目（havipd 契约：node + priority）。
type memberFile struct {
	Node     string `json:"node"`
	Priority int    `json:"priority"`
}

// haVipFile ha-vip.json 内容契约（havipd 消费；auth_pass 明文仅落该文件——
// 共享卷 0600 权限由部署保证，与 keepalived 配置同敏感度）。
type haVipFile struct {
	Group     string       `json:"group"`
	State     string       `json:"state"`
	Members   []memberFile `json:"members"`
	VRRP      vrrpFile     `json:"vrrp"`
	UpdatedAt string       `json:"updated_at"`
}

type vrrpFile struct {
	VRID         int      `json:"vrid"`
	VIPs         []string `json:"vips"`
	Iface        string   `json:"iface"`
	Preempt      bool     `json:"preempt"`
	AdvertIntMs  int      `json:"advert_int_ms"`
	AuthPass     string   `json:"auth_pass,omitempty"`
	UnicastPeers []string `json:"unicast_peers,omitempty"`
}

// buildHaVipFile 由组配置构造下发文件内容。
// authPass 为解密后的认证串（空串 = 未配置）；unicastPeers 单播对端地址列表
// （unicast=false 时忽略）。
func buildHaVipFile(g *Group, authPass string, unicastPeers []string, now time.Time) haVipFile {
	members := make([]memberFile, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, memberFile{Node: m.NodeName, Priority: m.Priority})
	}
	return haVipFile{
		Group:   g.Name,
		State:   g.State,
		Members: members,
		VRRP: vrrpFile{
			VRID:         g.VRID,
			VIPs:         g.VIPs,
			Iface:        g.Iface,
			Preempt:      g.Preempt,
			AdvertIntMs:  g.AdvertIntMs,
			AuthPass:     authPass,
			UnicastPeers: unicastPeers,
		},
		UpdatedAt: now.UTC().Format(time.RFC3339),
	}
}

// writeHaVipJSON 原子写 ha-vip.json（0600：含 VRRP 认证串明文；目录保持 0770 供同组边车使用）。
func writeHaVipJSON(dir string, f haVipFile) error {
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return fmt.Errorf("创建边车配置目录失败: %w", err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		return fmt.Errorf("设置边车配置目录权限失败: %w", err)
	}
	buf, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("序列化边车配置失败: %w", err)
	}
	buf = append(buf, '\n')
	path := filepath.Join(dir, haVipFileName)
	tmp, err := os.CreateTemp(dir, "."+haVipFileName+".*")
	if err != nil {
		return fmt.Errorf("创建边车配置临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("写入边车配置临时文件失败: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("设置边车配置权限失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("关闭边车配置临时文件失败: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("原子替换边车配置失败: %w", err)
	}
	return nil
}

// deleteHaVipJSON 删除 ha-vip.json（删除组 = 收回主备能力，havipd 停止实例释放 VIP）。
func deleteHaVipJSON(dir string) error {
	err := os.Remove(filepath.Join(dir, haVipFileName))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除边车配置失败: %w", err)
	}
	return nil
}

// readHaVipStatus 只读透传 havipd 状态（文件不存在/解析失败返回 nil）。
func readHaVipStatus(dir string) json.RawMessage {
	data, err := os.ReadFile(filepath.Join(dir, haVipStatusFileName))
	if err != nil {
		return nil
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		slog.Warn("ha-vip-status.json 解析失败（按无状态透传）", "error", err)
		return nil
	}
	return json.RawMessage(data)
}

// haVipRuntime ha-vip-status.json 中回切判定所需字段的镜像（havipd 回写契约；
// 仅本节点卷——双节点状态汇聚待采集通道，见设计 §15 M2 边界）。
type haVipRuntime struct {
	Node              string   `json:"node"`
	State             string   `json:"state"`
	KeepalivedRunning bool     `json:"keepalived_running"`
	VIPsPresent       []string `json:"vips_present"`
}

// vipStatusFreshCutoff 状态新鲜度上限：havipd 每秒刷新状态，超过该时长未刷新
// = havipd 疑似停止，状态不可信（与 hastatus 清扫器同一口径）。
const vipStatusFreshCutoff = 30 * time.Second

// readHaVipRuntime 读取本节点 havipd 运行状态（回切持有方判定用）；
// 文件缺失/过期/解析失败返回 nil = 持有方未知（解析失败记 Warn，不静默吞掉）。
func readHaVipRuntime(dir string, now time.Time) *haVipRuntime {
	path := filepath.Join(dir, haVipStatusFileName)
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if now.Sub(fi.ModTime()) > vipStatusFreshCutoff {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var st haVipRuntime
	if err := json.Unmarshal(data, &st); err != nil {
		slog.Warn("ha-vip-status.json 解析失败（回切按持有方未知处理）", "error", err)
		return nil
	}
	return &st
}
