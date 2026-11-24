// sidecar.go 网络配置边车通道（docs/NETWORK_MODES_DESIGN.md §七）：
// server 把期望配置原子写共享卷 sidecars/network.json（api 容器该目录可写，
// 网关节点 netmgrd 读取执行）；netmgrd 回写同目录 network-status.json，
// server 只读透传给前端。与 mirrorcap/tproxyd 边车同一共享卷、同一原子写纪律。
package netconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// DefaultSidecarDir 边车配置目录（api 容器内路径，该卷与网关容器共享；
// 与 gatewayconfig.DefaultSidecarDir 同一目录，保持一致）。
const DefaultSidecarDir = "/var/run/caddy/sidecars"

const (
	networkFileName       = "network.json"
	networkStatusFileName = "network-status.json"
)

// TransparentStatus 是 network-status.json 中可选的透明牵引状态 DTO（netmgrd 回写）。
type TransparentStatus struct {
	State          string   `json:"state"`
	Enabled        bool     `json:"enabled"`
	RedirectActive bool     `json:"redirect_active"`
	ListenPort     int      `json:"listen_port"`
	Ports          []int    `json:"ports,omitempty"`
	Bridges        []string `json:"bridges,omitempty"`
	TproxydHealthy bool     `json:"tproxyd_healthy"`
	CaddyHealthy   bool     `json:"caddy_healthy"`
	BridgeNFReady  bool     `json:"bridge_nf_ready"`
	Message        string   `json:"message,omitempty"`
	UpdatedAt      string   `json:"updated_at,omitempty"`
}

// NetworkStatus 是 sidecars/network-status.json 的结构化视图（含可选透明牵引状态）。
type NetworkStatus struct {
	OK          bool               `json:"ok"`
	Node        string             `json:"node,omitempty"`
	Message     string             `json:"message,omitempty"`
	AppliedAt   string             `json:"applied_at,omitempty"`
	Transparent *TransparentStatus `json:"transparent,omitempty"`
}

// ParseNetworkStatus 将 network-status.json 原始字节解析为强类型 NetworkStatus DTO。
func ParseNetworkStatus(raw json.RawMessage) (*NetworkStatus, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var st NetworkStatus
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// networkFile 是 sidecars/network.json 内容契约（netmgrd 消费；
// Bridges/Routes 恒为数组，空数组而非 null；DNSServers/NTPServers 可选，
// 空设置缺省不出现 = netmgrd 继承宿主机现状）。
type networkFile struct {
	Bridges    []Bridge `json:"bridges"`
	IPForward  bool     `json:"ip_forward"`
	Routes     []Route  `json:"routes"`
	DNSServers []string `json:"dns_servers,omitempty"`
	NTPServers []string `json:"ntp_servers,omitempty"`
	UpdatedAt  string   `json:"updated_at"`
}

// marshalNetworkJSON 按 network.json 边车契约序列化配置（本机落盘与远端 hasyncd 推送共用）。
func marshalNetworkJSON(cfg Config, updatedAt time.Time) ([]byte, error) {
	cfg.normalize()
	payload := networkFile{
		Bridges:    cfg.Bridges,
		IPForward:  cfg.IPForward,
		Routes:     cfg.Routes,
		DNSServers: cfg.DNSServers,
		NTPServers: cfg.NTPServers,
		UpdatedAt:  updatedAt.UTC().Format(time.RFC3339),
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化边车配置失败: %w", err)
	}
	return append(buf, '\n'), nil
}

// writeNetworkJSON 原子写 network.json（同目录临时文件 + rename；目录不存在则创建）。
// 文件 0644 / 目录 0770（显式 Chmod 避免 umask 剥离组写位）：供加入共享组 1000（无 CAP_DAC_OVERRIDE）
// 的 netmgrd 读取 network.json 并原子回写 network-status.json，同时不开放 other 权限。
func writeNetworkJSON(dir string, cfg Config, updatedAt time.Time) error {
	buf, err := marshalNetworkJSON(cfg, updatedAt)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return fmt.Errorf("创建边车配置目录失败: %w", err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		return fmt.Errorf("设置边车配置目录权限失败: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+networkFileName+".*")
	if err != nil {
		return fmt.Errorf("创建边车配置临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("写入边车配置临时文件失败: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("设置边车配置权限失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("关闭边车配置临时文件失败: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, networkFileName)); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("替换边车配置失败: %w", err)
	}
	return nil
}

// readNetworkStatus 读取 network-status.json 原样透传前端。
// 文件不存在（netmgrd 尚未回写，正常态）返回 nil；读取/解析失败返回 nil 并记
// Warn（不静默吞掉），均不视为接口错误（status 契约允许 null）。
func readNetworkStatus(dir string) json.RawMessage {
	raw, err := os.ReadFile(filepath.Join(dir, networkStatusFileName))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("read network status failed", "dir", dir, "error", err)
		}
		return nil
	}
	var probe interface{}
	if err := json.Unmarshal(raw, &probe); err != nil {
		slog.Warn("parse network status failed", "dir", dir, "error", err)
		return nil
	}
	return json.RawMessage(raw)
}
