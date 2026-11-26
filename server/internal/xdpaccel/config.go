// Package xdpaccel 提供内核级 eBPF/XDP 快速丢包加速控制面能力（Phase 9D-2）：
//   - 管理 system_settings 中 xdp_acceleration 配置组；
//   - 仅收集全局生效的 IP 黑名单（ip_access_rules DENY+GLOBAL）与全局临时封禁（temporary_blocks application_id IS NULL），
//     并在控制面独立执行 protected_addresses / 环回 / 链路本地 / 组播 / 广播 / 未指定地址重叠排除；
//   - 通过受控本地 Unix Domain Socket 与 xdpguard 守护进程通信（绝不走 TCP、绝不伪造内核已挂载）。
package xdpaccel

import "time"

// SchemaVersion 下发给 xdpguard POST /v1/sync 的协议版本号。
const SchemaVersion = 1

// system_settings 配置组与键名（对应迁移 000250）。
const (
	SettingsGroup          = "xdp_acceleration"
	KeyEnabled             = "enabled"
	KeySocketPath          = "socket_path"
	KeyInterfaces          = "interfaces"
	KeyAttachMode          = "attach_mode"
	KeySyncIntervalSeconds = "sync_interval_seconds"
)

// Unix Domain Socket 路径安全白名单目录与默认路径（三端统一冻结）。
const (
	DefaultSocketPath        = "/var/run/caddy/sidecars/xdpguard.sock"
	AllowedSocketPrefixCaddy = "/var/run/caddy/sidecars/"
	AllowedSocketPrefixRun   = "/run/jiuzhang/"
)

// XDP 网卡挂载请求模式（auto 优先驱动级 Native，不支持时回退内核 Generic）。
const (
	AttachModeAuto    = "auto"
	AttachModeNative  = "native"
	AttachModeGeneric = "generic"
)

// 守护进程运行时模式。
const (
	ModeXDPNative         = "xdp_native"
	ModeXDPGeneric        = "xdp_generic"
	ModeFallbackUserspace = "fallback_userspace"
)

// 守护进程健康与探测状态词表。
const (
	StatusOK                = "ok"
	StatusDegraded          = "degraded"
	StatusUnavailable       = "unavailable"
	StatusInvalidSocketPath = "invalid_socket_path"
)

// 冻结校验边界常量（与 gateway/xdpguard、server/internal/settings、web/src/api/xdpAccel.ts 1:1 对齐）。
const (
	MaxSocketPathLen           = 256
	MaxInterfaces              = 16
	MinSyncIntervalSeconds     = 1
	MaxSyncIntervalSeconds     = 300
	DefaultSyncIntervalSeconds = 5
	MaxReasonLen               = 500
)

// Config 是 XDP 加速配置 DTO（GET /api/v1/xdp-acceleration/config 与 PUT 响应 config 字段）。
type Config struct {
	Enabled             bool      `json:"enabled"`
	SocketPath          string    `json:"socket_path"`
	Interfaces          []string  `json:"interfaces"`
	AttachMode          string    `json:"attach_mode"`
	SyncIntervalSeconds int       `json:"sync_interval_seconds"`
	Version             int       `json:"version"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// DefaultConfig 返回默认关闭的安全基线配置。
func DefaultConfig() *Config {
	return &Config{
		Enabled:             false,
		SocketPath:          DefaultSocketPath,
		Interfaces:          []string{},
		AttachMode:          AttachModeAuto,
		SyncIntervalSeconds: DefaultSyncIntervalSeconds,
		Version:             0,
	}
}

// InterfaceStatus 单块物理网卡的 XDP 挂载状态（对应 xdpguard GET /v1/stats interfaces[]）。
type InterfaceStatus struct {
	Name     string `json:"name"`
	Attached bool   `json:"attached"`
	Mode     string `json:"mode"`
	Error    string `json:"error"`
}

// Status 是 XDP 守护进程实时状态与丢包遥测（GET /api/v1/xdp-acceleration/status）。
type Status struct {
	Available              bool              `json:"available"`
	Status                 string            `json:"status"`
	Mode                   string            `json:"mode"`
	KernelAttached         bool              `json:"kernel_attached"`
	SocketPath             string            `json:"socket_path"`
	AttachModeRequested    string            `json:"attach_mode_requested"`
	Interfaces             []InterfaceStatus `json:"interfaces"`
	DroppedV4Packets       uint64            `json:"dropped_v4_packets"`
	DroppedV6Packets       uint64            `json:"dropped_v6_packets"`
	PassedPackets          uint64            `json:"passed_packets"`
	SyncedV4CIDRs          int               `json:"synced_v4_cidrs"`
	SyncedV6CIDRs          int               `json:"synced_v6_cidrs"`
	ExcludedProtectedCount int               `json:"excluded_protected_count"`
	LastSyncAt             string            `json:"last_sync_at"`
	Error                  string            `json:"error"`
}

// SyncRequest 是发往 xdpguard POST /v1/sync 的精确冻结协议载荷（xdpguard 启用 DisallowUnknownFields）。
type SyncRequest struct {
	SchemaVersion  int      `json:"schema_version"`
	Enabled        bool     `json:"enabled"`
	AttachMode     string   `json:"attach_mode"`
	Interfaces     []string `json:"interfaces"`
	BlockedCIDRs   []string `json:"blocked_cidrs"`
	ProtectedCIDRs []string `json:"protected_cidrs"`
}

// SyncResponse 是 xdpguard POST /v1/sync 的精确冻结返回结构。
type SyncResponse struct {
	Synced                 bool     `json:"synced"`
	Mode                   string   `json:"mode"`
	KernelAttached         bool     `json:"kernel_attached"`
	AttachedInterfaces     []string `json:"attached_interfaces"`
	SyncedV4CIDRs          int      `json:"synced_v4_cidrs"`
	SyncedV6CIDRs          int      `json:"synced_v6_cidrs"`
	ExcludedProtectedCount int      `json:"excluded_protected_count"`
	InvalidCIDRsSkipped    int      `json:"invalid_cidrs_skipped"`
	LastSyncAt             string   `json:"last_sync_at"`
	Error                  string   `json:"error"`
}

// SyncResult 是管理面同步接口（POST /api/v1/xdp-acceleration/sync 及 PUT 联动）返回的汇总结果。
type SyncResult struct {
	Synced                    bool     `json:"synced"`
	Mode                      string   `json:"mode"`
	KernelAttached            bool     `json:"kernel_attached"`
	AttachedInterfaces        []string `json:"attached_interfaces"`
	SyncedV4CIDRs             int      `json:"synced_v4_cidrs"`
	SyncedV6CIDRs             int      `json:"synced_v6_cidrs"`
	ExcludedProtectedCount    int      `json:"excluded_protected_count"`
	ControlPlaneExcludedCount int      `json:"control_plane_excluded_count"`
	InvalidCIDRsSkipped       int      `json:"invalid_cidrs_skipped"`
	LastSyncAt                string   `json:"last_sync_at"`
	Error                     string   `json:"error"`
}

// UpdateConfigResponse 是 PUT /api/v1/xdp-acceleration/config 的响应载荷。
type UpdateConfigResponse struct {
	Config      *Config     `json:"config"`
	SyncResult  *SyncResult `json:"sync_result,omitempty"`
	SyncWarning string      `json:"sync_warning,omitempty"`
}

func nonNilStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
