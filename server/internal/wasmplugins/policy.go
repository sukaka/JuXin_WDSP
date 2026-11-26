// Package wasmplugins 提供 Wasm 自定义检测插件管理面能力（Phase 9D-1）：
//   - 全局/应用级 Wasm 插件的 CRUD、纯 Go 二进制结构校验与 SHA-256 完整性核验；
//   - 不可变版本历史记录与一键回滚（克隆目标版本为 version+1，绝不破坏历史）；
//   - 发布通道按应用编译全局 + 应用级插件切片（GuardWasmPluginsConfig，schema_version=1）。
package wasmplugins

import (
	"time"

	"github.com/google/uuid"
)

// SchemaVersion 下发网关 wasm_plugins 段的配置结构版本。
const SchemaVersion = 1

// ABIVersionWDSPV1 冻结的 Wasm 插件宿主 ABI 版本（wdsp_env 只读宿主接口）。
const ABIVersionWDSPV1 = "wdsp_v1"

// 插件运行模式（默认 OFF：不改变既有流量）。
const (
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
)

// 插件执行异常/超时/超内存时的降级策略（默认 FAIL_OPEN；FAIL_CLOSED 返回 503）。
const (
	FailPolicyOpen   = "FAIL_OPEN"
	FailPolicyClosed = "FAIL_CLOSED"
)

// 校验边界与默认常量（与网关 wasmplugin/policy.go、数据库 CHECK 及前端 WASM_PLUGIN_LIMITS 严格对齐）。
const (
	MaxPluginsPerScope  = 16
	MaxNameLen          = 128
	MaxDescriptionLen   = 1000
	MaxReasonLen        = 500
	MaxWasmBinaryBytes  = 4 * 1024 * 1024 // 4 MiB
	MaxRequestBodyBytes = 8 * 1024 * 1024 // 允许 4MiB 二进制 base64（~5.33MiB）+ 元数据

	MinPriority     = 0
	MaxPriority     = 10000
	DefaultPriority = 100

	MinTimeoutMs     = 1
	MaxTimeoutMs     = 50
	DefaultTimeoutMs = 2

	MinMaxMemoryKB     = 256
	MaxMaxMemoryKB     = 16384
	DefaultMaxMemoryKB = 4096

	MinMaxBodyBytes     = 0
	MaxMaxBodyBytes     = 65536
	DefaultMaxBodyBytes = 65536

	MaxPathPrefixes  = 32
	MaxPathPrefixLen = 256

	DefaultPage     = 1
	DefaultPageSize = 20
	MaxPageSize     = 100
)

// Plugin 是对外暴露的 Wasm 插件元数据（绝不包含 wasm_binary 或 wasm_base64）。
type Plugin struct {
	ID              uuid.UUID  `json:"id"`
	ApplicationID   *uuid.UUID `json:"application_id"`
	ApplicationCode string     `json:"application_code,omitempty"`
	ApplicationName string     `json:"application_name,omitempty"`
	Name            string     `json:"name"`
	Description     string     `json:"description"`
	Version         int        `json:"version"`
	ABIVersion      string     `json:"abi_version"`
	Mode            string     `json:"mode"`
	SHA256          string     `json:"sha256"`
	WasmSize        int        `json:"wasm_size"`
	Priority        int        `json:"priority"`
	TimeoutMs       int        `json:"timeout_ms"`
	MaxMemoryKB     int        `json:"max_memory_kb"`
	MaxBodyBytes    int        `json:"max_body_bytes"`
	FailPolicy      string     `json:"fail_policy"`
	PathPrefixes    []string   `json:"path_prefixes"`
	UpdatedBy       string     `json:"updated_by"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// PluginVersion 是对外暴露的不可变插件版本历史条目（绝不包含 wasm_binary 或 wasm_base64）。
type PluginVersion struct {
	ID         uuid.UUID `json:"id"`
	Version    int       `json:"version"`
	ABIVersion string    `json:"abi_version"`
	Mode       string    `json:"mode"`
	SHA256     string    `json:"sha256"`
	WasmSize   int       `json:"wasm_size"`
	Reason     string    `json:"reason"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
}

// ConfigSnapshot 保存在 wasm_plugin_versions.config_snapshot JSONB 中的配置快照（供一键回滚还原）。
type ConfigSnapshot struct {
	Description  string   `json:"description"`
	Priority     int      `json:"priority"`
	TimeoutMs    int      `json:"timeout_ms"`
	MaxMemoryKB  int      `json:"max_memory_kb"`
	MaxBodyBytes int      `json:"max_body_bytes"`
	FailPolicy   string   `json:"fail_policy"`
	PathPrefixes []string `json:"path_prefixes"`
}

// ListFilter 是插件分页列表查询条件。
type ListFilter struct {
	// GlobalOnly 为 true 时仅查询全局插件（application_id IS NULL）。
	GlobalOnly bool
	// ApplicationID 非 nil 时仅查询指定应用插件。
	ApplicationID *uuid.UUID
	Mode          string
	Keyword       string
	Page          int
	PageSize      int
}

// CreateInput 是创建插件的仓储输入（含已校验的二进制字节与 sha256）。
type CreateInput struct {
	ApplicationID *uuid.UUID
	Name          string
	Description   string
	ABIVersion    string
	Mode          string
	SHA256        string
	WasmBinary    []byte
	Priority      int
	TimeoutMs     int
	MaxMemoryKB   int
	MaxBodyBytes  int
	FailPolicy    string
	PathPrefixes  []string
	Reason        string
	CreatedBy     string
}

// UpdateInput 是更新插件的仓储输入（WasmBinary 为 nil 时保留现有二进制）。
type UpdateInput struct {
	ID              uuid.UUID
	ExpectedVersion int
	Description     *string
	Mode            string
	SHA256          string // 仅在替换 WasmBinary 时使用
	WasmBinary      []byte // nil = 保留现有二进制
	ExpectedSHA256  string // 可选：未替换二进制时也核验当前二进制的 SHA-256
	Priority        int
	TimeoutMs       int
	MaxMemoryKB     int
	MaxBodyBytes    int
	FailPolicy      string
	PathPrefixes    []string
	Reason          string
	UpdatedBy       string
}

// RollbackInput 是版本回滚的仓储输入。
type RollbackInput struct {
	ID              uuid.UUID
	TargetVersion   int
	ExpectedVersion int
	Reason          string
	UpdatedBy       string
}
