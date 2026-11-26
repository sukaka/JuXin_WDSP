// Package clientside 提供客户端供应链安全防护（Magecart 防护 / PCI DSS 4.0 6.4.3 & 11.6.1）
// 管理面策略、脚本资产清单、篡改/CSP 违规处置、事件回流与合规证据导出（Phase 9B）。
// 策略与已授权/已封禁脚本清单经既有配置发布通道下发网关 client_side_policy 段。
package clientside

import (
	"time"

	"github.com/google/uuid"
)

// SchemaVersion 下发网关 client_side_policy 段的配置结构版本。
const SchemaVersion = 1

// 策略运行模式（默认 OFF：不改变既有流量）。
const (
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
)

// CSP 响应头下发模式。
const (
	CSPModeOff        = "OFF"
	CSPModeReportOnly = "REPORT_ONLY"
	CSPModeEnforce    = "ENFORCE"
)

// 脚本类型枚举。
const (
	ScriptTypeExternal   = "EXTERNAL"
	ScriptTypeInlineHash = "INLINE_HASH"
)

// 脚本授权状态枚举（PCI DSS 4.0 6.4.3）。
const (
	ScriptStatusDiscovered = "DISCOVERED"
	ScriptStatusAuthorized = "AUTHORIZED"
	ScriptStatusBlocked    = "BLOCKED"
)

// 客户端安全违规类型枚举（PCI DSS 4.0 11.6.1）。
const (
	ViolationUnauthorizedScript = "UNAUTHORIZED_SCRIPT"
	ViolationScriptTampered     = "SCRIPT_TAMPERED"
	ViolationCSPViolation       = "CSP_VIOLATION"
	ViolationProbeAlert         = "PROBE_ALERT"
)

// 违规处置状态枚举。
const (
	ViolationStatusOpen          = "OPEN"
	ViolationStatusAcknowledged  = "ACKNOWLEDGED"
	ViolationStatusResolved      = "RESOLVED"
	ViolationStatusFalsePositive = "FALSE_POSITIVE"
)

// 状态摘要词表（与 jwttrust / aicrawl 保持一致）。
const (
	StateNotConfigured = "NOT_CONFIGURED"
	StateDraftPending  = "DRAFT_PENDING"
	StatePublished     = "PUBLISHED"
)

// 校验边界常量（与前端 web/src/api/clientSide.ts CLIENT_SIDE_LIMITS 对齐）。
const (
	MaxSensitivePaths      = 64
	MaxPathLen             = 512
	MaxOrigins             = 64
	MaxOriginLen           = 512
	MaxCustomDirectivesLen = 2048
	MaxJustificationLen    = 1000
	MaxReasonLen           = 500
	MaxNoteLen             = 1000
	MaxScriptURLLen        = 2048
	MaxSRILen              = 256
)

// Policy 应用级客户端供应链安全策略（草稿行，对应 client_side_policies 表）。
type Policy struct {
	ID                       uuid.UUID `json:"id"`
	ApplicationID            uuid.UUID `json:"application_id"`
	SchemaVersion            int       `json:"schema_version"`
	Mode                     string    `json:"mode"`
	Version                  int       `json:"version"`
	CSPMode                  string    `json:"csp_mode"`
	SensitivePaths           []string  `json:"sensitive_paths"`
	ProbeEnabled             bool      `json:"probe_enabled"`
	StripUnauthorizedScripts bool      `json:"strip_unauthorized_scripts"`
	AllowedScriptOrigins     []string  `json:"allowed_script_origins"`
	AllowedConnectOrigins    []string  `json:"allowed_connect_origins"`
	AllowedFormOrigins       []string  `json:"allowed_form_origins"`
	CustomCSPDirectives      string    `json:"custom_csp_directives"`
	UpdatedBy                string    `json:"updated_by"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}

// DefaultPolicy 无策略记录应用的默认 OFF 策略（version=0）。
func DefaultPolicy(appID uuid.UUID) *Policy {
	return &Policy{
		ApplicationID:            appID,
		SchemaVersion:            SchemaVersion,
		Mode:                     ModeOff,
		Version:                  0,
		CSPMode:                  CSPModeOff,
		SensitivePaths:           []string{},
		ProbeEnabled:             false,
		StripUnauthorizedScripts: false,
		AllowedScriptOrigins:     []string{},
		AllowedConnectOrigins:    []string{},
		AllowedFormOrigins:       []string{},
		CustomCSPDirectives:      "",
	}
}

// StatusSummary GET 策略状态摘要（草稿版本 vs 最近成功发布快照中的生效版本）。
type StatusSummary struct {
	State            string `json:"state"`
	DraftVersion     int    `json:"draft_version"`
	PublishedVersion int    `json:"published_version"`
}

// Script 客户端脚本资产条目（对应 client_script_inventory 表）。
type Script struct {
	ID              uuid.UUID  `json:"id"`
	ApplicationID   uuid.UUID  `json:"application_id"`
	ApplicationCode string     `json:"application_code,omitempty"`
	ApplicationName string     `json:"application_name,omitempty"`
	ScriptURL       string     `json:"script_url"`
	ScriptOrigin    string     `json:"script_origin"`
	ScriptType      string     `json:"script_type"`
	SRIHash         string     `json:"sri_hash"`
	ObservedSRI     string     `json:"observed_sri"`
	Status          string     `json:"status"`
	Justification   string     `json:"justification"`
	ApprovedBy      string     `json:"approved_by"`
	ApprovedAt      *time.Time `json:"approved_at"`
	SamplePagePath  string     `json:"sample_page_path"`
	FirstSeenAt     time.Time  `json:"first_seen_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	ObservedCount   int64      `json:"observed_count"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// Violation 客户端篡改/未授权脚本/CSP 违规/探针告警（对应 client_side_violations 表）。
type Violation struct {
	ID                uuid.UUID  `json:"id"`
	ApplicationID     uuid.UUID  `json:"application_id"`
	ApplicationCode   string     `json:"application_code,omitempty"`
	ApplicationName   string     `json:"application_name,omitempty"`
	RequestID         string     `json:"request_id"`
	OccurredAt        time.Time  `json:"occurred_at"`
	ViolationType     string     `json:"violation_type"`
	ScriptURL         string     `json:"script_url"`
	ScriptOrigin      string     `json:"script_origin"`
	ExpectedSRI       string     `json:"expected_sri"`
	ObservedSRI       string     `json:"observed_sri"`
	PagePath          string     `json:"page_path"`
	ViolatedDirective string     `json:"violated_directive"`
	BlockedURI        string     `json:"blocked_uri"`
	ActionTaken       string     `json:"action_taken"`
	Reason            string     `json:"reason"`
	ClientIP          string     `json:"client_ip"`
	Status            string     `json:"status"`
	Note              string     `json:"note"`
	HandledBy         string     `json:"handled_by"`
	HandledAt         *time.Time `json:"handled_at"`
	CreatedAt         time.Time  `json:"created_at"`
}

// ScriptFilter 脚本资产列表筛选条件。
type ScriptFilter struct {
	ApplicationID *uuid.UUID
	Status        string
	Keyword       string
	Page          int
	PageSize      int
}

// ViolationFilter 违规告警列表筛选条件。
type ViolationFilter struct {
	ApplicationID *uuid.UUID
	ViolationType string
	Status        string
	Page          int
	PageSize      int
}
