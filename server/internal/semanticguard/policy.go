// Package semanticguard 提供本地离线 ONNX/SLM 语义防火墙管理面能力（Phase 9C-2）：
//   - 应用级语义防火墙策略草稿、不可变版本历史与发布下发（semantic_guard_policy 段）；
//   - 受控 Unix Domain Socket 边车健康探测（GET /api/v1/semantic-guard/status）。
package semanticguard

import (
	"time"

	"github.com/google/uuid"
)

// SchemaVersion 下发网关 semantic_guard_policy 段的配置结构版本。
const SchemaVersion = 1

// 策略运行模式（默认 OFF：不改变既有流量）。
const (
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
)

// 边车不可用/超时/熔断时的降级策略（默认 FAIL_OPEN；FAIL_CLOSED 返回 503）。
const (
	FailPolicyOpen   = "FAIL_OPEN"
	FailPolicyClosed = "FAIL_CLOSED"
)

// 策略发布状态摘要词表（与 jwttrust / aicrawl / clientside / apia2a 保持一致）。
const (
	StateNotConfigured = "NOT_CONFIGURED"
	StateDraftPending  = "DRAFT_PENDING"
	StatePublished     = "PUBLISHED"
)

// Unix Socket 路径安全白名单目录与默认路径（网关、服务端、前端三端统一冻结）。
const (
	DefaultSocketPath        = "/var/run/caddy/sidecars/semantic.sock"
	AllowedSocketPrefixCaddy = "/var/run/caddy/sidecars/"
	AllowedSocketPrefixRun   = "/run/jiuzhang/"
)

// 校验边界与默认常量（与网关 gateway/dynamic_security/semantic 及前端 web/src/api/semanticGuard.ts 严格对齐）。
const (
	MaxSocketPathLen               = 256
	MinTimeoutMs                   = 5
	MaxTimeoutMs                   = 200
	DefaultTimeoutMs               = 15
	MinMaxConcurrency              = 1
	MaxMaxConcurrency              = 256
	DefaultMaxConcurrency          = 32
	MinMaxInputRunes               = 256
	MaxMaxInputRunes               = 8192
	DefaultMaxInputRunes           = 4096
	MinObserveThreshold            = 0.1
	MaxObserveThreshold            = 0.99
	DefaultObserveThreshold        = 0.50
	MinBlockThreshold              = 0.5
	MaxBlockThreshold              = 0.99
	DefaultBlockThreshold          = 0.85
	MinCircuitFailureThreshold     = 1
	MaxCircuitFailureThreshold     = 100
	DefaultCircuitFailureThreshold = 5
	MinCircuitOpenSeconds          = 5
	MaxCircuitOpenSeconds          = 300
	DefaultCircuitOpenSeconds      = 30
	MaxReasonLen                   = 500
)

// Policy 应用级本地离线语义防火墙策略（草稿行，对应 semantic_guard_policies 表）。
type Policy struct {
	ID                      uuid.UUID `json:"id"`
	ApplicationID           uuid.UUID `json:"application_id"`
	SchemaVersion           int       `json:"schema_version"`
	Mode                    string    `json:"mode"`
	Version                 int       `json:"version"`
	SocketPath              string    `json:"socket_path"`
	TimeoutMs               int       `json:"timeout_ms"`
	MaxConcurrency          int       `json:"max_concurrency"`
	MaxInputRunes           int       `json:"max_input_runes"`
	BlockThreshold          float64   `json:"block_threshold"`
	ObserveThreshold        float64   `json:"observe_threshold"`
	FailPolicy              string    `json:"fail_policy"`
	InspectLLMPrompts       bool      `json:"inspect_llm_prompts"`
	InspectMCPContent       bool      `json:"inspect_mcp_content"`
	InspectWebGrayzone      bool      `json:"inspect_web_grayzone"`
	CircuitFailureThreshold int       `json:"circuit_failure_threshold"`
	CircuitOpenSeconds      int       `json:"circuit_open_seconds"`
	UpdatedBy               string    `json:"updated_by"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// DefaultPolicy 无策略记录应用的默认 OFF 策略（version=0）。
func DefaultPolicy(appID uuid.UUID) *Policy {
	return &Policy{
		ApplicationID:           appID,
		SchemaVersion:           SchemaVersion,
		Mode:                    ModeOff,
		Version:                 0,
		SocketPath:              DefaultSocketPath,
		TimeoutMs:               DefaultTimeoutMs,
		MaxConcurrency:          DefaultMaxConcurrency,
		MaxInputRunes:           DefaultMaxInputRunes,
		BlockThreshold:          DefaultBlockThreshold,
		ObserveThreshold:        DefaultObserveThreshold,
		FailPolicy:              FailPolicyOpen,
		InspectLLMPrompts:       true,
		InspectMCPContent:       true,
		InspectWebGrayzone:      true,
		CircuitFailureThreshold: DefaultCircuitFailureThreshold,
		CircuitOpenSeconds:      DefaultCircuitOpenSeconds,
	}
}

// StatusSummary GET 策略状态摘要（草稿版本 vs 最近成功发布快照中的生效版本）。
type StatusSummary struct {
	State            string `json:"state"`
	DraftVersion     int    `json:"draft_version"`
	PublishedVersion int    `json:"published_version"`
}

// SidecarStatus 本地离线语义防火墙边车实时探测状态（GET /api/v1/semantic-guard/status）。
type SidecarStatus struct {
	Available   bool   `json:"available"`
	Status      string `json:"status"`
	SocketPath  string `json:"socket_path"`
	ModelID     string `json:"model_id"`
	ModelSHA256 string `json:"model_sha256"`
	Backend     string `json:"backend"`
	Error       string `json:"error,omitempty"`
}
