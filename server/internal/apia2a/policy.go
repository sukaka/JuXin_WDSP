// Package apia2a 提供 A2A 协议安全治理与 Agent 物料清单（AgBOM）管理面能力（Phase 9C-1）：
//   - 应用级 A2A 协议安全策略草稿、不可变版本历史与发布下发（api_a2a_policy 段）；
//   - Agent 物料清单（AgBOM）自动发现观测、登记、审批/封禁与删除；
//   - A2A 安全事件（委派越权、递归循环熔断、致命三要素拦截）采集回流与分页查询。
package apia2a

import (
	"time"

	"github.com/google/uuid"
)

// SchemaVersion 下发网关 api_a2a_policy 段的配置结构版本。
const SchemaVersion = 1

// 策略运行模式（默认 OFF：不改变既有流量）。
const (
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
)

// AgBOM Agent 治理状态枚举。
const (
	AgentStatusDiscovered = "DISCOVERED"
	AgentStatusApproved   = "APPROVED"
	AgentStatusBlocked    = "BLOCKED"
)

// 策略发布状态摘要词表（与 jwttrust / aicrawl / clientside 保持一致）。
const (
	StateNotConfigured = "NOT_CONFIGURED"
	StateDraftPending  = "DRAFT_PENDING"
	StatePublished     = "PUBLISHED"
)

// 校验边界与默认常量（与前端 web/src/api/apiA2a.ts API_A2A_LIMITS 严格对齐）。
const (
	MaxPathPrefixes           = 32
	MaxPathLen                = 256
	MaxAllowedAgents          = 64
	MaxAllowedAgentNameLen    = 128
	MaxAgBOMAgentNameLen      = 256
	MinDelegationDepth        = 1
	MaxDelegationDepth        = 10
	DefaultDelegationDepth    = 3
	MinLoopWindowSeconds      = 5
	MaxLoopWindowSeconds      = 3600
	DefaultLoopWindowSeconds  = 60
	MinCallsPerTaskWindow     = 1
	MaxCallsPerTaskWindow     = 10000
	DefaultCallsPerTaskWindow = 20
	MaxPatterns               = 64
	MaxPatternLen             = 256
	MaxReasonLen              = 500
	MaxDescriptionLen         = 2000
	MaxAgentURLLen            = 2048
	MaxAgentVersionLen        = 64
	MaxSkills                 = 64
	MaxSkillLen               = 128
	MaxAuthSchemes            = 16
	MaxAuthSchemeLen          = 64
)

// DefaultA2APathPrefixes 默认 A2A 端点与 Agent Card 路径前缀。
func DefaultA2APathPrefixes() []string {
	return []string{"/a2a", "/.well-known/agent.json", "/.well-known/agent-card.json"}
}

// DefaultConfidentialReadPatterns 默认致命三要素机密数据读取匹配模式。
func DefaultConfidentialReadPatterns() []string {
	return []string{"/api/v1/secrets", "/api/v1/customers", "read_secret", "query_pii"}
}

// DefaultExternalEgressPatterns 默认致命三要素外发出口匹配模式。
func DefaultExternalEgressPatterns() []string {
	return []string{"send_email", "webhook", "http_post", "upload_external"}
}

// Policy 应用级 A2A 协议安全策略（草稿行，对应 api_a2a_policies 表）。
type Policy struct {
	ID                       uuid.UUID `json:"id"`
	ApplicationID            uuid.UUID `json:"application_id"`
	SchemaVersion            int       `json:"schema_version"`
	Mode                     string    `json:"mode"`
	Version                  int       `json:"version"`
	CardDiscoveryEnabled     bool      `json:"card_discovery_enabled"`
	A2APathPrefixes          []string  `json:"a2a_path_prefixes"`
	AllowedCallerAgents      []string  `json:"allowed_caller_agents"`
	MaxDelegationDepth       int       `json:"max_delegation_depth"`
	EnforceScopeAttenuation  bool      `json:"enforce_scope_attenuation"`
	LoopWindowSeconds        int       `json:"loop_window_seconds"`
	MaxCallsPerTaskWindow    int       `json:"max_calls_per_task_window"`
	LethalTrifectaEnabled    bool      `json:"lethal_trifecta_enabled"`
	ConfidentialReadPatterns []string  `json:"confidential_read_patterns"`
	ExternalEgressPatterns   []string  `json:"external_egress_patterns"`
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
		CardDiscoveryEnabled:     true,
		A2APathPrefixes:          DefaultA2APathPrefixes(),
		AllowedCallerAgents:      []string{},
		MaxDelegationDepth:       DefaultDelegationDepth,
		EnforceScopeAttenuation:  true,
		LoopWindowSeconds:        DefaultLoopWindowSeconds,
		MaxCallsPerTaskWindow:    DefaultCallsPerTaskWindow,
		LethalTrifectaEnabled:    true,
		ConfidentialReadPatterns: DefaultConfidentialReadPatterns(),
		ExternalEgressPatterns:   DefaultExternalEgressPatterns(),
	}
}

// StatusSummary GET 策略状态摘要（草稿版本 vs 最近成功发布快照中的生效版本）。
type StatusSummary struct {
	State            string `json:"state"`
	DraftVersion     int    `json:"draft_version"`
	PublishedVersion int    `json:"published_version"`
}

// Agent Agent 物料清单条目（AgBOM，对应 api_a2a_agents 表）。
type Agent struct {
	ID              uuid.UUID `json:"id"`
	ApplicationID   uuid.UUID `json:"application_id"`
	ApplicationCode string    `json:"application_code,omitempty"`
	ApplicationName string    `json:"application_name,omitempty"`
	AgentName       string    `json:"agent_name"`
	AgentURL        string    `json:"agent_url"`
	AgentVersion    string    `json:"agent_version"`
	Status          string    `json:"status"`
	Description     string    `json:"description"`
	Skills          []string  `json:"skills"`
	AllowedSkills   []string  `json:"allowed_skills"`
	AuthSchemes     []string  `json:"auth_schemes"`
	FirstSeenAt     time.Time `json:"first_seen_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	ObservedCount   int64     `json:"observed_count"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Event A2A 协议安全事件记录（对应 api_a2a_events 表）。
type Event struct {
	ID              uuid.UUID `json:"id"`
	ApplicationID   uuid.UUID `json:"application_id"`
	ApplicationCode string    `json:"application_code,omitempty"`
	ApplicationName string    `json:"application_name,omitempty"`
	RequestID       string    `json:"request_id"`
	OccurredAt      time.Time `json:"occurred_at"`
	EventType       string    `json:"event_type"`
	Method          string    `json:"method"`
	AgentName       string    `json:"agent_name"`
	DelegationDepth int       `json:"delegation_depth"`
	RuleID          string    `json:"rule_id"`
	ActionTaken     string    `json:"action_taken"`
	Reason          string    `json:"reason"`
	ClientIP        string    `json:"client_ip"`
	CreatedAt       time.Time `json:"created_at"`
}

// AgentFilter AgBOM 列表筛选条件。
type AgentFilter struct {
	ApplicationID *uuid.UUID
	Status        string
	Keyword       string
	Page          int
	PageSize      int
}

// EventFilter A2A 安全事件列表筛选条件。
type EventFilter struct {
	ApplicationID *uuid.UUID
	EventType     string
	RuleID        string
	Page          int
	PageSize      int
}
