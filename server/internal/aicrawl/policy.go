// Package aicrawl 提供 AI 爬虫治理、Web Bot Auth（RFC 9421）爬虫公钥目录管理与
// 离线 AI 迷宫诱捕策略管理面（Phase 9A-2）。策略经既有配置发布通道下发网关
// ai_crawl_policy 段，迷宫签名密钥通过加密系统设置独立管理且绝不通过 REST 回显。
package aicrawl

import (
	"time"

	"github.com/google/uuid"
)

// SchemaVersion 下发网关 ai_crawl_policy 段的配置结构版本。
const SchemaVersion = 1

// 策略运行模式（默认 OFF：不改变既有流量）。
const (
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
)

// AI 爬虫处置动作。
const (
	ActionAllow     = "ALLOW"
	ActionRateLimit = "RATE_LIMIT"
	ActionChallenge = "CHALLENGE"
	ActionTarpit    = "TARPIT"
	ActionHTTP402   = "HTTP_402"
	ActionBlock     = "BLOCK"
)

// 爬虫分类枚举。
const (
	CategorySearchEngine = "SEARCH_ENGINE"
	CategoryAITraining   = "AI_TRAINING"
	CategoryAIAssistant  = "AI_ASSISTANT"
	CategoryAIAgent      = "AI_AGENT"
	CategoryUnknownBot   = "UNKNOWN_BOT"
)

// Web Bot Auth 目录公钥算法白名单（RFC 9421）。
const (
	KeyAlgEd25519   = "ed25519"
	KeyAlgECDSAP256 = "ecdsa-p256-sha256"
)

// 策略参数默认值与产品限制边界。
const (
	DefaultLabyrinthMaxDepth       = 5
	MinLabyrinthMaxDepth           = 1
	MaxLabyrinthMaxDepth           = 16
	DefaultLabyrinthMaxConcurrency = 256
	MinLabyrinthMaxConcurrency     = 1
	MaxLabyrinthMaxConcurrency     = 4096
	DefaultLabyrinthDelayMs        = 150
	MinLabyrinthDelayMs            = 0
	MaxLabyrinthDelayMs            = 5000

	MaxRules              = 64
	MaxRuleIDLen          = 64
	MaxRuleNameLen        = 128
	MaxRuleAgentIDLen     = 256
	MaxRuleUAPatterns     = 32
	MaxUAPatternLen       = 256
	MaxContentSignalLen   = 512
	MaxHTTP402MessageLen  = 512
	MaxHTTP402PriceLen    = 128
	MaxHTTP402ContactLen  = 512
	MaxHTTP402ReceiptLen  = 64
	MaxReasonLen          = 500
	MaxDirectorySlugLen   = 64
	MaxDirectoryNameLen   = 128
	MaxSignatureAgentLen  = 512
	MaxDirectoryURLLen    = 1024
	MaxDirectoryKeys      = 32
	MaxKIDLen             = 256
	MaxDirectoryBodyBytes = 256 * 1024
	MaxImportDirectories  = 64
	directorySyncTimeout  = 5 * time.Second
)

// 状态摘要词表（与 jwttrust 保持一致）。
const (
	StateNotConfigured = "NOT_CONFIGURED"
	StateDraftPending  = "DRAFT_PENDING"
	StatePublished     = "PUBLISHED"
)

// HTTP402Config HTTP 402 Payment Required 响应配置。
type HTTP402Config struct {
	Message       string `json:"message"`
	PriceHint     string `json:"price_hint"`
	ContactURL    string `json:"contact_url"`
	ReceiptHeader string `json:"receipt_header"`
}

// Rule AI 爬虫分级处置规则（按 priority 升序评估，首中即停）。
type Rule struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Category           string   `json:"category"`
	AgentID            string   `json:"agent_id,omitempty"`
	UAPatterns         []string `json:"ua_patterns"`
	RequireVerifiedSig bool     `json:"require_verified_sig"`
	Action             string   `json:"action"`
	ExemptBotChallenge bool     `json:"exempt_bot_challenge"`
	RateLimitRPM       int      `json:"rate_limit_rpm"`
	Priority           int      `json:"priority"`
}

// Policy 应用级 AI 爬虫治理与迷宫诱捕策略（草稿行，对应 ai_crawl_policies 表）。
// 注意：迷宫 HMAC 签名密钥不在此结构及 REST 接口中回显，仅由发布链路从加密设置注入网关。
type Policy struct {
	ID                      uuid.UUID     `json:"id"`
	ApplicationID           uuid.UUID     `json:"application_id"`
	SchemaVersion           int           `json:"schema_version"`
	Mode                    string        `json:"mode"`
	Version                 int           `json:"version"`
	DefaultAIAction         string        `json:"default_ai_action"`
	ContentSignal           string        `json:"content_signal"`
	VerifyWebBotAuth        bool          `json:"verify_web_bot_auth"`
	LabyrinthEnabled        bool          `json:"labyrinth_enabled"`
	LabyrinthInjectLinks    bool          `json:"labyrinth_inject_links"`
	LabyrinthMaxDepth       int           `json:"labyrinth_max_depth"`
	LabyrinthMaxConcurrency int           `json:"labyrinth_max_concurrency"`
	LabyrinthDelayMs        int           `json:"labyrinth_delay_ms"`
	HTTP402                 HTTP402Config `json:"http_402"`
	Rules                   []Rule        `json:"rules"`
	UpdatedBy               string        `json:"updated_by"`
	CreatedAt               time.Time     `json:"created_at"`
	UpdatedAt               time.Time     `json:"updated_at"`
}

// DefaultPolicy 无策略记录应用的默认 OFF 策略（version=0）。
func DefaultPolicy(appID uuid.UUID) *Policy {
	return &Policy{
		ApplicationID:           appID,
		SchemaVersion:           SchemaVersion,
		Mode:                    ModeOff,
		Version:                 0,
		DefaultAIAction:         ActionAllow,
		ContentSignal:           "",
		VerifyWebBotAuth:        true,
		LabyrinthEnabled:        false,
		LabyrinthInjectLinks:    false,
		LabyrinthMaxDepth:       DefaultLabyrinthMaxDepth,
		LabyrinthMaxConcurrency: DefaultLabyrinthMaxConcurrency,
		LabyrinthDelayMs:        DefaultLabyrinthDelayMs,
		HTTP402:                 HTTP402Config{},
		Rules:                   []Rule{},
	}
}

// StatusSummary GET 状态摘要（草稿版本 vs 最近成功发布快照中的生效版本）。
type StatusSummary struct {
	State            string `json:"state"`
	DraftVersion     int    `json:"draft_version"`
	PublishedVersion int    `json:"published_version"`
}
