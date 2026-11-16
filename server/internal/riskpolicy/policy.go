// policy.go 身份风险处置策略（WDSP AI 自动化渗透防护增强 阶段3）。
// 单行全局策略（security_risk_policy 表 scope='GLOBAL'，迁移 000101 种子）；
// 管理面全量更新（version 乐观锁），经发布通道下发网关 jiuzhang_guard
// risk_policy 段（跨分片契约见 gatewayconfig.GuardRiskPolicy，已冻结）。
package riskpolicy

import (
	"time"

	"github.com/google/uuid"
)

// 策略作用域与模式（GLOBAL 为全局策略，APPLICATION 为按应用覆盖；OBSERVE 仅观测——事件 action_taken
// 为 would_block/would_rate_limit，PROTECT 实际处置——blocked/rate_limited）。
const (
	ScopeGlobal      = "GLOBAL"
	ScopeApplication = "APPLICATION"
	ModeObserve      = "OBSERVE"
	ModeProtect      = "PROTECT"
)

// 风险等级阈值键（risk_levels 合法键，三键须全量提供；score ≥ 阈值 → 对应等级，
// 与阶段1 身份风险分级口径一致：0-19 LOW / 20-39 MEDIUM / 40-69 HIGH / 70+ CRITICAL）。
var ValidRiskLevels = []string{"medium", "high", "critical"}

// Policy 风险处置策略（全局字段与可选应用 ID；应用覆盖由 security_risk_policy_overrides 承载）。
type Policy struct {
	ID                       uuid.UUID      `json:"id"`
	Scope                    string         `json:"scope"`
	ApplicationID            *uuid.UUID     `json:"application_id,omitempty"`
	Enabled                  bool           `json:"enabled"`
	Mode                     string         `json:"mode"`
	Version                  int            `json:"version"`
	BlockThreshold           int            `json:"block_threshold"`
	RateLimitThreshold       int            `json:"rate_limit_threshold"`
	RateLimitRPS             int            `json:"rate_limit_rps"`
	SignalWindowSeconds      int            `json:"signal_window_seconds"`
	SharedDeviceAccountLimit int            `json:"shared_device_account_limit,omitempty"`
	Scores                   map[string]int `json:"scores"`
	RiskLevels               map[string]int `json:"risk_levels"`
	UpdatedBy                string         `json:"updated_by"`
	CreatedAt                time.Time      `json:"created_at"`
	UpdatedAt                time.Time      `json:"updated_at"`
}
