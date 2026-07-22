// Package ratelimitpolicies 提供CC防护（限速）策略管理：
// CRUD、参数校验、启停、乐观锁与请求模拟测试（干跑，不触达网关）。
package ratelimitpolicies

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// 作用范围
const (
	ScopeGlobal      = "GLOBAL"      // 全局（不得关联应用）
	ScopeApplication = "APPLICATION" // 指定应用
	ScopeURI         = "URI"         // 指定应用 + URI匹配
)

// 统计维度
const (
	DimensionClientIP               = "CLIENT_IP"                 // 按客户端IP
	DimensionApplication            = "APPLICATION"               // 按应用（共享计数）
	DimensionClientIPAndURI         = "CLIENT_IP_AND_URI"         // 按客户端IP+URI
	DimensionClientIPAndApplication = "CLIENT_IP_AND_APPLICATION" // 按客户端IP+应用
)

// 限速算法（与网关 jiuzhang_guard/ratelimit 同语义）
const (
	AlgorithmTokenBucket   = "TOKEN_BUCKET"   // 令牌桶：容量burst（缺省=limit），速率limit/window匀速补充
	AlgorithmSlidingWindow = "SLIDING_WINDOW" // 滑动窗口：双固定窗口加权近似
)

// 触发动作
const (
	ActionLog       = "LOG"        // 仅记录日志
	ActionObserve   = "OBSERVE"    // 观察（记录并标记，不阻断）
	ActionReject    = "REJECT"     // 拒绝（429）
	ActionTempBlock = "TEMP_BLOCK" // 临时封禁（需 block_duration_seconds）
)

// URI 匹配方式
const (
	URIMatchAll    = "ALL"    // 全部URI（pattern必须为空）
	URIMatchExact  = "EXACT"  // 精确匹配
	URIMatchPrefix = "PREFIX" // 前缀匹配
	URIMatchRegex  = "REGEX"  // 正则匹配（Go regexp / RE2，线性时间，天然防ReDoS）
)

// 策略状态
const (
	StatusActive   = "ACTIVE"
	StatusDisabled = "DISABLED"
)

// 错误
var (
	ErrNotFound      = errors.New("rate limit policy not found")
	ErrInvalidInput  = errors.New("invalid rate limit policy input")
	ErrInvalidStatus = errors.New("invalid rate limit policy status")
)

// Policy 是CC防护（限速）策略。
type Policy struct {
	ID                   uuid.UUID  `json:"id"`
	Name                 string     `json:"name"`
	Description          string     `json:"description"`
	ScopeType            string     `json:"scope_type"`
	ApplicationID        *uuid.UUID `json:"application_id"`
	URIMatchType         string     `json:"uri_match_type"`
	URIPattern           string     `json:"uri_pattern"`
	Dimension            string     `json:"dimension"`
	Algorithm            string     `json:"algorithm"`
	RequestsLimit        int        `json:"requests_limit"`
	WindowSeconds        int        `json:"window_seconds"`
	BurstCapacity        int        `json:"burst_capacity"`
	Action               string     `json:"action"`
	BlockDurationSeconds int        `json:"block_duration_seconds"`
	Status               string     `json:"status"`
	ObserveOnly          bool       `json:"observe_only"`
	Priority             int        `json:"priority"`
	EffectiveFrom        *time.Time `json:"effective_from"`
	EffectiveUntil       *time.Time `json:"effective_until"`
	CreatedBy            *uuid.UUID `json:"created_by"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedBy            *uuid.UUID `json:"updated_by"`
	UpdatedAt            time.Time  `json:"updated_at"`
	Version              int        `json:"version"`
}

// EffectiveBurst 返回实际突发容量（0 表示取 requests_limit，与网关语义一致）。
func (p *Policy) EffectiveBurst() int {
	if p.BurstCapacity <= 0 {
		return p.RequestsLimit
	}
	return p.BurstCapacity
}
