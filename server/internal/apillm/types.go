// types.go LLM 观测实体、采集输入与统计聚合类型（recorder/store/handler 共用）。
package apillm

import (
	"time"

	"github.com/google/uuid"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 看板/列表窗口与 TOP 上限（与 apifiles/apigeo 同口径纪律）。
const (
	ListDefaultDays = 7
	ListMaxDays     = 30
	topLimit        = 10
)

// LLMObservation 网关事件 llm_observation 的采集端镜像（JSON 契约与
// gateway dsctx.LLMObservation 一一对应；旧版网关事件缺该键时为零值，全程容忍缺失）。
type LLMObservation struct {
	Model           string `json:"model"`
	PromptPresent   bool   `json:"prompt_present"`
	PromptLenBucket string `json:"prompt_len_bucket"`
	TotalTokens     int    `json:"total_tokens"`
	Stream          bool   `json:"stream"`
	// MCPMethod MCP JSON-RPC 方法名（W12-GW；空 = 非 MCP 端点或响应对象，容忍缺失）
	MCPMethod string `json:"mcp_method"`
}

// ObservationInput 采集输入（由 apiruntime 采集器从统一主事件映射装配）：
// 观测本体 + 身份/端点维度 + 事件检测明细（findings 口径来源）。
type ObservationInput struct {
	RequestID           string                // 幂等键来源（空 = 防御路径退化随机主键）
	OccurredAt          time.Time             // 事件时间（零值防御回退当前时间）
	EndpointKey         string                // 端点键（空 = 不产出，观测必须归属端点）
	IdentityFingerprint string                // 身份指纹（匿名空串）
	Observation         LLMObservation        // 观测本体
	Details             []dsctx.DetectorMatch // 事件检测明细（仅 llm.* 入 findings）
}

// Observation 观测行（api_llm_observations）。
type Observation struct {
	ID                  uuid.UUID             `json:"id"`
	OccurredAt          time.Time             `json:"occurred_at"`
	EndpointKey         string                `json:"endpoint_key"`
	Model               string                `json:"model"`
	IdentityFingerprint string                `json:"identity_fingerprint"` // 匿名流量为空串
	PromptLenBucket     string                `json:"prompt_len_bucket"`
	TotalTokens         int                   `json:"total_tokens"` // 0 = 流式/缺失未采集到
	Stream              bool                  `json:"stream"`
	MCPMethod           string                `json:"mcp_method"` // MCP 方法名（W12-GW；空 = 非 MCP 端点或响应对象）
	Findings            []dsctx.DetectorMatch `json:"findings"`   // llm.* 明细（证据不含原文）
	CreatedAt           time.Time             `json:"created_at"`
}

// ObservationFilter 列表过滤（枚举值已在 handler 层归一校验；时间窗按 occurred_at 口径）。
type ObservationFilter struct {
	Days         int
	Model        string // 精确匹配
	EndpointKey  string // 精确匹配
	FindingsOnly bool   // 仅 findings 非空的命中观测（涉敏/异常口径）
	Page         int
	PageSize     int
}

// StatsSummary 汇总：观测数/带命中观测数/token 合计/流式调用数/涉及模型数。
type StatsSummary struct {
	Observations   int64 `json:"observations"`    // 窗口内观测总数
	WithFindings   int64 `json:"with_findings"`   // findings 非空的观测数（涉敏/异常命中口径）
	TotalTokens    int64 `json:"total_tokens"`    // token 用量合计（缺失为 0 的行自然不计）
	StreamCalls    int64 `json:"stream_calls"`    // 流式调用数
	DistinctModels int64 `json:"distinct_models"` // 涉及不同模型数（含空串一组，口径如实）
}

// ModelStat 模型分布（按观测数聚合；空串 = 未声明模型单列一组如实呈现）。
type ModelStat struct {
	Model        string `json:"model"`
	Observations int64  `json:"observations"`
	TotalTokens  int64  `json:"total_tokens"`
	Findings     int64  `json:"findings"` // 该模型观测携带的 findings 条数
}

// TokenTrendPoint token 用量趋势（按天聚合）。
type TokenTrendPoint struct {
	Day          string `json:"day"` // YYYY-MM-DD
	Observations int64  `json:"observations"`
	TotalTokens  int64  `json:"total_tokens"`
}

// FindingRuleStat 命中规则分布（findings jsonb 展开按 rule_id 计数，复用 findings 口径）。
type FindingRuleStat struct {
	RuleID string `json:"rule_id"`
	Count  int64  `json:"count"`
}

// StatsData LLM 观测统计（窗口按 occurred_at 口径，与列表明细同窗口）。
type StatsData struct {
	Days           int               `json:"days"`
	Summary        StatsSummary      `json:"summary"`
	ByModel        []ModelStat       `json:"by_model"`    // 模型分布 TOP
	TokenTrend     []TokenTrendPoint `json:"token_trend"` // 按天 token 用量
	FindingsByRule []FindingRuleStat `json:"findings_by_rule"`
}

// clampDays 归一窗口（1..ListMaxDays，默认 ListDefaultDays）。
func clampDays(days int) int {
	if days <= 0 {
		return ListDefaultDays
	}
	if days > ListMaxDays {
		return ListMaxDays
	}
	return days
}
