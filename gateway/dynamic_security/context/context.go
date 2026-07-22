// Package context 定义 WDSP/阶段8 统一请求上下文（RequestContext）。
// 同一 HTTP 请求只创建一份上下文；检测器只写结论，不直接决定阻断（统一决策在后续波次）。
//
// 数据最小化：不得在上下文中长期保存完整密码、Token、Cookie 明文等高敏感数据。
package context

import (
	"net/netip"
	"sync"
	"time"
)

// FinalAction 统一决策动作（检测器不得擅自执行，仅由决策引擎写入）。
type FinalAction string

const (
	ActionAllow      FinalAction = "ALLOW"
	ActionObserve    FinalAction = "OBSERVE"
	ActionBlock      FinalAction = "BLOCK"
	ActionRateLimit  FinalAction = "RATE_LIMIT"
	ActionTempBlock  FinalAction = "TEMP_BLOCK"
	ActionMaskResp   FinalAction = "MASK_RESPONSE"
	ActionUnset      FinalAction = ""
)

// RiskLevel 风险等级。
type RiskLevel string

const (
	RiskNone     RiskLevel = "NONE"
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// ParseLimits 大报文与结构解析上限（防内存失控）。
type ParseLimits struct {
	MaxBodyParseBytes  int // 完整解析上限
	MaxBodySampleBytes int // 超限采样长度
	MaxJSONDepth       int
	MaxXMLDepth        int
	MaxFieldCount      int
	MaxFileMetaCount   int
}

// DefaultParseLimits 安全默认值。
func DefaultParseLimits() ParseLimits {
	return ParseLimits{
		MaxBodyParseBytes:  1 << 20, // 1 MiB
		MaxBodySampleBytes: 64 << 10,
		MaxJSONDepth:       32,
		MaxXMLDepth:        32,
		MaxFieldCount:      2048,
		MaxFileMetaCount:   64,
	}
}

// DetectorMatch 单条检测结论（WAF/API/敏感数据等写入同一列表）。
type DetectorMatch struct {
	Detector   string            `json:"detector"`             // waf / api_schema / auth / ...
	RuleID     string            `json:"rule_id,omitempty"`
	Category   string            `json:"category,omitempty"`
	Severity   string            `json:"severity,omitempty"`
	Message    string            `json:"message,omitempty"`
	Evidence   map[string]string `json:"evidence,omitempty"` // 已脱敏的键值
	ScoreDelta int               `json:"score_delta,omitempty"`
}

// RequestContext 统一请求上下文（请求路径只建一份）。
// 字段按任务书 §7 裁剪为核心可序列化集合；扩展经 Extensions 注册写入。
type RequestContext struct {
	mu sync.RWMutex

	// --- 关联与连接 ---
	RequestID         string
	TraceID           string
	ConnectionID      string
	ConnectionIP      netip.Addr
	ClientIP          netip.Addr
	TrustedProxyChain []string
	OccurredAt        time.Time

	// --- 应用与请求线 ---
	ApplicationID string
	DomainID      string
	Domain        string
	Scheme        string
	ProtocolVer   string
	HTTPMethod    string
	RawPath       string
	NormalizedPath string

	// --- API 识别（Wave B 填充）---
	APIEndpointID  string
	APICandidateID string
	APIConfidence  float64 // 0..1

	// --- 内容类型与体量 ---
	RequestContentType  string
	ResponseContentType string
	RequestBodySize     int64
	RequestBodyHash     string // 哈希，非明文
	ResponseStatus      int
	ResponseBodySize    int64
	ResponseBodyHash    string

	// --- 身份指纹（仅指纹，不存明文 Token）---
	AuthenticationType string
	IdentityFingerprint string
	TokenFingerprint    string
	APIKeyFingerprint   string
	SessionFingerprint  string
	TenantFingerprint   string

	// --- 解析限制与截断标记 ---
	Limits           ParseLimits
	BodyTruncated    bool
	FieldCountCapped bool

	// --- 检测与决策 ---
	Matches     []DetectorMatch
	RiskScore   int
	RiskLevel   RiskLevel
	FinalAction FinalAction
	EventID     string

	// Extensions 受控扩展（检测器写入前应使用已知键；禁止无界动态膨胀）
	Extensions map[string]any
}

// New 创建上下文；limits 为零值时使用 DefaultParseLimits。
func New(requestID string, limits ParseLimits) *RequestContext {
	if limits.MaxBodyParseBytes <= 0 {
		limits = DefaultParseLimits()
	}
	return &RequestContext{
		RequestID:  requestID,
		OccurredAt: time.Now().UTC(),
		Limits:     limits,
		RiskLevel:  RiskNone,
		Extensions: map[string]any{},
	}
}

// AddMatch 追加检测结论（线程安全）。
func (c *RequestContext) AddMatch(m DetectorMatch) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Matches = append(c.Matches, m)
	if m.ScoreDelta != 0 {
		c.RiskScore += m.ScoreDelta
		c.RiskLevel = scoreToLevel(c.RiskScore)
	}
}

// MatchCount 当前检测明细数。
func (c *RequestContext) MatchCount() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Matches)
}

// CopyMatches 返回 Matches 副本（决策引擎与测试用）。
func (c *RequestContext) CopyMatches() []DetectorMatch {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.Matches) == 0 {
		return nil
	}
	out := make([]DetectorMatch, len(c.Matches))
	copy(out, c.Matches)
	return out
}

// SetFinalAction 仅决策引擎应调用。
func (c *RequestContext) SetFinalAction(a FinalAction) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.FinalAction = a
}

// GetFinalAction 读取最终动作。
func (c *RequestContext) GetFinalAction() FinalAction {
	if c == nil {
		return ActionUnset
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.FinalAction
}

// SetExtension 写入扩展字段（键非空；值由调用方保证可序列化且已脱敏）。
func (c *RequestContext) SetExtension(key string, value any) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Extensions == nil {
		c.Extensions = map[string]any{}
	}
	c.Extensions[key] = value
}

func scoreToLevel(score int) RiskLevel {
	switch {
	case score >= 80:
		return RiskCritical
	case score >= 50:
		return RiskHigh
	case score >= 25:
		return RiskMedium
	case score > 0:
		return RiskLow
	default:
		return RiskNone
	}
}
