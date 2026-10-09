// Package events 访问控制/CC 事件输出（JSON Lines，由管理平台采集入库）。
package events

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
)

// Type 事件类型。
type Type string

const (
	IPAllowMatch           Type = "IP_ALLOW_MATCH"
	IPDenyMatch            Type = "IP_DENY_MATCH"
	CCThresholdExceeded    Type = "CC_THRESHOLD_EXCEEDED"
	CCRequestRejected      Type = "CC_REQUEST_REJECTED"
	CCTempBlockCreated     Type = "CC_TEMP_BLOCK_CREATED"
	CCTempBlockExpired     Type = "CC_TEMP_BLOCK_EXPIRED"
	CCTempBlockReleased    Type = "CC_TEMP_BLOCK_RELEASED"
	TrustedProxyInvalid    Type = "TRUSTED_PROXY_INVALID"
	ForwardedHeaderInvalid Type = "FORWARDED_HEADER_INVALID"
	ForwardedChainTooLong  Type = "FORWARDED_CHAIN_TOO_LONG"
	RateLimitEngineError   Type = "RATE_LIMIT_ENGINE_ERROR"
	// L7 访问控制规则命中事件（规则 ID 写入 access_rule_id 字段，供管理面按规则聚合命中数）
	L7RuleAllow    Type = "L7_RULE_ALLOW"
	L7RuleBlock    Type = "L7_RULE_BLOCK"
	L7RuleRedirect Type = "L7_RULE_REDIRECT"
	L7RuleCustom   Type = "L7_RULE_CUSTOM"
	// 身份风险策略处置事件（WDSP 阶段3 Risk Engine；明细写入 risk 字段——OBSERVE 模式
	// action_taken 为 would_block/would_rate_limit（假设会处置，未实断），PROTECT 为
	// blocked/rate_limited；reason 固定 identity_risk_policy，不伪装成规则阻断）
	RiskPolicyBlock     Type = "RISK_POLICY_BLOCK"
	RiskPolicyRateLimit Type = "RISK_POLICY_RATE_LIMIT"
	// JWT 信任链事件（WDSP P0-03；网关 jwt_trust 段验证处置产生——
	// JWT_OBSERVED 为 OBSERVE 模式的放行记录（action=OBSERVE），
	// JWT_AUTH_FAILED 为 PROTECT 认证失败 401，JWT_UNAVAILABLE 为
	// PROTECT 验证基础设施不可用 503（不伪装成 Token 错误）。
	// 验证摘要嵌套在 jwt_verification 对象下（不落原始 Token/payload/明文 sub/tenant）。
	JWTObserved    Type = "JWT_OBSERVED"
	JWTAuthFailed  Type = "JWT_AUTH_FAILED"
	JWTUnavailable Type = "JWT_UNAVAILABLE"
	// Bot 挑战事件（WDSP P1-02 B2；网关 jiuzhang_guard botchallenge 包产生——
	// 挑战明细嵌套在 bot 对象下，不落 nonce/solution/通行 Cookie/会话 Cookie/签名材料；
	// flow_id 为挑战 ID 的 SHA-256 截断指纹（单向、脱敏，供挑战/通行两阶段关联）。
	BotChallengeOffered  Type = "BOT_CHALLENGE_OFFERED"
	BotVerifySuccess     Type = "BOT_VERIFY_SUCCESS"
	BotVerifyRejected    Type = "BOT_VERIFY_REJECTED"
	BotChallengeExpired  Type = "BOT_CHALLENGE_EXPIRED"
	BotStateUnavailable  Type = "BOT_STATE_UNAVAILABLE"
	BotClearanceAccepted Type = "BOT_CLEARANCE_ACCEPTED"
	// 机器身份事件（NG-ID G1；网关 machineid 十步验证链产生——MID_OBSERVED 为
	// OBSERVE 模式放行记录（action=OBSERVE），MID_AUTH_FAILED 为 PROTECT 证明未
	// 通过 401（不带 WWW-Authenticate——RFC 9421 未注册标准 challenge 方案），
	// MID_UNAVAILABLE 为 PROTECT 依赖不可用 503/体预算 413（不伪装签名错误），
	// MID_SCOPE_DENIED 为 PROTECT 证明通过但越界 403，MID_BOT_EXEMPT 为 Bot
	// 挑战三重显式豁免（§1.7）。明细嵌套在 machine_id 对象下（不落签名原文/
	// nonce 原文/公钥原文/体原文——身份为 HMAC 指纹）。
	MIDVerified    Type = "MID_VERIFIED"
	MIDObserved    Type = "MID_OBSERVED"
	MIDAuthFailed  Type = "MID_AUTH_FAILED"
	MIDUnavailable Type = "MID_UNAVAILABLE"
	MIDScopeDenied Type = "MID_SCOPE_DENIED"
	MIDBotExempt   Type = "MID_BOT_EXEMPT"
)

// Event 访问控制/CC 事件（字段与数据库 access_control_events 对应）。
type Event struct {
	RequestID     string    `json:"request_id"`
	OccurredAt    time.Time `json:"occurred_at"`
	ApplicationID string    `json:"application_id,omitempty"`
	AppCode       string    `json:"application_code,omitempty"`
	ClientIP      string    `json:"client_ip"`
	ConnectionIP  string    `json:"connection_ip"`
	// ClientIPSource 真实客户端 IP 识别来源（阶段5 §6.5；CONNECTION/X_FORWARDED_FOR/
	// X_REAL_IP/FORWARDED/CUSTOM_HEADER；旧网关不携带时缺省，采集端落 NULL）
	ClientIPSource string `json:"client_ip_source,omitempty"`
	// TrustedProxyUsed 命中的可信代理名（未经过可信代理解析时为空缺省）
	TrustedProxyUsed string `json:"trusted_proxy_used,omitempty"`
	// ForwardedChainSummary 截断的代理链摘要（网关 clientip 已截断 128；伪造头场景
	// 为原始头值截断片段）
	ForwardedChainSummary string     `json:"forwarded_chain_summary,omitempty"`
	Domain                string     `json:"domain,omitempty"`
	Method                string     `json:"request_method,omitempty"`
	Path                  string     `json:"request_path,omitempty"`
	EventType             Type       `json:"event_type"`
	Action                string     `json:"action,omitempty"`
	PolicyID              string     `json:"policy_id,omitempty"`
	AccessRuleID          string     `json:"access_rule_id,omitempty"`
	CurrentCount          int64      `json:"current_count,omitempty"`
	LimitValue            int64      `json:"limit_value,omitempty"`
	WindowSeconds         int        `json:"window_seconds,omitempty"`
	BlockExpiresAt        *time.Time `json:"block_expires_at,omitempty"`
	ResponseStatus        int        `json:"response_status,omitempty"`
	GatewayNode           string     `json:"gateway_node_id"`
	Message               string     `json:"message,omitempty"`
	// Proto HTTP 协议版本（r.Proto 原样 HTTP/1.1 / HTTP/2.0 / HTTP/3；
	// 空 = 不可得省略，采集端容忍缺失落 NULL）。
	Proto string `json:"proto,omitempty"`
	// Risk 身份风险策略处置明细（仅 RISK_POLICY_* 事件携带；其余事件为 nil 零变化）
	Risk *RiskPolicyDetail `json:"risk,omitempty"`
	// JWT JWT 信任链验证摘要（仅 JWT_* 事件携带；与 dynamic_security/events
	// 共享同一 JSON 契约，不落原始 Token/payload/明文 sub/tenant；其余事件为 nil 零变化）
	JWT *dsevents.JWTVerification `json:"jwt_verification,omitempty"`
	// Bot Bot 挑战明细（仅 BOT_* 事件携带；不落 nonce/solution/通行 Cookie/会话 Cookie/
	// 签名材料——flow_id 为挑战 ID 的 SHA-256 截断指纹；其余事件为 nil 零变化）
	Bot *BotDetail `json:"bot,omitempty"`
	// MachineID 机器身份验证明细（仅 MID_* 事件携带；不落签名原文/nonce 原文/
	// 公钥原文/体原文——身份为 HMAC 指纹，nonce 仅以 sha256 摘要参与存储与事件；
	// 其余事件为 nil 零变化）
	MachineID *MachineIDDetail `json:"machine_id,omitempty"`
	// FinalDecision 请求最终处置上下文快照（WDSP P0-04，final_decision JSON
	// schema_version=1）：仅终止分支事件挂载（RecordTerminal 后取，内容完整——
	// 终止后不再产生新事实）；放行/观察事件不挂（请求未完成，提前 Finalize 会
	// 落 UNKNOWN 且锁死后续记录）。采集端写入 access_control_events.details.final_decision
	FinalDecision json.RawMessage `json:"final_decision,omitempty"`
}

// MachineIDDetail 机器身份验证明细（NG-ID G1；字段与跨分片冻结契约一致）：
// 仅承载状态/reason 词表/身份指纹（HMAC）/kid/注册表版本/撤销水位——
// 绝不出现签名原文/nonce 原文/公钥原文/体原文（构造处保证）。
type MachineIDDetail struct {
	Status          string `json:"status"` // VERIFIED|INVALID|UNAVAILABLE|NOT_PRESENT|OUT_OF_SCOPE
	ReasonCode      string `json:"reason_code,omitempty"`
	MachineIDFP     string `json:"machine_id_fp,omitempty"` // 身份指纹（HMAC-SHA256 截断）
	KeyID           string `json:"key_id,omitempty"`
	RegistryVersion int64  `json:"registry_version,omitempty"`
	Watermark       int64  `json:"watermark,omitempty"`
	// Detail 依赖不可用明细（仅 UNAVAILABLE 携带——dependency_unavailable 披露
	// 语义的 access_control 事件承载；证明判定细节不落此字段）
	Detail string `json:"detail,omitempty"`
}

// RiskSignalEntry 风险信号明细（与 riskengine.SignalEntry 同构；事件侧独立定义防循环依赖）。
type RiskSignalEntry struct {
	Type   string    `json:"type"`
	Score  int       `json:"score"`
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at"`
}

// RiskPolicyDetail 身份风险策略处置明细（字段与跨分片冻结契约一致）：
// signals 为滑窗内完整信号列表（服务端可据以解释"为什么得 N 分"）。
type RiskPolicyDetail struct {
	IdentityKey   string            `json:"identity_key"`
	Score         int               `json:"score"`
	RiskLevel     string            `json:"risk_level"` // LOW|MEDIUM|HIGH|CRITICAL
	Threshold     int               `json:"threshold"`  // 命中的策略阈值
	Mode          string            `json:"mode"`       // OBSERVE|PROTECT
	PolicyVersion int               `json:"policy_version"`
	Reason        string            `json:"reason"`       // 固定 identity_risk_policy
	ActionTaken   string            `json:"action_taken"` // would_block|would_rate_limit|blocked|rate_limited
	Signals       []RiskSignalEntry `json:"signals"`
}

// BotDetail Bot 挑战明细（WDSP P1-02 B2；字段与跨分片冻结契约一致）：
// 仅承载策略有效版本/代次、模式、结构化理由码与脱敏 flow_id——
// 绝不出现 nonce/solution/通行 Cookie/会话 Cookie/签名材料（网关 botchallenge
// 包在构造处保证，采集端按既有 details JSONB 落点纪律处理）。
type BotDetail struct {
	PolicyVersion int    `json:"policy_version"`     // 策略有效版本
	PolicyEpoch   int    `json:"policy_epoch"`       // 撤销代次（B2 冻结 = 策略版本）
	Mode          string `json:"mode"`               // OBSERVE|PROTECT
	Reason        string `json:"reason"`             // 结构化理由码（offered 时为信号理由）
	FlowID        string `json:"flow_id,omitempty"`  // 挑战 ID 的 SHA-256 截断指纹（脱敏关联）
	KeyID         string `json:"key_id,omitempty"`   // 验签密钥引用名（非密钥材料）
	Attempts      int    `json:"attempts,omitempty"` // 已消费验证尝试次数（verify 结果事件）
	ResponseNote  string `json:"note,omitempty"`     // 补充说明（静态文本，不携带外部输入原文）
}

// 字段长度上限（防超大输入撑爆日志）。
const (
	maxPathLen         = 512
	maxDomainLen       = 255
	maxMsgLen          = 512
	maxProtoLen        = 32
	maxVerLen          = 128
	maxSourceLen       = 32
	maxProxyNameLen    = 128
	maxChainSummaryLen = 256
)

// Logger JSON Lines 事件记录器（并发安全）。
type Logger struct {
	mu   sync.Mutex
	f    *os.File
	node string
}

// NewLogger 打开事件日志文件（追加写入）。
func NewLogger(path, gatewayNode string) (*Logger, error) {
	if path == "" {
		return nil, fmt.Errorf("events log path required")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open events log: %w", err)
	}
	return &Logger{f: f, node: gatewayNode}, nil
}

// sanitize 截断超长字段、剥离控制字符（防日志注入；JSON 转义为第二道防线）。
func sanitize(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}

// Emit 输出一条事件（出错返回，不静默丢弃）。
func (l *Logger) Emit(e Event) error {
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	e.GatewayNode = l.node
	e.Path = sanitize(e.Path, maxPathLen)
	e.Domain = sanitize(e.Domain, maxDomainLen)
	e.Message = sanitize(e.Message, maxMsgLen)
	e.Proto = sanitize(e.Proto, maxProtoLen)
	e.ClientIPSource = sanitize(e.ClientIPSource, maxSourceLen)
	e.TrustedProxyUsed = sanitize(e.TrustedProxyUsed, maxProxyNameLen)
	e.ForwardedChainSummary = sanitize(e.ForwardedChainSummary, maxChainSummaryLen)
	if e.JWT != nil {
		e.JWT.Status = sanitize(e.JWT.Status, 32)
		e.JWT.ReasonCode = sanitize(e.JWT.ReasonCode, 32)
		e.JWT.PolicyVersion = sanitize(e.JWT.PolicyVersion, maxVerLen)
		e.JWT.IssuerConfigID = sanitize(e.JWT.IssuerConfigID, maxVerLen)
		e.JWT.KeysetVersion = sanitize(e.JWT.KeysetVersion, maxVerLen)
		e.JWT.VerifiedPrincipalID = sanitize(e.JWT.VerifiedPrincipalID, maxVerLen)
		e.JWT.VerifiedTenantID = sanitize(e.JWT.VerifiedTenantID, maxVerLen)
		e.JWT.VerifiedIdentityType = sanitize(e.JWT.VerifiedIdentityType, 32)
		e.JWT.EvaluatedAt = sanitize(e.JWT.EvaluatedAt, 64)
	}
	if e.Bot != nil {
		e.Bot.Mode = sanitize(e.Bot.Mode, 16)
		e.Bot.Reason = sanitize(e.Bot.Reason, 64)
		e.Bot.FlowID = sanitize(e.Bot.FlowID, 32)
		e.Bot.KeyID = sanitize(e.Bot.KeyID, 64)
		e.Bot.ResponseNote = sanitize(e.Bot.ResponseNote, maxMsgLen)
	}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write event: %w", err)
	}
	return nil
}

// Close 关闭文件。
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
