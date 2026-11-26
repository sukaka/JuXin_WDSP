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
	URLAllowMatch          Type = "URL_ALLOW_MATCH"
	IPDenyMatch            Type = "IP_DENY_MATCH"
	IdentityManualBlock    Type = "IDENTITY_MANUAL_BLOCK"
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
	// action_taken 为 would_block/would_challenge/would_rate_limit（假设会处置，未实断），
	// PROTECT 为 blocked/challenged/rate_limited；challenged 仅用于实际 403 挑战页；
	// reason 固定 identity_risk_policy，不伪装成规则阻断）
	RiskPolicyBlock     Type = "RISK_POLICY_BLOCK"
	RiskPolicyChallenge Type = "RISK_POLICY_CHALLENGE"
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
	// AI 爬虫治理与离线迷宫事件（Phase 9A-2；网关 ai_crawl_policy 产生——
	// AI_CRAWL_VERIFIED 为 Web Bot Auth 签名验签通过，
	// AI_CRAWL_OBSERVED 为 OBSERVE 模式观察命中（不实断），
	// AI_CRAWL_ACTION 为 PROTECT 模式策略处置（ALLOW/RATE_LIMIT/CHALLENGE/TARPIT/HTTP_402/BLOCK），
	// AI_CRAWL_TRAP_HIT 为命中 /_wdsp/labyrinth/v1/ 保留命名空间陷阱。
	// 明细嵌套在 ai_crawl 对象下，绝不落签名原文/公钥原文/迷宫 HMAC 密钥。）
	AICrawlVerified Type = "AI_CRAWL_VERIFIED"
	AICrawlObserved Type = "AI_CRAWL_OBSERVED"
	AICrawlAction   Type = "AI_CRAWL_ACTION"
	AICrawlTrapHit  Type = "AI_CRAWL_TRAP_HIT"
	// 客户端供应链安全事件（Phase 9B / Magecart 防护 / PCI DSS 4.0 6.4.3 & 11.6.1；
	// 网关 client_side_policy 产生——明细嵌套在 client_side 对象下，URL 剥离凭据与查询串）。
	ClientSideScriptObserved     Type = "CLIENT_SIDE_SCRIPT_OBSERVED"
	ClientSideUnauthorizedScript Type = "CLIENT_SIDE_UNAUTHORIZED_SCRIPT"
	ClientSideScriptTampered     Type = "CLIENT_SIDE_SCRIPT_TAMPERED"
	ClientSideCSPViolation       Type = "CLIENT_SIDE_CSP_VIOLATION"
	ClientSideProbeAlert         Type = "CLIENT_SIDE_PROBE_ALERT"
	// A2A 协议安全与 Agent 物料清单事件（Phase 9C-1；网关 api_a2a_policy 产生——
	// 明细嵌套在 a2a 对象下，URL 剥离凭据与查询串，绝不落原始 JWT/Token/明文 sub）。
	A2AAgentCardDiscovered Type = "A2A_AGENT_CARD_DISCOVERED"
	A2AObserved            Type = "A2A_OBSERVED"
	A2ABlocked             Type = "A2A_BLOCKED"
	A2ALoopKilled          Type = "A2A_LOOP_KILLED"
	A2ALethalTrifecta      Type = "A2A_LETHAL_TRIFECTA"
	// 本地离线语义防火墙事件（Phase 9C-2；网关 semantic_guard_policy 产生——
	// 明细嵌套在 semantic 对象下，绝不落原始提示词、请求体或响应体原文。）
	SemanticObserved    Type = "SEMANTIC_OBSERVED"
	SemanticBlocked     Type = "SEMANTIC_BLOCKED"
	SemanticUnavailable Type = "SEMANTIC_UNAVAILABLE"
	// Wasm 自定义检测插件沙箱事件（Phase 9D-1；网关 wasm_plugins 产生——
	// 明细嵌套在 wasm_plugin 对象下，绝不落原始请求体、凭据或 Wasm 字节码。）
	WasmPluginObserved  Type = "WASM_PLUGIN_OBSERVED"
	WasmPluginBlock     Type = "WASM_PLUGIN_BLOCK"
	WasmPluginRateLimit Type = "WASM_PLUGIN_RATE_LIMIT"
	WasmPluginError     Type = "WASM_PLUGIN_ERROR"
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
	// AICrawl AI 爬虫治理与离线迷宫明细（仅 AI_CRAWL_* 事件携带；不落签名原文/
	// 公钥原文/迷宫 HMAC 密钥；其余事件为 nil 零变化）
	AICrawl *AICrawlDetail `json:"ai_crawl,omitempty"`
	// ClientSide 客户端供应链安全明细（仅 CLIENT_SIDE_* 事件携带；URL 均已剥离查询串与凭据；
	// 其余事件为 nil 零变化）
	ClientSide *ClientSideDetail `json:"client_side,omitempty"`
	// A2A A2A 协议安全与 AgBOM 发现明细（仅 A2A_* 事件携带；URL 已剥离查询串与凭据；
	// 其余事件为 nil 零变化）
	A2A *A2ADetail `json:"a2a,omitempty"`
	// Semantic 本地离线语义防火墙明细（仅 SEMANTIC_* 事件携带；绝不落提示词/请求体/响应体原文；
	// 其余事件为 nil 零变化）
	Semantic *SemanticDetail `json:"semantic,omitempty"`
	// WasmPlugin Wasm 自定义检测插件沙箱明细（仅 WASM_PLUGIN_* 事件携带；绝不落原始请求体/凭据；
	// 其余事件为 nil 零变化）
	WasmPlugin *WasmPluginDetail `json:"wasm_plugin,omitempty"`
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
	ActionTaken   string            `json:"action_taken"` // would_block|would_challenge|would_rate_limit|blocked|challenged|rate_limited
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

// AICrawlDetail AI 爬虫治理与离线迷宫明细（Phase 9A-2）：
// 仅承载策略版本/模式/验证状态/代理元信息/命中规则与迷宫深度——
// 绝不出现签名原文、公钥原文或迷宫 HMAC 密钥材料。
type AICrawlDetail struct {
	PolicyVersion      int    `json:"policy_version,omitempty"`
	Mode               string `json:"mode,omitempty"`
	Category           string `json:"category,omitempty"`
	AgentID            string `json:"agent_id,omitempty"`
	AgentSlug          string `json:"agent_slug,omitempty"`
	AgentName          string `json:"agent_name,omitempty"`
	SignatureAgent     string `json:"signature_agent,omitempty"`
	SignatureVerified  bool   `json:"signature_verified,omitempty"`
	SignatureKeyID     string `json:"signature_key_id,omitempty"`
	SignatureReason    string `json:"signature_reason,omitempty"`
	RuleID             string `json:"rule_id,omitempty"`
	RuleName           string `json:"rule_name,omitempty"`
	Action             string `json:"action,omitempty"`
	ExemptBotChallenge bool   `json:"exempt_bot_challenge,omitempty"`
	LabyrinthDepth     int    `json:"labyrinth_depth,omitempty"`
	TrapValid          bool   `json:"trap_valid,omitempty"`
}

// ClientSideDetail 客户端供应链安全明细（Phase 9B / PCI DSS 4.0 6.4.3 & 11.6.1）：
// 承载策略版本/模式、违规类型、脱敏脚本 URL 与来源、SRI 比对、违规指令与处置动作。
type ClientSideDetail struct {
	PolicyVersion     int    `json:"policy_version,omitempty"`
	Mode              string `json:"mode,omitempty"`
	ViolationType     string `json:"violation_type,omitempty"`
	ScriptURL         string `json:"script_url,omitempty"`
	ScriptOrigin      string `json:"script_origin,omitempty"`
	ScriptType        string `json:"script_type,omitempty"`
	ExpectedSRI       string `json:"expected_sri,omitempty"`
	ObservedSRI       string `json:"observed_sri,omitempty"`
	PagePath          string `json:"page_path,omitempty"`
	ViolatedDirective string `json:"violated_directive,omitempty"`
	BlockedURI        string `json:"blocked_uri,omitempty"`
	ActionTaken       string `json:"action_taken,omitempty"`
	Reason            string `json:"reason,omitempty"`
}

// A2ADetail A2A 协议安全与 Agent 物料清单明细（Phase 9C-1）：
// 承载策略版本/模式、方法、脱敏 Agent 卡片元数据、委派深度、命中规则与处置动作；
// 绝不落原始 JWT/Token/明文 sub 或未脱敏参数原值。
type A2ADetail struct {
	PolicyVersion   int      `json:"policy_version,omitempty"`
	Mode            string   `json:"mode,omitempty"`
	Method          string   `json:"method,omitempty"`
	AgentName       string   `json:"agent_name,omitempty"`
	AgentURL        string   `json:"agent_url,omitempty"`
	AgentVersion    string   `json:"agent_version,omitempty"`
	Skills          []string `json:"skills,omitempty"`
	AuthSchemes     []string `json:"auth_schemes,omitempty"`
	DelegationDepth int      `json:"delegation_depth,omitempty"`
	RuleID          string   `json:"rule_id,omitempty"`
	ActionTaken     string   `json:"action_taken,omitempty"`
	Reason          string   `json:"reason,omitempty"`
}

// SemanticDetail 本地离线语义防火墙明细（Phase 9C-2）：
// 仅承载策略版本/模式、通道、规则、分类标签/分数、模型标识、耗时、输入 rune 数与故障处置——
// 绝不落原始提示词、MCP 参数或请求/响应体文本。
type SemanticDetail struct {
	PolicyVersion int     `json:"policy_version,omitempty"`
	Mode          string  `json:"mode,omitempty"`
	Channel       string  `json:"channel,omitempty"`
	RuleID        string  `json:"rule_id,omitempty"`
	Label         string  `json:"label,omitempty"`
	Score         float64 `json:"score,omitempty"`
	ModelID       string  `json:"model_id,omitempty"`
	LatencyMS     int64   `json:"latency_ms,omitempty"`
	InputRunes    int     `json:"input_runes,omitempty"`
	FailPolicy    string  `json:"fail_policy,omitempty"`
	ActionTaken   string  `json:"action_taken,omitempty"`
	Reason        string  `json:"reason,omitempty"`
}

// WasmPluginDetail Wasm 自定义检测插件沙箱事件明细（Phase 9D-1）：
// 仅承载插件标识/版本/模式/摘要、命中规则、原因、评分增量、耗时、故障策略与脱敏错误说明——
// 绝不落原始请求体、凭据头或 Wasm 字节码。
type WasmPluginDetail struct {
	PluginID      string `json:"plugin_id,omitempty"`
	PluginName    string `json:"plugin_name,omitempty"`
	PluginVersion int    `json:"plugin_version,omitempty"`
	ABIVersion    string `json:"abi_version,omitempty"`
	Mode          string `json:"mode,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	RuleID        string `json:"rule_id,omitempty"`
	Reason        string `json:"reason,omitempty"`
	ScoreDelta    int    `json:"score_delta,omitempty"`
	LatencyMS     int64  `json:"latency_ms,omitempty"`
	FailPolicy    string `json:"fail_policy,omitempty"`
	ActionTaken   string `json:"action_taken,omitempty"`
	Error         string `json:"error,omitempty"`
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
		e.JWT.TokenBindingVerified = sanitize(e.JWT.TokenBindingVerified, 32)
		e.JWT.EvaluatedAt = sanitize(e.JWT.EvaluatedAt, 64)
	}
	if e.Bot != nil {
		e.Bot.Mode = sanitize(e.Bot.Mode, 16)
		e.Bot.Reason = sanitize(e.Bot.Reason, 64)
		e.Bot.FlowID = sanitize(e.Bot.FlowID, 32)
		e.Bot.KeyID = sanitize(e.Bot.KeyID, 64)
		e.Bot.ResponseNote = sanitize(e.Bot.ResponseNote, maxMsgLen)
	}
	if e.AICrawl != nil {
		ac := *e.AICrawl
		ac.Mode = sanitize(ac.Mode, 16)
		ac.Category = sanitize(ac.Category, 32)
		ac.AgentID = sanitize(ac.AgentID, maxVerLen)
		ac.AgentSlug = sanitize(ac.AgentSlug, maxVerLen)
		ac.AgentName = sanitize(ac.AgentName, maxVerLen)
		ac.SignatureAgent = sanitize(ac.SignatureAgent, maxChainSummaryLen)
		ac.SignatureKeyID = sanitize(ac.SignatureKeyID, maxVerLen)
		ac.SignatureReason = sanitize(ac.SignatureReason, 64)
		ac.RuleID = sanitize(ac.RuleID, maxVerLen)
		ac.RuleName = sanitize(ac.RuleName, maxVerLen)
		ac.Action = sanitize(ac.Action, 32)
		e.AICrawl = &ac
	}
	if e.ClientSide != nil {
		cs := *e.ClientSide
		cs.Mode = sanitize(cs.Mode, 16)
		cs.ViolationType = sanitize(cs.ViolationType, 32)
		cs.ScriptURL = sanitize(cs.ScriptURL, 1024)
		cs.ScriptOrigin = sanitize(cs.ScriptOrigin, 256)
		cs.ScriptType = sanitize(cs.ScriptType, 16)
		cs.ExpectedSRI = sanitize(cs.ExpectedSRI, 256)
		cs.ObservedSRI = sanitize(cs.ObservedSRI, 256)
		cs.PagePath = sanitize(cs.PagePath, maxPathLen)
		cs.ViolatedDirective = sanitize(cs.ViolatedDirective, 128)
		cs.BlockedURI = sanitize(cs.BlockedURI, 1024)
		cs.ActionTaken = sanitize(cs.ActionTaken, 32)
		cs.Reason = sanitize(cs.Reason, maxMsgLen)
		e.ClientSide = &cs
	}
	if e.A2A != nil {
		a2 := *e.A2A
		a2.Mode = sanitize(a2.Mode, 16)
		a2.Method = sanitize(a2.Method, 128)
		a2.AgentName = sanitize(a2.AgentName, 256)
		a2.AgentURL = sanitize(a2.AgentURL, 512)
		a2.AgentVersion = sanitize(a2.AgentVersion, 64)
		a2.RuleID = sanitize(a2.RuleID, 128)
		a2.ActionTaken = sanitize(a2.ActionTaken, 32)
		a2.Reason = sanitize(a2.Reason, maxMsgLen)
		if len(a2.Skills) > 0 {
			n := len(a2.Skills)
			if n > 32 {
				n = 32
			}
			skills := make([]string, 0, n)
			for i := 0; i < n; i++ {
				if s := sanitize(a2.Skills[i], 128); s != "" {
					skills = append(skills, s)
				}
			}
			a2.Skills = skills
		}
		if len(a2.AuthSchemes) > 0 {
			n := len(a2.AuthSchemes)
			if n > 16 {
				n = 16
			}
			schemes := make([]string, 0, n)
			for i := 0; i < n; i++ {
				if s := sanitize(a2.AuthSchemes[i], 64); s != "" {
					schemes = append(schemes, s)
				}
			}
			a2.AuthSchemes = schemes
		}
		e.A2A = &a2
	}
	if e.Semantic != nil {
		sm := *e.Semantic
		sm.Mode = sanitize(sm.Mode, 16)
		sm.Channel = sanitize(sm.Channel, 32)
		sm.RuleID = sanitize(sm.RuleID, 128)
		sm.Label = sanitize(sm.Label, 64)
		sm.ModelID = sanitize(sm.ModelID, maxVerLen)
		sm.FailPolicy = sanitize(sm.FailPolicy, 16)
		sm.ActionTaken = sanitize(sm.ActionTaken, 32)
		sm.Reason = sanitize(sm.Reason, maxMsgLen)
		e.Semantic = &sm
	}
	if e.WasmPlugin != nil {
		wp := *e.WasmPlugin
		wp.PluginID = sanitize(wp.PluginID, maxVerLen)
		wp.PluginName = sanitize(wp.PluginName, maxVerLen)
		wp.ABIVersion = sanitize(wp.ABIVersion, 32)
		wp.Mode = sanitize(wp.Mode, 16)
		wp.SHA256 = sanitize(wp.SHA256, 64)
		wp.RuleID = sanitize(wp.RuleID, 128)
		wp.Reason = sanitize(wp.Reason, 128)
		wp.FailPolicy = sanitize(wp.FailPolicy, 16)
		wp.ActionTaken = sanitize(wp.ActionTaken, 32)
		wp.Error = sanitize(wp.Error, 256)
		e.WasmPlugin = &wp
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
