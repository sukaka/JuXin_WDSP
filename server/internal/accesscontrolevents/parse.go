// Package accesscontrolevents 提供访问控制事件（IP黑白名单/CC防护）的解析、存储、查询与采集。
package accesscontrolevents

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 事件类型（网关 jiuzhang_guard 产生 + 管理面到期/解封补齐）
const (
	EventTypeIPAllowMatch        = "IP_ALLOW_MATCH"
	EventTypeURLAllowMatch       = "URL_ALLOW_MATCH"
	EventTypeIPDenyMatch         = "IP_DENY_MATCH"
	EventTypeCCTempBlockCreated  = "CC_TEMP_BLOCK_CREATED"
	EventTypeCCTempBlockExpired  = "CC_TEMP_BLOCK_EXPIRED"
	EventTypeCCTempBlockReleased = "CC_TEMP_BLOCK_RELEASED"
	EventTypeCCThresholdExceeded = "CC_THRESHOLD_EXCEEDED"
	EventTypeCCRequestRejected   = "CC_REQUEST_REJECTED"
	// EventTypeCCTempBlockDowngraded 阶段5 §十五：管理面共享出口（NAT）风险检查
	// 命中后对 CC 自动封禁降档缩短时长的审计事件（temporaryblocks 产生，
	// 证据载荷 identity_count/threshold/block_minutes/原与降档到期时间/valkey_synced
	// 落 details.nat_guard；非 CC 拦截动作，不计入 CC 统计——isRejected 精确匹配
	// CC_REQUEST_REJECTED/CC_TEMP_BLOCK_CREATED，本类型天然不落入）。
	EventTypeCCTempBlockDowngraded = "CC_TEMP_BLOCK_DOWNGRADED"
)

// L7 访问控制命中事件类型（网关 jiuzhang_guard L7 规则引擎产生，access_rule_id 存 L7 规则 ID）
const (
	EventTypeL7RuleAllow    = "L7_RULE_ALLOW"
	EventTypeL7RuleBlock    = "L7_RULE_BLOCK"
	EventTypeL7RuleRedirect = "L7_RULE_REDIRECT"
	EventTypeL7RuleCustom   = "L7_RULE_CUSTOM"
)

// L7RuleEventTypes 全部 L7 命中事件类型（事件过滤与规则命中聚合用）。
var L7RuleEventTypes = []string{
	EventTypeL7RuleAllow, EventTypeL7RuleBlock, EventTypeL7RuleRedirect, EventTypeL7RuleCustom,
}

// 身份风险处置事件类型（WDSP AI 自动化渗透防护增强 阶段3；网关 jiuzhang_guard
// 按 security_risk_policy 处置产生——身份风险分达 block_threshold 阻断 /
// 达非零 challenge_threshold 挑战 / 达 rate_limit_threshold 限速；
// OBSERVE 模式仅观测上报 would_* 动作，challenged 映射 CHALLENGE 而非 REJECT）。
// 证据载荷（identity_key/score/risk_level/threshold/signals/mode/policy_version/
// action_taken/reason）落 access_control_events.details JSONB 列（迁移 000101；
// 表无专用列），不产生 temporary_blocks 记录、不计入 CC 统计（event_type 独立取值，
// 各 CC 消费方按 CC_* 精确匹配，互不污染）。
const (
	EventTypeRiskPolicyBlock     = "RISK_POLICY_BLOCK"
	EventTypeRiskPolicyRateLimit = "RISK_POLICY_RATE_LIMIT"
	EventTypeRiskPolicyChallenge = "RISK_POLICY_CHALLENGE"
)

// JWT 信任链事件类型（WDSP P0-03；网关 jiuzhang_guard jwt_trust 段验证处置产生——
// JWT_OBSERVED 为 OBSERVE 模式的放行记录（action=OBSERVE），JWT_AUTH_FAILED 为
// PROTECT 认证失败 401（action=REJECT），JWT_UNAVAILABLE 为 PROTECT 验证基础设施
// 不可用 503（action=REJECT，不伪装成 Token 错误）。验证摘要嵌套在网关事件的
// jwt_verification 对象下，落 access_control_events.details JSONB 列（与
// RISK_POLICY_* 同一落点纪律；不落原始 Token/payload/明文 sub/tenant——
// verified_principal_id 为 HMAC 主体指纹，verified_tenant_id 为加盐指纹）。
const (
	EventTypeJWTObserved    = "JWT_OBSERVED"
	EventTypeJWTAuthFailed  = "JWT_AUTH_FAILED"
	EventTypeJWTUnavailable = "JWT_UNAVAILABLE"
)

// Bot 挑战事件类型（WDSP P1-02 B2/B3；网关 jiuzhang_guard botchallenge 包产生——
// BOT_CHALLENGE_OFFERED 挑战提出（PROTECT 403 挑战页 / OBSERVE 仅记录），
// BOT_VERIFY_SUCCESS/REJECTED 验证结果，BOT_CHALLENGE_EXPIRED nonce/通行过期或
// 重放，BOT_STATE_UNAVAILABLE 共享状态/密钥不可用（PROTECT fail-closed 503），
// BOT_CLEARANCE_ACCEPTED 有效通行放行）。挑战明细嵌套在网关事件的 bot 对象下，
// 落 access_control_events.details JSONB 列（与 RISK_POLICY_*/JWT_* 同一落点纪律；
// 不落 nonce/solution/通行 Cookie/会话 Cookie/签名材料——flow_id 为挑战 ID 的
// SHA-256 截断指纹，key_id 仅密钥引用名）。
const (
	EventTypeBotChallengeOffered  = "BOT_CHALLENGE_OFFERED"
	EventTypeBotVerifySuccess     = "BOT_VERIFY_SUCCESS"
	EventTypeBotVerifyRejected    = "BOT_VERIFY_REJECTED"
	EventTypeBotChallengeExpired  = "BOT_CHALLENGE_EXPIRED"
	EventTypeBotStateUnavailable  = "BOT_STATE_UNAVAILABLE"
	EventTypeBotClearanceAccepted = "BOT_CLEARANCE_ACCEPTED"
)

// BotEventTypes 全部 Bot 挑战事件类型（事件过滤用）。
var BotEventTypes = []string{
	EventTypeBotChallengeOffered, EventTypeBotVerifySuccess, EventTypeBotVerifyRejected,
	EventTypeBotChallengeExpired, EventTypeBotStateUnavailable, EventTypeBotClearanceAccepted,
}

// 客户端供应链安全事件类型（Phase 9B；PCI DSS 4.0 6.4.3 & 11.6.1；
// 网关 jiuzhang_guard clientside 包产生——明细嵌套在 client_side 对象下，
// 落 access_control_events.details.client_side JSONB 列，并经 Collector 旁路回流
// client_script_inventory / client_side_violations 表）。
const (
	EventTypeClientSideScriptObserved     = "CLIENT_SIDE_SCRIPT_OBSERVED"
	EventTypeClientSideUnauthorizedScript = "CLIENT_SIDE_UNAUTHORIZED_SCRIPT"
	EventTypeClientSideScriptTampered     = "CLIENT_SIDE_SCRIPT_TAMPERED"
	EventTypeClientSideCSPViolation       = "CLIENT_SIDE_CSP_VIOLATION"
	EventTypeClientSideProbeAlert         = "CLIENT_SIDE_PROBE_ALERT"
)

// ClientSideEventTypes 全部客户端供应链安全事件类型。
var ClientSideEventTypes = []string{
	EventTypeClientSideScriptObserved,
	EventTypeClientSideUnauthorizedScript,
	EventTypeClientSideScriptTampered,
	EventTypeClientSideCSPViolation,
	EventTypeClientSideProbeAlert,
}

// A2A 协议安全治理事件类型（Phase 9C-1；网关 jiuzhang_guard apia2a/a2aguard 包产生——
// 明细嵌套在 a2a 对象下，落 access_control_events.details.a2a JSONB 列，并经 Collector
// 旁路回流 api_a2a_agents（AgBOM 发现）与 api_a2a_events 表）。
const (
	EventTypeA2AAgentCardDiscovered = "A2A_AGENT_CARD_DISCOVERED"
	EventTypeA2AObserved            = "A2A_OBSERVED"
	EventTypeA2ABlocked             = "A2A_BLOCKED"
	EventTypeA2ALoopKilled          = "A2A_LOOP_KILLED"
	EventTypeA2ALethalTrifecta      = "A2A_LETHAL_TRIFECTA"
)

// A2AEventTypes 全部 A2A 协议安全事件类型。
var A2AEventTypes = []string{
	EventTypeA2AAgentCardDiscovered,
	EventTypeA2AObserved,
	EventTypeA2ABlocked,
	EventTypeA2ALoopKilled,
	EventTypeA2ALethalTrifecta,
}

// 本地离线 ONNX/SLM 语义防火墙事件类型（Phase 9C-2；网关 jiuzhang_guard apisemantic/semantic 包产生——
// 明细嵌套在 semantic 对象下，落 access_control_events.details.semantic JSONB 列；
// 绝不落原始 Prompt/请求体/响应体原文，仅保留通道、标签、分数、模型 ID、耗时与截断字符数等结构化元数据）。
const (
	EventTypeSemanticObserved    = "SEMANTIC_OBSERVED"
	EventTypeSemanticBlocked     = "SEMANTIC_BLOCKED"
	EventTypeSemanticUnavailable = "SEMANTIC_UNAVAILABLE"
)

// SemanticEventTypes 全部本地语义防火墙事件类型。
var SemanticEventTypes = []string{
	EventTypeSemanticObserved,
	EventTypeSemanticBlocked,
	EventTypeSemanticUnavailable,
}

// Wasm 自定义检测插件沙箱事件类型（Phase 9D-1；网关 jiuzhang_guard apiwasm/wasmplugin 包产生——
// 明细嵌套在 wasm_plugin 对象下，落 access_control_events.details.wasm_plugin JSONB 列；
// 绝不落原始 wasm_binary/wasm_base64/请求体或凭据头原文）。
const (
	EventTypeWasmPluginObserved  = "WASM_PLUGIN_OBSERVED"
	EventTypeWasmPluginBlock     = "WASM_PLUGIN_BLOCK"
	EventTypeWasmPluginRateLimit = "WASM_PLUGIN_RATE_LIMIT"
	EventTypeWasmPluginError     = "WASM_PLUGIN_ERROR"
)

// WasmPluginEventTypes 全部 Wasm 检测插件事件类型。
var WasmPluginEventTypes = []string{
	EventTypeWasmPluginObserved,
	EventTypeWasmPluginBlock,
	EventTypeWasmPluginRateLimit,
	EventTypeWasmPluginError,
}

// 风险处置动作契约（action_taken → 事件 action 列映射；blocked/rate_limited
// 为实际拒绝记 REJECT，challenged 记 CHALLENGE，OBSERVE 模式的 would_* 记 OBSERVE）。
var riskPolicyActionTaken = map[string]string{
	"blocked":          ActionReject,
	"rate_limited":     ActionReject,
	"challenged":       ActionChallenge,
	"would_block":      ActionObserve,
	"would_rate_limit": ActionObserve,
	"would_challenge":  ActionObserve,
}

// 动作
const (
	ActionLog       = "LOG"
	ActionObserve   = "OBSERVE"
	ActionReject    = "REJECT"
	ActionChallenge = "CHALLENGE"
	ActionTempBlock = "TEMP_BLOCK"
)

// Event 是一条访问控制事件。
type Event struct {
	ID              uuid.UUID  `json:"id"`
	RequestID       string     `json:"request_id"`
	OccurredAt      time.Time  `json:"occurred_at"`
	ApplicationID   *uuid.UUID `json:"application_id"`
	ApplicationCode string     `json:"application_code"`
	ClientIP        string     `json:"client_ip"`
	ConnectionIP    string     `json:"connection_ip"`
	// 阶段5 §6.5 真实 IP 识别日志字段（迁移 000144；旧数据为 NULL，读取侧归一空串）
	ClientIPSource        string     `json:"client_ip_source"`
	TrustedProxyUsed      string     `json:"trusted_proxy_used"`
	ForwardedChainSummary string     `json:"forwarded_chain_summary"`
	Domain                string     `json:"domain"`
	RequestMethod         string     `json:"request_method"`
	RequestPath           string     `json:"request_path"`
	EventType             string     `json:"event_type"`
	Action                string     `json:"action"`
	PolicyID              string     `json:"policy_id"`
	AccessRuleID          string     `json:"access_rule_id"`
	CurrentCount          *int64     `json:"current_count"`
	LimitValue            *int64     `json:"limit_value"`
	WindowSeconds         *int       `json:"window_seconds"`
	BlockExpiresAt        *time.Time `json:"block_expires_at"`
	ResponseStatus        *int       `json:"response_status"`
	GatewayNodeID         string     `json:"gateway_node_id"`
	Message               string     `json:"message"`
	// Proto HTTP 协议版本（HTTP/1.1/2/3，W20 起网关上报；缺失为空串，容忍，落库为 NULL）。
	Proto string `json:"proto"`
	// Details 证据载荷（风险处置事件 RISK_POLICY_*：identity_key/score/risk_level/
	// threshold/signals/mode/policy_version/action_taken/reason；JWT_*：jwt_verification
	// 嵌套对象；BOT_*：bot 嵌套对象；其余事件类型为空对象，
	// 落 access_control_events.details JSONB 列，迁移 000101）。
	Details   map[string]interface{} `json:"details"`
	CreatedAt time.Time              `json:"created_at"`
}

// rawEvent 是网关 guard 事件 JSONL 行结构。
type rawEvent struct {
	RequestID       string `json:"request_id"`
	OccurredAt      string `json:"occurred_at"`
	ApplicationID   string `json:"application_id"`
	ApplicationCode string `json:"application_code"`
	ClientIP        string `json:"client_ip"`
	ConnectionIP    string `json:"connection_ip"`
	// 阶段5 §6.5 真实 IP 识别日志字段（网关事件 omitempty 键；旧网关/历史事件
	// 无此键，缺省容忍，不回填）
	ClientIPSource        string     `json:"client_ip_source"`
	TrustedProxyUsed      string     `json:"trusted_proxy_used"`
	ForwardedChainSummary string     `json:"forwarded_chain_summary"`
	Domain                string     `json:"domain"`
	RequestMethod         string     `json:"request_method"`
	RequestPath           string     `json:"request_path"`
	EventType             string     `json:"event_type"`
	Action                string     `json:"action"`
	PolicyID              string     `json:"policy_id"`
	AccessRuleID          string     `json:"access_rule_id"`
	CurrentCount          *int64     `json:"current_count"`
	LimitValue            *int64     `json:"limit_value"`
	WindowSeconds         *int       `json:"window_seconds"`
	BlockExpiresAt        *time.Time `json:"block_expires_at"`
	ResponseStatus        *int       `json:"response_status"`
	GatewayNodeID         string     `json:"gateway_node_id"`
	Message               string     `json:"message"`
	Proto                 string     `json:"proto"`
	// 身份风险处置事件扩展字段（RISK_POLICY_* 契约：网关将证据载荷嵌套在 "risk"
	// 对象下，见 events.RiskPolicyDetail 线格式；其余事件类型不出现，缺省容忍）。
	Risk *rawRiskDetail `json:"risk"`
	// JWT 信任链验证摘要（JWT_* 契约：网关将验证摘要嵌套在 "jwt_verification"
	// 对象下；其余事件类型不出现，缺省容忍——历史事件无此键，不回填）。
	JWT *rawJWTVerification `json:"jwt_verification"`
	// FinalDecision 请求最终处置上下文（WDSP P0-04：网关终止分支事件挂载
	// final_decision JSON schema_version=1；其余事件不出现，缺省容忍——历史
	// 事件无此键，不回填）。统一合并进 details.final_decision（迁移 000101
	// 先例：证据载荷落 details JSONB 列，不新增表）。
	FinalDecision json.RawMessage `json:"final_decision"`
	// Bot Bot 挑战明细（BOT_* 契约：网关将挑战明细嵌套在 "bot" 对象下，
	// 见 events.BotDetail 线格式；其余事件类型不出现，缺省容忍——历史事件
	// 无此键，不回填）。采集端仅按声明字段落 details.bot：未声明字段
	// （nonce/solution/Cookie/签名材料等）在解码期即被丢弃，不落库。
	Bot *rawBotDetail `json:"bot"`
	// ClientSide 客户端供应链安全事件明细（CLIENT_SIDE_* 契约：网关将明细嵌套在
	// "client_side" 对象下，仅按声明字段落 details.client_side，未声明字段解码期丢弃）。
	ClientSide *rawClientSideDetail `json:"client_side"`
	// A2A 协议安全事件明细（A2A_* 契约：网关将明细嵌套在 "a2a" 对象下，
	// 仅按声明字段落 details.a2a，未声明字段解码期丢弃）。
	A2A *rawA2ADetail `json:"a2a"`
	// Semantic 本地离线语义防火墙事件明细（SEMANTIC_* 契约：网关将明细嵌套在 "semantic" 对象下，
	// 仅按声明字段落 details.semantic，未声明字段（如 raw prompt/body）解码期即丢弃）。
	Semantic *rawSemanticDetail `json:"semantic"`
	// WasmPlugin Wasm 检测插件事件明细（WASM_PLUGIN_* 契约：网关将明细嵌套在 "wasm_plugin" 对象下，
	// 仅按声明字段落 details.wasm_plugin，未声明字段解码期即丢弃）。
	WasmPlugin *rawWasmPluginDetail `json:"wasm_plugin"`
}

// rawWasmPluginDetail WASM_PLUGIN_* 事件的嵌套明细（与网关 events.WasmPluginDetail 同形；
// 独立定义防循环依赖，且由类型系统保证未声明敏感字段在解码期丢弃）。
type rawWasmPluginDetail struct {
	PluginID      string `json:"plugin_id"`
	PluginName    string `json:"plugin_name"`
	PluginVersion *int   `json:"plugin_version"`
	ABIVersion    string `json:"abi_version"`
	Mode          string `json:"mode"`
	SHA256        string `json:"sha256"`
	RuleID        string `json:"rule_id"`
	Reason        string `json:"reason"`
	ScoreDelta    *int   `json:"score_delta"`
	LatencyMs     *int64 `json:"latency_ms"`
	FailPolicy    string `json:"fail_policy"`
	ActionTaken   string `json:"action_taken"`
	Error         string `json:"error"`
}

// rawSemanticDetail SEMANTIC_* 事件的嵌套明细（与网关 events.SemanticDetail 同形；
// 独立定义防循环依赖，且由类型系统保证原始提示词/请求体/凭据等未声明字段在解码期丢弃）。
type rawSemanticDetail struct {
	PolicyVersion *int     `json:"policy_version"`
	Mode          string   `json:"mode"`
	Channel       string   `json:"channel"`
	RuleID        string   `json:"rule_id"`
	Label         string   `json:"label"`
	Score         *float64 `json:"score"`
	ModelID       string   `json:"model_id"`
	LatencyMs     *int64   `json:"latency_ms"`
	InputRunes    *int     `json:"input_runes"`
	FailPolicy    string   `json:"fail_policy"`
	ActionTaken   string   `json:"action_taken"`
	Reason        string   `json:"reason"`
}

// rawA2ADetail A2A_* 事件的嵌套明细（与网关 events.A2ADetail 同形；
// 独立定义防循环依赖，且由类型系统保证未声明字段在解码期丢弃）。
type rawA2ADetail struct {
	PolicyVersion   *int     `json:"policy_version"`
	Mode            string   `json:"mode"`
	Method          string   `json:"method"`
	AgentName       string   `json:"agent_name"`
	AgentURL        string   `json:"agent_url"`
	AgentVersion    string   `json:"agent_version"`
	Skills          []string `json:"skills"`
	AuthSchemes     []string `json:"auth_schemes"`
	DelegationDepth *int     `json:"delegation_depth"`
	RuleID          string   `json:"rule_id"`
	ActionTaken     string   `json:"action_taken"`
	Reason          string   `json:"reason"`
}

// rawClientSideDetail CLIENT_SIDE_* 事件的嵌套明细（与网关 events.ClientSideDetail 同形；
// 独立定义防循环依赖，且由类型系统保证未声明字段在解码期丢弃）。
type rawClientSideDetail struct {
	PolicyVersion     *int   `json:"policy_version"`
	Mode              string `json:"mode"`
	ViolationType     string `json:"violation_type"`
	ScriptURL         string `json:"script_url"`
	ScriptOrigin      string `json:"script_origin"`
	ScriptType        string `json:"script_type"`
	ExpectedSRI       string `json:"expected_sri"`
	ObservedSRI       string `json:"observed_sri"`
	PagePath          string `json:"page_path"`
	ViolatedDirective string `json:"violated_directive"`
	BlockedURI        string `json:"blocked_uri"`
	ActionTaken       string `json:"action_taken"`
	Reason            string `json:"reason"`
}

// rawBotDetail BOT_* 事件的嵌套挑战明细（与网关 events.BotDetail 同形；
// 事件侧独立定义防循环依赖，与 rawRiskDetail/rawJWTVerification 同一纪律）。
// 只声明允许落库的字段——nonce/solution/通行 Cookie/会话 Cookie/签名材料
// 无对应字段，即使网关火线出现异常字段也在解码期丢弃（脱敏由类型系统保证）。
type rawBotDetail struct {
	PolicyVersion *int   `json:"policy_version"` // 策略有效版本（缺省容忍，不落 NULL 键）
	PolicyEpoch   *int   `json:"policy_epoch"`   // 撤销代次（B2 冻结 = 策略版本）
	Mode          string `json:"mode"`           // OBSERVE|PROTECT
	Reason        string `json:"reason"`         // 结构化理由码
	FlowID        string `json:"flow_id"`        // 挑战 ID 的 SHA-256 截断指纹（脱敏关联）
	KeyID         string `json:"key_id"`         // 验签密钥引用名（非密钥材料）
	Attempts      *int   `json:"attempts"`       // 已消费验证尝试次数（verify 结果事件）
	ResponseNote  string `json:"note"`           // 补充说明（静态文本）
}

// rawJWTVerification JWT_* 事件的嵌套验证摘要（与网关 dynamic_security/events
// .JWTVerification 同形；事件侧独立定义防循环依赖，与 rawRiskDetail 同一纪律）。
type rawJWTVerification struct {
	Status              string `json:"status"`
	ReasonCode          string `json:"reason_code"`
	PolicyVersion       string `json:"policy_version"`
	IssuerConfigID      string `json:"issuer_config_id"`
	KeysetVersion       string `json:"keyset_version"`
	VerifiedPrincipalID string `json:"verified_principal_id"`
	VerifiedTenantID    string `json:"verified_tenant_id"`
	EvaluatedAt         string `json:"evaluated_at"`
}

// rawRiskDetail RISK_POLICY_* 事件的嵌套证据对象（与网关 events.RiskPolicyDetail 同形）。
type rawRiskDetail struct {
	IdentityKey   string          `json:"identity_key"`
	Score         *int            `json:"score"`
	RiskLevel     string          `json:"risk_level"`
	Threshold     *int            `json:"threshold"`
	Signals       json.RawMessage `json:"signals"`
	Mode          string          `json:"mode"`
	PolicyVersion interface{}     `json:"policy_version"` // 数值或字符串均容忍，原样落 details
	ActionTaken   string          `json:"action_taken"`
	Reason        string          `json:"reason"`
}

// ParseEventLine 解析单行 guard 事件 JSONL。defaultNode 为事件缺省网关节点。
// 解析失败的行由采集器写入错误文件，不得静默丢弃。
func ParseEventLine(line []byte, defaultNode string) (*Event, error) {
	line = []byte(strings.TrimSpace(string(line)))
	if len(line) == 0 {
		return nil, fmt.Errorf("empty line")
	}
	var raw rawEvent
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, fmt.Errorf("invalid event json: %w", err)
	}
	if raw.EventType == "" {
		return nil, fmt.Errorf("missing event_type")
	}
	if raw.OccurredAt == "" {
		return nil, fmt.Errorf("missing occurred_at")
	}
	occurredAt, err := time.Parse(time.RFC3339Nano, raw.OccurredAt)
	if err != nil {
		return nil, fmt.Errorf("invalid occurred_at: %w", err)
	}
	if raw.ClientIP == "" {
		return nil, fmt.Errorf("missing client_ip")
	}
	clientIP, err := netip.ParseAddr(raw.ClientIP)
	if err != nil {
		return nil, fmt.Errorf("invalid client_ip %q: %w", raw.ClientIP, err)
	}
	var connIP string
	if raw.ConnectionIP != "" {
		addr, err := netip.ParseAddr(raw.ConnectionIP)
		if err != nil {
			return nil, fmt.Errorf("invalid connection_ip %q: %w", raw.ConnectionIP, err)
		}
		connIP = addr.String()
	}
	var appID *uuid.UUID
	if raw.ApplicationID != "" {
		id, err := uuid.Parse(raw.ApplicationID)
		if err != nil {
			return nil, fmt.Errorf("invalid application_id %q: %w", raw.ApplicationID, err)
		}
		appID = &id
	}

	evt := &Event{
		RequestID:             truncate(raw.RequestID, 64),
		OccurredAt:            occurredAt.UTC(),
		ApplicationID:         appID,
		ApplicationCode:       truncate(raw.ApplicationCode, 64),
		ClientIP:              clientIP.String(),
		ConnectionIP:          connIP,
		ClientIPSource:        truncate(raw.ClientIPSource, 32),
		TrustedProxyUsed:      truncate(raw.TrustedProxyUsed, 128),
		ForwardedChainSummary: truncate(raw.ForwardedChainSummary, 256),
		Domain:                truncate(raw.Domain, 255),
		RequestMethod:         truncate(raw.RequestMethod, 10),
		RequestPath:           truncate(raw.RequestPath, 512),
		EventType:             truncate(raw.EventType, 40),
		Action:                truncate(raw.Action, 20),
		PolicyID:              truncate(raw.PolicyID, 64),
		AccessRuleID:          truncate(raw.AccessRuleID, 64),
		CurrentCount:          raw.CurrentCount,
		LimitValue:            raw.LimitValue,
		WindowSeconds:         raw.WindowSeconds,
		BlockExpiresAt:        raw.BlockExpiresAt,
		ResponseStatus:        raw.ResponseStatus,
		GatewayNodeID:         truncate(raw.GatewayNodeID, 100),
		Message:               truncate(raw.Message, 512),
		Proto:                 truncate(raw.Proto, 32),
	}
	if evt.GatewayNodeID == "" {
		evt.GatewayNodeID = defaultNode
	}
	if evt.EventType == EventTypeRiskPolicyBlock || evt.EventType == EventTypeRiskPolicyRateLimit || evt.EventType == EventTypeRiskPolicyChallenge {
		if err := applyRiskPolicyEvent(evt, &raw); err != nil {
			return nil, err
		}
	}
	if evt.EventType == EventTypeJWTObserved || evt.EventType == EventTypeJWTAuthFailed || evt.EventType == EventTypeJWTUnavailable {
		if err := applyJWTEvent(evt, &raw); err != nil {
			return nil, err
		}
	}
	if isBotEventType(evt.EventType) {
		if err := applyBotEvent(evt, &raw); err != nil {
			return nil, err
		}
	}
	if isClientSideEventType(evt.EventType) {
		if err := applyClientSideEvent(evt, &raw); err != nil {
			return nil, err
		}
	}
	if isA2AEventType(evt.EventType) {
		if err := applyA2AEvent(evt, &raw); err != nil {
			return nil, err
		}
	}
	if isSemanticEventType(evt.EventType) {
		if err := applySemanticEvent(evt, &raw); err != nil {
			return nil, err
		}
	}
	if isWasmPluginEventType(evt.EventType) {
		if err := applyWasmPluginEvent(evt, &raw); err != nil {
			return nil, err
		}
	}
	// P0-04：final_decision 统一合并进 details（所有事件类型；risk/jwt 分支已设
	// Details 时合并而非覆盖）。校验是合法 JSON 对象，非法则解析失败入错误文件
	// （与 applyRiskPolicyEvent 同一纪律：不静默落库）
	if len(raw.FinalDecision) > 0 {
		var fd map[string]interface{}
		if err := json.Unmarshal(raw.FinalDecision, &fd); err != nil {
			return nil, fmt.Errorf("invalid final_decision: %w", err)
		}
		if evt.Details == nil {
			evt.Details = map[string]interface{}{}
		}
		evt.Details["final_decision"] = fd
	}
	return evt, nil
}

// applyJWTEvent 校验 JWT 信任链事件并填充 details 证据载荷（jwt_verification
// 对象缺失或 status/reason_code 为空 → 解析失败入错误文件，不静默落库；
// 与 applyRiskPolicyEvent 同一纪律）。action 列沿用网关上报值（OBSERVE/REJECT）。
func applyJWTEvent(evt *Event, raw *rawEvent) error {
	jwt := raw.JWT
	if jwt == nil || jwt.Status == "" || jwt.ReasonCode == "" {
		return fmt.Errorf("jwt trust event missing jwt_verification.status/reason_code")
	}
	details := map[string]interface{}{
		"status":      truncate(jwt.Status, 32),
		"reason_code": truncate(jwt.ReasonCode, 32),
	}
	if jwt.PolicyVersion != "" {
		details["policy_version"] = truncate(jwt.PolicyVersion, 128)
	}
	if jwt.IssuerConfigID != "" {
		details["issuer_config_id"] = truncate(jwt.IssuerConfigID, 128)
	}
	if jwt.KeysetVersion != "" {
		details["keyset_version"] = truncate(jwt.KeysetVersion, 128)
	}
	if jwt.VerifiedPrincipalID != "" {
		details["verified_principal_id"] = truncate(jwt.VerifiedPrincipalID, 128)
	}
	if jwt.VerifiedTenantID != "" {
		details["verified_tenant_id"] = truncate(jwt.VerifiedTenantID, 128)
	}
	if jwt.EvaluatedAt != "" {
		details["evaluated_at"] = truncate(jwt.EvaluatedAt, 64)
	}
	evt.Details = map[string]interface{}{"jwt_verification": details}
	return nil
}

// isBotEventType 判定 Bot 挑战事件类型（BOT_*；未知事件类型不进入本分支，
// 按既有通用字段落库——旧采集端对新类型保持容忍）。
func isBotEventType(t string) bool {
	switch t {
	case EventTypeBotChallengeOffered, EventTypeBotVerifySuccess, EventTypeBotVerifyRejected,
		EventTypeBotChallengeExpired, EventTypeBotStateUnavailable, EventTypeBotClearanceAccepted:
		return true
	}
	return false
}

// applyBotEvent 校验 Bot 挑战事件并填充 details.bot 证据载荷（bot 对象缺失或
// mode/reason 为空 → 解析失败入错误文件，不静默落库；与 applyJWTEvent 同一纪律）。
// action 列沿用网关上报值（CHALLENGE/OBSERVE/REJECT/PASS——挑战与业务成功分属
// 不同请求，经 details.bot.flow_id 脱敏关联，任务书 §6）。
// 脱敏断言由类型系统保证：rawBotDetail 不声明 nonce/solution/Cookie/会话/签名
// 材料字段，解码期即丢弃；details 仅含下列显式键。
func applyBotEvent(evt *Event, raw *rawEvent) error {
	bot := raw.Bot
	if bot == nil || bot.Mode == "" || bot.Reason == "" {
		return fmt.Errorf("bot event missing bot.mode/reason")
	}
	details := map[string]interface{}{
		"mode":   truncate(bot.Mode, 16),
		"reason": truncate(bot.Reason, 64),
	}
	if bot.PolicyVersion != nil {
		details["policy_version"] = *bot.PolicyVersion
	}
	if bot.PolicyEpoch != nil {
		details["policy_epoch"] = *bot.PolicyEpoch
	}
	if bot.FlowID != "" {
		details["flow_id"] = truncate(bot.FlowID, 128)
	}
	if bot.KeyID != "" {
		details["key_id"] = truncate(bot.KeyID, 64)
	}
	if bot.Attempts != nil {
		details["attempts"] = *bot.Attempts
	}
	if bot.ResponseNote != "" {
		details["note"] = truncate(bot.ResponseNote, 256)
	}
	evt.Details = map[string]interface{}{"bot": details}
	return nil
}

// isClientSideEventType 判定客户端供应链安全事件类型（CLIENT_SIDE_*）。
func isClientSideEventType(t string) bool {
	switch t {
	case EventTypeClientSideScriptObserved,
		EventTypeClientSideUnauthorizedScript,
		EventTypeClientSideScriptTampered,
		EventTypeClientSideCSPViolation,
		EventTypeClientSideProbeAlert:
		return true
	}
	return false
}

// applyClientSideEvent 校验 CLIENT_SIDE_* 事件并填充 details.client_side 证据载荷
// （client_side 对象缺失 → 解析失败入错误文件，不静默落库；未声明字段由类型系统丢弃）。
func applyClientSideEvent(evt *Event, raw *rawEvent) error {
	cs := raw.ClientSide
	if cs == nil {
		return fmt.Errorf("client side event missing client_side details")
	}
	details := map[string]interface{}{}
	if cs.PolicyVersion != nil {
		details["policy_version"] = *cs.PolicyVersion
	}
	if cs.Mode != "" {
		details["mode"] = truncate(cs.Mode, 16)
	}
	if cs.ViolationType != "" {
		details["violation_type"] = truncate(cs.ViolationType, 32)
	}
	if cs.ScriptURL != "" {
		details["script_url"] = truncate(cs.ScriptURL, 2048)
	}
	if cs.ScriptOrigin != "" {
		details["script_origin"] = truncate(cs.ScriptOrigin, 512)
	}
	if cs.ScriptType != "" {
		details["script_type"] = truncate(cs.ScriptType, 16)
	}
	if cs.ExpectedSRI != "" {
		details["expected_sri"] = truncate(cs.ExpectedSRI, 256)
	}
	if cs.ObservedSRI != "" {
		details["observed_sri"] = truncate(cs.ObservedSRI, 256)
	}
	if cs.PagePath != "" {
		details["page_path"] = truncate(cs.PagePath, 512)
	}
	if cs.ViolatedDirective != "" {
		details["violated_directive"] = truncate(cs.ViolatedDirective, 128)
	}
	if cs.BlockedURI != "" {
		details["blocked_uri"] = truncate(cs.BlockedURI, 2048)
	}
	if cs.ActionTaken != "" {
		details["action_taken"] = truncate(cs.ActionTaken, 32)
	}
	if cs.Reason != "" {
		details["reason"] = truncate(cs.Reason, 512)
	}
	evt.Details = map[string]interface{}{"client_side": details}
	return nil
}

// isA2AEventType 判定 A2A 协议安全事件类型（A2A_*）。
func isA2AEventType(t string) bool {
	switch t {
	case EventTypeA2AAgentCardDiscovered,
		EventTypeA2AObserved,
		EventTypeA2ABlocked,
		EventTypeA2ALoopKilled,
		EventTypeA2ALethalTrifecta:
		return true
	}
	return false
}

// applyA2AEvent 校验 A2A_* 事件并填充 details.a2a 证据载荷
// （a2a 对象缺失 → 解析失败入错误文件，不静默落库；未声明字段由类型系统丢弃）。
func applyA2AEvent(evt *Event, raw *rawEvent) error {
	a2a := raw.A2A
	if a2a == nil {
		return fmt.Errorf("a2a event missing a2a details")
	}
	details := map[string]interface{}{}
	if a2a.PolicyVersion != nil {
		details["policy_version"] = *a2a.PolicyVersion
	}
	if a2a.Mode != "" {
		details["mode"] = truncate(a2a.Mode, 16)
	}
	if a2a.Method != "" {
		details["method"] = truncate(a2a.Method, 128)
	}
	if a2a.AgentName != "" {
		details["agent_name"] = truncate(a2a.AgentName, 256)
	}
	if a2a.AgentURL != "" {
		details["agent_url"] = truncate(a2a.AgentURL, 2048)
	}
	if a2a.AgentVersion != "" {
		details["agent_version"] = truncate(a2a.AgentVersion, 64)
	}
	if len(a2a.Skills) > 0 {
		details["skills"] = clampStringSlice(a2a.Skills, 32, 128)
	}
	if len(a2a.AuthSchemes) > 0 {
		details["auth_schemes"] = clampStringSlice(a2a.AuthSchemes, 16, 64)
	}
	if a2a.DelegationDepth != nil {
		details["delegation_depth"] = *a2a.DelegationDepth
	}
	if a2a.RuleID != "" {
		details["rule_id"] = truncate(a2a.RuleID, 128)
	}
	if a2a.ActionTaken != "" {
		details["action_taken"] = truncate(a2a.ActionTaken, 32)
	}
	if a2a.Reason != "" {
		details["reason"] = truncate(a2a.Reason, 512)
	}
	evt.Details = map[string]interface{}{"a2a": details}
	return nil
}

// isSemanticEventType 判定本地语义防火墙事件类型（SEMANTIC_*）。
func isSemanticEventType(t string) bool {
	switch t {
	case EventTypeSemanticObserved,
		EventTypeSemanticBlocked,
		EventTypeSemanticUnavailable:
		return true
	}
	return false
}

// applySemanticEvent 校验 SEMANTIC_* 事件并填充 details.semantic 证据载荷
// （semantic 对象缺失 → 解析失败入错误文件，不静默落库；未声明字段由类型系统丢弃，绝不落原始文本）。
func applySemanticEvent(evt *Event, raw *rawEvent) error {
	sem := raw.Semantic
	if sem == nil {
		return fmt.Errorf("semantic event missing semantic details")
	}
	details := map[string]interface{}{}
	if sem.PolicyVersion != nil {
		details["policy_version"] = *sem.PolicyVersion
	}
	if sem.Mode != "" {
		details["mode"] = truncate(sem.Mode, 16)
	}
	if sem.Channel != "" {
		details["channel"] = truncate(sem.Channel, 32)
	}
	if sem.RuleID != "" {
		details["rule_id"] = truncate(sem.RuleID, 128)
	}
	if sem.Label != "" {
		details["label"] = truncate(sem.Label, 64)
	}
	if sem.Score != nil && !math.IsNaN(*sem.Score) && !math.IsInf(*sem.Score, 0) {
		details["score"] = *sem.Score
	}
	if sem.ModelID != "" {
		details["model_id"] = truncate(sem.ModelID, 128)
	}
	if sem.LatencyMs != nil {
		details["latency_ms"] = *sem.LatencyMs
	}
	if sem.InputRunes != nil {
		details["input_runes"] = *sem.InputRunes
	}
	if sem.FailPolicy != "" {
		details["fail_policy"] = truncate(sem.FailPolicy, 16)
	}
	if sem.ActionTaken != "" {
		details["action_taken"] = truncate(sem.ActionTaken, 32)
	}
	if sem.Reason != "" {
		details["reason"] = truncate(sem.Reason, 512)
	}
	evt.Details = map[string]interface{}{"semantic": details}
	return nil
}

// isWasmPluginEventType 判定 Wasm 检测插件事件类型（WASM_PLUGIN_*）。
func isWasmPluginEventType(t string) bool {
	switch t {
	case EventTypeWasmPluginObserved,
		EventTypeWasmPluginBlock,
		EventTypeWasmPluginRateLimit,
		EventTypeWasmPluginError:
		return true
	}
	return false
}

// applyWasmPluginEvent 校验 WASM_PLUGIN_* 事件并填充 details.wasm_plugin 证据载荷
// （wasm_plugin 对象缺失 → 解析失败入错误文件，不静默落库；未声明字段由类型系统丢弃）。
func applyWasmPluginEvent(evt *Event, raw *rawEvent) error {
	wp := raw.WasmPlugin
	if wp == nil {
		return fmt.Errorf("wasm plugin event missing wasm_plugin details")
	}
	details := map[string]interface{}{}
	if wp.PluginID != "" {
		details["plugin_id"] = truncate(wp.PluginID, 64)
	}
	if wp.PluginName != "" {
		details["plugin_name"] = truncate(wp.PluginName, 128)
	}
	if wp.PluginVersion != nil {
		details["plugin_version"] = *wp.PluginVersion
	}
	if wp.ABIVersion != "" {
		details["abi_version"] = truncate(wp.ABIVersion, 32)
	}
	if wp.Mode != "" {
		details["mode"] = truncate(wp.Mode, 16)
	}
	if wp.SHA256 != "" {
		details["sha256"] = truncate(wp.SHA256, 64)
	}
	if wp.RuleID != "" {
		details["rule_id"] = truncate(wp.RuleID, 128)
	}
	if wp.Reason != "" {
		details["reason"] = truncate(wp.Reason, 256)
	}
	if wp.ScoreDelta != nil {
		details["score_delta"] = *wp.ScoreDelta
	}
	if wp.LatencyMs != nil {
		details["latency_ms"] = *wp.LatencyMs
	}
	if wp.FailPolicy != "" {
		details["fail_policy"] = truncate(wp.FailPolicy, 16)
	}
	if wp.ActionTaken != "" {
		details["action_taken"] = truncate(wp.ActionTaken, 32)
	}
	if wp.Error != "" {
		details["error"] = truncate(wp.Error, 256)
	}
	evt.Details = map[string]interface{}{"wasm_plugin": details}
	return nil
}

func clampStringSlice(in []string, maxItems, maxItemLen int) []string {
	limit := len(in)
	if limit > maxItems {
		limit = maxItems
	}
	out := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		s := strings.TrimSpace(in[i])
		if s == "" {
			continue
		}
		out = append(out, truncate(s, maxItemLen))
	}
	return out
}

// applyRiskPolicyEvent 校验风险处置事件并填充 details 证据载荷与 action 列
// （risk 对象或 identity_key 缺失、action_taken 非契约值 → 解析失败入错误文件，不静默落库）。
func applyRiskPolicyEvent(evt *Event, raw *rawEvent) error {
	risk := raw.Risk
	if risk == nil || risk.IdentityKey == "" {
		return fmt.Errorf("risk policy event missing risk.identity_key")
	}
	action, ok := riskPolicyActionTaken[risk.ActionTaken]
	if !ok {
		return fmt.Errorf("risk policy event invalid action_taken %q", risk.ActionTaken)
	}
	// 网关顶层 action 为动作原文（blocked/challenged/would_block/…），动作列统一映射为
	// REJECT/CHALLENGE/OBSERVE；动作原文保留在 details.action_taken。
	evt.Action = action
	details := map[string]interface{}{
		"identity_key": truncate(risk.IdentityKey, 128),
		"action_taken": risk.ActionTaken,
	}
	if risk.Score != nil {
		details["score"] = *risk.Score
	}
	if risk.RiskLevel != "" {
		details["risk_level"] = truncate(risk.RiskLevel, 16)
	}
	if risk.Threshold != nil {
		details["threshold"] = *risk.Threshold
	}
	if risk.Mode != "" {
		details["mode"] = truncate(risk.Mode, 16)
	}
	if risk.PolicyVersion != nil {
		details["policy_version"] = risk.PolicyVersion
	}
	if risk.Reason != "" {
		details["reason"] = truncate(risk.Reason, 128)
	}
	if len(risk.Signals) > 0 {
		var signals []interface{}
		if err := json.Unmarshal(risk.Signals, &signals); err != nil {
			return fmt.Errorf("risk policy event invalid signals: %w", err)
		}
		details["signals"] = signals
	}
	evt.Details = details
	return nil
}

// isRejected 判断事件是否为拒绝类（运行汇总 rejected 计数）。
func isRejected(evt *Event) bool {
	if evt.Action == ActionReject || evt.Action == ActionTempBlock {
		return true
	}
	return evt.EventType == EventTypeCCRequestRejected || evt.EventType == EventTypeCCTempBlockCreated
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
