// Package accesscontrolevents 提供访问控制事件（IP黑白名单/CC防护）的解析、存储、查询与采集。
package accesscontrolevents

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 事件类型（网关 jiuzhang_guard 产生 + 管理面到期/解封补齐）
const (
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
