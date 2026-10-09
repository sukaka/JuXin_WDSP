// Package events 统一运行时主事件：同一 Request ID 下聚合多检测明细。
package events

import (
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// JWTVerification JWT 信任链验证摘要（WDSP P0-03；网关 jiuzhang_guard jwt_trust
// 段验证产物随事件上报的可选对象）。数据最小化纪律：仅状态/固定 reason_code/
// 策略与密钥版本/可信主体指纹；不落原始 Token、完整 payload、明文 sub/tenant
// （verified_tenant_id 为网关侧加盐指纹，非明文 tenant 值）。
// 历史事件无此对象（键省略/NULL），消费端必须容忍缺失。
type JWTVerification struct {
	Status               string `json:"status"`
	ReasonCode           string `json:"reason_code"`
	PolicyVersion        string `json:"policy_version,omitempty"`
	IssuerConfigID       string `json:"issuer_config_id,omitempty"`
	KeysetVersion        string `json:"keyset_version,omitempty"`
	VerifiedPrincipalID  string `json:"verified_principal_id,omitempty"`
	VerifiedTenantID     string `json:"verified_tenant_id,omitempty"`
	VerifiedIdentityType string `json:"verified_identity_type,omitempty"`
	EvaluatedAt          string `json:"evaluated_at,omitempty"`
}

// PrimaryEvent 主事件（管理面/库表可映射）。
type PrimaryEvent struct {
	ID            string                      `json:"id"`
	RequestID     string                      `json:"request_id"`
	OccurredAt    time.Time                   `json:"occurred_at"`
	ApplicationID string                      `json:"application_id,omitempty"`
	EndpointKey   string                      `json:"endpoint_key,omitempty"`
	RiskScore     int                         `json:"risk_score"`
	RiskLevel     string                      `json:"risk_level"`
	FinalAction   string                      `json:"final_action"`
	Details       []dsctx.DetectorMatch       `json:"details"`
	AuthzDecision *AuthorizationDecisionGroup `json:"authz_decision,omitempty"`
	// StrongFlow 强流程步骤动作条目（NG-FLOW-02；冻结形状见 strongflow.go——
	// 采集端按冻结字段名消费落 api_strong_flow_step_events，不得改名）；
	// 无强流程活动为 nil，键省略零变化。
	StrongFlow []*StrongFlowAction `json:"strong_flow,omitempty"`
	// DeviceFingerprint 被动客户端指纹（任务书 §7；UA/Accept 族 HMAC 哈希，
	// 低熵群体特征非设备唯一标识；空 = UA 缺失未计算，键省略零变化）。
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
	// ObjectIdentifiers 对象标识哈希集合（任务书 §7；只记哈希不落明文，
	// 条数有界 dsctx.MaxObjectIdentifiers；空 = 无可识别对象标识，键省略零变化）。
	ObjectIdentifiers []dsctx.ObjectIdentifier `json:"object_identifiers,omitempty"`
}

// BuildPrimary 从统一上下文构建主事件（多 detector 明细）。
func BuildPrimary(eventID string, ctx *dsctx.RequestContext, endpointKey string) *PrimaryEvent {
	if ctx == nil {
		return nil
	}
	details := ctx.CopyMatches()
	if details == nil {
		details = []dsctx.DetectorMatch{}
	}
	return &PrimaryEvent{
		ID:            eventID,
		RequestID:     ctx.RequestID,
		OccurredAt:    ctx.OccurredAt,
		ApplicationID: ctx.ApplicationID,
		EndpointKey:   endpointKey,
		RiskScore:     ctx.RiskScore,
		RiskLevel:     string(ctx.RiskLevel),
		FinalAction:   string(ctx.GetFinalAction()),
		Details:       details,
		AuthzDecision: authzDecisionFromContext(ctx),
		StrongFlow:    strongFlowActionsFromContext(ctx),
		// §7 字段快照（拷贝，事件不随上下文后续写回变化）
		DeviceFingerprint: ctx.DeviceFingerprint,
		ObjectIdentifiers: ctx.CopyObjectIdentifiers(),
	}
}

func authzDecisionFromContext(ctx *dsctx.RequestContext) *AuthorizationDecisionGroup {
	v, ok := ctx.GetExtension("authz.decision_group")
	if !ok {
		return nil
	}
	g, ok := v.(*AuthorizationDecisionGroup)
	if !ok || g == nil {
		return nil
	}
	return g
}

// strongFlowActionsFromContext 取强流程动作条目（NG-FLOW-02；扩展键
// "sflow.actions" 与 flowguard 检测器写入键一致——跨包镜像：detectors/flowguard
// 写入，本包读取，类型断言失败容忍为 nil 不panic）。
func strongFlowActionsFromContext(ctx *dsctx.RequestContext) []*StrongFlowAction {
	v, ok := ctx.GetExtension("sflow.actions")
	if !ok {
		return nil
	}
	actions, _ := v.([]*StrongFlowAction)
	return actions
}
