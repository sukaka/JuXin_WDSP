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
