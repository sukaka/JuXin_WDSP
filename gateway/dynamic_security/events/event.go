// Package events 统一运行时主事件：同一 Request ID 下聚合多检测明细。
package events

import (
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// PrimaryEvent 主事件（管理面/库表可映射）。
type PrimaryEvent struct {
	ID            string               `json:"id"`
	RequestID     string               `json:"request_id"`
	OccurredAt    time.Time            `json:"occurred_at"`
	ApplicationID string               `json:"application_id,omitempty"`
	EndpointKey   string               `json:"endpoint_key,omitempty"`
	RiskScore     int                  `json:"risk_score"`
	RiskLevel     string               `json:"risk_level"`
	FinalAction   string               `json:"final_action"`
	Details       []dsctx.DetectorMatch `json:"details"`
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
	}
}
