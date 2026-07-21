package exceptions

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// EventLike 是从事件创建例外所需的最小事件信息。
type EventLike interface {
	GetID() uuid.UUID
	GetClientIP() string
	GetDomain() string
	GetURI() string
	GetPath() string
	GetAttackType() string
	GetRuleIDs() []int
}

// CreateFromEventInput 是从事件创建例外的输入。
type CreateFromEventInput struct {
	EventID   uuid.UUID
	ClientIP  string
	Domain    string
	URI       string
	Path      string
	AttackType string
	RuleIDs   []int
	CreatedBy uuid.UUID
}

// CreateFromEvent 从安全事件创建精确例外草稿。
// 优先精确例外：域名/路径 + 规则ID + 参数（如有）。
func (s *Store) CreateFromEvent(ctx context.Context, in CreateFromEventInput) (uuid.UUID, error) {
	if in.CreatedBy == uuid.Nil {
		return uuid.Nil, fmt.Errorf("missing creator")
	}
	exc := &Exception{
		Name:        fmt.Sprintf("事件例外-%s", in.EventID.String()[:8]),
		Description: fmt.Sprintf("从安全事件 %s 创建的例外草稿", in.EventID),
		ScopeType:   "APPLICATION",
		Domain:      in.Domain,
		URIExact:    in.URI,
		RuleIDs:     in.RuleIDs,
		AttackTypes: nonEmpty(in.AttackType),
		ExceptionAction: ActionRemoveRule,
		Status:      "DRAFT", // 草稿状态，需审核后启用
		Reason:      fmt.Sprintf("事件 %s 误报处置", in.EventID),
	}
	// 精确例外不需要风险确认（已限定到具体路径/规则）
	if !exc.IsBroad() {
		exc.RiskAcknowledged = true
	}
	if err := s.Create(ctx, exc, in.CreatedBy); err != nil {
		return uuid.Nil, err
	}
	return exc.ID, nil
}

func nonEmpty(s string) []string {
	if s == "" || s == "OTHER" {
		return nil
	}
	return []string{s}
}
