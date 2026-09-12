package exceptions

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
)

// eventDraftTTL 事件草稿默认临时有效期（验收场景：30 分钟精确例外，到期无需再发布）。
const eventDraftTTL = 30 * time.Minute

// CreateFromEventInput 是从事件创建例外的输入。
// P0-04 契约 §9：ApplicationID/Method/Path（不含 query）/RuleIDs/SourceEventID
// 由服务端从事件记录提取（可信源），客户端入参不能覆盖。
type CreateFromEventInput struct {
	EventID       uuid.UUID   // 来源事件 ID（命名/理由文案）
	SourceEventID uuid.UUID   // 可信绑定（落 source_event_id 列；空时回退 EventID）
	ApplicationID *uuid.UUID  // 事件归属应用（空 → 草稿 NEEDS_REVIEW，禁止启用）
	Method        string      // 事件原方法（后端不擅自扩为全部方法）
	Path          string      // 事件路径（不含 query）
	ClientIP      string      // 事件客户端 IP（合法则入 SourceIPs 维度）
	Domain        string
	AttackType    string
	RuleIDs       []int // 事件 matches 提取的去重规则 ID（空 → NEEDS_REVIEW）
	CreatedBy     uuid.UUID
}

// CreateFromEvent 从安全事件创建精确例外草稿（30 分钟临时、DRAFT、REMOVE_RULE）。
// 缺应用/方法/路径/规则证据时仍创建草稿——保存层审查自动标 NEEDS_REVIEW（预览列明
// 缺失项），启用门禁拒绝启用。宽泛判定不再自动勾选 risk_acknowledged（契约 §9：
// 启用授权以结构化范围校验为准，风险勾选不能被单字段绕过）。
func (s *Store) CreateFromEvent(ctx context.Context, in CreateFromEventInput) (uuid.UUID, error) {
	if in.CreatedBy == uuid.Nil {
		return uuid.Nil, fmt.Errorf("missing creator")
	}
	src := in.SourceEventID
	if src == uuid.Nil {
		src = in.EventID
	}
	now := time.Now()
	until := now.Add(eventDraftTTL)
	exc := &Exception{
		Name:            fmt.Sprintf("事件例外-%s", src.String()[:8]),
		Description:     fmt.Sprintf("从安全事件 %s 创建的例外草稿", src),
		ScopeType:       "APPLICATION",
		ApplicationID:   in.ApplicationID,
		Domain:          in.Domain,
		URIExact:        stripQuery(in.Path),
		RuleIDs:         in.RuleIDs,
		AttackTypes:     nonEmpty(in.AttackType),
		ExceptionAction: ActionRemoveRule,
		IsTemporary:     true,
		EffectiveFrom:   &now,
		EffectiveUntil:  &until,
		Status:          "DRAFT",
		Reason:          fmt.Sprintf("事件 %s 误报处置", src),
		SourceEventID:   &src,
	}
	if m := strings.ToUpper(strings.TrimSpace(in.Method)); allowedMethods[m] {
		exc.Methods = []string{m}
	}
	if ip, err := netip.ParseAddr(strings.TrimSpace(in.ClientIP)); err == nil {
		exc.SourceIPs = []string{ip.String()}
	}
	if err := s.Create(ctx, exc, in.CreatedBy); err != nil {
		return uuid.Nil, err
	}
	return exc.ID, nil
}

// stripQuery 防御性剔除 query（Path 契约上不含 query，历史事件数据可能带）。
func stripQuery(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return p
}

func nonEmpty(s string) []string {
	if s == "" || s == "OTHER" {
		return nil
	}
	return []string{s}
}
