package exceptions

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// eventDraftTTL 事件草稿默认临时有效期（验收场景：30 分钟精确例外，到期无需再发布）。
const eventDraftTTL = 30 * time.Minute

// maxEventDraftDurationMinutes 从事件创建临时例外的最大时长（365 天）。
const maxEventDraftDurationMinutes = 365 * 24 * 60

// IsBlockingEvalRuleID 判断规则 ID 是否为 OWASP CRS 异常评分汇总/阻断评估规则。
// 这类规则本身不检测具体攻击载荷，若被纳入例外会放宽该接口上的全部 CRS 入站/出站防护，
// 因此从安全事件生成例外时必须自动排除，仅保留上游具体检测规则 ID。
func IsBlockingEvalRuleID(id int) bool {
	switch id {
	case 949110, 949111, 959100, 959101, 9000102, 9000104, 980170:
		return true
	default:
		return false
	}
}

// FilterEventRuleIDs 从事件命中规则集中过滤掉异常评分评估规则并去重排序；
// 若客户端显式勾选了 selectedRuleIDs，则严格校验其为可信检测规则集的子集（防客户端越权扩大/伪造规则 ID）。
func FilterEventRuleIDs(rawRuleIDs []int, selectedRuleIDs []int) ([]int, error) {
	trustedSet := make(map[int]bool, len(rawRuleIDs))
	trusted := make([]int, 0, len(rawRuleIDs))
	for _, rid := range rawRuleIDs {
		if rid <= 0 || IsBlockingEvalRuleID(rid) || trustedSet[rid] {
			continue
		}
		trustedSet[rid] = true
		trusted = append(trusted, rid)
	}
	sort.Ints(trusted)
	if len(selectedRuleIDs) == 0 {
		return trusted, nil
	}
	chosenSet := make(map[int]bool, len(selectedRuleIDs))
	chosen := make([]int, 0, len(selectedRuleIDs))
	for _, rid := range selectedRuleIDs {
		if !trustedSet[rid] {
			return nil, fmt.Errorf("规则 ID %d 不属于该事件命中的可例外检测规则", rid)
		}
		if chosenSet[rid] {
			continue
		}
		chosenSet[rid] = true
		chosen = append(chosen, rid)
	}
	sort.Ints(chosen)
	return chosen, nil
}

// CreateFromEventInput 是从事件创建例外的输入。
// P0-04 契约 §9：ApplicationID/Method/Path（不含 query）/RuleIDs/SourceEventID
// 由服务端从事件记录提取（可信源），客户端入参不能覆盖。
type CreateFromEventInput struct {
	EventID          uuid.UUID  // 来源事件 ID（命名/理由文案）
	SourceEventID    uuid.UUID  // 可信绑定（落 source_event_id 列；空时回退 EventID）
	ApplicationID    *uuid.UUID // 事件归属应用（空 → 草稿 NEEDS_REVIEW，禁止启用）
	Method           string     // 事件原方法（后端不擅自扩为全部方法）
	Path             string     // 事件路径（不含 query）
	ClientIP         string     // 事件客户端 IP（RestrictSourceIP 缺省/true 且合法则入 SourceIPs 维度）
	Domain           string
	AttackType       string
	RuleIDs          []int // 事件 matches 提取的去重检测规则 ID（空 → NEEDS_REVIEW）
	CreatedBy        uuid.UUID
	Name             string // 可选覆盖默认名称（空则使用 "事件例外-<id前8位>"）
	Reason           string // 可选覆盖默认原因（空则使用 "事件 <id> 误报处置"）
	RestrictSourceIP *bool  // nil/true=仅限本事件客户端 IP；false=不限来源 IP（全访客生效）
	IsTemporary      *bool  // nil/true=临时例外；false=永久例外（需管理员显式选择）
	DurationMinutes  *int   // 临时例外时长（分钟，nil 时默认 30，范围 1..525600）
}

// buildFromEventException 构造从事件派生的例外草稿对象（纯函数，便于单测）。
func buildFromEventException(in CreateFromEventInput, now time.Time) (*Exception, error) {
	if in.CreatedBy == uuid.Nil {
		return nil, fmt.Errorf("missing creator")
	}
	src := in.SourceEventID
	if src == uuid.Nil {
		src = in.EventID
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = fmt.Sprintf("事件例外-%s", src.String()[:8])
	}
	if len(name) > 128 {
		return nil, fmt.Errorf("例外名称不能超过 128 字符")
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		reason = fmt.Sprintf("事件 %s 误报处置", src)
	}
	if utf8.RuneCountInString(reason) > 500 {
		return nil, fmt.Errorf("例外原因不能超过 500 字符")
	}
	if in.DurationMinutes != nil && (*in.DurationMinutes < 1 || *in.DurationMinutes > maxEventDraftDurationMinutes) {
		return nil, fmt.Errorf("临时有效期须在 1 分钟至 365 天之间")
	}
	isTemp := true
	if in.IsTemporary != nil {
		isTemp = *in.IsTemporary
	}
	var until *time.Time
	if isTemp {
		dur := eventDraftTTL
		if in.DurationMinutes != nil {
			dur = time.Duration(*in.DurationMinutes) * time.Minute
		}
		u := now.Add(dur)
		until = &u
	}
	exc := &Exception{
		Name:            name,
		Description:     fmt.Sprintf("从安全事件 %s 创建的例外草稿", src),
		ScopeType:       "APPLICATION",
		ApplicationID:   in.ApplicationID,
		Domain:          in.Domain,
		URIExact:        stripQuery(in.Path),
		RuleIDs:         in.RuleIDs,
		AttackTypes:     nonEmpty(in.AttackType),
		ExceptionAction: ActionRemoveRule,
		IsTemporary:     isTemp,
		EffectiveFrom:   &now,
		EffectiveUntil:  until,
		Status:          "DRAFT",
		Reason:          reason,
		SourceEventID:   &src,
	}
	if m := strings.ToUpper(strings.TrimSpace(in.Method)); allowedMethods[m] {
		exc.Methods = []string{m}
	}
	restrictIP := true
	if in.RestrictSourceIP != nil {
		restrictIP = *in.RestrictSourceIP
	}
	if restrictIP {
		if ip, err := netip.ParseAddr(strings.TrimSpace(in.ClientIP)); err == nil {
			exc.SourceIPs = []string{ip.String()}
		}
	}
	return exc, nil
}

// CreateFromEvent 从安全事件创建精确例外草稿（默认 30 分钟临时、限定事件 IP、DRAFT、REMOVE_RULE）。
// 缺应用/方法/路径/规则证据时仍创建草稿——保存层审查自动标 NEEDS_REVIEW（预览列明
// 缺失项），启用门禁拒绝启用。宽泛判定不再自动勾选 risk_acknowledged（契约 §9：
// 启用授权以结构化范围校验为准，风险勾选不能被单字段绕过）。
func (s *Store) CreateFromEvent(ctx context.Context, in CreateFromEventInput) (uuid.UUID, error) {
	exc, err := buildFromEventException(in, time.Now())
	if err != nil {
		return uuid.Nil, err
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
