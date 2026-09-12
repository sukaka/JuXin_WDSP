package accessrules

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jiuzhang-waf/server/internal/response"
)

// ErrEventNotFound 来源安全事件不存在。
var ErrEventNotFound = errors.New("security event not found")

// HitRuleStat 近 24h 同 IP 命中规则统计。
type HitRuleStat struct {
	RuleID   int    `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Hits     int64  `json:"hits"`
}

// SharedEgressHint 共享出口/代理迹象提示（无身份数据时整体省略，不编造）。
type SharedEgressHint struct {
	IdentityCount int64 `json:"identity_count"` // 近 24h 同 IP 关联的不同身份数
	Suspected     bool  `json:"suspected"`      // >=2 个身份视为疑似共享出口/代理
}

// ExistingDenyRule 同地址已有黑名单规则的简要信息（提示管理员避免重复）。
type ExistingDenyRule struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	Status         string     `json:"status"`
	ValidityType   string     `json:"validity_type"`
	EffectiveUntil *time.Time `json:"effective_until"`
}

// BlacklistPrefill 是「从安全事件加入黑名单」的预填数据（阶段5 §十一：8 字段 + 确认项）。
// 仅为建议值，不落库；管理员确认后走 POST /access-rules（source_type=SECURITY_EVENT）。
type BlacklistPrefill struct {
	EventID           uuid.UUID         `json:"event_id"`
	Address           string            `json:"address"`   // 事件客户端 IP（规范化后）
	RuleType          string            `json:"rule_type"` // 固定 DENY
	SuggestedName     string            `json:"suggested_name"`
	SuggestedReason   string            `json:"suggested_reason"`
	ApplicationID     *uuid.UUID        `json:"application_id"`
	ApplicationName   string            `json:"application_name"`
	AttackType        string            `json:"attack_type"`
	Severity          string            `json:"severity"`
	RelatedEventCount int64             `json:"related_event_count_24h"`
	LastAttackAt      *time.Time        `json:"last_attack_at"`
	HitRules          []HitRuleStat     `json:"hit_rules"`
	SuggestedDuration int               `json:"suggested_duration_hours"`
	ProtectedHit      bool              `json:"protected_hit"`
	ProtectedName     string            `json:"protected_name,omitempty"`
	SharedEgress      *SharedEgressHint `json:"shared_egress_hint,omitempty"`
	ExistingDenyRule  *ExistingDenyRule `json:"existing_deny_rule,omitempty"`
}

// 建议封禁时长分档规则（纯函数，便于审计与测试）：
//   - 基础档按事件严重度：HIGH→24h、MEDIUM→6h、LOW→2h、INFO/其他→1h；
//   - 近 24h 同 IP 相关事件数 >=10 升一档（1→2→6→24→72），>=50 直接 72h；
//   - 上限 72h：超过 3 天的封禁必须由管理员显式决策，不由系统自动建议
//     （§十一「不得未经确认自动永久封禁」——预填只允许建议临时时长）。
func SuggestBlockDurationHours(severity string, related24h int64) int {
	base := 1
	switch severity {
	case "HIGH":
		base = 24
	case "MEDIUM":
		base = 6
	case "LOW":
		base = 2
	}
	if related24h >= 50 {
		return 72
	}
	if related24h >= 10 {
		switch base {
		case 1:
			base = 2
		case 2:
			base = 6
		case 6:
			base = 24
		default:
			base = 72
		}
	}
	return base
}

// suggestBlacklistName 生成建议规则名（不超过 200 字符的名称限制，IP 最长 64 字符，
// 前缀固定，必然不超）。
func suggestBlacklistName(address string) string {
	return "事件封禁-" + address
}

// suggestBlacklistReason 生成建议封禁原因（攻击类型与来源事件 ID 均为系统数据，拼装后
// 截断到 500 字符上限内——实际远小于上限，仅防御性截断）。
func suggestBlacklistReason(attackType string, eventID uuid.UUID) string {
	reason := fmt.Sprintf("安全事件联动封禁：%s（来源事件 %s）", attackType, eventID.String())
	if utf8.RuneCountInString(reason) > 500 {
		reason = string([]rune(reason)[:500])
	}
	return reason
}

// validateAPISource 校验管理面 API 入参的来源白名单：只接受 MANUAL / SECURITY_EVENT；
// IMPORT / AUTO_BLOCK / SYSTEM 由对应内部通道写入，不开放给 API 调用方伪造。
func validateAPISource(in *CreateInput) error {
	switch in.SourceType {
	case "", SourceManual:
		if in.SourceEventID != nil {
			return fmt.Errorf("%w: 仅 SECURITY_EVENT 来源允许携带 source_event_id", ErrInvalidInput)
		}
	case SourceSecurityEvent:
		if in.SourceEventID == nil || *in.SourceEventID == uuid.Nil {
			return fmt.Errorf("%w: SECURITY_EVENT 来源必须提供有效的 source_event_id", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: 来源类型仅支持 MANUAL 或 SECURITY_EVENT", ErrInvalidInput)
	}
	return nil
}

// prefillEvent 是预填所需的事件字段子集。
type prefillEvent struct {
	ID        uuid.UUID
	ClientIP  string
	Severity  string
	AttackTyp string
	AppID     *uuid.UUID
	AppName   string
}

// EventExists 判断安全事件是否存在（Create 校验 source_event_id 用）。
func (s *Store) EventExists(ctx context.Context, id uuid.UUID) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM security_events WHERE id = $1)`, id).Scan(&ok)
	return ok, err
}

// eventForPrefill 读取事件基本字段（client_ip 为 inet 类型，转文本返回）。
func (s *Store) eventForPrefill(ctx context.Context, id uuid.UUID) (*prefillEvent, error) {
	var e prefillEvent
	err := s.db.QueryRow(ctx, `
SELECT id, COALESCE(host(client_ip), ''), COALESCE(severity, ''), COALESCE(attack_type, ''),
  application_id, COALESCE(application_name_snapshot, '')
FROM security_events WHERE id = $1`, id).
		Scan(&e.ID, &e.ClientIP, &e.Severity, &e.AttackTyp, &e.AppID, &e.AppName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrEventNotFound
		}
		return nil, err
	}
	return &e, nil
}

// ipEventStats24h 聚合同 IP 近 24h 事件数与最近攻击时间。
func (s *Store) ipEventStats24h(ctx context.Context, ip string, since time.Time) (int64, *time.Time, error) {
	var count int64
	var lastAt *time.Time
	err := s.db.QueryRow(ctx, `
SELECT count(*), max(occurred_at) FROM security_events
WHERE client_ip = $1::inet AND occurred_at >= $2`, ip, since).Scan(&count, &lastAt)
	if err != nil {
		return 0, nil, err
	}
	return count, lastAt, nil
}

// hitRules24h 聚合同 IP 近 24h 命中规则（按命中次数降序，最多 10 条）。
func (s *Store) hitRules24h(ctx context.Context, ip string, since time.Time) ([]HitRuleStat, error) {
	rows, err := s.db.Query(ctx, `
SELECT m.rule_id, COALESCE(m.rule_name, ''), count(*) AS hits
FROM security_event_matches m
JOIN security_events e ON e.id = m.event_id
WHERE e.client_ip = $1::inet AND e.occurred_at >= $2
GROUP BY m.rule_id, m.rule_name
ORDER BY hits DESC, m.rule_id
LIMIT 10`, ip, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HitRuleStat{}
	for rows.Next() {
		var h HitRuleStat
		if err := rows.Scan(&h.RuleID, &h.RuleName, &h.Hits); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// sharedEgressHint 查询同 IP 近 24h 关联身份数（identity_ip_history，迁移 000097）。
// 无任何身份数据返回 nil——无数据则省略该项，不编造。
func (s *Store) sharedEgressHint(ctx context.Context, ip string, since time.Time) (*SharedEgressHint, error) {
	var n int64
	err := s.db.QueryRow(ctx, `
SELECT count(DISTINCT identity_id) FROM identity_ip_history
WHERE ip = $1 AND last_seen_at >= $2`, ip, since).Scan(&n)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	return &SharedEgressHint{IdentityCount: n, Suspected: n >= 2}, nil
}

// existingDenyRule 查询同地址（规范化后）已存在的黑名单规则，无则返回 nil。
func (s *Store) existingDenyRule(ctx context.Context, address string) (*ExistingDenyRule, error) {
	var r ExistingDenyRule
	err := s.db.QueryRow(ctx, `
SELECT id, name, status, validity_type, effective_until FROM ip_access_rules
WHERE deleted_at IS NULL AND rule_type = $1 AND address = $2
ORDER BY created_at DESC LIMIT 1`, RuleTypeDeny, address).
		Scan(&r.ID, &r.Name, &r.Status, &r.ValidityType, &r.EffectiveUntil)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// BlacklistPrefill 从安全事件预填「加入黑名单」数据（只读不落库；确认创建走
// POST /access-rules 并携带 source_type=SECURITY_EVENT + source_event_id）。
func (h *Handler) BlacklistPrefill(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的事件ID")
		return
	}
	evt, err := h.store.eventForPrefill(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrEventNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "事件不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if evt.ClientIP == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "事件无客户端 IP，无法预填黑名单")
		return
	}
	norm, _, err := NormalizeAddress(evt.ClientIP)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "事件客户端 IP 无效: "+err.Error())
		return
	}
	since := time.Now().Add(-24 * time.Hour)
	count, lastAt, err := h.store.ipEventStats24h(r.Context(), norm, since)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	hitRules, err := h.store.hitRules24h(r.Context(), norm, since)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	egress, err := h.store.sharedEgressHint(r.Context(), norm, since)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	existing, err := h.store.existingDenyRule(r.Context(), norm)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	// 保护地址命中只做提示（管理员确认项），真正拦截仍在 Create 的 CheckProtected
	protectedHit := false
	protectedName := ""
	if h.checker != nil {
		hit, name, perr := h.checker.IsProtected(r.Context(), norm)
		if perr != nil {
			response.InternalError(w, r, perr)
			return
		}
		protectedHit = hit
		protectedName = name
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"prefill": BlacklistPrefill{
			EventID:           evt.ID,
			Address:           norm,
			RuleType:          RuleTypeDeny,
			SuggestedName:     suggestBlacklistName(norm),
			SuggestedReason:   suggestBlacklistReason(evt.AttackTyp, evt.ID),
			ApplicationID:     evt.AppID,
			ApplicationName:   evt.AppName,
			AttackType:        evt.AttackTyp,
			Severity:          evt.Severity,
			RelatedEventCount: count,
			LastAttackAt:      lastAt,
			HitRules:          hitRules,
			SuggestedDuration: SuggestBlockDurationHours(evt.Severity, count),
			ProtectedHit:      protectedHit,
			ProtectedName:     protectedName,
			SharedEgress:      egress,
			ExistingDenyRule:  existing,
		},
	})
}
