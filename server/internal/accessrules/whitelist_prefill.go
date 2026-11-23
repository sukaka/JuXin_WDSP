package accessrules

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jiuzhang-waf/server/internal/response"
)

// ExistingURLWhitelist 描述同路径已存在的 URL 白名单简要信息。
type ExistingURLWhitelist struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	MatchType  string    `json:"match_type"`
	URIPattern string    `json:"uri_pattern"`
	Status     string    `json:"status"`
}

// URLWhitelistChecker 用于白名单预填检查同路径是否已有 URL 白名单规则（解耦 urlwhitelists 包）。
type URLWhitelistChecker interface {
	FindExistingURLWhitelist(ctx context.Context, pathStr string, appID *uuid.UUID) (*ExistingURLWhitelist, error)
}

// WhitelistPrefill 是「从安全事件加入白名单」的预填数据（支持 IP 白名单、URL 白名单及联动精确 WAF 例外）。
// 只读不落库；管理员确认后分别走 POST /access-rules（ALLOW）、POST /url-whitelists 及可选 POST /security-events/{id}/create-exception。
type WhitelistPrefill struct {
	EventID               uuid.UUID             `json:"event_id"`
	Address               string                `json:"address"`
	RequestPath           string                `json:"request_path"`
	RequestMethod         string                `json:"request_method"`
	Domain                string                `json:"domain"`
	ApplicationID         *uuid.UUID            `json:"application_id"`
	ApplicationName       string                `json:"application_name"`
	AttackType            string                `json:"attack_type"`
	Severity              string                `json:"severity"`
	RelatedEventCount     int64                 `json:"related_event_count_24h"`
	LastAttackAt          *time.Time            `json:"last_attack_at"`
	HitRules              []HitRuleStat         `json:"hit_rules"`
	EventRuleIDs          []int                 `json:"event_rule_ids"`
	CanCreateWAFException bool                  `json:"can_create_waf_exception"`
	SuggestedIPName       string                `json:"suggested_ip_name"`
	SuggestedURLName      string                `json:"suggested_url_name"`
	SuggestedReason       string                `json:"suggested_reason"`
	SharedEgress          *SharedEgressHint     `json:"shared_egress_hint,omitempty"`
	ExistingAllowRule     *ExistingDenyRule     `json:"existing_allow_rule,omitempty"`
	ExistingDenyRule      *ExistingDenyRule     `json:"existing_deny_rule,omitempty"`
	ExistingURLWhitelist  *ExistingURLWhitelist `json:"existing_url_whitelist,omitempty"`
}

type whitelistPrefillEvent struct {
	ID            uuid.UUID
	ClientIP      string
	RequestURI    string
	RequestMethod string
	Domain        string
	Severity      string
	AttackType    string
	AppID         *uuid.UUID
	AppName       string
}

func extractRequestPath(rawURI string) string {
	s := strings.TrimSpace(rawURI)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	return s
}

func suggestWhitelistIPName(address string) string {
	if address == "" {
		return "事件IP白名单"
	}
	return "事件白名单-" + address
}

func suggestWhitelistURLName(reqPath string) string {
	if reqPath == "" {
		return "事件URL白名单"
	}
	name := "事件URL白名单-" + reqPath
	if utf8.RuneCountInString(name) > 120 {
		name = string([]rune(name)[:120])
	}
	return name
}

func suggestWhitelistReason(attackType string, eventID uuid.UUID) string {
	reason := fmt.Sprintf("安全事件误报/可信放行：%s（来源事件 %s）", attackType, eventID.String())
	if utf8.RuneCountInString(reason) > 500 {
		reason = string([]rune(reason)[:500])
	}
	return reason
}

func (s *Store) eventForWhitelistPrefill(ctx context.Context, id uuid.UUID) (*whitelistPrefillEvent, error) {
	var e whitelistPrefillEvent
	err := s.db.QueryRow(ctx, `
SELECT id, COALESCE(host(client_ip), ''), COALESCE(request_uri, ''), COALESCE(request_method, ''),
  COALESCE(domain, ''), COALESCE(severity, ''), COALESCE(attack_type, ''),
  application_id, COALESCE(application_name_snapshot, '')
FROM security_events WHERE id = $1`, id).
		Scan(&e.ID, &e.ClientIP, &e.RequestURI, &e.RequestMethod, &e.Domain,
			&e.Severity, &e.AttackType, &e.AppID, &e.AppName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrEventNotFound
		}
		return nil, err
	}
	return &e, nil
}

func (s *Store) eventMatchedRuleIDs(ctx context.Context, eventID uuid.UUID) ([]int, error) {
	rows, err := s.db.Query(ctx, `
SELECT DISTINCT rule_id FROM security_event_matches
WHERE event_id = $1 AND rule_id > 0
ORDER BY rule_id ASC LIMIT 50`, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int{}
	for rows.Next() {
		var rid int
		if err := rows.Scan(&rid); err != nil {
			return nil, err
		}
		out = append(out, rid)
	}
	return out, rows.Err()
}

func (s *Store) existingRuleByType(ctx context.Context, ruleType, address string) (*ExistingDenyRule, error) {
	if address == "" {
		return nil, nil
	}
	var r ExistingDenyRule
	err := s.db.QueryRow(ctx, `
SELECT id, name, status, validity_type, effective_until FROM ip_access_rules
WHERE deleted_at IS NULL AND rule_type = $1 AND address = $2
ORDER BY created_at DESC LIMIT 1`, ruleType, address).
		Scan(&r.ID, &r.Name, &r.Status, &r.ValidityType, &r.EffectiveUntil)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// WhitelistPrefill 从安全事件预填「加入白名单（IP 白名单 / URL 白名单 + 可选 WAF 精确例外）」数据。
func (h *Handler) WhitelistPrefill(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的事件ID")
		return
	}
	evt, err := h.store.eventForWhitelistPrefill(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrEventNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "事件不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	reqPath := extractRequestPath(evt.RequestURI)
	var normIP string
	if evt.ClientIP != "" {
		if n, _, nerr := NormalizeAddress(evt.ClientIP); nerr == nil {
			normIP = n
		}
	}
	if normIP == "" && reqPath == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "事件缺少客户端 IP 与请求路径，无法预填白名单")
		return
	}

	since := time.Now().Add(-24 * time.Hour)
	var count int64
	var lastAt *time.Time
	hitRules := []HitRuleStat{}
	var egress *SharedEgressHint
	var existingAllow, existingDeny *ExistingDenyRule
	if normIP != "" {
		count, lastAt, err = h.store.ipEventStats24h(r.Context(), normIP, since)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		hitRules, err = h.store.hitRules24h(r.Context(), normIP, since)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		egress, err = h.store.sharedEgressHint(r.Context(), normIP, since)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		existingAllow, err = h.store.existingRuleByType(r.Context(), RuleTypeAllow, normIP)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		existingDeny, err = h.store.existingRuleByType(r.Context(), RuleTypeDeny, normIP)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
	}

	eventRuleIDs, err := h.store.eventMatchedRuleIDs(r.Context(), evt.ID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}

	var existingURL *ExistingURLWhitelist
	if h.urlChecker != nil && reqPath != "" {
		existingURL, err = h.urlChecker.FindExistingURLWhitelist(r.Context(), reqPath, evt.AppID)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
	}

	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"prefill": WhitelistPrefill{
			EventID:               evt.ID,
			Address:               normIP,
			RequestPath:           reqPath,
			RequestMethod:         strings.ToUpper(strings.TrimSpace(evt.RequestMethod)),
			Domain:                evt.Domain,
			ApplicationID:         evt.AppID,
			ApplicationName:       evt.AppName,
			AttackType:            evt.AttackType,
			Severity:              evt.Severity,
			RelatedEventCount:     count,
			LastAttackAt:          lastAt,
			HitRules:              hitRules,
			EventRuleIDs:          eventRuleIDs,
			CanCreateWAFException: evt.AppID != nil && reqPath != "" && len(eventRuleIDs) > 0,
			SuggestedIPName:       suggestWhitelistIPName(normIP),
			SuggestedURLName:      suggestWhitelistURLName(reqPath),
			SuggestedReason:       suggestWhitelistReason(evt.AttackType, evt.ID),
			SharedEgress:          egress,
			ExistingAllowRule:     existingAllow,
			ExistingDenyRule:      existingDeny,
			ExistingURLWhitelist:  existingURL,
		},
	})
}
