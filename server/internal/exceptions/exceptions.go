// Package exceptions 提供WAF例外策略：精确例外、临时例外、宽泛例外受控与 SecLang 生成。
package exceptions

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/validation"
)

// 例外动作
const (
	ActionRemoveRule         = "REMOVE_RULE"           // 移除指定规则
	ActionRemoveRuleTag      = "REMOVE_RULE_TAG"       // 移除规则标签
	ActionRemoveVarDetection = "REMOVE_VAR_DETECTION"  // 移除指定变量检测
	ActionAdjustScore        = "ADJUST_SCORE"          // 调整异常评分
	ActionLogOnly            = "LOG_ONLY"              // 仅记录不阻断
)

// 错误
var (
	ErrNotFound       = errors.New("exception not found")
	ErrInvalidInput   = errors.New("invalid exception input")
	ErrTooBroad       = errors.New("exception too broad")
	ErrRiskRequired   = errors.New("broad exception requires risk acknowledgment")
	ErrInvalidTime    = errors.New("invalid effective time range")
)

// 宽泛例外判定（高风险，需要确认）
// 禁止：全局关闭WAF、关闭全部SQLi/XSS规则、对全部应用移除高风险规则
var broadAttackTypes = map[string]bool{
	"SQL_INJECTION": true, "XSS": true, "COMMAND_INJECTION": true,
}

// Exception 是例外策略。
type Exception struct {
	ID               uuid.UUID  `json:"id"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	ScopeType        string     `json:"scope_type"`
	ApplicationID    *uuid.UUID `json:"application_id"`
	PolicyID         *uuid.UUID `json:"policy_id"`
	Domain           string     `json:"domain"`
	URIExact         string     `json:"uri_exact"`
	URIPrefix        string     `json:"uri_prefix"`
	URIRegex         string     `json:"uri_regex"`
	Methods          []string   `json:"methods"`
	SourceIPs        []string   `json:"source_ips"`
	ParamNames       []string   `json:"param_names"`
	CookieNames      []string   `json:"cookie_names"`
	HeaderNames      []string   `json:"header_names"`
	RuleIDs          []int      `json:"rule_ids"`
	RuleTags         []string   `json:"rule_tags"`
	AttackTypes      []string   `json:"attack_types"`
	ContentTypes     []string   `json:"content_types"`
	ExceptionAction  string     `json:"exception_action"`
	ActionTarget     string     `json:"action_target"`
	IsTemporary      bool       `json:"is_temporary"`
	EffectiveFrom    *time.Time `json:"effective_from"`
	EffectiveUntil   *time.Time `json:"effective_until"`
	Status           string     `json:"status"`
	RiskAcknowledged bool       `json:"risk_acknowledged"`
	Reason           string     `json:"reason"`
	Version          int        `json:"version"`
}

// hasSpecificCondition 判断是否有具体限定条件（限定后不算宽泛）。
func (e *Exception) hasSpecificCondition() bool {
	return e.Domain != "" || e.URIExact != "" || e.URIPrefix != "" ||
		len(e.ParamNames) > 0 || len(e.RuleIDs) > 0 || len(e.SourceIPs) > 0 ||
		len(e.CookieNames) > 0 || len(e.HeaderNames) > 0
}

// IsBroad 判断是否为宽泛例外（高风险）。
// 宽泛定义：对全部SQLi/XSS/CMDi攻击类型且无任何具体限定条件，
// 或全局且无条件，或无应用限定的规则标签例外。
func (e *Exception) IsBroad() bool {
	// 有具体限定条件的例外不算宽泛（精确例外）
	if e.hasSpecificCondition() {
		return false
	}
	// 对全部SQLi/XSS/CMDi攻击类型的无条件例外
	for _, at := range e.AttackTypes {
		if broadAttackTypes[at] {
			return true
		}
	}
	// 全局 + 无具体限定条件
	if e.ScopeType == "GLOBAL" {
		return true
	}
	// 无应用限定的规则标签例外
	if len(e.RuleTags) > 0 && e.ApplicationID == nil {
		for _, t := range e.RuleTags {
			if strings.Contains(strings.ToUpper(t), "SQLI") || strings.Contains(strings.ToUpper(t), "XSS") {
				return true
			}
		}
	}
	return false
}

// ValidateInput 校验例外策略输入。
func ValidateInput(e *Exception) error {
	if e.Name == "" || len(e.Name) > 128 {
		return fmt.Errorf("%w: 例外名称不能为空且不超过128字符", ErrInvalidInput)
	}
	// 时间范围
	if e.EffectiveFrom != nil && e.EffectiveUntil != nil {
		if e.EffectiveUntil.Before(*e.EffectiveFrom) {
			return fmt.Errorf("%w: 失效时间必须晚于生效时间", ErrInvalidTime)
		}
	}
	if e.IsTemporary && e.EffectiveUntil == nil {
		return fmt.Errorf("%w: 临时例外必须设置失效时间", ErrInvalidInput)
	}
	// URI 正则校验
	if e.URIRegex != "" {
		if _, err := regexp.Compile(e.URIRegex); err != nil {
			return fmt.Errorf("%w: URI正则语法错误: %v", ErrInvalidInput, err)
		}
	}
	// 来源 IP 校验
	for _, ip := range e.SourceIPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			if _, err := netip.ParsePrefix(ip); err != nil {
				return fmt.Errorf("%w: 无效的来源IP或CIDR: %s", ErrInvalidInput, ip)
			}
		}
	}
	// 域名校验
	if e.Domain != "" {
		if _, _, err := validation.ValidateHostname(e.Domain); err != nil {
			return fmt.Errorf("%w: 域名格式错误: %v", ErrInvalidInput, err)
		}
	}
	// 动作校验
	validActions := map[string]bool{
		ActionRemoveRule: true, ActionRemoveRuleTag: true,
		ActionRemoveVarDetection: true, ActionAdjustScore: true, ActionLogOnly: true,
	}
	if !validActions[e.ExceptionAction] {
		return fmt.Errorf("%w: 无效的例外动作", ErrInvalidInput)
	}
	// 宽泛例外需要风险确认
	if e.IsBroad() && !e.RiskAcknowledged {
		return fmt.Errorf("%w: 宽泛例外存在高风险，必须确认风险后才能创建", ErrRiskRequired)
	}
	return nil
}

// GenerateSecLang 生成例外对应的 SecLang 规则。
// 优先精确例外：指定应用＋指定路径＋指定规则＋指定参数。
func GenerateSecLang(e *Exception, ruleID int) string {
	var conditions []string
	// URI 条件
	uriCond := "REQUEST_URI"
	switch {
	case e.URIExact != "":
		conditions = append(conditions, fmt.Sprintf(`SecRule %s "@streq %s"`, uriCond, escapeArg(e.URIExact)))
	case e.URIPrefix != "":
		conditions = append(conditions, fmt.Sprintf(`SecRule %s "@beginsWith %s"`, uriCond, escapeArg(e.URIPrefix)))
	case e.URIRegex != "":
		conditions = append(conditions, fmt.Sprintf(`SecRule %s "@rx %s"`, uriCond, escapeArg(e.URIRegex)))
	case e.Domain != "":
		conditions = append(conditions, fmt.Sprintf(`SecRule REQUEST_HEADERS:Host "@streq %s"`, escapeArg(e.Domain)))
	default:
		conditions = append(conditions, `SecRule REQUEST_URI "@rx .*"`)
	}

	// 动作
	var actions []string
	actions = append(actions, fmt.Sprintf("id:%d", ruleID), "phase:1", "pass", "nolog")

	// ctl 例外动作
	ctls := buildCtlActions(e)
	actions = append(actions, ctls...)
	actions = append(actions, "tag:'jiuzhang-exception'")

	return fmt.Sprintf("%s \"%s\"", strings.Join(conditions, " \\\n    "), strings.Join(actions, ","))
}

// buildCtlActions 构建 ctl 例外动作。
func buildCtlActions(e *Exception) []string {
	var ctls []string
	switch e.ExceptionAction {
	case ActionRemoveRule:
		for _, rid := range e.RuleIDs {
			// 精确到参数时移除规则对特定变量的检测
			if len(e.ParamNames) > 0 {
				for _, p := range e.ParamNames {
					ctls = append(ctls, fmt.Sprintf("ctl:ruleRemoveTargetById=%d;ARGS:%s", rid, escapeVar(p)))
				}
			} else {
				ctls = append(ctls, fmt.Sprintf("ctl:ruleRemoveById=%d", rid))
			}
		}
	case ActionRemoveRuleTag:
		for _, t := range e.RuleTags {
			ctls = append(ctls, fmt.Sprintf("ctl:ruleRemoveByTag=%s", escapeVar(t)))
		}
	case ActionRemoveVarDetection:
		for _, p := range e.ParamNames {
			for _, rid := range e.RuleIDs {
				ctls = append(ctls, fmt.Sprintf("ctl:ruleRemoveTargetById=%d;ARGS:%s", rid, escapeVar(p)))
			}
		}
	case ActionLogOnly:
		ctls = append(ctls, "ctl:ruleEngine=DetectionOnly")
	case ActionAdjustScore:
		// 降低评分（通过设置 tx 变量，需在规则评估前）
		ctls = append(ctls, "ctl:ruleEngine=DetectionOnly")
	}
	return ctls
}

func escapeArg(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func escapeVar(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// Store 是例外策略仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// Create 创建例外。
func (s *Store) Create(ctx context.Context, e *Exception, createdBy uuid.UUID) error {
	if err := ValidateInput(e); err != nil {
		return err
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO exception_policies (name, description, scope_type, application_id, policy_id, domain,
  uri_exact, uri_prefix, uri_regex, methods, source_ips, param_names, cookie_names, header_names,
  rule_ids, rule_tags, attack_types, content_types, exception_action, action_target, is_temporary,
  effective_from, effective_until, status, risk_acknowledged, reason, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)
RETURNING id, version`,
		e.Name, e.Description, e.ScopeType, e.ApplicationID, e.PolicyID, e.Domain,
		e.URIExact, e.URIPrefix, e.URIRegex, jsonArray(e.Methods), jsonArray(e.SourceIPs),
		jsonArray(e.ParamNames), jsonArray(e.CookieNames), jsonArray(e.HeaderNames),
		jsonIntArray(e.RuleIDs), jsonArray(e.RuleTags), jsonArray(e.AttackTypes), jsonArray(e.ContentTypes),
		e.ExceptionAction, e.ActionTarget, e.IsTemporary, e.EffectiveFrom, e.EffectiveUntil,
		e.Status, e.RiskAcknowledged, e.Reason, createdBy,
	).Scan(&e.ID, &e.Version)
	return err
}

// GetByID 查询例外。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*Exception, error) {
	row := s.db.QueryRow(ctx, `
SELECT id, name, description, scope_type, application_id, policy_id, domain, uri_exact, uri_prefix,
  uri_regex, methods, source_ips, param_names, cookie_names, header_names, rule_ids, rule_tags,
  attack_types, content_types, exception_action, action_target, is_temporary, effective_from,
  effective_until, status, risk_acknowledged, reason, version
FROM exception_policies WHERE id = $1 AND deleted_at IS NULL`, id)
	return scanException(row)
}

// List 分页查询。
func (s *Store) List(ctx context.Context, scopeType, status string, page, pageSize int) ([]Exception, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "deleted_at IS NULL"
	args := []interface{}{}
	argIdx := 1
	if scopeType != "" {
		where += fmt.Sprintf(" AND scope_type = $%d", argIdx)
		args = append(args, scopeType)
		argIdx++
	}
	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM exception_policies WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `
SELECT id, name, description, scope_type, application_id, policy_id, domain, uri_exact, uri_prefix,
  uri_regex, methods, source_ips, param_names, cookie_names, header_names, rule_ids, rule_tags,
  attack_types, content_types, exception_action, action_target, is_temporary, effective_from,
  effective_until, status, risk_acknowledged, reason, version
FROM exception_policies WHERE ` + where + fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Exception
	for rows.Next() {
		e, err := scanExceptionRows(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *e)
	}
	return out, total, rows.Err()
}

// Delete 删除例外。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx,
		`UPDATE exception_policies SET deleted_at=now(), updated_at=now(), version=version+1 WHERE id=$1 AND deleted_at IS NULL`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetStatus 设置例外状态。
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	res, err := s.db.Exec(ctx, `UPDATE exception_policies SET status=$1, updated_at=now(), version=version+1 WHERE id=$2 AND deleted_at IS NULL`, status, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Update 更新例外策略（乐观锁：version 不匹配则失败）。
// 状态不在此方法修改，须走 SetStatus。
func (s *Store) Update(ctx context.Context, e *Exception, expectedVersion int) error {
	if err := ValidateInput(e); err != nil {
		return err
	}
	res, err := s.db.Exec(ctx, `
UPDATE exception_policies SET name=$1, description=$2, scope_type=$3, application_id=$4, policy_id=$5,
  domain=$6, uri_exact=$7, uri_prefix=$8, uri_regex=$9, methods=$10, source_ips=$11, param_names=$12,
  cookie_names=$13, header_names=$14, rule_ids=$15, rule_tags=$16, attack_types=$17, content_types=$18,
  exception_action=$19, action_target=$20, is_temporary=$21, effective_from=$22, effective_until=$23,
  risk_acknowledged=$24, reason=$25, updated_at=now(), version=version+1
WHERE id=$26 AND version=$27 AND deleted_at IS NULL`,
		e.Name, e.Description, e.ScopeType, e.ApplicationID, e.PolicyID,
		e.Domain, e.URIExact, e.URIPrefix, e.URIRegex, jsonArray(e.Methods), jsonArray(e.SourceIPs),
		jsonArray(e.ParamNames), jsonArray(e.CookieNames), jsonArray(e.HeaderNames),
		jsonIntArray(e.RuleIDs), jsonArray(e.RuleTags), jsonArray(e.AttackTypes), jsonArray(e.ContentTypes),
		e.ExceptionAction, e.ActionTarget, e.IsTemporary, e.EffectiveFrom, e.EffectiveUntil,
		e.RiskAcknowledged, e.Reason, e.ID, expectedVersion)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	e.Version = expectedVersion + 1
	return nil
}

// ExpireTemporary 到期临时例外自动失效（定时任务）。
func (s *Store) ExpireTemporary(ctx context.Context) (int, error) {
	res, err := s.db.Exec(ctx, `
UPDATE exception_policies SET status='EXPIRED', updated_at=now()
WHERE is_temporary = TRUE AND status = 'ENABLED' AND effective_until IS NOT NULL AND effective_until < now()`)
	if err != nil {
		return 0, err
	}
	return int(res.RowsAffected()), nil
}

func scanException(row pgx.Row) (*Exception, error) {
	var e Exception
	var methods, ips, params, cookies, headers, ruleIDs, ruleTags, attackTypes, contentTypes []byte
	err := row.Scan(&e.ID, &e.Name, &e.Description, &e.ScopeType, &e.ApplicationID, &e.PolicyID,
		&e.Domain, &e.URIExact, &e.URIPrefix, &e.URIRegex, &methods, &ips, &params, &cookies,
		&headers, &ruleIDs, &ruleTags, &attackTypes, &contentTypes, &e.ExceptionAction, &e.ActionTarget,
		&e.IsTemporary, &e.EffectiveFrom, &e.EffectiveUntil, &e.Status, &e.RiskAcknowledged, &e.Reason, &e.Version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	e.Methods = parseStrArray(methods)
	e.SourceIPs = parseStrArray(ips)
	e.ParamNames = parseStrArray(params)
	e.CookieNames = parseStrArray(cookies)
	e.HeaderNames = parseStrArray(headers)
	e.RuleIDs = parseIntArray(ruleIDs)
	e.RuleTags = parseStrArray(ruleTags)
	e.AttackTypes = parseStrArray(attackTypes)
	e.ContentTypes = parseStrArray(contentTypes)
	return &e, nil
}

func scanExceptionRows(rows pgx.Rows) (*Exception, error) {
	var e Exception
	var methods, ips, params, cookies, headers, ruleIDs, ruleTags, attackTypes, contentTypes []byte
	err := rows.Scan(&e.ID, &e.Name, &e.Description, &e.ScopeType, &e.ApplicationID, &e.PolicyID,
		&e.Domain, &e.URIExact, &e.URIPrefix, &e.URIRegex, &methods, &ips, &params, &cookies,
		&headers, &ruleIDs, &ruleTags, &attackTypes, &contentTypes, &e.ExceptionAction, &e.ActionTarget,
		&e.IsTemporary, &e.EffectiveFrom, &e.EffectiveUntil, &e.Status, &e.RiskAcknowledged, &e.Reason, &e.Version)
	if err != nil {
		return nil, err
	}
	e.Methods = parseStrArray(methods)
	e.SourceIPs = parseStrArray(ips)
	e.ParamNames = parseStrArray(params)
	e.CookieNames = parseStrArray(cookies)
	e.HeaderNames = parseStrArray(headers)
	e.RuleIDs = parseIntArray(ruleIDs)
	e.RuleTags = parseStrArray(ruleTags)
	e.AttackTypes = parseStrArray(attackTypes)
	e.ContentTypes = parseStrArray(contentTypes)
	return &e, nil
}

func jsonArray(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteString("[")
	for i, s := range v {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"` + strings.ReplaceAll(s, `"`, `\"`) + `"`)
	}
	b.WriteString("]")
	return b.String()
}

func jsonIntArray(v []int) string {
	if len(v) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteString("[")
	for i, n := range v {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(fmt.Sprintf("%d", n))
	}
	b.WriteString("]")
	return b.String()
}

func parseStrArray(data []byte) []string {
	if len(data) == 0 || string(data) == "[]" || string(data) == "null" {
		return nil
	}
	var out []string
	s := strings.Trim(string(data), "[]")
	for _, part := range strings.Split(s, ",") {
		part = strings.Trim(part, ` "`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseIntArray(data []byte) []int {
	if len(data) == 0 || string(data) == "[]" || string(data) == "null" {
		return nil
	}
	var out []int
	s := strings.Trim(string(data), "[]")
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err == nil {
			out = append(out, n)
		}
	}
	return out
}
