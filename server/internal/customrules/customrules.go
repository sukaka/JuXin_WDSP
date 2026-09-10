// Package customrules 提供九章自定义WAF规则：结构化编辑 → SecLang 生成与校验。
package customrules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 规则 ID 规划
const (
	JiuzhangBuiltinMin = 7000000
	JiuzhangBuiltinMax = 7099999
	UserCustomMin      = 7100000
	UserCustomMax      = 7199999
)

// 错误
var (
	ErrNotFound         = errors.New("custom rule not found")
	ErrIDConflict       = errors.New("rule id conflict")
	ErrIDOutOfRange     = errors.New("rule id out of allowed range")
	ErrInvalidRule      = errors.New("invalid custom rule")
	ErrDangerousContent = errors.New("dangerous content in rule")
)

// 允许的操作符（白名单，禁止任意命令执行/文件读取）
var allowedOperators = map[string]bool{
	"rx": true, "pm": true, "pmFromFile": false, // pmFromFile 禁止（任意文件读取）
	"streq": true, "contains": true, "beginsWith": true, "endsWith": true,
	"eq": true, "ne": true, "gt": true, "lt": true, "ge": true, "le": true,
	"ipMatch": true, "validateUrlEncoding": true, "validateUtf8Encoding": true,
	"detectSQLi": true, "detectXSS": true,
}

// 允许的检测变量（白名单）
var allowedVariables = map[string]bool{
	"ARGS": true, "ARGS_GET": true, "ARGS_POST": true, "ARGS_NAMES": true,
	"QUERY_STRING": true, "REQUEST_URI": true, "REQUEST_METHOD": true,
	"REQUEST_HEADERS": true, "REQUEST_HEADERS_NAMES": true, "REQUEST_COOKIES": true,
	"REQUEST_BODY": true, "REQUEST_FILENAME": true, "REQUEST_BASENAME": true,
	"REMOTE_ADDR": true, "HTTP_USER_AGENT": true, "CONTENT_TYPE": true,
	"REQUEST_PROTOCOL": true, "REQUEST_LINE": true,
}

// 检测变量形态白名单：变量名[:选择器]，整体限定字符集。
// GenerateSecLang 将变量以 | 原样拼接进 SecRule 首参，不转义——
// 必须在此拒绝引号、空白与一切控制字符，否则可注入独立指令行（如 SecAction ctl:ruleEngine=Off）。
var variablePattern = regexp.MustCompile(`^[A-Z_]+(:[A-Za-z0-9_.-]+)?$`)

// 允许的动作
var allowedActions = map[string]bool{
	"LOG": true, "OBSERVE": true, "BLOCK": true,
}

// 危险内容模式（禁止出现在规则中）
var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)exec\s*\(`),
	regexp.MustCompile(`(?i)@exec\b`),
	regexp.MustCompile(`(?i)@readFile\b`),
	regexp.MustCompile(`(?i)@pmFromFile\s+/`),
	regexp.MustCompile("(?i)`[^`]*`"), // 命令替换
	regexp.MustCompile(`\$\{[^}]*\}`),
	regexp.MustCompile(`(?i)/etc/passwd`),
	regexp.MustCompile(`(?i)/etc/shadow`),
}

// CustomRule 是自定义规则。
type CustomRule struct {
	ID              uuid.UUID `json:"id"`
	RuleID          int       `json:"rule_id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	AttackType      string    `json:"attack_type"`
	Severity        string    `json:"severity"`
	Phase           int       `json:"phase"`
	Operator        string    `json:"operator"`
	OperatorValue   string    `json:"operator_value"`
	TargetVariables []string  `json:"target_variables"`
	Action          string    `json:"action"`
	Tags            []string  `json:"tags"`
	Status          string    `json:"status"`
	ScopeType       string    `json:"scope_type"`
	ScopeIDs        []string  `json:"scope_ids"`
	GeneratedRule   string    `json:"generated_rule"`
	Version         int       `json:"version"`
}

// ValidateInput 校验自定义规则输入并生成 SecLang。
func ValidateInput(r *CustomRule) (generated string, err error) {
	// 规则 ID 范围
	if r.RuleID < UserCustomMin || r.RuleID > UserCustomMax {
		return "", fmt.Errorf("%w: 自定义规则ID必须在 %d-%d 之间", ErrIDOutOfRange, UserCustomMin, UserCustomMax)
	}
	// 名称
	if r.Name == "" || len(r.Name) > 128 {
		return "", fmt.Errorf("%w: 规则名称不能为空且不超过128字符", ErrInvalidRule)
	}
	// 操作符白名单
	op := strings.TrimSpace(r.Operator)
	if !allowedOperators[op] {
		return "", fmt.Errorf("%w: 不支持的操作符 %q", ErrInvalidRule, op)
	}
	// 操作值必填（除部分无值操作符）
	if op != "detectSQLi" && op != "detectXSS" && op != "validateUrlEncoding" && op != "validateUtf8Encoding" {
		if strings.TrimSpace(r.OperatorValue) == "" {
			return "", fmt.Errorf("%w: 操作符 %q 需要匹配内容", ErrInvalidRule, op)
		}
	}
	// 操作值嵌入双引号 SecLang 参数；引号和换行会改变指令边界，必须拒绝。
	if strings.ContainsAny(r.OperatorValue, "\"\r\n") {
		return "", fmt.Errorf("%w: 操作值包含非法 SecLang 控制字符", ErrInvalidRule)
	}
	// 危险内容检测（覆盖全部进入 SecLang 的自由文本面，含检测变量）
	fullText := r.OperatorValue + " " + r.Name + " " + r.Description + " " + strings.Join(r.TargetVariables, " ")
	for _, dp := range dangerousPatterns {
		if dp.MatchString(fullText) {
			return "", fmt.Errorf("%w: 规则包含禁止内容（命令执行/文件读取/危险引用）", ErrDangerousContent)
		}
	}
	// 正则语法校验（rx 操作符）
	if op == "rx" {
		if _, err := regexp.Compile(r.OperatorValue); err != nil {
			return "", fmt.Errorf("%w: 正则表达式语法错误: %v", ErrInvalidRule, err)
		}
	}
	// 检测变量白名单
	if len(r.TargetVariables) == 0 {
		return "", fmt.Errorf("%w: 至少选择一个检测变量", ErrInvalidRule)
	}
	for _, v := range r.TargetVariables {
		// 先校验整体形态（拒绝控制字符/引号/管道符等 SecLang 元字符），再查白名单
		if !variablePattern.MatchString(v) {
			return "", fmt.Errorf("%w: 检测变量格式非法 %q（仅允许 变量名[:选择器]）", ErrInvalidRule, v)
		}
		base := strings.Split(v, ":")[0]
		if !allowedVariables[base] && !allowedVariables[v] {
			return "", fmt.Errorf("%w: 不支持的检测变量 %q", ErrInvalidRule, v)
		}
	}
	// 动作白名单
	action := strings.ToUpper(strings.TrimSpace(r.Action))
	if !allowedActions[action] {
		return "", fmt.Errorf("%w: 不支持的动作 %q（允许 LOG/OBSERVE/BLOCK）", ErrInvalidRule, action)
	}
	// 阶段
	if r.Phase < 1 || r.Phase > 5 {
		return "", fmt.Errorf("%w: 执行阶段必须在1至5之间", ErrInvalidRule)
	}
	// 风险等级
	sev := strings.ToUpper(strings.TrimSpace(r.Severity))
	if sev != "CRITICAL" && sev != "ERROR" && sev != "WARNING" && sev != "NOTICE" {
		sev = "WARNING"
	}

	// 生成 SecLang
	generated = GenerateSecLang(r.RuleID, r.Name, r.TargetVariables, op, r.OperatorValue, action, sev, r.Phase, r.AttackType, r.Tags)
	return generated, nil
}

// GenerateSecLang 生成 SecLang 规则文本（安全转义）。
func GenerateSecLang(ruleID int, name string, variables []string, operator, operatorValue, action, severity string, phase int, attackType string, tags []string) string {
	// 变量列表
	vars := strings.Join(variables, "|")
	// 操作表达式
	var opExpr string
	switch operator {
	case "detectSQLi", "detectXSS", "validateUrlEncoding", "validateUtf8Encoding":
		opExpr = "@" + operator
	default:
		opExpr = "@" + operator + " " + escapeSecLangArg(operatorValue)
	}
	// 动作
	var actionParts []string
	actionParts = append(actionParts, "id:"+strconv.Itoa(ruleID))
	actionParts = append(actionParts, "phase:"+strconv.Itoa(phase))
	switch action {
	case "BLOCK":
		actionParts = append(actionParts, "deny", "status:403", "log")
	case "OBSERVE":
		actionParts = append(actionParts, "pass", "log")
	default: // LOG
		actionParts = append(actionParts, "pass", "log")
	}
	actionParts = append(actionParts, "msg:'"+escapeSecLangString(name)+"'")
	actionParts = append(actionParts, "severity:'"+severity+"'")
	actionParts = append(actionParts, "tag:'jiuzhang-custom'")
	if attackType != "" && attackType != "OTHER" {
		actionParts = append(actionParts, "tag:'"+escapeSecLangString(attackType)+"'")
	}
	for _, t := range tags {
		actionParts = append(actionParts, "tag:'"+escapeSecLangString(t)+"'")
	}

	return fmt.Sprintf("SecRule %s \"%s\" \"%s\"", vars, opExpr, strings.Join(actionParts, ","))
}

// escapeSecLangArg 转义 SecLang 操作值参数（防注入）。
func escapeSecLangArg(s string) string {
	// 正则反斜杠是语义的一部分，不能像普通字符串那样加倍；引号由输入校验拒绝，
	// 这里保留转义以保证直接调用 GenerateSecLang 时仍不会打开参数边界。
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// escapeSecLangString 转义 SecLang 单引号字符串。
func escapeSecLangString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	// 移除控制字符
	var b strings.Builder
	for _, c := range s {
		if c >= 0x20 && c != 0x7f {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// Store 是自定义规则仓储。
type Store struct {
	db *pgxpool.Pool
}

// NewStore 创建仓储。
func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

// Create 创建自定义规则。
func (s *Store) Create(ctx context.Context, r *CustomRule, createdBy uuid.UUID) error {
	generated, err := ValidateInput(r)
	if err != nil {
		return err
	}
	r.GeneratedRule = generated
	// ID 冲突检查（全库）
	var exists bool
	err = s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM custom_rules WHERE rule_id = $1)`, r.RuleID).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return ErrIDConflict
	}
	tagsJSON := mustJSON(r.Tags)
	varsJSON := mustJSON(r.TargetVariables)
	scopeJSON := mustJSON(r.ScopeIDs)
	err = s.db.QueryRow(ctx, `
INSERT INTO custom_rules (rule_id, name, description, attack_type, severity, phase, operator,
  operator_value, target_variables, action, tags, status, scope_type, scope_ids, generated_rule, created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
RETURNING id, version`,
		r.RuleID, r.Name, r.Description, r.AttackType, r.Severity, r.Phase, r.Operator,
		r.OperatorValue, varsJSON, r.Action, tagsJSON, defaultStatus(r.Status), r.ScopeType, scopeJSON, r.GeneratedRule, createdBy,
	).Scan(&r.ID, &r.Version)
	if err != nil {
		if strings.Contains(err.Error(), "custom_rules_rule_id_key") {
			return ErrIDConflict
		}
		return err
	}
	return nil
}

// GetByID 查询规则。
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*CustomRule, error) {
	row := s.db.QueryRow(ctx, `
SELECT id, rule_id, name, description, attack_type, severity, phase, operator, operator_value,
  target_variables, action, tags, status, scope_type, scope_ids, generated_rule, version
FROM custom_rules WHERE id = $1`, id)
	return scanRule(row)
}

// List 分页查询。
func (s *Store) List(ctx context.Context, keyword, status string, page, pageSize int) ([]CustomRule, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}
	where := "1=1"
	args := []interface{}{}
	argIdx := 1
	if keyword != "" {
		where += fmt.Sprintf(" AND (name ILIKE $%d OR description ILIKE $%d OR rule_id::text ILIKE $%d)", argIdx, argIdx, argIdx)
		args = append(args, "%"+keyword+"%")
		argIdx++
	}
	if status != "" {
		where += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM custom_rules WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	query := `
SELECT id, rule_id, name, description, attack_type, severity, phase, operator, operator_value,
  target_variables, action, tags, status, scope_type, scope_ids, generated_rule, version
FROM custom_rules WHERE ` + where + fmt.Sprintf(" ORDER BY rule_id LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []CustomRule
	for rows.Next() {
		r, err := scanRuleRows(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *r)
	}
	return out, total, rows.Err()
}

// Update 更新规则。
func (s *Store) Update(ctx context.Context, r *CustomRule) error {
	generated, err := ValidateInput(r)
	if err != nil {
		return err
	}
	r.GeneratedRule = generated
	res, err := s.db.Exec(ctx, `
UPDATE custom_rules SET name=$1, description=$2, attack_type=$3, severity=$4, phase=$5,
  operator=$6, operator_value=$7, target_variables=$8, action=$9, tags=$10, scope_type=$11,
  scope_ids=$12, generated_rule=$13, updated_at=now(), version=version+1
WHERE id=$14 AND version=$15`,
		r.Name, r.Description, r.AttackType, r.Severity, r.Phase, r.Operator, r.OperatorValue,
		mustJSON(r.TargetVariables), r.Action, mustJSON(r.Tags), r.ScopeType, mustJSON(r.ScopeIDs),
		r.GeneratedRule, r.ID, r.Version)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	r.Version++
	return nil
}

// SetStatus 设置规则状态。
func (s *Store) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	res, err := s.db.Exec(ctx, `UPDATE custom_rules SET status=$1, updated_at=now(), version=version+1 WHERE id=$2`, status, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListEnabledSecLang 返回所有 ENABLED 自定义规则的 SecLang（按 rule_id 升序，确定性）。
func (s *Store) ListEnabledSecLang(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `
SELECT generated_rule FROM custom_rules
WHERE status = 'ENABLED' AND generated_rule <> ''
ORDER BY rule_id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out, rows.Err()
}

// Delete 删除规则。
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.Exec(ctx, `DELETE FROM custom_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanRule(row pgx.Row) (*CustomRule, error) {
	var r CustomRule
	var vars, tags, scope []byte
	err := row.Scan(&r.ID, &r.RuleID, &r.Name, &r.Description, &r.AttackType, &r.Severity,
		&r.Phase, &r.Operator, &r.OperatorValue, &vars, &r.Action, &tags, &r.Status,
		&r.ScopeType, &scope, &r.GeneratedRule, &r.Version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	r.TargetVariables = fromJSON(vars)
	r.Tags = fromJSON(tags)
	r.ScopeIDs = fromJSON(scope)
	return &r, nil
}

func scanRuleRows(rows pgx.Rows) (*CustomRule, error) {
	var r CustomRule
	var vars, tags, scope []byte
	err := rows.Scan(&r.ID, &r.RuleID, &r.Name, &r.Description, &r.AttackType, &r.Severity,
		&r.Phase, &r.Operator, &r.OperatorValue, &vars, &r.Action, &tags, &r.Status,
		&r.ScopeType, &scope, &r.GeneratedRule, &r.Version)
	if err != nil {
		return nil, err
	}
	r.TargetVariables = fromJSON(vars)
	r.Tags = fromJSON(tags)
	r.ScopeIDs = fromJSON(scope)
	return &r, nil
}

func defaultStatus(s string) string {
	if s == "DISABLED" {
		return "DISABLED"
	}
	return "ENABLED"
}

func mustJSON(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	data, err := json.Marshal(v)
	if err != nil {
		// []string 序列化不会失败；兜底返回空数组而非损坏数据
		return "[]"
	}
	return string(data)
}

func fromJSON(data []byte) []string {
	if len(data) == 0 || string(data) == "[]" || string(data) == "null" {
		return nil
	}
	var out []string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}
