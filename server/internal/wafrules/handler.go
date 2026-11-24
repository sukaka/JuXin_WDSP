package wafrules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

const (
	maxDescriptionFieldRunes = 2000
	maxDescriptionBodyBytes  = 64 << 10
)

// ErrRuleNotFound 表示目标规则 ID 不存在。
var ErrRuleNotFound = errors.New("规则不存在")

// Handler 是WAF规则处理器。
type Handler struct {
	db         *pgxpool.Pool
	syncSvc    *SyncService
	audits     *audits.Service
	crsDir     string
	crsVersion string
}

// NewHandler 创建规则处理器。
func NewHandler(db *pgxpool.Pool, au *audits.Service, crsDir, crsVersion string) *Handler {
	return &Handler{db: db, syncSvc: NewSyncService(db), audits: au, crsDir: crsDir, crsVersion: crsVersion}
}

// ValidateDescriptionOverrideInput 校验并清洗管理员提交的规则中文说明覆盖内容。
func ValidateDescriptionOverrideInput(in *RuleDescriptionOverride) error {
	if in == nil {
		return errors.New("请求参数不能为空")
	}
	fields := []struct {
		label string
		ptr   *string
	}{
		{"规则概述", &in.Summary},
		{"检测原理与检查目标", &in.DetectionLogic},
		{"安全风险与防护意义", &in.RiskImpact},
		{"误报排查与调优建议", &in.TuningAdvice},
	}
	for _, f := range fields {
		v := strings.TrimSpace(*f.ptr)
		if !utf8.ValidString(v) {
			return fmt.Errorf("%s包含非法字符编码", f.label)
		}
		for _, r := range v {
			if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
				return fmt.Errorf("%s包含不允许的控制字符", f.label)
			}
		}
		if len([]rune(v)) > maxDescriptionFieldRunes {
			return fmt.Errorf("%s长度不能超过 %d 字", f.label, maxDescriptionFieldRunes)
		}
		*f.ptr = v
	}
	if !in.HasAnyContent() {
		return errors.New("请至少填写一项说明内容；如需恢复系统默认说明请使用重置功能")
	}
	return nil
}

// List 规则列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	ruleIDStr := r.URL.Query().Get("rule_id")
	keyword := r.URL.Query().Get("keyword")
	attackType := r.URL.Query().Get("attack_type")
	severity := r.URL.Query().Get("severity")
	source := r.URL.Query().Get("rule_source")
	tag := r.URL.Query().Get("tag")
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)

	where := "1=1"
	args := []interface{}{}
	argIdx := 1
	add := func(cond string, v interface{}) {
		where += " AND " + cond
		args = append(args, v)
		argIdx++
	}
	if ruleIDStr != "" {
		if id, err := strconv.Atoi(ruleIDStr); err == nil {
			add("r.rule_id = $"+itoa(argIdx), id)
		}
	}
	if keyword != "" {
		p := "$" + itoa(argIdx)
		add("(r.name ILIKE "+p+" OR r.message ILIKE "+p+" OR COALESCE(d.summary, '') ILIKE "+p+")", "%"+keyword+"%")
	}
	if attackType != "" {
		add("r.attack_type = $"+itoa(argIdx), attackType)
	}
	if severity != "" {
		add("r.severity = $"+itoa(argIdx), severity)
	}
	if source != "" {
		add("r.rule_source = $"+itoa(argIdx), source)
	}
	if tag != "" {
		add("r.tags::text ILIKE $"+itoa(argIdx), "%"+tag+"%")
	}

	var total int64
	countSQL := `SELECT count(*) FROM waf_rules r LEFT JOIN waf_rule_descriptions d ON d.rule_id = r.rule_id WHERE ` + where
	if err := h.db.QueryRow(r.Context(), countSQL, args...).Scan(&total); err != nil {
		response.InternalError(w, r, err)
		return
	}
	query := `
SELECT r.id, r.rule_id, r.rule_source, r.file_name, r.name, r.message, r.severity, r.phase,
       r.tags, r.attack_type, r.default_state, r.crs_version, r.parsed_spec,
       COALESCE(d.summary, ''), COALESCE(d.detection_logic, ''), COALESCE(d.risk_impact, ''),
       COALESCE(d.tuning_advice, ''), COALESCE(d.updated_by_name, ''), d.updated_at
FROM waf_rules r
LEFT JOIN waf_rule_descriptions d ON d.rule_id = r.rule_id
WHERE ` + where + " ORDER BY r.rule_id LIMIT $" + itoa(argIdx) + " OFFSET $" + itoa(argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := h.db.Query(r.Context(), query, args...)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer rows.Close()
	var items []map[string]interface{}
	for rows.Next() {
		item, _, err := scanRuleRow(rows, false)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, pageSize)
}

// Get 规则详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	ruleID, ok := parseRuleIDPath(w, r)
	if !ok {
		return
	}
	payload, _, err := h.fetchRuleDetail(r.Context(), ruleID)
	if err != nil {
		if errors.Is(err, ErrRuleNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, payload)
}

// UpdateDescription 新增或更新管理员手工维护的规则中文详细说明（方案 B）。
func (h *Handler) UpdateDescription(w http.ResponseWriter, r *http.Request) {
	ruleID, ok := parseRuleIDPath(w, r)
	if !ok {
		return
	}
	var req RuleDescriptionOverride
	dec := json.NewDecoder(io.LimitReader(r.Body, maxDescriptionBodyBytes))
	if err := dec.Decode(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体 JSON 格式错误")
		return
	}
	if err := ValidateDescriptionOverrideInput(&req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if h.db == nil {
		response.InternalError(w, r, errors.New("database unavailable"))
		return
	}

	_, ruleName, err := h.fetchRuleDetail(r.Context(), ruleID)
	if err != nil {
		if errors.Is(err, ErrRuleNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	p := authz.PrincipalFrom(r.Context())
	var operatorID *uuid.UUID
	operatorName := ""
	if p != nil {
		uid := p.UserID
		operatorID = &uid
		operatorName = p.Username
	}

	_, err = h.db.Exec(r.Context(), `
INSERT INTO waf_rule_descriptions (
  rule_id, summary, detection_logic, risk_impact, tuning_advice, updated_by, updated_by_name, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, now())
ON CONFLICT (rule_id) DO UPDATE SET
  summary = EXCLUDED.summary,
  detection_logic = EXCLUDED.detection_logic,
  risk_impact = EXCLUDED.risk_impact,
  tuning_advice = EXCLUDED.tuning_advice,
  updated_by = EXCLUDED.updated_by,
  updated_by_name = EXCLUDED.updated_by_name,
  updated_at = now()`,
		ruleID, req.Summary, req.DetectionLogic, req.RiskImpact, req.TuningAdvice, operatorID, operatorName)
	if err != nil {
		h.recordAudit(r, p, "waf_rules", "update_description", "waf_rule", itoa(ruleID), ruleName,
			"error="+err.Error(), audits.ResultFailure, audits.RiskLow)
		response.InternalError(w, r, err)
		return
	}

	payload, _, err := h.fetchRuleDetail(r.Context(), ruleID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "waf_rules", "update_description", "waf_rule", itoa(ruleID), ruleName,
		"summary="+truncate(req.Summary, 120), audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, payload)
}

// ResetDescription 清除管理员手工覆盖的规则中文说明，恢复系统内置或规则文件自动解析说明（方案 B）。
func (h *Handler) ResetDescription(w http.ResponseWriter, r *http.Request) {
	ruleID, ok := parseRuleIDPath(w, r)
	if !ok {
		return
	}
	if h.db == nil {
		response.InternalError(w, r, errors.New("database unavailable"))
		return
	}

	_, ruleName, err := h.fetchRuleDetail(r.Context(), ruleID)
	if err != nil {
		if errors.Is(err, ErrRuleNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	p := authz.PrincipalFrom(r.Context())
	if _, err := h.db.Exec(r.Context(), `DELETE FROM waf_rule_descriptions WHERE rule_id = $1`, ruleID); err != nil {
		h.recordAudit(r, p, "waf_rules", "reset_description", "waf_rule", itoa(ruleID), ruleName,
			"error="+err.Error(), audits.ResultFailure, audits.RiskLow)
		response.InternalError(w, r, err)
		return
	}

	payload, _, err := h.fetchRuleDetail(r.Context(), ruleID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "waf_rules", "reset_description", "waf_rule", itoa(ruleID), ruleName,
		"reset_to_default", audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, payload)
}

func (h *Handler) fetchRuleDetail(ctx context.Context, ruleID int) (map[string]interface{}, string, error) {
	rows, err := h.db.Query(ctx, `
SELECT r.id, r.rule_id, r.rule_source, r.file_name, r.name, r.message, r.severity, r.phase,
       r.tags, r.attack_type, r.default_state, r.crs_version, r.parsed_spec,
       COALESCE(d.summary, ''), COALESCE(d.detection_logic, ''), COALESCE(d.risk_impact, ''),
       COALESCE(d.tuning_advice, ''), COALESCE(d.updated_by_name, ''), d.updated_at
FROM waf_rules r
LEFT JOIN waf_rule_descriptions d ON d.rule_id = r.rule_id
WHERE r.rule_id = $1
ORDER BY r.crs_version DESC
LIMIT 1`, ruleID)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, "", err
		}
		return nil, "", ErrRuleNotFound
	}
	return scanRuleRow(rows, true)
}

func scanRuleRow(rows pgx.Rows, includeDetail bool) (map[string]interface{}, string, error) {
	var (
		id            uuid.UUID
		ruleID        int
		source, file  string
		name, message string
		severity      string
		phase         int
		tags          []byte
		attackType    string
		defaultState  string
		crsVersion    string
		parsedSpec    []byte
		ovSummary     string
		ovLogic       string
		ovRisk        string
		ovTuning      string
		ovUpdatedBy   string
		ovUpdatedAt   *time.Time
	)
	if err := rows.Scan(
		&id, &ruleID, &source, &file, &name, &message, &severity, &phase,
		&tags, &attackType, &defaultState, &crsVersion, &parsedSpec,
		&ovSummary, &ovLogic, &ovRisk, &ovTuning, &ovUpdatedBy, &ovUpdatedAt,
	); err != nil {
		return nil, "", err
	}
	name = LocalizeRule(ruleID, file, name)
	message = LocalizeRule(ruleID, file, message)

	var customOv *RuleDescriptionOverride
	ov := &RuleDescriptionOverride{
		Summary:        ovSummary,
		DetectionLogic: ovLogic,
		RiskImpact:     ovRisk,
		TuningAdvice:   ovTuning,
		UpdatedByName:  ovUpdatedBy,
		UpdatedAt:      ovUpdatedAt,
	}
	if ov.HasAnyContent() {
		customOv = ov
	}

	detail := DescribeRule(RuleDescribeInput{
		RuleID:         ruleID,
		RuleSource:     source,
		FileName:       file,
		Name:           name,
		Message:        message,
		Severity:       severity,
		Phase:          phase,
		AttackType:     attackType,
		DefaultState:   defaultState,
		CRSVersion:     crsVersion,
		Tags:           ParseTagsJSON(tags),
		ParsedSpec:     json.RawMessage(parsedSpec),
		CustomOverride: customOv,
	})

	item := map[string]interface{}{
		"id": id, "rule_id": ruleID, "rule_source": source, "file_name": file,
		"name": name, "message": message, "description": detail.Summary,
		"severity": severity, "phase": phase,
		"tags": tags, "attack_type": attackType, "default_state": defaultState, "crs_version": crsVersion,
	}
	if includeDetail {
		item["detail"] = detail
	}
	return item, name, nil
}

func parseRuleIDPath(w http.ResponseWriter, r *http.Request) (int, bool) {
	ruleIDStr := r.PathValue("rule_id")
	ruleID, err := strconv.Atoi(ruleIDStr)
	if err != nil || ruleID <= 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return 0, false
	}
	return ruleID, true
}

// Categories 规则分类统计。
func (h *Handler) Categories(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(), `
SELECT attack_type, count(*) FROM waf_rules GROUP BY attack_type ORDER BY count(*) DESC`)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer rows.Close()
	var items []map[string]interface{}
	for rows.Next() {
		var at string
		var n int
		if err := rows.Scan(&at, &n); err != nil {
			response.InternalError(w, r, err)
			return
		}
		items = append(items, map[string]interface{}{"attack_type": at, "count": n})
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": items})
}

// Versions 规则版本列表。
func (h *Handler) Versions(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(), `
SELECT DISTINCT crs_version FROM waf_rules WHERE rule_source = $1 ORDER BY crs_version DESC`, SourceCRS)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer rows.Close()
	var versions []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			response.InternalError(w, r, err)
			return
		}
		versions = append(versions, v)
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"versions": versions})
}

// Sync 触发规则元数据同步（CRS 主包 + CRS 插件 + 第三方/自建 contrib 包 + 九章内置规则）。
func (h *Handler) Sync(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	report, err := h.syncSvc.SyncFromSources(r.Context(), h.crsVersion, h.syncSources())
	if err != nil {
		h.recordAudit(r, p, "waf_rules", "sync", "crs", h.crsVersion, h.crsVersion,
			"error="+err.Error(), audits.ResultFailure, audits.RiskMedium)
		if errors.Is(err, ErrCRSDirEmpty) {
			response.Error(w, r, http.StatusServiceUnavailable, "CRS_RULES_UNAVAILABLE", err.Error())
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "waf_rules", "sync", "crs", h.crsVersion, h.crsVersion,
		"added="+itoa(report.Added)+",updated="+itoa(report.Updated)+",total="+itoa(report.TotalInDB), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, report)
}

// syncSources 组装同步来源：CRS 主包、CRS 插件目录、contrib 分包目录与九章内置目录。
func (h *Handler) syncSources() []SourceDir {
	return BuildSyncSources(h.crsDir)
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, module, action, objType, objID, objName, summary, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       module,
		Action:       action,
		ObjectType:   objType,
		ObjectID:     objID,
		ObjectName:   objName,
		AfterSummary: summary,
		Result:       result,
		RiskLevel:    risk,
		RequestID:    response.RequestIDFrom(r),
	})
}

func itoa(v int) string {
	return strconv.Itoa(v)
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
