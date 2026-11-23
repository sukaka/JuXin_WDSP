package wafrules

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

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
			add("rule_id = $"+itoa(argIdx), id)
		}
	}
	if keyword != "" {
		add("(name ILIKE $"+itoa(argIdx)+" OR message ILIKE $"+itoa(argIdx)+")", "%"+keyword+"%")
	}
	if attackType != "" {
		add("attack_type = $"+itoa(argIdx), attackType)
	}
	if severity != "" {
		add("severity = $"+itoa(argIdx), severity)
	}
	if source != "" {
		add("rule_source = $"+itoa(argIdx), source)
	}
	if tag != "" {
		add("tags::text ILIKE $"+itoa(argIdx), "%"+tag+"%")
	}

	var total int64
	if err := h.db.QueryRow(r.Context(), `SELECT count(*) FROM waf_rules WHERE `+where, args...).Scan(&total); err != nil {
		response.InternalError(w, r, err)
		return
	}
	query := `
SELECT id, rule_id, rule_source, file_name, name, message, severity, phase, tags, attack_type, default_state, crs_version
FROM waf_rules WHERE ` + where + " ORDER BY rule_id LIMIT $" + itoa(argIdx) + " OFFSET $" + itoa(argIdx+1)
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := h.db.Query(r.Context(), query, args...)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer rows.Close()
	var items []map[string]interface{}
	for rows.Next() {
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
		)
		if err := rows.Scan(&id, &ruleID, &source, &file, &name, &message, &severity, &phase, &tags, &attackType, &defaultState, &crsVersion); err != nil {
			response.InternalError(w, r, err)
			return
		}
		name = LocalizeRule(ruleID, file, name)
		message = LocalizeRule(ruleID, file, message)
		items = append(items, map[string]interface{}{
			"id": id, "rule_id": ruleID, "rule_source": source, "file_name": file,
			"name": name, "message": message, "severity": severity, "phase": phase,
			"tags": tags, "attack_type": attackType, "default_state": defaultState, "crs_version": crsVersion,
		})
	}
	response.Page(w, r, items, total, page, pageSize)
}

// Get 规则详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	ruleIDStr := r.PathValue("rule_id")
	ruleID, err := strconv.Atoi(ruleIDStr)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return
	}
	rows, err := h.db.Query(r.Context(), `
SELECT id, rule_id, rule_source, file_name, name, message, severity, phase, tags, attack_type, default_state, crs_version
FROM waf_rules WHERE rule_id = $1 ORDER BY crs_version DESC LIMIT 1`, ruleID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer rows.Close()
	if !rows.Next() {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则不存在")
		return
	}
	var (
		id            uuid.UUID
		rid           int
		source, file  string
		name, message string
		severity      string
		phase         int
		tags          []byte
		attackType    string
		defaultState  string
		crsVersion    string
	)
	if err := rows.Scan(&id, &rid, &source, &file, &name, &message, &severity, &phase, &tags, &attackType, &defaultState, &crsVersion); err != nil {
		response.InternalError(w, r, err)
		return
	}
	name = LocalizeRule(rid, file, name)
	message = LocalizeRule(rid, file, message)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"id": id, "rule_id": rid, "rule_source": source, "file_name": file,
		"name": name, "message": message, "severity": severity, "phase": phase,
		"tags": tags, "attack_type": attackType, "default_state": defaultState, "crs_version": crsVersion,
	})
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
