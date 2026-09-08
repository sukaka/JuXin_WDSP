package accessrules

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 是 IP 访问控制规则处理器。
type Handler struct {
	store   *Store
	audits  *audits.Service
	checker ProtectedChecker
}

// NewHandler 创建处理器。checker 为保护地址检查器，可为 nil 表示不检查。
func NewHandler(store *Store, au *audits.Service, checker ProtectedChecker) *Handler {
	return &Handler{store: store, audits: au, checker: checker}
}

// List 规则列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := listFilterFrom(r)
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if list == nil {
		list = []Rule{}
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Get 规则详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	rule, ok := h.getRule(w, r)
	if !ok {
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"rule": rule})
}

type ruleRequest struct {
	Name           string     `json:"name"`
	RuleType       string     `json:"rule_type"`
	ScopeType      string     `json:"scope_type"`
	ApplicationID  *uuid.UUID `json:"application_id"`
	Address        string     `json:"address"`
	Priority       *int       `json:"priority"`
	ValidityType   string     `json:"validity_type"`
	EffectiveFrom  *string    `json:"effective_from"`
	EffectiveUntil *string    `json:"effective_until"`
	Reason         string     `json:"reason"`
}

// toCreateInput 转换并解析时间字段。
func (req *ruleRequest) toCreateInput() (CreateInput, error) {
	in := CreateInput{
		Name:          req.Name,
		RuleType:      req.RuleType,
		ScopeType:     req.ScopeType,
		ApplicationID: req.ApplicationID,
		Address:       req.Address,
		ValidityType:  req.ValidityType,
		Reason:        req.Reason,
	}
	if req.Priority != nil {
		in.Priority = *req.Priority
	}
	if req.EffectiveFrom != nil && *req.EffectiveFrom != "" {
		t, err := parseTimeFlex(*req.EffectiveFrom)
		if err != nil {
			return in, fmt.Errorf("effective_from: %w", err)
		}
		in.EffectiveFrom = &t
	}
	if req.EffectiveUntil != nil && *req.EffectiveUntil != "" {
		t, err := parseTimeFlex(*req.EffectiveUntil)
		if err != nil {
			return in, fmt.Errorf("effective_until: %w", err)
		}
		in.EffectiveUntil = &t
	}
	return in, nil
}

// Create 创建规则。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req ruleRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	in, err := req.toCreateInput()
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := ValidateInput(&in, time.Now()); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	norm, _, _ := NormalizeAddress(in.Address)
	if err := CheckProtected(r.Context(), h.checker, in.RuleType, norm); err != nil {
		h.writeProtectedError(w, r, p, "create", "", in.Name, err)
		return
	}
	rule, err := h.store.Create(r.Context(), in, p.UserID)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", rule.ID.String(), rule.Name, "", ruleSummary(rule),
		audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"rule": rule})
}

type updateRuleRequest struct {
	Name           string  `json:"name"`
	Address        string  `json:"address"`
	Priority       *int    `json:"priority"`
	ValidityType   string  `json:"validity_type"`
	EffectiveFrom  *string `json:"effective_from"`
	EffectiveUntil *string `json:"effective_until"`
	Reason         string  `json:"reason"`
	Version        int     `json:"version"`
}

// Update 更新规则（乐观锁）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	cur, ok := h.getRule(w, r)
	if !ok {
		return
	}
	var req updateRuleRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Version != cur.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "规则已被其他人修改，请刷新后重试")
		return
	}
	in := UpdateInput{
		ID:           cur.ID,
		Version:      req.Version,
		Name:         req.Name,
		Address:      req.Address,
		ValidityType: req.ValidityType,
		Reason:       req.Reason,
		Priority:     cur.Priority,
	}
	if req.Priority != nil {
		in.Priority = *req.Priority
	}
	if req.EffectiveFrom != nil && *req.EffectiveFrom != "" {
		t, err := parseTimeFlex(*req.EffectiveFrom)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "effective_from: "+err.Error())
			return
		}
		in.EffectiveFrom = &t
	}
	if req.EffectiveUntil != nil && *req.EffectiveUntil != "" {
		t, err := parseTimeFlex(*req.EffectiveUntil)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "effective_until: "+err.Error())
			return
		}
		in.EffectiveUntil = &t
	}
	if err := validateUpdateInput(&in, time.Now()); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	norm, _, _ := NormalizeAddress(in.Address)
	if err := CheckProtected(r.Context(), h.checker, cur.RuleType, norm); err != nil {
		h.writeProtectedError(w, r, p, "update", cur.ID.String(), cur.Name, err)
		return
	}
	before := ruleSummary(cur)
	rule, err := h.store.Update(r.Context(), in, p.UserID)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", rule.ID.String(), rule.Name, before, ruleSummary(rule),
		audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"rule": rule})
}

// Delete 删除规则（软删除）。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	rule, ok := h.getRule(w, r)
	if !ok {
		return
	}
	if err := h.store.SoftDelete(r.Context(), rule.ID, p.UserID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", rule.ID.String(), rule.Name, ruleSummary(rule), "deleted=true",
		audits.ResultSuccess, "", audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "规则已删除"})
}

// Enable 启用规则。
func (h *Handler) Enable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, StatusActive, "enable")
}

// Disable 停用规则。
func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, StatusDisabled, "disable")
}

func (h *Handler) setStatus(w http.ResponseWriter, r *http.Request, status, action string) {
	p := authz.PrincipalFrom(r.Context())
	rule, ok := h.getRule(w, r)
	if !ok {
		return
	}
	if err := h.store.SetStatus(r.Context(), rule.ID, status, p.UserID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, action, rule.ID.String(), rule.Name, "status="+rule.Status, "status="+status,
		audits.ResultSuccess, "", audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "操作成功"})
}

type extendRequest struct {
	EffectiveUntil string `json:"effective_until"`
}

// Extend 延长临时规则失效时间。
func (h *Handler) Extend(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	rule, ok := h.getRule(w, r)
	if !ok {
		return
	}
	var req extendRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if rule.ValidityType != ValidityTemporary {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅临时规则支持延期")
		return
	}
	until, err := parseTimeFlex(req.EffectiveUntil)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if !until.After(time.Now()) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "失效时间必须晚于当前时间")
		return
	}
	if rule.EffectiveFrom != nil && !until.After(*rule.EffectiveFrom) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "失效时间必须晚于生效时间")
		return
	}
	if err := h.store.Extend(r.Context(), rule.ID, until, p.UserID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "extend", rule.ID.String(), rule.Name,
		"effective_until="+formatTime(rule.EffectiveUntil), "effective_until="+until.UTC().Format(time.RFC3339),
		audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "规则已延期"})
}

// Release 立即解封临时规则。
func (h *Handler) Release(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	rule, ok := h.getRule(w, r)
	if !ok {
		return
	}
	if rule.ValidityType != ValidityTemporary {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅临时规则支持解封")
		return
	}
	if err := h.store.Release(r.Context(), rule.ID, p.UserID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "release", rule.ID.String(), rule.Name, "status="+rule.Status, "status="+StatusDisabled,
		audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "规则已解封"})
}

// Copy 复制规则（名称加“-副本”）。
func (h *Handler) Copy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	src, ok := h.getRule(w, r)
	if !ok {
		return
	}
	in := CreateInput{
		Name:           copyName(src.Name),
		RuleType:       src.RuleType,
		ScopeType:      src.ScopeType,
		ApplicationID:  src.ApplicationID,
		Address:        src.Address,
		Priority:       src.Priority,
		ValidityType:   src.ValidityType,
		EffectiveFrom:  src.EffectiveFrom,
		EffectiveUntil: src.EffectiveUntil,
		Reason:         src.Reason,
		SourceType:     SourceManual,
	}
	rule, err := h.store.Create(r.Context(), in, p.UserID)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "copy", rule.ID.String(), rule.Name, ruleSummary(src), ruleSummary(rule),
		audits.ResultSuccess, "", audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"rule": rule})
}

// Validate 校验规则输入（不落库）。
func (h *Handler) Validate(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	in, err := req.toCreateInput()
	if err != nil {
		response.JSON(w, r, http.StatusOK, map[string]interface{}{"valid": false, "errors": []string{err.Error()}})
		return
	}
	var errs []string
	if verr := ValidateInput(&in, time.Now()); verr != nil {
		errs = append(errs, verr.Error())
	} else {
		norm, _, _ := NormalizeAddress(in.Address)
		if perr := CheckProtected(r.Context(), h.checker, in.RuleType, norm); perr != nil {
			errs = append(errs, perr.Error())
		}
		ok, cerr := conflictExists(r.Context(), h.store.db, in.ScopeType, in.ApplicationID, norm, in.RuleType, nil)
		if cerr != nil {
			response.InternalError(w, r, cerr)
			return
		}
		if ok {
			errs = append(errs, fmt.Sprintf("相同范围下已存在地址 %s 的 %s 规则", norm, in.RuleType))
		}
	}
	if errs == nil {
		errs = []string{}
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"valid": len(errs) == 0, "errors": errs})
}

type importRequest struct {
	Content        string     `json:"content"`
	Format         string     `json:"format"` // csv | text
	Mode           string     `json:"mode"`   // ALL_OR_NOTHING | SKIP_ERRORS
	DryRun         bool       `json:"dry_run"`
	RuleType       string     `json:"rule_type"`
	ScopeType      string     `json:"scope_type"`
	ApplicationID  *uuid.UUID `json:"application_id"`
	EffectiveUntil *string    `json:"effective_until"`
	Reason         string     `json:"reason"`
}

// Import 批量导入规则（CSV 或纯文本）。
func (h *Handler) Import(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req importRequest
	if err := response.DecodeJSON(w, r, &req, ImportMaxBytes+128*1024); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或内容过大")
		return
	}
	if len(req.Content) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "导入内容不能为空")
		return
	}
	if len(req.Content) > ImportMaxBytes {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "导入内容超过 1MB 上限")
		return
	}
	format, err := normalizeImportFormat(req.Format)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	mode, err := normalizeImportMode(req.Mode)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	var records []csvRecord
	if format == "csv" {
		records, err = parseCSVContent(req.Content)
	} else {
		records, err = parseTextLines(req.Content)
	}
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	def := ImportDefaults{
		RuleType:      req.RuleType,
		ScopeType:     req.ScopeType,
		ApplicationID: req.ApplicationID,
		Reason:        req.Reason,
	}
	if req.EffectiveUntil != nil && *req.EffectiveUntil != "" {
		t, terr := parseTimeFlex(*req.EffectiveUntil)
		if terr != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "effective_until: "+terr.Error())
			return
		}
		def.EffectiveUntil = &t
	}
	valid, rowErrs := buildImportInputs(r.Context(), records, def,
		h.store.ApplicationIDByCode, h.checker, time.Now())
	if rowErrs == nil {
		rowErrs = []ImportRowError{}
	}
	result := map[string]interface{}{
		"total":   len(records),
		"valid":   len(valid),
		"invalid": len(rowErrs),
		"errors":  rowErrs,
	}
	// 预览模式：只校验不落库，附前 50 条预览
	if req.DryRun {
		preview := make([]map[string]interface{}, 0, 50)
		for i, row := range valid {
			if i >= 50 {
				break
			}
			preview = append(preview, map[string]interface{}{
				"line":            row.Line,
				"address":         row.Input.Address,
				"rule_type":       row.Input.RuleType,
				"scope_type":      row.Input.ScopeType,
				"application_id":  row.Input.ApplicationID,
				"effective_until": row.Input.EffectiveUntil,
				"reason":          row.Input.Reason,
			})
		}
		result["preview"] = preview
		response.JSON(w, r, http.StatusOK, result)
		return
	}
	// 正式导入
	if len(rowErrs) > 0 && mode == ImportModeAllOrNothing {
		risk := audits.RiskMedium
		if hasProtectedErr(rowErrs) {
			risk = audits.RiskHigh
		}
		h.recordAudit(r, p, "import", "", "批量导入", "",
			importSummary(len(records), 0, len(rowErrs), mode), audits.ResultFailure, "存在错误行，整体未导入", risk)
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"存在错误行，按 ALL_OR_NOTHING 模式整体未导入", rowErrs)
		return
	}
	imported := 0
	if mode == ImportModeAllOrNothing {
		inputs := make([]CreateInput, 0, len(valid))
		for _, row := range valid {
			inputs = append(inputs, row.Input)
		}
		if err := h.store.CreateBatch(r.Context(), inputs, p.UserID); err != nil {
			if errors.Is(err, ErrConflict) {
				h.recordAudit(r, p, "import", "", "批量导入", "",
					importSummary(len(records), 0, 0, mode), audits.ResultFailure, err.Error(), audits.RiskMedium)
				response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
				return
			}
			response.InternalError(w, r, err)
			return
		}
		imported = len(valid)
	} else {
		// SKIP_ERRORS：逐条插入，冲突/失败记为行错误
		for _, row := range valid {
			if _, err := h.store.Create(r.Context(), row.Input, p.UserID); err != nil {
				code := ImportErrInvalid
				if errors.Is(err, ErrConflict) {
					code = ImportErrConflict
				}
				rowErrs = append(rowErrs, ImportRowError{Line: row.Line, Content: row.Raw, Error: err.Error(), Code: code})
				continue
			}
			imported++
		}
	}
	risk := audits.RiskMedium
	if hasProtectedErr(rowErrs) {
		risk = audits.RiskHigh
	}
	h.recordAudit(r, p, "import", "", "批量导入", "",
		importSummary(len(records), imported, len(records)-imported, mode), audits.ResultSuccess, "", risk)
	result["imported"] = imported
	result["errors"] = rowErrs
	result["invalid"] = len(rowErrs)
	response.JSON(w, r, http.StatusOK, result)
}

// Export 导出规则（CSV，含表头，防公式注入，最多 10000 条）。
func (h *Handler) Export(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	f := listFilterFrom(r)
	f.Page = 1
	f.PageSize = 100
	// 复用 List 分批拉取（单页上限 100），最多 10000 条
	var all []Rule
	appIDSet := map[uuid.UUID]bool{}
	for {
		list, total, err := h.store.List(r.Context(), f)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		for _, rule := range list {
			if rule.ApplicationID != nil {
				appIDSet[*rule.ApplicationID] = true
			}
		}
		all = append(all, list...)
		if int64(len(all)) >= total || len(all) >= 10000 || len(list) == 0 {
			break
		}
		f.Page++
	}
	if len(all) > 10000 {
		all = all[:10000]
	}
	ids := make([]uuid.UUID, 0, len(appIDSet))
	for id := range appIDSet {
		ids = append(ids, id)
	}
	codes, err := h.store.ApplicationCodes(r.Context(), ids)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	csvContent := RenderExportCSV(all, codes)
	h.recordAudit(r, p, "export", "", "导出规则", "", fmt.Sprintf("count=%d", len(all)),
		audits.ResultSuccess, "", audits.RiskLow)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="ip_access_rules_%s.csv"`, time.Now().Format("20060102")))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(csvContent))
}

// ---------- 辅助 ----------

// getRule 解析路径 ID 并查询规则，失败时已写出响应，返回 ok=false。
func (h *Handler) getRule(w http.ResponseWriter, r *http.Request) (*Rule, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return nil, false
	}
	rule, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则不存在")
		return nil, false
	}
	return rule, true
}

// writeProtectedError 处理保护地址冲突：拒绝并记高风险审计。
func (h *Handler) writeProtectedError(w http.ResponseWriter, r *http.Request, p *authz.Principal,
	action, objID, objName string, err error) {
	if IsProtectedError(err) {
		h.recordAudit(r, p, action, objID, objName, "", "", audits.ResultFailure, err.Error(), audits.RiskHigh)
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	response.InternalError(w, r, err)
}

// writeStoreError 将仓储错误映射为 HTTP 响应。
func (h *Handler) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则不存在")
	case errors.Is(err, ErrConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
	case errors.Is(err, ErrVersionConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrInvalidAddress),
		errors.Is(err, ErrInvalidTime), errors.Is(err, ErrInvalidState):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
	default:
		response.InternalError(w, r, err)
	}
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName,
	before, after, result, failureReason, risk string) {
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "access_control",
		Action:        action,
		ObjectType:    "ip_access_rule",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		FailureReason: failureReason,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

func listFilterFrom(r *http.Request) ListFilter {
	f := ListFilter{
		RuleType:   r.URL.Query().Get("rule_type"),
		ScopeType:  r.URL.Query().Get("scope_type"),
		Status:     r.URL.Query().Get("status"),
		SourceType: r.URL.Query().Get("source_type"),
		Keyword:    r.URL.Query().Get("keyword"),
		Address:    r.URL.Query().Get("address"),
		Page:       queryInt(r, "page", 1),
		PageSize:   queryInt(r, "page_size", 20),
	}
	if v := r.URL.Query().Get("application_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.ApplicationID = &id
		}
	}
	return f
}

func ruleSummary(r *Rule) string {
	return `{"name":"` + r.Name + `","rule_type":"` + r.RuleType + `","scope_type":"` + r.ScopeType +
		`","address":"` + r.Address + `","status":"` + r.Status + `","validity_type":"` + r.ValidityType + `"}`
}

func importSummary(total, imported, invalid int, mode string) string {
	return fmt.Sprintf(`{"total":%d,"imported":%d,"invalid":%d,"mode":"%s"}`, total, imported, invalid, mode)
}

func hasProtectedErr(errs []ImportRowError) bool {
	for _, e := range errs {
		if e.Code == ImportErrProtected {
			return true
		}
	}
	return false
}

// copyName 生成副本名称（不超过200字符）。
func copyName(name string) string {
	const suffix = "-副本"
	runes := []rune(name)
	if len(runes) > 200-len([]rune(suffix)) {
		runes = runes[:200-len([]rune(suffix))]
	}
	return string(runes) + suffix
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
