package exceptions

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 是例外策略处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
	hooks  EnableHooks
}

// NewHandler 创建处理器（启用门禁外部能力默认取仓储真实查库实现）。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au, hooks: store.enableHooks()}
}

// SetEnableHooks 覆盖启用门禁外部能力（测试注入用）。
func (h *Handler) SetEnableHooks(hooks EnableHooks) {
	h.hooks = hooks
}

// List 例外列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	scopeType := r.URL.Query().Get("scope_type")
	status := r.URL.Query().Get("status")
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.List(r.Context(), scopeType, status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// Get 例外详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的例外ID")
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "例外不存在")
		return
	}
	var resolvedOverride []int
	if e.normalizedEngine() == EngineWAF && e.ExceptionAction == ActionRemoveRuleTag &&
		len(e.ResolvedRuleIDs) == 0 && len(e.RuleTags) > 0 && h.hooks.ResolveRuleTags != nil {
		if byTag, rerr := h.hooks.ResolveRuleTags(r.Context(), e.RuleTags); rerr == nil && len(byTag) > 0 {
			seen := map[int]bool{}
			for _, ids := range byTag {
				for _, rid := range ids {
					if !seen[rid] {
						seen[rid] = true
						resolvedOverride = append(resolvedOverride, rid)
					}
				}
			}
			sort.Ints(resolvedOverride)
		}
	}
	secLang, apiPayload, compileErr := CompilePreviewContent(e, resolvedOverride)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"exception":              e,
		"is_broad":               e.IsBroad(),
		"generated_seclang":      secLang,
		"compiled_api_exception": apiPayload,
		"compile_error":          compileErr,
	})
}

type exceptionRequest struct {
	Name             string       `json:"name"`
	Description      string       `json:"description"`
	ScopeType        string       `json:"scope_type"`
	ApplicationID    *uuid.UUID   `json:"application_id"`
	PolicyID         *uuid.UUID   `json:"policy_id"`
	Domain           string       `json:"domain"`
	URIExact         string       `json:"uri_exact"`
	URIPrefix        string       `json:"uri_prefix"`
	URIRegex         string       `json:"uri_regex"`
	Methods          []string     `json:"methods"`
	SourceIPs        []string     `json:"source_ips"`
	ParamNames       []string     `json:"param_names"`
	CookieNames      []string     `json:"cookie_names"`
	HeaderNames      []string     `json:"header_names"`
	RuleIDs          []int        `json:"rule_ids"`
	RuleTags         []string     `json:"rule_tags"`
	AttackTypes      []string     `json:"attack_types"`
	ContentTypes     []string     `json:"content_types"`
	TargetEngine     string       `json:"target_engine"`
	APIRuleRefs      []APIRuleRef `json:"api_rule_refs"`
	ExceptionAction  string       `json:"exception_action"`
	ActionTarget     string       `json:"action_target"`
	IsTemporary      bool         `json:"is_temporary"`
	EffectiveFrom    *string      `json:"effective_from"`
	EffectiveUntil   *string      `json:"effective_until"`
	RiskAcknowledged bool         `json:"risk_acknowledged"`
	Reason           string       `json:"reason"`
	Version          int          `json:"version"` // 乐观锁（更新必填）
}

// Create 创建例外（P0-04：默认 DRAFT，启用须走 Enable 门禁；不支持组合返回字段级错误）。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req exceptionRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	e := buildException(&req)
	e.Status = "DRAFT"
	if err := h.store.Create(r.Context(), e, p.UserID); err != nil {
		h.writeSaveError(w, r, err)
		return
	}
	risk := audits.RiskMedium
	if e.IsBroad() {
		risk = audits.RiskHigh
	}
	h.recordAudit(r, p, "create", e.ID.String(), e.Name, audits.ResultSuccess, risk)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"exception": e,
		"is_broad":  e.IsBroad(),
	})
}

// Update 更新例外（乐观锁 version，请求体 version 必填）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的例外ID")
		return
	}
	existing, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "例外不存在")
		return
	}
	var req exceptionRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Version <= 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "version 必填（乐观锁）")
		return
	}
	e := buildException(&req)
	e.ID = id
	e.Status = existing.Status
	if err := h.store.Update(r.Context(), e, req.Version); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "例外不存在或版本冲突，请刷新后重试")
			return
		}
		h.writeSaveError(w, r, err)
		return
	}
	risk := audits.RiskMedium
	if e.IsBroad() {
		risk = audits.RiskHigh
	}
	h.recordAudit(r, p, "update", e.ID.String(), e.Name, audits.ResultSuccess, risk)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"exception": e,
		"is_broad":  e.IsBroad(),
	})
}

// writeSaveError 保存层错误映射：字段级校验错误带 field_errors 明细（含
// UNSUPPORTED_ACTION 业务码——EXC-04 不支持动作组合）；宽泛风险确认为用户输入错误；
// 其余（含审查期查库失败）按内部错误处理，不静默、不误导为重试可解的 400。
func (h *Handler) writeSaveError(w http.ResponseWriter, r *http.Request, err error) {
	var verrs *ValidationErrors
	if errors.As(err, &verrs) {
		code := response.CodeInvalidArgument
		if verrs.HasUnsupportedAction() {
			code = "UNSUPPORTED_ACTION"
		}
		response.ErrorWithDetails(w, r, http.StatusBadRequest, code, verrs.Error(),
			map[string]interface{}{"field_errors": verrs.Fields})
		return
	}
	if errors.Is(err, ErrRiskRequired) || errors.Is(err, ErrInvalidInput) ||
		errors.Is(err, ErrTooBroad) || errors.Is(err, ErrInvalidTime) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	response.InternalError(w, r, err)
}

// Delete 删除例外。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的例外ID")
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "例外不存在")
		return
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", id.String(), e.Name, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "例外已删除"})
}

// Enable 启用例外（P0-04 启用门禁：结构化范围校验通过才落库 ENABLED；
// 门禁拒绝返回字段级错误，不支持动作携带 UNSUPPORTED_ACTION 与迁移预览——EXC-04）。
func (h *Handler) Enable(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的例外ID")
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "例外不存在")
		return
	}
	plan, verrs := ValidateForEnable(r.Context(), e, h.hooks)
	if verrs != nil {
		code := response.CodeInvalidArgument
		if verrs.HasUnsupportedAction() {
			code = "UNSUPPORTED_ACTION"
		}
		h.recordAudit(r, p, "enable", id.String(), e.Name, audits.ResultFailure, audits.RiskMedium)
		response.ErrorWithDetails(w, r, http.StatusBadRequest, code, "启用门禁未通过",
			map[string]interface{}{"field_errors": verrs.Fields})
		return
	}
	updated, err := h.store.Enable(r.Context(), id, plan.ResolvedRuleIDs)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "例外不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "enable", id.String(), e.Name, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"exception": updated})
}

// Disable 停用例外。
func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的例外ID")
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "例外不存在")
		return
	}
	if err := h.store.SetStatus(r.Context(), id, "DISABLED"); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "disable", id.String(), e.Name, audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "操作成功"})
}

// previewRequest 预览请求（契约 §8：expected_version 与当前版本不符 → 409）。
type previewRequest struct {
	ExpectedVersion int `json:"expected_version"`
}

// Preview 例外生效预览（契约 §8）：重算校验状态与编译摘要，列明不支持项的迁移预览
// 与不变的保护模块；不启用、不发布、不回放真实请求；操作写审计。
// 历史日志字段不足，historical_sample_coverage/estimated_match_count 恒为 null（不显示零影响）。
func (h *Handler) Preview(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的例外ID")
		return
	}
	var req previewRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "例外不存在")
		return
	}
	if req.ExpectedVersion != e.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "例外已被修改（版本不符），请刷新后重试")
		return
	}

	// 与保存层同一结构化校验重算（不落库）；查库等外部能力失败 → 预览失败
	plan, verrs := validateForEnable(r.Context(), e, h.hooks, false)
	if verrs != nil {
		for _, f := range verrs.Fields {
			if f.infra {
				response.InternalError(w, r, errors.New("预览校验失败: "+f.Message))
				return
			}
		}
	}

	validationStatus := ValidationValid
	var fieldErrors []FieldError
	if verrs != nil {
		validationStatus = ValidationNeedsReview
		fieldErrors = verrs.Fields
	}

	// 编译摘要：门禁通过取门禁计划（含标签展开冻结产物），否则尽力重算；
	// 预览后草稿被改 → 版本推进 → 指纹变化，发布前重验可检出（EXC-12）。
	fingerprint := ""
	if plan != nil {
		fingerprint = plan.CompiledFingerprint
	} else if fp, ferr := CompiledFingerprint(e); ferr == nil {
		fingerprint = fp
	}

	// 不支持项（含迁移预览文案）
	var unsupported []map[string]string
	if verrs != nil {
		for _, f := range verrs.Fields {
			if f.Code != "UNSUPPORTED_ACTION" {
				continue
			}
			foa := f.Field
			if f.Field == "exception_action" {
				foa = e.ExceptionAction
			}
			unsupported = append(unsupported, map[string]string{
				"field_or_action":   foa,
				"migration_preview": f.Message,
			})
		}
	}

	// 规范化范围（方法与启用门禁同口径大写排序；时间为 RFC3339）
	normalizedScope := map[string]interface{}{
		"domain":          e.Domain,
		"uri_exact":       e.URIExact,
		"uri_prefix":      e.URIPrefix,
		"uri_regex":       e.URIRegex,
		"methods":         normalizedMethods(e.Methods),
		"source_ips":      e.SourceIPs,
		"content_types":   e.ContentTypes,
		"effective_from":  e.EffectiveFrom,
		"effective_until": e.EffectiveUntil,
	}

	// 目标规则引用（WAF：rule_ids + 冻结展开集；API：api_rule_refs）
	var resolvedRefs []map[string]interface{}
	appendWAF := func(ids []int) {
		for _, rid := range ids {
			resolvedRefs = append(resolvedRefs, map[string]interface{}{"engine": EngineWAF, "rule_id": rid})
		}
	}
	appendWAF(e.RuleIDs)
	if plan != nil {
		appendWAF(plan.ResolvedRuleIDs)
	} else {
		appendWAF(e.ResolvedRuleIDs)
	}
	for _, ref := range sortedAPIRuleRefs(e.APIRuleRefs) {
		item := map[string]interface{}{"engine": EngineAPI, "detector_id": ref.DetectorID, "rule_id": ref.RuleID}
		if ref.ModelVersion != "" {
			item["model_version"] = ref.ModelVersion
		}
		resolvedRefs = append(resolvedRefs, item)
	}

	// 生效窗口（半开区间 from≤now<until）
	effectiveWindow := map[string]interface{}{
		"from":      e.EffectiveFrom,
		"until":     e.EffectiveUntil,
		"half_open": true,
	}

	// 必需发布目标（应用编码；经 applications 反查，未绑定为空数组）
	publishTargets := []string{}
	code, err := h.store.ApplicationCode(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if code != "" {
		publishTargets = append(publishTargets, code)
	}

	var previewResolved []int
	if plan != nil {
		previewResolved = plan.ResolvedRuleIDs
	}
	secLang, apiPayload, compileErr := CompilePreviewContent(e, previewResolved)

	h.recordAudit(r, p, "preview", id.String(), e.Name, audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"validation_status":   validationStatus,
		"field_errors":        fieldErrors,
		"normalized_scope":    normalizedScope,
		"resolved_rule_refs":  resolvedRefs,
		"effective_window":    effectiveWindow,
		"unsupported":         unsupported,
		"protected_modules_unchanged": []string{
			"JWT", "ACCESS_CONTROL", "CC", "RATE_LIMIT_QUOTA", "MANUAL_BAN", "PROTOCOL_LIMITS", "RISK_POLICY",
		},
		"compiled_fingerprint":       fingerprint,
		"generated_seclang":          secLang,
		"compiled_api_exception":     apiPayload,
		"compile_error":              compileErr,
		"required_publish_targets":   publishTargets,
		"historical_sample_coverage": nil,
		"estimated_match_count":      nil,
	})
}

func buildException(req *exceptionRequest) *Exception {
	e := &Exception{
		Name:             req.Name,
		Description:      req.Description,
		ScopeType:        req.ScopeType,
		ApplicationID:    req.ApplicationID,
		PolicyID:         req.PolicyID,
		Domain:           req.Domain,
		URIExact:         req.URIExact,
		URIPrefix:        req.URIPrefix,
		URIRegex:         req.URIRegex,
		Methods:          req.Methods,
		SourceIPs:        req.SourceIPs,
		ParamNames:       req.ParamNames,
		CookieNames:      req.CookieNames,
		HeaderNames:      req.HeaderNames,
		RuleIDs:          req.RuleIDs,
		RuleTags:         req.RuleTags,
		AttackTypes:      req.AttackTypes,
		ContentTypes:     req.ContentTypes,
		TargetEngine:     req.TargetEngine,
		APIRuleRefs:      req.APIRuleRefs,
		ExceptionAction:  req.ExceptionAction,
		ActionTarget:     req.ActionTarget,
		IsTemporary:      req.IsTemporary,
		RiskAcknowledged: req.RiskAcknowledged,
		Reason:           req.Reason,
	}
	e.EffectiveFrom = parseTimePtr(req.EffectiveFrom)
	e.EffectiveUntil = parseTimePtr(req.EffectiveUntil)
	return e
}

// parseTimePtr 解析 RFC3339 时间字符串指针（非法值返回 nil——原行为保留，
// 格式错误由请求层 DecodeJSON 之外的既有宽松口径兼容；门禁对临时例外强制 until 非空）。
func parseTimePtr(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	return &t
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName string, result, risk string) {
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "exceptions",
		Action:       action,
		ObjectType:   "exception_policy",
		ObjectID:     objID,
		ObjectName:   objName,
		Result:       result,
		RiskLevel:    risk,
		RequestID:    response.RequestIDFrom(r),
	})
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
