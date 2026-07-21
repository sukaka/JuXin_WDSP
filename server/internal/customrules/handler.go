package customrules

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 是自定义规则处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// List 规则列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	keyword := r.URL.Query().Get("keyword")
	status := r.URL.Query().Get("status")
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.List(r.Context(), keyword, status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// Get 规则详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return
	}
	rule, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, rule)
}

type ruleRequest struct {
	RuleID          int      `json:"rule_id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	AttackType      string   `json:"attack_type"`
	Severity        string   `json:"severity"`
	Phase           int      `json:"phase"`
	Operator        string   `json:"operator"`
	OperatorValue   string   `json:"operator_value"`
	TargetVariables []string `json:"target_variables"`
	Action          string   `json:"action"`
	Tags            []string `json:"tags"`
	Version         int      `json:"version"`
}

// Create 创建规则。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req ruleRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	rule := &CustomRule{
		RuleID: req.RuleID, Name: req.Name, Description: req.Description,
		AttackType: req.AttackType, Severity: req.Severity, Phase: req.Phase,
		Operator: req.Operator, OperatorValue: req.OperatorValue,
		TargetVariables: req.TargetVariables, Action: req.Action, Tags: req.Tags,
		Status: "ENABLED", ScopeType: "GLOBAL",
	}
	if err := h.store.Create(r.Context(), rule, p.UserID); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "create", rule.ID.String(), req.Name, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, rule)
}

// Update 更新规则。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return
	}
	rule, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则不存在")
		return
	}
	var req ruleRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Version != rule.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "规则已被其他人修改，请刷新后重试")
		return
	}
	rule.Name = req.Name
	rule.Description = req.Description
	rule.AttackType = req.AttackType
	rule.Severity = req.Severity
	rule.Phase = req.Phase
	rule.Operator = req.Operator
	rule.OperatorValue = req.OperatorValue
	rule.TargetVariables = req.TargetVariables
	rule.Action = req.Action
	rule.Tags = req.Tags
	if err := h.store.Update(r.Context(), rule); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "update", id.String(), req.Name, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, rule)
}

// Delete 删除规则。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return
	}
	rule, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则不存在")
		return
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", id.String(), rule.Name, audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "规则已删除"})
}

// Validate 校验规则（不保存）。
func (h *Handler) Validate(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	rule := &CustomRule{
		RuleID: req.RuleID, Name: req.Name, AttackType: req.AttackType, Severity: req.Severity,
		Phase: req.Phase, Operator: req.Operator, OperatorValue: req.OperatorValue,
		TargetVariables: req.TargetVariables, Action: req.Action, Tags: req.Tags,
	}
	generated, err := ValidateInput(rule)
	if err != nil {
		response.JSON(w, r, http.StatusOK, map[string]interface{}{"valid": false, "error": err.Error()})
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"valid": true, "generated_rule": generated})
}

// Enable 启用规则。
func (h *Handler) Enable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, "ENABLED", "enable")
}

// Disable 停用规则。
func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, "DISABLED", "disable")
}

func (h *Handler) setStatus(w http.ResponseWriter, r *http.Request, status, action string) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return
	}
	rule, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规则不存在")
		return
	}
	if err := h.store.SetStatus(r.Context(), id, status); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, action, id.String(), rule.Name, audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "操作成功"})
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName string, result, risk string) {
	_ = h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.RemoteIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "custom_rules",
		Action:        action,
		ObjectType:    "custom_rule",
		ObjectID:      objID,
		ObjectName:    objName,
		Result:        result,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
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
