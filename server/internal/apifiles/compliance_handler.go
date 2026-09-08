// compliance_handler.go 文件合规规则（P2-03 管理面）HTTP 处理器：
//
//	GET    /api/v1/api-security/file-compliance-rules        明细分页（过滤 direction/match_type/action/enabled）
//	POST   /api/v1/api-security/file-compliance-rules        新建（match_value 按类型校验）
//	PATCH  /api/v1/api-security/file-compliance-rules/{id}   部分更新
//	DELETE /api/v1/api-security/file-compliance-rules/{id}   硬删除
//
// 权限点 api_data.read（读）/ api_data.manage（写），与 apidata 同一权限域；
// 全部写操作带参数校验 + 操作审计。
package apifiles

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apidata"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// complianceBodyMaxBytes 请求体上限（单条规则足够）。
const complianceBodyMaxBytes = 32 << 10

// ComplianceHandler 文件合规规则处理器。
type ComplianceHandler struct {
	store  ComplianceRepository
	audits *audits.Service
}

// NewComplianceHandler 创建处理器（构造注入审计服务，语义同 apidata）。
func NewComplianceHandler(store ComplianceRepository, audit *audits.Service) *ComplianceHandler {
	return &ComplianceHandler{store: store, audits: audit}
}

// RegisterComplianceRoutes 注册路由（统一 /api/v1/api-security 前缀；
// 权限点 api_data.read/manage，种子见迁移 000041）。
func RegisterComplianceRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *ComplianceHandler) {
	mux.Handle("GET /api/v1/api-security/file-compliance-rules",
		authz(middleware.RequirePermission(apidata.PermDataRead)(http.HandlerFunc(h.ListRules))))
	mux.Handle("POST /api/v1/api-security/file-compliance-rules",
		authz(middleware.RequirePermission(apidata.PermDataManage)(http.HandlerFunc(h.CreateRule))))
	mux.Handle("PATCH /api/v1/api-security/file-compliance-rules/{id}",
		authz(middleware.RequirePermission(apidata.PermDataManage)(http.HandlerFunc(h.UpdateRule))))
	mux.Handle("DELETE /api/v1/api-security/file-compliance-rules/{id}",
		authz(middleware.RequirePermission(apidata.PermDataManage)(http.HandlerFunc(h.DeleteRule))))
}

// ListRules GET /api/v1/api-security/file-compliance-rules
// 查询参数：direction/match_type/action 枚举过滤、enabled=true|false、page/page_size 分页。
func (h *ComplianceHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	direction := strings.ToUpper(strings.TrimSpace(q.Get("direction")))
	if direction != "" && !validDirection(direction) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 direction 取值（UPLOAD/DOWNLOAD）")
		return
	}
	matchType := strings.ToUpper(strings.TrimSpace(q.Get("match_type")))
	if matchType != "" && !validMatchType(matchType) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 match_type 取值（EXT/MIME/FILENAME_REGEX）")
		return
	}
	action := strings.ToUpper(strings.TrimSpace(q.Get("action")))
	if action != "" && !validComplianceAction(action) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 action 取值（OBSERVE/BLOCK）")
		return
	}
	var enabled *bool
	if v := strings.TrimSpace(q.Get("enabled")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 enabled 取值（true/false）")
			return
		}
		enabled = &b
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	if pageSize > assetPageSizeMax {
		pageSize = assetPageSizeMax
	}
	list, total, err := h.store.ListComplianceRules(r.Context(), ComplianceFilter{
		Direction: direction, MatchType: matchType, Action: action,
		Enabled: enabled, Page: page, PageSize: pageSize,
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// ruleRequest 规则新建请求。
type ruleRequest struct {
	Direction  string `json:"direction"`
	MatchType  string `json:"match_type"`
	MatchValue string `json:"match_value"`
	Action     string `json:"action"`
	Reason     string `json:"reason"`
	Enabled    *bool  `json:"enabled"` // 缺省 true
}

// toRule 转实体（normalize+validate 由调用方执行；ID/时间戳由 store 填）。
func (req *ruleRequest) toRule() *ComplianceRule {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return &ComplianceRule{
		Direction:  req.Direction,
		MatchType:  req.MatchType,
		MatchValue: req.MatchValue,
		Action:     req.Action,
		Reason:     req.Reason,
		Enabled:    enabled,
	}
}

// CreateRule POST /api/v1/api-security/file-compliance-rules
func (h *ComplianceHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req ruleRequest
	if err := response.DecodeJSON(w, r, &req, complianceBodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	rule := req.toRule()
	rule.normalize()
	if err := rule.validate(); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if p != nil {
		rule.CreatedBy = &p.UserID
	}
	if err := h.store.CreateComplianceRule(r.Context(), rule); err != nil {
		if errors.Is(err, ErrComplianceConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "同方向同类型同匹配值的规则已存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	after, _ := json.Marshal(rule)
	h.recordAudit(r, p, "create", "api_file_compliance_rule", rule.ID.String(),
		rule.MatchType+":"+rule.MatchValue, "", string(after), audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, rule)
}

// updateRuleRequest 规则编辑请求（指针字段 = 仅更新提供的字段）。
type updateRuleRequest struct {
	Direction  *string `json:"direction"`
	MatchType  *string `json:"match_type"`
	MatchValue *string `json:"match_value"`
	Action     *string `json:"action"`
	Reason     *string `json:"reason"`
	Enabled    *bool   `json:"enabled"`
}

// UpdateRule PATCH /api/v1/api-security/file-compliance-rules/{id}
// 部分更新：取出合并后整体校验再落库（match_type 与 match_value 联动校验，
// 不允许只改其一而产生形态错位）。
func (h *ComplianceHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return
	}
	var req updateRuleRequest
	if err := response.DecodeJSON(w, r, &req, complianceBodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	cur, err := h.store.GetComplianceRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrComplianceNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "文件合规规则不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	merged := *cur
	if req.Direction != nil {
		merged.Direction = *req.Direction
	}
	if req.MatchType != nil {
		merged.MatchType = *req.MatchType
	}
	if req.MatchValue != nil {
		merged.MatchValue = *req.MatchValue
	}
	if req.Action != nil {
		merged.Action = *req.Action
	}
	if req.Reason != nil {
		merged.Reason = *req.Reason
	}
	if req.Enabled != nil {
		merged.Enabled = *req.Enabled
	}
	merged.normalize()
	if err := merged.validate(); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.store.UpdateComplianceRule(r.Context(), &merged); err != nil {
		if errors.Is(err, ErrComplianceConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "同方向同类型同匹配值的规则已存在")
			return
		}
		if errors.Is(err, ErrComplianceNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "文件合规规则不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	before, _ := json.Marshal(cur)
	after, _ := json.Marshal(&merged)
	h.recordAudit(r, p, "update", "api_file_compliance_rule", id.String(),
		merged.MatchType+":"+merged.MatchValue, string(before), string(after), audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, merged)
}

// DeleteRule DELETE /api/v1/api-security/file-compliance-rules/{id}
func (h *ComplianceHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return
	}
	cur, err := h.store.GetComplianceRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrComplianceNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "文件合规规则不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.DeleteComplianceRule(r.Context(), id); err != nil {
		if errors.Is(err, ErrComplianceNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "文件合规规则不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	before, _ := json.Marshal(cur)
	h.recordAudit(r, p, "delete", "api_file_compliance_rule", id.String(),
		cur.MatchType+":"+cur.MatchValue, string(before), "", audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

// recordAudit 写操作审计（含操作者、动作、对象、前后摘要、风险等级）。
// 审计服务未注入（旧接线/单测）或无操作者上下文时跳过，不影响主流程。
func (h *ComplianceHandler) recordAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName, before, after, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_files",
		Action:        action,
		ObjectType:    objType,
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}
