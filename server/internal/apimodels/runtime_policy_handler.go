// runtime_policy_handler.go 运行时策略版本 HTTP 接口（P0-03/21）：
// 列表/状态/版本查询、模型→策略溯源、回滚到上一已知良好版本（恢复 FORMAL 模型 + 重触发整站发布）。
package apimodels

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// RuntimePolicyStore 运行时策略存取（*Store 实现；包内单测用 fake，遵循 apisecurity fakePolicySettings 模式）。
type RuntimePolicyStore interface {
	ListRuntimePolicies(ctx context.Context, f RuntimePolicyFilter) ([]RuntimePolicy, int64, error)
	ListRuntimePoliciesByModel(ctx context.Context, modelVersionID uuid.UUID) ([]RuntimePolicy, error)
	GetRuntimePolicyByID(ctx context.Context, id uuid.UUID) (*RuntimePolicy, error)
	RollbackToKnownGood(ctx context.Context, id, operatorID uuid.UUID) (*RuntimePolicyRollback, error)
	MarkRuntimePolicyFailed(ctx context.Context, id uuid.UUID, reason string) error
}

// publishStatusSuccess 发布任务成功状态（镜像 gatewayconfig.TaskSuccess，本包不反引发布包）。
const publishStatusSuccess = "SUCCESS"

// RuntimePolicyPublishResult 发布触发结果摘要。
type RuntimePolicyPublishResult struct {
	TaskID string `json:"task_id"`
	Status string `json:"status"`
}

// RuntimePolicyPublishFunc 重触发整站发布（app 装配时接线 publisher.PublishSync）。
type RuntimePolicyPublishFunc func(ctx context.Context, requestedBy uuid.UUID, requestID string) (*RuntimePolicyPublishResult, error)

// SetRuntimePolicyStore 注入策略存取实现（默认 NewHandler 以 *Store 接线；测试注入 fake）。
func (h *Handler) SetRuntimePolicyStore(s RuntimePolicyStore) { h.runtime = s }

// SetRuntimePolicyPublishFunc 注入整站发布触发函数（回滚接口用；nil 时回滚返回 503）。
func (h *Handler) SetRuntimePolicyPublishFunc(fn RuntimePolicyPublishFunc) { h.runtimePublish = fn }

// ListRuntimePolicies GET /api/v1/api-security/runtime-policies?endpoint_id=&status=&page=&page_size=
func (h *Handler) ListRuntimePolicies(w http.ResponseWriter, r *http.Request) {
	var f RuntimePolicyFilter
	if raw := r.URL.Query().Get("endpoint_id"); raw != "" {
		endpointID, err := uuid.Parse(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的接口ID")
			return
		}
		f.EndpointID = &endpointID
	}
	if st := r.URL.Query().Get("status"); st != "" {
		if !ValidPolicyStatus(st) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略状态")
			return
		}
		f.Status = st
	}
	if h.runtime == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeInternalError, "运行时策略存储未配置")
		return
	}
	f.Page = queryInt(r, "page", 1)
	f.PageSize = queryInt(r, "page_size", 20)
	list, total, err := h.runtime.ListRuntimePolicies(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// GetModelRuntimePolicies GET /api/v1/api-security/models/{id}/runtime（模型 → 策略溯源）
func (h *Handler) GetModelRuntimePolicies(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模型版本ID")
		return
	}
	if h.runtime == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeInternalError, "运行时策略存储未配置")
		return
	}
	list, err := h.runtime.ListRuntimePoliciesByModel(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": list})
}

// RollbackRuntimePolicy POST /api/v1/api-security/runtime-policies/{id}/rollback
// 将端点回退到上一已知良好版本：事务内恢复其来源模型为 FORMAL（受控恢复通道，发布内容源
// 随之回到旧模型）并克隆内容创建新 DRAFT 策略，随后重触发整站发布；
// 发布成功经 MarkRuntimePoliciesPublishResult 落 ACTIVE（语义见 runtime_policy.go 状态机注释）。
// 失败路径：发布触发失败——草稿落 FAILED（不残留操作者无感知的孤儿 DRAFT）并记失败审计；
// 发布执行失败（任务 FAILED）——发布回写已落 FAILED，记失败审计并返回 502，不假报「已回退」。
func (h *Handler) RollbackRuntimePolicy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略ID")
		return
	}
	if h.runtime == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeInternalError, "运行时策略存储未配置")
		return
	}
	if h.runtimePublish == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeInternalError, "发布通道未配置")
		return
	}
	before, err := h.runtime.GetRuntimePolicyByID(r.Context(), id)
	if errors.Is(err, ErrRuntimePolicyNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "运行时策略不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	outcome, err := h.runtime.RollbackToKnownGood(r.Context(), id, operatorID(p))
	switch {
	case errors.Is(err, ErrRuntimePolicyNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "运行时策略不存在")
		return
	case errors.Is(err, ErrNoPreviousGoodPolicy):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "该端点无上一已知良好版本，无法回滚")
		return
	case errors.Is(err, ErrModelNotRestorable):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "上一已知良好版本的来源模型已归档或状态异常，无法恢复")
		return
	case errors.Is(err, ErrInvalidTransition):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "仅 ACTIVE 或 FAILED 状态的策略允许回滚")
		return
	case err != nil:
		response.InternalError(w, r, err)
		return
	}
	beforeSummary := "status=" + before.Status + ", version=" + before.RuntimeVersion
	afterSummary := "恢复模型版本 v" + strconv.Itoa(outcome.RestoredModel.VersionNumber) +
		"(FORMAL) 并创建回滚策略 " + outcome.Draft.RuntimeVersion
	result, err := h.runtimePublish(r.Context(), operatorID(p), response.RequestIDFrom(r))
	if err != nil {
		// 发布触发失败：草稿落 FAILED（操作者可见终态），记失败审计；标记失败仅 Warn 不掩盖原始错误
		reason := "回滚发布触发失败: " + err.Error()
		if merr := h.runtime.MarkRuntimePolicyFailed(r.Context(), outcome.Draft.ID, reason); merr != nil {
			slog.Warn("mark rollback draft failed", "policy", outcome.Draft.ID, "error", merr)
		}
		h.recordAuditOutcome(r, p, "rollback", "api_runtime_policy", id.String(), before.EndpointKey,
			beforeSummary, afterSummary+"，发布触发失败", audits.ResultFailure, reason, audits.RiskHigh)
		response.InternalError(w, r, err)
		return
	}
	if result.Status != publishStatusSuccess {
		// 发布执行失败：MarkRuntimePoliciesPublishResult 已将待发布集合落 FAILED，记失败审计
		h.recordAuditOutcome(r, p, "rollback", "api_runtime_policy", id.String(), before.EndpointKey,
			beforeSummary, afterSummary+"，发布任务状态 "+result.Status, audits.ResultFailure,
			"发布任务状态: "+result.Status, audits.RiskHigh)
		response.Error(w, r, http.StatusBadGateway, response.CodeInternalError,
			"回滚发布失败（任务状态 "+result.Status+"），回滚策略已标记失败，可重新激活后再次发布")
		return
	}
	h.recordAuditOutcome(r, p, "rollback", "api_runtime_policy", id.String(), before.EndpointKey,
		beforeSummary, afterSummary+" 并触发发布, status="+result.Status, audits.ResultSuccess, "", audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"policy": outcome.Draft, "task_id": result.TaskID, "status": result.Status,
		"message": "已回退到上一已知良好版本并重新触发发布",
	})
}

// recordAuditOutcome 带结果（成功/失败 + 失败原因）的操作审计，语义同 recordAudit；
// 审计服务未接线或主体缺失时跳过，不影响主流程。
func (h *Handler) recordAuditOutcome(r *http.Request, p *authz.Principal, action, objType, objID, objName, before, after, result, failReason, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_security",
		Action:        action,
		ObjectType:    objType,
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		FailureReason: failReason,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}
