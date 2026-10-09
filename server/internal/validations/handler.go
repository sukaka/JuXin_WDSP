// handler.go 无副作用模拟管理面 HTTP 处理器（NG-COV-03）：
//
//	POST /api/v1/api-security/protection/validations        创建模拟报告（api_protection.validate）
//	GET  /api/v1/api-security/protection/validations        报告分页列表（api_protection.read）
//	GET  /api/v1/api-security/protection/validations/{id}   单份报告（api_protection.read）
//
// 纪律：输入为脱敏 Finding 批次（拒绝 evidence 原文/超长批次字段，见 service
// validateBatches）；would_block 为模拟判定（非已执行）；STALE 读出时求值；
// 模拟不是 PROTECT 实测，报告不能单独满足上线条件。
package validations

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 权限点（api_protection 模块；种子见迁移 000169/000170）。
const (
	PermProtectionRead     = "api_protection.read"
	PermProtectionValidate = "api_protection.validate"
)

// listPageSizeMax 列表页大小上限（防过宽拉取）。
const listPageSizeMax = 100

// Handler 模拟管理面处理器。
type Handler struct {
	svc *Service
}

// NewHandler 创建处理器。
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// RegisterRoutes 注册路由（/api/v1/api-security 命名空间）。
func RegisterRoutes(mux *http.ServeMux, authzFn func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("POST /api/v1/api-security/protection/validations",
		authzFn(middleware.RequirePermission(PermProtectionValidate)(http.HandlerFunc(h.Create))))
	mux.Handle("GET /api/v1/api-security/protection/validations",
		authzFn(middleware.RequirePermission(PermProtectionRead)(http.HandlerFunc(h.List))))
	mux.Handle("GET /api/v1/api-security/protection/validations/{id}",
		authzFn(middleware.RequirePermission(PermProtectionRead)(http.HandlerFunc(h.Get))))
}

// createRequest 创建请求（输入即脱敏 Finding 批次；服务端白名单校验）。
type createRequest struct {
	Batches []FindingBatch `json:"batches"`
}

// Create POST /api/v1/api-security/protection/validations
// 创建模拟报告（200 带完整报告；输入非法 400）。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	var actorID uuid.UUID
	if p := authz.PrincipalFrom(r.Context()); p != nil {
		actorID = p.UserID
	}
	rep, err := h.svc.Create(r.Context(), actorID, req.Batches)
	if err != nil {
		var ie InputError
		if errors.As(err, &ie) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, ie.Error())
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, rep)
}

// List GET /api/v1/api-security/protection/validations
// 查询参数：page/page_size（默认 1/20，页大小上限 100）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page := queryPositiveInt(r, "page", 1)
	pageSize := queryPositiveInt(r, "page_size", 20)
	if pageSize > listPageSizeMax {
		pageSize = listPageSizeMax
	}
	reps, total, err := h.svc.List(r.Context(), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if reps == nil {
		reps = []Report{}
	}
	response.Page(w, r, reps, total, page, pageSize)
}

// Get GET /api/v1/api-security/protection/validations/{id}
// 单份报告（读出时 STALE 求值；id 非法 400、不存在 404）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 id（需 UUID）")
		return
	}
	rep, err := h.svc.Get(r.Context(), id)
	if err != nil {
		if err == ErrReportNotFound {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "报告不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, rep)
}

// queryPositiveInt 查询参数正整数（非法/非正回退默认值）。
func queryPositiveInt(r *http.Request, key string, def int) int {
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
