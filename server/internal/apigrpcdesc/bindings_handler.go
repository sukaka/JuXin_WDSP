// bindings_handler.go gRPC 描述符 per-app 绑定管理端点（NG-GRPC G1 批次 B1，
// 设计 §1.3/§1.9）：
//
//	GET    /api/v1/api-security/grpc-bindings（api_spec.read；application_id 可选过滤）
//	POST   /api/v1/api-security/grpc-bindings（api_spec.manage；HIGH 审计）
//	PUT    /api/v1/api-security/grpc-bindings/{id}（同上；version 乐观锁）
//	DELETE /api/v1/api-security/grpc-bindings/{id}（同上）
//	GET    /api/v1/api-security/grpc-bindings/undocumented-services（api_spec.read）
//
// 写操作 HIGH 审计（绑定变更影响深检范围与实断面——与对象模型 PATCH 同纪律）。
package apigrpcdesc

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// ListBindings GET /api/v1/api-security/grpc-bindings
func (h *Handler) ListBindings(w http.ResponseWriter, r *http.Request) {
	if h.bindRepo == nil {
		response.InternalError(w, r, errBindingRepoMissing)
		return
	}
	var applicationID uuid.UUID
	if v := strings.TrimSpace(r.URL.Query().Get("application_id")); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的站点ID")
			return
		}
		applicationID = id
	}
	list, err := h.bindRepo.ListBindings(r.Context(), applicationID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": list, "total": len(list)})
}

// CreateBinding POST /api/v1/api-security/grpc-bindings（同（应用,服务）409）
func (h *Handler) CreateBinding(w http.ResponseWriter, r *http.Request) {
	if h.bindRepo == nil {
		response.InternalError(w, r, errBindingRepoMissing)
		return
	}
	p := authz.PrincipalFrom(r.Context())
	var req BindingInput
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if msg := ValidateBindingInput(req); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	createdBy := ""
	if p != nil {
		createdBy = p.Username
	}
	b, err := h.bindRepo.CreateBinding(r.Context(), req, createdBy)
	if err != nil {
		writeBindingError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "api_grpc_binding", b.ID.String(), b.Service,
		"", bindingSummary(b), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, b)
}

// UpdateBinding PUT /api/v1/api-security/grpc-bindings/{id}
// 仅 mode/descriptor_name 可改（绑定身份维度（应用/服务）不可改——改即删建）；
// version 乐观锁（不匹配 409）。
func (h *Handler) UpdateBinding(w http.ResponseWriter, r *http.Request) {
	if h.bindRepo == nil {
		response.InternalError(w, r, errBindingRepoMissing)
		return
	}
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "id 非法")
		return
	}
	var req BindingInput
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	// Update 语义下 application_id/service 以路径行为准（载荷给出须一致，防误改身份维度）
	if msg := validateBindingUpdateInput(req); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	b, err := h.bindRepo.UpdateBinding(r.Context(), id, req)
	if err != nil {
		writeBindingError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "api_grpc_binding", b.ID.String(), b.Service,
		"", bindingSummary(b), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, b)
}

// DeleteBinding DELETE /api/v1/api-security/grpc-bindings/{id}
func (h *Handler) DeleteBinding(w http.ResponseWriter, r *http.Request) {
	if h.bindRepo == nil {
		response.InternalError(w, r, errBindingRepoMissing)
		return
	}
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "id 非法")
		return
	}
	if err := h.bindRepo.DeleteBinding(r.Context(), id); err != nil {
		writeBindingError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", "api_grpc_binding", id.String(), "", "", "",
		audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

// ListUndocumentedServices GET .../grpc-bindings/undocumented-services
// 未登记服务清单（D3 红线管理面可见性：流量观测到但（按绑定语义）未覆盖
// 描述符的 service/method 差集；read 权限只读）。
func (h *Handler) ListUndocumentedServices(w http.ResponseWriter, r *http.Request) {
	if h.bindRepo == nil {
		response.InternalError(w, r, errBindingRepoMissing)
		return
	}
	list, err := h.bindRepo.ListUndocumentedServices(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": list, "total": len(list)})
}

// errBindingRepoMissing 装配遗漏（bindRepo 未注入）——如实 500 不静默降级。
var errBindingRepoMissing = errors.New("grpc binding repository not wired")

// validateBindingUpdateInput Update 载荷校验（service 若给出仅形态校验
// （不参与更新——身份维度不可改）；descriptor_name/mode/version 必填语义）。
func validateBindingUpdateInput(in BindingInput) string {
	if strings.TrimSpace(in.DescriptorName) == "" || len(strings.TrimSpace(in.DescriptorName)) > maxNameLen {
		return "descriptor_name 必填（≤128 字符）"
	}
	switch strings.ToUpper(strings.TrimSpace(in.Mode)) {
	case "", ModeObserve, ModeProtect:
	default:
		return "mode 非法（OBSERVE|PROTECT）"
	}
	if in.Version < 1 {
		return "version 必须 ≥1（乐观锁与绑定行 version 比对）"
	}
	if s := strings.TrimSpace(in.Service); s != "" && (len(s) > maxServiceLen || !servicePattern.MatchString(s)) {
		return "service 非法（pkg.Service 点路径形态）"
	}
	return ""
}

// writeBindingError 绑定错误→HTTP 精确映射（400 校验 / 404 不存在 / 409 冲突）。
func writeBindingError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrBindingNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "绑定不存在")
	case errors.Is(err, ErrBindingDuplicate):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "同（应用,服务）绑定已存在（恰一条）")
	case errors.Is(err, ErrDescriptorNotFound):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "引用的描述符集不存在")
	case errors.Is(err, ErrApplicationNotFound):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "引用的应用不存在")
	case errors.Is(err, ErrBindingVersionConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, ErrBindingVersionConflict.Error())
	default:
		response.InternalError(w, r, err)
	}
}

// bindingSummary 绑定审计摘要（JSON 形态：既有审计脱敏器对非 JSON 摘要整段遮蔽，
// 键均非敏感键白名单全值保留——FLOW-03 resolveSummary 先例）。
func bindingSummary(b *Binding) string {
	return fmt.Sprintf(`{"application_id":%q,"service":%q,"descriptor_name":%q,"mode":%q,"version":%d}`,
		b.ApplicationID.String(), b.Service, b.DescriptorName, b.Mode, b.Version)
}
