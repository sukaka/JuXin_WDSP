// handler.go 授权实体层 HTTP 处理器：角色基线 CRUD/确认、对象权属只读查询、
// 字段权限 CRUD、BOLA 五档评估。全部写操作带参数校验 + 操作审计。
package apiauthz

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 请求体上限。
const (
	baselineBodyMaxBytes  = 16 << 10 // 单条角色基线
	fieldPermBodyMaxBytes = 16 << 10 // 单条字段权限
)

// Handler 授权实体层处理器。
type Handler struct {
	store  Repository
	audits *audits.Service
}

// NewHandler 创建处理器（构造注入审计服务，语义同 apidata）。
func NewHandler(store Repository, audit *audits.Service) *Handler {
	return &Handler{store: store, audits: audit}
}

// RegisterRoutes 注册路由（统一 /api/v1/api-security/authz 前缀；权限点
// api_authorization.read/manage，种子迁移由集成方登记）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	// 角色基线（BFLA）
	mux.Handle("GET /api/v1/api-security/authz/role-baselines",
		authz(middleware.RequirePermission(PermAuthzRead)(http.HandlerFunc(h.ListRoleBaselines))))
	mux.Handle("POST /api/v1/api-security/authz/role-baselines",
		authz(middleware.RequirePermission(PermAuthzManage)(http.HandlerFunc(h.CreateRoleBaseline))))
	mux.Handle("GET /api/v1/api-security/authz/role-baselines/{id}",
		authz(middleware.RequirePermission(PermAuthzRead)(http.HandlerFunc(h.GetRoleBaseline))))
	mux.Handle("PATCH /api/v1/api-security/authz/role-baselines/{id}",
		authz(middleware.RequirePermission(PermAuthzManage)(http.HandlerFunc(h.UpdateRoleBaseline))))
	mux.Handle("DELETE /api/v1/api-security/authz/role-baselines/{id}",
		authz(middleware.RequirePermission(PermAuthzManage)(http.HandlerFunc(h.DeleteRoleBaseline))))
	mux.Handle("POST /api/v1/api-security/authz/role-baselines/{id}/confirm",
		authz(middleware.RequirePermission(PermAuthzManage)(http.HandlerFunc(h.ConfirmRoleBaseline))))
	// 对象权属（BOLA 基线，只读查询；生产方为 SweepOnce）
	mux.Handle("GET /api/v1/api-security/authz/ownership",
		authz(middleware.RequirePermission(PermAuthzRead)(http.HandlerFunc(h.ListOwnership))))
	// 字段权限（Mass Assignment / 字段越权）
	mux.Handle("GET /api/v1/api-security/authz/field-permissions",
		authz(middleware.RequirePermission(PermAuthzRead)(http.HandlerFunc(h.ListFieldPermissions))))
	mux.Handle("POST /api/v1/api-security/authz/field-permissions",
		authz(middleware.RequirePermission(PermAuthzManage)(http.HandlerFunc(h.CreateFieldPermission))))
	mux.Handle("GET /api/v1/api-security/authz/field-permissions/{id}",
		authz(middleware.RequirePermission(PermAuthzRead)(http.HandlerFunc(h.GetFieldPermission))))
	mux.Handle("PATCH /api/v1/api-security/authz/field-permissions/{id}",
		authz(middleware.RequirePermission(PermAuthzManage)(http.HandlerFunc(h.UpdateFieldPermission))))
	mux.Handle("DELETE /api/v1/api-security/authz/field-permissions/{id}",
		authz(middleware.RequirePermission(PermAuthzManage)(http.HandlerFunc(h.DeleteFieldPermission))))
	// BOLA 五档评估（只读）
	mux.Handle("GET /api/v1/api-security/authz/evaluate",
		authz(middleware.RequirePermission(PermAuthzRead)(http.HandlerFunc(h.EvaluateBOLA))))
}

// ---------- 角色基线 ----------

// ListRoleBaselines GET /api/v1/api-security/authz/role-baselines
// 过滤 endpoint_id/role/method/source/confirmed + 分页。
func (h *Handler) ListRoleBaselines(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	endpointID, ok := parseOptionalEndpointID(w, r)
	if !ok {
		return
	}
	method := strings.ToUpper(strings.TrimSpace(q.Get("method")))
	if method != "" && !validMethods[method] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 method 取值（GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS）")
		return
	}
	source := strings.ToUpper(strings.TrimSpace(q.Get("source")))
	if source != "" && !validSource(source) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 source 取值（MANUAL/SPEC/OBSERVED/IMPORTED）")
		return
	}
	var confirmed *bool
	if raw := strings.TrimSpace(q.Get("confirmed")); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 confirmed 取值（true/false）")
			return
		}
		confirmed = &v
	}
	page := queryInt(r, "page", 1)
	pageSize := queryPageSize(r, 20)
	list, total, err := h.store.ListRoleBaselines(r.Context(), RoleBaselineFilter{
		EndpointID: endpointID,
		Role:       strings.TrimSpace(q.Get("role")),
		Method:     method,
		Source:     source,
		Confirmed:  confirmed,
		Page:       page,
		PageSize:   pageSize,
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// GetRoleBaseline GET /api/v1/api-security/authz/role-baselines/{id}
func (h *Handler) GetRoleBaseline(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的基线ID")
		return
	}
	b, err := h.store.GetRoleBaseline(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "角色基线不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, b)
}

// baselineRequest 角色基线创建/编辑请求（编辑场景指针字段 = 仅更新提供的字段）。
type baselineRequest struct {
	EndpointID *string  `json:"endpoint_id"`
	Role       *string  `json:"role"`
	Method     *string  `json:"method"`
	Action     *string  `json:"action"`
	Allowed    *bool    `json:"allowed"`
	Source     *string  `json:"source"`
	Confidence *float64 `json:"confidence"`
}

// buildBaseline 从创建请求构造实体（默认：source=MANUAL、confidence=0）。
func (req *baselineRequest) buildBaseline(createdBy *string) (*RoleBaseline, error) {
	b := &RoleBaseline{Source: SourceManual}
	if req.EndpointID != nil {
		id, err := uuid.Parse(strings.TrimSpace(*req.EndpointID))
		if err != nil {
			return nil, errors.New("无效的 endpoint_id")
		}
		b.EndpointID = id
	}
	if req.Role != nil {
		b.Role = strings.TrimSpace(*req.Role)
	}
	if req.Method != nil {
		b.Method = strings.ToUpper(strings.TrimSpace(*req.Method))
	}
	if req.Action != nil {
		b.Action = strings.ToUpper(strings.TrimSpace(*req.Action))
	}
	if req.Allowed != nil {
		b.Allowed = *req.Allowed
	}
	if req.Source != nil {
		b.Source = strings.ToUpper(strings.TrimSpace(*req.Source))
	}
	if req.Confidence != nil {
		b.Confidence = *req.Confidence
	}
	b.CreatedBy = createdBy
	if err := validateRoleBaseline(b); err != nil {
		return nil, err
	}
	return b, nil
}

// mergeBaseline 把编辑请求合并到现有实体（仅覆盖提供的字段；endpoint_id/confirmed 不可经此变更）。
func (req *baselineRequest) mergeBaseline(cur *RoleBaseline) (*RoleBaseline, error) {
	merged := *cur
	if req.Role != nil {
		merged.Role = strings.TrimSpace(*req.Role)
	}
	if req.Method != nil {
		merged.Method = strings.ToUpper(strings.TrimSpace(*req.Method))
	}
	if req.Action != nil {
		merged.Action = strings.ToUpper(strings.TrimSpace(*req.Action))
	}
	if req.Allowed != nil {
		merged.Allowed = *req.Allowed
	}
	if req.Source != nil {
		merged.Source = strings.ToUpper(strings.TrimSpace(*req.Source))
	}
	if req.Confidence != nil {
		merged.Confidence = *req.Confidence
	}
	if err := validateRoleBaseline(&merged); err != nil {
		return nil, err
	}
	return &merged, nil
}

// CreateRoleBaseline POST /api/v1/api-security/authz/role-baselines
// 新建为候选（confirmed=FALSE），确认走 confirm 接口。
func (h *Handler) CreateRoleBaseline(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req baselineRequest
	if err := response.DecodeJSON(w, r, &req, baselineBodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	var createdBy *string
	if p != nil {
		createdBy = &p.Username
	}
	b, err := req.buildBaseline(createdBy)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.store.CreateRoleBaseline(r.Context(), b); err != nil {
		if errors.Is(err, ErrBaselineConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "相同角色/方法/动作的基线已存在")
			return
		}
		if errors.Is(err, ErrEndpointNotFound) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "引用的端点资产不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	after, _ := json.Marshal(b)
	h.recordAudit(r, p, "create", "api_role_baseline", b.ID.String(), b.Role+" "+b.Method+" "+b.Action,
		"", string(after), audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, b)
}

// UpdateRoleBaseline PATCH /api/v1/api-security/authz/role-baselines/{id}
// 部分更新；endpoint_id 不可改（换端点 = 删除后重建）；confirmed 不随编辑变更。
func (h *Handler) UpdateRoleBaseline(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的基线ID")
		return
	}
	var req baselineRequest
	if err := response.DecodeJSON(w, r, &req, baselineBodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	cur, err := h.store.GetRoleBaseline(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "角色基线不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	merged, err := req.mergeBaseline(cur)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.store.UpdateRoleBaseline(r.Context(), merged); err != nil {
		if errors.Is(err, ErrBaselineConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "相同角色/方法/动作的基线已存在")
			return
		}
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "角色基线不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	before, _ := json.Marshal(cur)
	after, _ := json.Marshal(merged)
	h.recordAudit(r, p, "update", "api_role_baseline", id.String(), merged.Role+" "+merged.Method+" "+merged.Action,
		string(before), string(after), audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, merged)
}

// DeleteRoleBaseline DELETE /api/v1/api-security/authz/role-baselines/{id}
func (h *Handler) DeleteRoleBaseline(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的基线ID")
		return
	}
	cur, err := h.store.GetRoleBaseline(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "角色基线不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.DeleteRoleBaseline(r.Context(), id); err != nil {
		response.InternalError(w, r, err)
		return
	}
	before, _ := json.Marshal(cur)
	h.recordAudit(r, p, "delete", "api_role_baseline", id.String(), cur.Role+" "+cur.Method+" "+cur.Action,
		string(before), "", audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "角色基线已删除"})
}

// confirmRequest 确认请求。
type confirmRequest struct {
	Confirmed *bool `json:"confirmed"`
}

// ConfirmRoleBaseline POST /api/v1/api-security/authz/role-baselines/{id}/confirm
// 候选 → 正式基线（confirmed=true）；传 false 可撤回确认。
func (h *Handler) ConfirmRoleBaseline(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的基线ID")
		return
	}
	var req confirmRequest
	if err := response.DecodeJSON(w, r, &req, baselineBodyMaxBytes); err != nil || req.Confirmed == nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误（期望 {\"confirmed\": true|false}）")
		return
	}
	b, err := h.store.ConfirmRoleBaseline(r.Context(), id, *req.Confirmed)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "角色基线不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	after, _ := json.Marshal(b)
	h.recordAudit(r, p, "confirm", "api_role_baseline", id.String(), b.Role+" "+b.Method+" "+b.Action,
		"", string(after), audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, b)
}

// ---------- 对象权属（只读查询） ----------

// ListOwnership GET /api/v1/api-security/authz/ownership
// 过滤 endpoint_id/identity/object_type/object_id + 分页（按最近访问倒序）。
func (h *Handler) ListOwnership(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	endpointID, ok := parseOptionalEndpointID(w, r)
	if !ok {
		return
	}
	identity := strings.TrimSpace(q.Get("identity"))
	if len(identity) > maxIdentity {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "identity 长度不能超过 128")
		return
	}
	objectID := strings.TrimSpace(q.Get("object_id"))
	if len(objectID) > maxObjectID {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "object_id 长度不能超过 256")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryPageSize(r, 20)
	list, total, err := h.store.ListOwnership(r.Context(), OwnershipFilter{
		EndpointID: endpointID,
		Identity:   identity,
		ObjectType: strings.TrimSpace(q.Get("object_type")),
		ObjectID:   objectID,
		Page:       page,
		PageSize:   pageSize,
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// ---------- 字段权限 ----------

// fieldPermRequest 字段权限创建/编辑请求（编辑场景指针字段 = 仅更新提供的字段；
// 可空字段显式传空串表示清除为 NULL = 回到默认行语义）。
type fieldPermRequest struct {
	EndpointID *string `json:"endpoint_id"`
	FieldPath  *string `json:"field_path"`
	Direction  *string `json:"direction"`
	Attribute  *string `json:"attribute"`
	Role       *string `json:"role"`
	Tenant     *string `json:"tenant"`
}

// buildFieldPermission 从创建请求构造实体。
func (req *fieldPermRequest) buildFieldPermission(createdBy *string) (*FieldPermission, error) {
	fp := &FieldPermission{}
	if req.EndpointID != nil {
		id, err := uuid.Parse(strings.TrimSpace(*req.EndpointID))
		if err != nil {
			return nil, errors.New("无效的 endpoint_id")
		}
		fp.EndpointID = id
	}
	if req.FieldPath != nil {
		fp.FieldPath = strings.TrimSpace(*req.FieldPath)
	}
	if req.Direction != nil {
		fp.Direction = strings.ToUpper(strings.TrimSpace(*req.Direction))
	}
	if req.Attribute != nil {
		fp.Attribute = strings.ToUpper(strings.TrimSpace(*req.Attribute))
	}
	fp.Role = optionalString(req.Role)
	fp.Tenant = optionalString(req.Tenant)
	fp.CreatedBy = createdBy
	if err := validateFieldPermission(fp); err != nil {
		return nil, err
	}
	return fp, nil
}

// mergeFieldPermission 把编辑请求合并到现有实体（仅覆盖提供的字段；endpoint_id 不可改）。
func (req *fieldPermRequest) mergeFieldPermission(cur *FieldPermission) (*FieldPermission, error) {
	merged := *cur
	if req.FieldPath != nil {
		merged.FieldPath = strings.TrimSpace(*req.FieldPath)
	}
	if req.Direction != nil {
		merged.Direction = strings.ToUpper(strings.TrimSpace(*req.Direction))
	}
	if req.Attribute != nil {
		merged.Attribute = strings.ToUpper(strings.TrimSpace(*req.Attribute))
	}
	if req.Role != nil {
		merged.Role = optionalString(req.Role)
	}
	if req.Tenant != nil {
		merged.Tenant = optionalString(req.Tenant)
	}
	if err := validateFieldPermission(&merged); err != nil {
		return nil, err
	}
	return &merged, nil
}

// ListFieldPermissions GET /api/v1/api-security/authz/field-permissions
// 过滤 endpoint_id/direction/attribute/role/tenant/defaults_only + 分页。
func (h *Handler) ListFieldPermissions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	endpointID, ok := parseOptionalEndpointID(w, r)
	if !ok {
		return
	}
	direction := strings.ToUpper(strings.TrimSpace(q.Get("direction")))
	if direction != "" && !validDirection(direction) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 direction 取值（REQUEST/RESPONSE）")
		return
	}
	attribute := strings.ToUpper(strings.TrimSpace(q.Get("attribute")))
	if attribute != "" && !validAttribute(attribute) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 attribute 取值（READABLE/WRITABLE/READ_ONLY/ADMIN_WRITABLE/SERVER_GENERATED/SENSITIVE/FORBIDDEN）")
		return
	}
	defaultsOnly := false
	if raw := strings.TrimSpace(q.Get("defaults_only")); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 defaults_only 取值（true/false）")
			return
		}
		defaultsOnly = v
	}
	page := queryInt(r, "page", 1)
	pageSize := queryPageSize(r, 20)
	list, total, err := h.store.ListFieldPermissions(r.Context(), FieldPermFilter{
		EndpointID:   endpointID,
		Direction:    direction,
		Attribute:    attribute,
		Role:         strings.TrimSpace(q.Get("role")),
		Tenant:       strings.TrimSpace(q.Get("tenant")),
		DefaultsOnly: defaultsOnly,
		Page:         page,
		PageSize:     pageSize,
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// GetFieldPermission GET /api/v1/api-security/authz/field-permissions/{id}
func (h *Handler) GetFieldPermission(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的字段权限ID")
		return
	}
	fp, err := h.store.GetFieldPermission(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "字段权限不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, fp)
}

// CreateFieldPermission POST /api/v1/api-security/authz/field-permissions
func (h *Handler) CreateFieldPermission(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req fieldPermRequest
	if err := response.DecodeJSON(w, r, &req, fieldPermBodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	var createdBy *string
	if p != nil {
		createdBy = &p.Username
	}
	fp, err := req.buildFieldPermission(createdBy)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.store.CreateFieldPermission(r.Context(), fp); err != nil {
		if errors.Is(err, ErrFieldPermConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "相同字段/方向/角色/租户的权限已存在")
			return
		}
		if errors.Is(err, ErrEndpointNotFound) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "引用的端点资产不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	after, _ := json.Marshal(fp)
	h.recordAudit(r, p, "create", "api_field_permission", fp.ID.String(), fp.Direction+" "+fp.FieldPath,
		"", string(after), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, fp)
}

// UpdateFieldPermission PATCH /api/v1/api-security/authz/field-permissions/{id}
// 部分更新；endpoint_id 不可改；role/tenant 显式传空串清除为 NULL（回到默认行）。
func (h *Handler) UpdateFieldPermission(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的字段权限ID")
		return
	}
	var req fieldPermRequest
	if err := response.DecodeJSON(w, r, &req, fieldPermBodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	cur, err := h.store.GetFieldPermission(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "字段权限不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	merged, err := req.mergeFieldPermission(cur)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.store.UpdateFieldPermission(r.Context(), merged); err != nil {
		if errors.Is(err, ErrFieldPermConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "相同字段/方向/角色/租户的权限已存在")
			return
		}
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "字段权限不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	before, _ := json.Marshal(cur)
	after, _ := json.Marshal(merged)
	h.recordAudit(r, p, "update", "api_field_permission", id.String(), merged.Direction+" "+merged.FieldPath,
		string(before), string(after), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, merged)
}

// DeleteFieldPermission DELETE /api/v1/api-security/authz/field-permissions/{id}
func (h *Handler) DeleteFieldPermission(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的字段权限ID")
		return
	}
	cur, err := h.store.GetFieldPermission(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "字段权限不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.DeleteFieldPermission(r.Context(), id); err != nil {
		response.InternalError(w, r, err)
		return
	}
	before, _ := json.Marshal(cur)
	h.recordAudit(r, p, "delete", "api_field_permission", id.String(), cur.Direction+" "+cur.FieldPath,
		string(before), "", audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "字段权限已删除"})
}

// ---------- BOLA 五档评估 ----------

// EvaluateBOLA GET /api/v1/api-security/authz/evaluate?endpoint_id&identity&object_id
// 五档结论（POLICY_CONFIRMED/HIGH_CONFIDENCE/LIKELY/POSSIBLE/INSUFFICIENT_EVIDENCE），
// 判定阶梯与「不仅凭 ID 变化定罪」纪律见 evaluate.go 文件头注释。
// identity 可空（空 = 匿名身份，不做权属匹配，只走对象侧信号）。
func (h *Handler) EvaluateBOLA(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	endpointID, err := uuid.Parse(strings.TrimSpace(q.Get("endpoint_id")))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "endpoint_id 必填且必须是合法 UUID")
		return
	}
	objectID := strings.TrimSpace(q.Get("object_id"))
	if objectID == "" || len(objectID) > maxObjectID {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "object_id 必填且长度不能超过 256")
		return
	}
	identity := strings.TrimSpace(q.Get("identity"))
	if len(identity) > maxIdentity {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "identity 长度不能超过 128")
		return
	}
	result, err := h.store.EvaluateBOLA(r.Context(), EvaluateInput{
		EndpointID: endpointID,
		Identity:   identity,
		ObjectID:   objectID,
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点资产不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, result)
}

// ---------- 通用 ----------

// parseOptionalEndpointID 可空端点过滤参数（空 = 不过滤；非法即 400 并写响应）。
func parseOptionalEndpointID(w http.ResponseWriter, r *http.Request) (*uuid.UUID, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("endpoint_id"))
	if raw == "" {
		return nil, true
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 endpoint_id")
		return nil, false
	}
	return &id, true
}

// optionalString 可空字符串字段：nil 不提供 / 空串清除为 NULL / 其余 trim。
func optionalString(raw *string) *string {
	if raw == nil {
		return nil
	}
	v := strings.TrimSpace(*raw)
	if v == "" {
		return nil
	}
	return &v
}

// recordAudit 写操作审计（含操作者、动作、对象、前后摘要、风险等级）。
// 审计服务未注入（旧接线/单测）或无操作者上下文时跳过，不影响主流程。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName, before, after, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_authorization",
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

// queryPageSize 分页大小（夹取 ≤100，非法回退默认值；与 store normPage 口径一致）。
func queryPageSize(r *http.Request, def int) int {
	n := queryInt(r, "page_size", def)
	if n > 100 {
		n = 100
	}
	return n
}

// queryInt 查询参数整型（正数，非法回退默认值）。
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
