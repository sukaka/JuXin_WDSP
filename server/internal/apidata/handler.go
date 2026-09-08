// handler.go 敏感数据管理面 HTTP 处理器：敏感数据类型 CRUD/启停/导入导出、
// 脱敏规则 CRUD、敏感数据态势。全部写操作带参数校验 + 操作审计。
package apidata

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 请求体上限。
const (
	typeBodyMaxBytes   = 32 << 10 // 单个类型定义（regex/词根列表足够）
	typeImportMaxBytes = 1 << 20  // 导入批量
	ruleBodyMaxBytes   = 64 << 10 // 单条规则（params/exclusions 对象）
	importMaxItems     = 500      // 单次导入条数上限
)

// Handler 敏感数据管理面处理器。
type Handler struct {
	store  Repository
	audits *audits.Service
}

// NewHandler 创建处理器（构造注入审计服务，语义同 apiassets）。
func NewHandler(store Repository, audit *audits.Service) *Handler {
	return &Handler{store: store, audits: audit}
}

// RegisterRoutes 注册路由（统一 /api/v1/api-security 前缀；权限点 api_data.read/manage，
// 种子迁移由集成方登记）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	// 敏感数据类型
	mux.Handle("GET /api/v1/api-security/sensitive-types",
		authz(middleware.RequirePermission(PermDataRead)(http.HandlerFunc(h.ListTypes))))
	mux.Handle("POST /api/v1/api-security/sensitive-types",
		authz(middleware.RequirePermission(PermDataManage)(http.HandlerFunc(h.CreateType))))
	// 静态段 export/import 优先于 {id} 通配（Go 1.22+ ServeMux 最具体匹配）
	mux.Handle("GET /api/v1/api-security/sensitive-types/export",
		authz(middleware.RequirePermission(PermDataRead)(http.HandlerFunc(h.ExportTypes))))
	mux.Handle("POST /api/v1/api-security/sensitive-types/import",
		authz(middleware.RequirePermission(PermDataManage)(http.HandlerFunc(h.ImportTypes))))
	mux.Handle("GET /api/v1/api-security/sensitive-types/{id}",
		authz(middleware.RequirePermission(PermDataRead)(http.HandlerFunc(h.GetType))))
	mux.Handle("PATCH /api/v1/api-security/sensitive-types/{id}",
		authz(middleware.RequirePermission(PermDataManage)(http.HandlerFunc(h.UpdateType))))
	mux.Handle("DELETE /api/v1/api-security/sensitive-types/{id}",
		authz(middleware.RequirePermission(PermDataManage)(http.HandlerFunc(h.DeleteType))))
	// 脱敏规则
	mux.Handle("GET /api/v1/api-security/masking-rules",
		authz(middleware.RequirePermission(PermDataRead)(http.HandlerFunc(h.ListMaskingRules))))
	mux.Handle("POST /api/v1/api-security/masking-rules",
		authz(middleware.RequirePermission(PermDataManage)(http.HandlerFunc(h.CreateMaskingRule))))
	mux.Handle("GET /api/v1/api-security/masking-rules/{id}",
		authz(middleware.RequirePermission(PermDataRead)(http.HandlerFunc(h.GetMaskingRule))))
	mux.Handle("PATCH /api/v1/api-security/masking-rules/{id}",
		authz(middleware.RequirePermission(PermDataManage)(http.HandlerFunc(h.UpdateMaskingRule))))
	mux.Handle("DELETE /api/v1/api-security/masking-rules/{id}",
		authz(middleware.RequirePermission(PermDataManage)(http.HandlerFunc(h.DeleteMaskingRule))))
	// 敏感数据态势
	mux.Handle("GET /api/v1/api-security/sensitive/overview",
		authz(middleware.RequirePermission(PermDataRead)(http.HandlerFunc(h.SensitiveOverview))))
}

// ---------- 敏感数据类型 ----------

// ListTypes GET /api/v1/api-security/sensitive-types
// 过滤 status/level/category/keyword(name 子串) + 分页。
func (h *Handler) ListTypes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := strings.ToUpper(strings.TrimSpace(q.Get("status")))
	if status != "" && !validTypeStatus(status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 status 取值（ENABLED/DISABLED）")
		return
	}
	level := strings.ToUpper(strings.TrimSpace(q.Get("level")))
	if level != "" && !validLevel(level) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 level 取值（NON_SENSITIVE/GENERAL/SENSITIVE/IMPORTANT/CORE）")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryPageSize(r, 20)
	list, total, err := h.store.ListTypes(r.Context(), TypeFilter{
		Status:   status,
		Level:    level,
		Category: strings.TrimSpace(q.Get("category")),
		Keyword:  strings.TrimSpace(q.Get("keyword")),
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// GetType GET /api/v1/api-security/sensitive-types/{id}
func (h *Handler) GetType(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的类型ID")
		return
	}
	t, err := h.store.GetType(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "敏感数据类型不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, t)
}

// typeRequest 类型创建请求。
type typeRequest struct {
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	Category      string   `json:"category"`
	Level         string   `json:"level"`
	DataType      string   `json:"data_type"`
	Locations     []string `json:"locations"`
	Keywords      []string `json:"keywords"`
	Regex         string   `json:"regex"`
	Validator     string   `json:"validator"`
	ExcludeFields []string `json:"exclude_fields"`
	Status        string   `json:"status"`
}

// normalize 归一（trim + 大写枚举 + 默认值 + locations 小写）。
func (req *typeRequest) normalize() {
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	req.Category = strings.TrimSpace(req.Category)
	req.Level = strings.ToUpper(strings.TrimSpace(req.Level))
	if req.Level == "" {
		req.Level = LevelGeneral
	}
	req.DataType = strings.TrimSpace(req.DataType)
	req.Locations = normalizeLocations(req.Locations)
	req.Keywords = trimStrList(req.Keywords)
	req.Regex = strings.TrimSpace(req.Regex)
	req.Validator = strings.TrimSpace(req.Validator)
	req.ExcludeFields = trimStrList(req.ExcludeFields)
	req.Status = strings.ToUpper(strings.TrimSpace(req.Status))
	if req.Status == "" {
		req.Status = TypeStatusEnabled
	}
}

// trimStrList 逐项 trim。
func trimStrList(items []string) []string {
	if items == nil {
		return nil
	}
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = strings.TrimSpace(it)
	}
	return out
}

// normalizeLocations 逐项 trim + 小写（位置白名单为小写）。
func normalizeLocations(items []string) []string {
	if items == nil {
		return nil
	}
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = strings.ToLower(strings.TrimSpace(it))
	}
	return out
}

// toType 转实体（ID/Version/IsBuiltin/时间戳由 store 填）。
func (req *typeRequest) toType() *SensitiveDataType {
	return &SensitiveDataType{
		Name: req.Name, Description: req.Description, Category: req.Category,
		Level: req.Level, DataType: req.DataType, Locations: req.Locations,
		Keywords: req.Keywords, Regex: req.Regex, Validator: req.Validator,
		ExcludeFields: req.ExcludeFields, Status: req.Status,
	}
}

// CreateType POST /api/v1/api-security/sensitive-types
func (h *Handler) CreateType(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req typeRequest
	if err := response.DecodeJSON(w, r, &req, typeBodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.normalize()
	t := req.toType()
	if err := validateType(t); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.store.CreateType(r.Context(), t); err != nil {
		if errors.Is(err, ErrNameConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "类型名称已存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	after, _ := json.Marshal(t)
	h.recordAudit(r, p, "create", "api_sensitive_data_type", t.ID.String(), t.Name, "", string(after),
		audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, t)
}

// updateTypeRequest 类型编辑请求（指针字段 = 仅更新提供的字段）。
type updateTypeRequest struct {
	Name          *string   `json:"name"`
	Description   *string   `json:"description"`
	Category      *string   `json:"category"`
	Level         *string   `json:"level"`
	DataType      *string   `json:"data_type"`
	Locations     *[]string `json:"locations"`
	Keywords      *[]string `json:"keywords"`
	Regex         *string   `json:"regex"`
	Validator     *string   `json:"validator"`
	ExcludeFields *[]string `json:"exclude_fields"`
	Status        *string   `json:"status"`
}

// UpdateType PATCH /api/v1/api-security/sensitive-types/{id}
// 部分更新，编辑 version 自增；内置类型名称不可改（与网关证据标签对齐键），其余字段可改。
// status 取 ENABLED/DISABLED 即启用/禁用。
func (h *Handler) UpdateType(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的类型ID")
		return
	}
	var req updateTypeRequest
	if err := response.DecodeJSON(w, r, &req, typeBodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	cur, err := h.store.GetType(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "敏感数据类型不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	merged := *cur
	if req.Name != nil {
		merged.Name = strings.TrimSpace(*req.Name)
	}
	if cur.IsBuiltin && merged.Name != cur.Name {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "内置类型名称不可修改")
		return
	}
	if req.Description != nil {
		merged.Description = strings.TrimSpace(*req.Description)
	}
	if req.Category != nil {
		merged.Category = strings.TrimSpace(*req.Category)
	}
	if req.Level != nil {
		merged.Level = strings.ToUpper(strings.TrimSpace(*req.Level))
	}
	if req.DataType != nil {
		merged.DataType = strings.TrimSpace(*req.DataType)
	}
	if req.Locations != nil {
		merged.Locations = normalizeLocations(*req.Locations)
	}
	if req.Keywords != nil {
		merged.Keywords = trimStrList(*req.Keywords)
	}
	if req.Regex != nil {
		merged.Regex = strings.TrimSpace(*req.Regex)
	}
	if req.Validator != nil {
		merged.Validator = strings.TrimSpace(*req.Validator)
	}
	if req.ExcludeFields != nil {
		merged.ExcludeFields = trimStrList(*req.ExcludeFields)
	}
	if req.Status != nil {
		merged.Status = strings.ToUpper(strings.TrimSpace(*req.Status))
	}
	if err := validateType(&merged); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.store.UpdateType(r.Context(), &merged); err != nil {
		if errors.Is(err, ErrNameConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "类型名称已存在")
			return
		}
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "敏感数据类型不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	before, _ := json.Marshal(cur)
	after, _ := json.Marshal(&merged)
	h.recordAudit(r, p, "update", "api_sensitive_data_type", id.String(), merged.Name,
		string(before), string(after), audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, &merged)
}

// DeleteType DELETE /api/v1/api-security/sensitive-types/{id}
// 内置类型禁删（is_builtin，由迁移种子授予；与网关词表对齐的基线不可移除）。
func (h *Handler) DeleteType(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的类型ID")
		return
	}
	cur, err := h.store.GetType(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "敏感数据类型不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if cur.IsBuiltin {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "内置敏感数据类型不可删除")
		return
	}
	if err := h.store.DeleteType(r.Context(), id); err != nil {
		response.InternalError(w, r, err)
		return
	}
	before, _ := json.Marshal(cur)
	h.recordAudit(r, p, "delete", "api_sensitive_data_type", id.String(), cur.Name, string(before), "",
		audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "敏感数据类型已删除"})
}

// ExportTypes GET /api/v1/api-security/sensitive-types/export
// 导出全量类型（内置 + 自定义）为 JSON 文档（与导入格式对称，可回灌）。
func (h *Handler) ExportTypes(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListAllTypes(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"format":      "jiuzhang-api-sensitive-data-types",
		"version":     1,
		"exported_at": time.Now().UTC(),
		"types":       list,
	})
}

// importTypesRequest 导入请求（与导出格式对称；仅 types 字段被读取，
// 条目的 id/version/is_builtin/时间戳一律忽略，由服务端重新授予）。
type importTypesRequest struct {
	Types []typeRequest `json:"types"`
}

// ImportTypes POST /api/v1/api-security/sensitive-types/import
// 按 name upsert：存在更新（version+1，内置身份保持），不存在创建；
// 全量校验通过后单事务应用（任一条非法整体 400，不产生部分写入）。
func (h *Handler) ImportTypes(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req importTypesRequest
	if err := response.DecodeJSON(w, r, &req, typeImportMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误（期望 {\"types\": [...]}）")
		return
	}
	if len(req.Types) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "types 不能为空")
		return
	}
	if len(req.Types) > importMaxItems {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("单次导入不能超过 %d 条", importMaxItems))
		return
	}
	items := make([]SensitiveDataType, 0, len(req.Types))
	seen := map[string]bool{}
	for i := range req.Types {
		item := &req.Types[i]
		item.normalize()
		t := item.toType()
		if err := validateType(t); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("第 %d 条（name=%q）：%v", i+1, t.Name, err))
			return
		}
		if seen[t.Name] {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("第 %d 条名称重复：%s", i+1, t.Name))
			return
		}
		seen[t.Name] = true
		items = append(items, *t)
	}
	created, updated, err := h.store.ImportTypes(r.Context(), items)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "import", "api_sensitive_data_type", "", "批量导入", "",
		fmt.Sprintf("created=%d updated=%d", created, updated), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"created": created, "updated": updated})
}

// ---------- 脱敏规则 ----------

// ruleRequest 脱敏规则创建/编辑请求（编辑场景指针字段 = 仅更新提供的字段；
// 可空字段显式传空串表示清除为 NULL）。
type ruleRequest struct {
	Name          *string         `json:"name"`
	Enabled       *bool           `json:"enabled"`
	Scope         *string         `json:"scope"`
	ApplicationID *string         `json:"application_id"`
	EndpointKey   *string         `json:"endpoint_key"`
	FieldPath     *string         `json:"field_path"`
	DataType      *string         `json:"data_type"`
	Algorithm     *string         `json:"algorithm"`
	Params        json.RawMessage `json:"params_json"`
	Exclusions    json.RawMessage `json:"exclusions_json"`
}

// parseOptionalUUID 可空 UUID 字段：nil 不提供 / 空串清除 / 其余解析（非法返回错误）。
func parseOptionalUUID(raw *string) (*uuid.UUID, error) {
	if raw == nil {
		return nil, nil
	}
	v := strings.TrimSpace(*raw)
	if v == "" {
		return nil, nil
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return nil, fmt.Errorf("无效的 application_id")
	}
	return &id, nil
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

// ListMaskingRules GET /api/v1/api-security/masking-rules
// 过滤 scope/application_id/endpoint_key/enabled + 分页。
func (h *Handler) ListMaskingRules(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scope := strings.ToUpper(strings.TrimSpace(q.Get("scope")))
	if scope != "" && !validScope(scope) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 scope 取值（GLOBAL/APPLICATION/ENDPOINT）")
		return
	}
	var appID *uuid.UUID
	if raw := strings.TrimSpace(q.Get("application_id")); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 application_id")
			return
		}
		appID = &id
	}
	var enabled *bool
	if raw := strings.TrimSpace(q.Get("enabled")); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 enabled 取值（true/false）")
			return
		}
		enabled = &v
	}
	page := queryInt(r, "page", 1)
	pageSize := queryPageSize(r, 20)
	list, total, err := h.store.ListMaskingRules(r.Context(), RuleFilter{
		Scope:         scope,
		ApplicationID: appID,
		EndpointKey:   strings.TrimSpace(q.Get("endpoint_key")),
		Enabled:       enabled,
		Page:          page,
		PageSize:      pageSize,
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// GetMaskingRule GET /api/v1/api-security/masking-rules/{id}
func (h *Handler) GetMaskingRule(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return
	}
	rule, err := h.store.GetMaskingRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "脱敏规则不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, rule)
}

// buildRule 从创建请求构造实体（默认值：enabled=true、scope=GLOBAL、algorithm=MASK、
// params/exclusions 空对象归一）。
func (req *ruleRequest) buildRule(createdBy *string) (*MaskingRule, error) {
	rule := &MaskingRule{Enabled: true, Scope: ScopeGlobal, Algorithm: AlgorithmMask}
	if req.Name != nil {
		rule.Name = strings.TrimSpace(*req.Name)
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.Scope != nil {
		rule.Scope = strings.ToUpper(strings.TrimSpace(*req.Scope))
	}
	if req.Algorithm != nil {
		rule.Algorithm = strings.ToUpper(strings.TrimSpace(*req.Algorithm))
	}
	appID, err := parseOptionalUUID(req.ApplicationID)
	if err != nil {
		return nil, err
	}
	rule.ApplicationID = appID
	rule.EndpointKey = optionalString(req.EndpointKey)
	if req.FieldPath != nil {
		rule.FieldPath = strings.TrimSpace(*req.FieldPath)
	}
	rule.DataType = optionalString(req.DataType)
	params, err := validateJSONObject("params_json", req.Params)
	if err != nil {
		return nil, err
	}
	rule.Params = params
	exclusions, err := validateJSONObject("exclusions_json", req.Exclusions)
	if err != nil {
		return nil, err
	}
	rule.Exclusions = exclusions
	rule.CreatedBy = createdBy
	if err := validateMaskingRule(rule); err != nil {
		return nil, err
	}
	return rule, nil
}

// mergeRule 把编辑请求合并到现有实体（仅覆盖提供的字段；可空字段空串清除）。
func (req *ruleRequest) mergeRule(cur *MaskingRule) (*MaskingRule, error) {
	merged := *cur
	if req.Name != nil {
		merged.Name = strings.TrimSpace(*req.Name)
	}
	if req.Enabled != nil {
		merged.Enabled = *req.Enabled
	}
	if req.Scope != nil {
		merged.Scope = strings.ToUpper(strings.TrimSpace(*req.Scope))
	}
	if req.Algorithm != nil {
		merged.Algorithm = strings.ToUpper(strings.TrimSpace(*req.Algorithm))
	}
	if req.ApplicationID != nil {
		appID, err := parseOptionalUUID(req.ApplicationID)
		if err != nil {
			return nil, err
		}
		merged.ApplicationID = appID
	}
	if req.EndpointKey != nil {
		merged.EndpointKey = optionalString(req.EndpointKey)
	}
	if req.FieldPath != nil {
		merged.FieldPath = strings.TrimSpace(*req.FieldPath)
	}
	if req.DataType != nil {
		merged.DataType = optionalString(req.DataType)
	}
	if req.Params != nil {
		params, err := validateJSONObject("params_json", req.Params)
		if err != nil {
			return nil, err
		}
		merged.Params = params
	}
	if req.Exclusions != nil {
		exclusions, err := validateJSONObject("exclusions_json", req.Exclusions)
		if err != nil {
			return nil, err
		}
		merged.Exclusions = exclusions
	}
	if err := validateMaskingRule(&merged); err != nil {
		return nil, err
	}
	return &merged, nil
}

// CreateMaskingRule POST /api/v1/api-security/masking-rules
func (h *Handler) CreateMaskingRule(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req ruleRequest
	if err := response.DecodeJSON(w, r, &req, ruleBodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	var createdBy *string
	if p != nil {
		createdBy = &p.Username
	}
	rule, err := req.buildRule(createdBy)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.store.CreateMaskingRule(r.Context(), rule); err != nil {
		response.InternalError(w, r, err)
		return
	}
	after, _ := json.Marshal(rule)
	h.recordAudit(r, p, "create", "api_masking_rule", rule.ID.String(), rule.Name, "", string(after),
		audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, rule)
}

// UpdateMaskingRule PATCH /api/v1/api-security/masking-rules/{id}
// 部分更新；修改 scope 时需同时把不再适用的可空字段显式置空串
// （如 GLOBAL←APPLICATION 须带 application_id:""），否则按合并后状态校验失败返回 400。
func (h *Handler) UpdateMaskingRule(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return
	}
	var req ruleRequest
	if err := response.DecodeJSON(w, r, &req, ruleBodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	cur, err := h.store.GetMaskingRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "脱敏规则不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	merged, err := req.mergeRule(cur)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.store.UpdateMaskingRule(r.Context(), merged); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "脱敏规则不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	before, _ := json.Marshal(cur)
	after, _ := json.Marshal(merged)
	h.recordAudit(r, p, "update", "api_masking_rule", id.String(), merged.Name,
		string(before), string(after), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, merged)
}

// DeleteMaskingRule DELETE /api/v1/api-security/masking-rules/{id}
func (h *Handler) DeleteMaskingRule(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则ID")
		return
	}
	cur, err := h.store.GetMaskingRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "脱敏规则不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.DeleteMaskingRule(r.Context(), id); err != nil {
		response.InternalError(w, r, err)
		return
	}
	before, _ := json.Marshal(cur)
	h.recordAudit(r, p, "delete", "api_masking_rule", id.String(), cur.Name, string(before), "",
		audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "脱敏规则已删除"})
}

// ---------- 敏感数据态势 ----------

// SensitiveOverview GET /api/v1/api-security/sensitive/overview?days=7
// 涉敏 API 数、类型分布、近 N 天趋势（api_sensitive_fields + api_runtime_events 聚合）。
func (h *Handler) SensitiveOverview(w http.ResponseWriter, r *http.Request) {
	overview, err := h.store.SensitiveOverview(r.Context(), queryInt(r, "days", OverviewDefaultDays))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, overview)
}

// ---------- 通用 ----------

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
		Module:        "api_data",
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

// queryPageSize 分页大小（夹取 ≤100，非法回退默认值；与兄弟包上限口径一致）。
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
