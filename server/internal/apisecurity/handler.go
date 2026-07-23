// handler.go 任务书 51.4 分类图谱 / 51.5 规范导入 / 51.6 风险运行时 HTTP 处理器。
package apisecurity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// specImportMaxBytes 规范导入请求体上限（OpenAPI 文档可能较大）。
const specImportMaxBytes = 16 << 20 // 16 MiB

// Handler API 安全处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, audit *audits.Service) *Handler {
	return &Handler{store: store, audits: audit}
}

// ---------- 51.4 用途分类 ----------

// ListClassifications GET /api/v1/api-security/classifications
// 内置分类（api_classifications）+ 自定义分类法（api_custom_taxonomies）合并返回。
func (h *Handler) ListClassifications(w http.ResponseWriter, r *http.Request) {
	list, err := h.store.ListClassifications(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, list)
}

type createTaxonomyRequest struct {
	Dimension   string `json:"dimension"`
	Value       string `json:"value"`
	Description string `json:"description"`
}

// CreateClassification POST /api/v1/api-security/classifications
// 新增自定义分类法条目（api_custom_taxonomies），写操作审计。
func (h *Handler) CreateClassification(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req createTaxonomyRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.Dimension = strings.TrimSpace(req.Dimension)
	req.Value = strings.TrimSpace(req.Value)
	if req.Dimension == "" || len(req.Dimension) > 64 || req.Value == "" || len(req.Value) > 128 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "dimension（1-64字符）与 value（1-128字符）必填")
		return
	}
	// 同 (dimension, value) 已存在则冲突
	exists, err := h.store.ExistsCustomTaxonomy(r.Context(), req.Dimension, req.Value)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if exists {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "该维度下分类值已存在")
		return
	}
	item := &CustomTaxonomyItem{
		Dimension:   req.Dimension,
		Value:       req.Value,
		Description: strings.TrimSpace(req.Description),
		CreatedBy:   &p.UserID,
	}
	if err := h.store.CreateCustomTaxonomy(r.Context(), item); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "api_custom_taxonomy", item.ID.String(),
		fmt.Sprintf("%s=%s", item.Dimension, item.Value), "",
		fmt.Sprintf("dimension=%s value=%s", item.Dimension, item.Value),
		audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, item)
}

type endpointDimensionInput struct {
	Dimension string `json:"dimension"`
	Value     string `json:"value"`
}

type putClassificationRequest struct {
	Dimensions []endpointDimensionInput `json:"dimensions"`
}

// PutEndpointClassification PUT /api/v1/api-security/endpoints/{id}/classification
// 手动覆盖端点分类维度（source=MANUAL）并锁定 classification_locked，写操作审计。
func (h *Handler) PutEndpointClassification(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	endpointID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的端点ID")
		return
	}
	var req putClassificationRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if len(req.Dimensions) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "dimensions 不能为空")
		return
	}
	dims := make([]ClassificationDimension, 0, len(req.Dimensions))
	seen := map[string]bool{}
	for _, d := range req.Dimensions {
		dim := strings.TrimSpace(d.Dimension)
		val := strings.TrimSpace(d.Value)
		if dim == "" || len(dim) > 64 || val == "" || len(val) > 128 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "dimension（1-64字符）与 value（1-128字符）必填")
			return
		}
		if seen[dim] {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "dimension 重复："+dim)
			return
		}
		seen[dim] = true
		dims = append(dims, ClassificationDimension{Dimension: dim, Value: val})
	}
	exists, err := h.store.EndpointExists(r.Context(), endpointID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if !exists {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	// 审计前摘要：覆盖前的维度
	beforeDims, err := h.store.GetEndpointDimensions(r.Context(), endpointID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.SetEndpointClassification(r.Context(), endpointID, dims); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	afterDims, err := h.store.GetEndpointDimensions(r.Context(), endpointID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	beforeJSON, _ := json.Marshal(beforeDims)
	afterJSON, _ := json.Marshal(afterDims)
	h.recordAudit(r, p, "update", "api_endpoint_classification", endpointID.String(),
		endpointID.String(), string(beforeJSON), string(afterJSON),
		audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"endpoint_id":           endpointID,
		"classification_locked": true,
		"dimensions":            afterDims,
	})
}

// ---------- 51.4 调用图谱 / 拓扑 ----------

// Graph GET /api/v1/api-security/graph
func (h *Handler) Graph(w http.ResponseWriter, r *http.Request) {
	g, err := h.store.ListGraph(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, g)
}

// Topology GET /api/v1/api-security/topology
func (h *Handler) Topology(w http.ResponseWriter, r *http.Request) {
	t, err := h.store.ListTopology(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, t)
}

// ---------- 51.5 规范导入 ----------

// ImportSpec POST /api/v1/api-security/specs/import
// body 为 OpenAPI 3 JSON 文档或 {"spec": {...}, "file_name": "..."}；
// 仅支持 JSON（YAML 返回 400），导入后与运行时端点对比生成 api_spec_diffs。
func (h *Handler) ImportSpec(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, specImportMaxBytes))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体过大或读取失败（上限16MiB）")
		return
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		// YAML 等非 JSON 输入在此明确拒绝
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅支持 JSON 格式的 OpenAPI 3 文档（暂不支持 YAML）")
		return
	}
	// 兼容 {spec: {...}, file_name: "..."} 包装形式
	fileName := ""
	specDoc := doc
	if _, hasOpenAPI := doc["openapi"]; !hasOpenAPI {
		if raw, ok := doc["spec"]; ok {
			inner, ok := raw.(map[string]any)
			if !ok {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "spec 字段必须为 JSON 对象")
				return
			}
			specDoc = inner
			if fn, ok := doc["file_name"].(string); ok {
				fileName = strings.TrimSpace(fn)
			}
		}
	}
	// 规范化字节（map 序列化键序确定），用于内容哈希与落库
	canonical, err := json.Marshal(specDoc)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "规范文档序列化失败")
		return
	}
	endpoints, err := ParseOpenAPI3(specDoc)
	if err != nil {
		switch {
		case errors.Is(err, ErrSpecNotOpenAPI3):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅支持 OpenAPI 3.x 文档（缺少 openapi: 3.x 版本声明）")
		case errors.Is(err, ErrSpecNoPaths):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "规范文档缺少有效的 paths 定义")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	runtimeKeys, err := h.store.ListEndpointKeys(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	specKeys := make([]string, 0, len(endpoints))
	byKey := make(map[string]SpecEndpoint, len(endpoints))
	for _, ep := range endpoints {
		specKeys = append(specKeys, ep.Key)
		byKey[ep.Key] = ep
	}
	missingInRuntime, missingInSpec := DiffEndpointKeys(specKeys, runtimeKeys)

	spec := &ImportSpec{
		Format:        "openapi3",
		FileName:      fileName,
		ContentHash:   HashSpecContent(canonical),
		SpecJSON:      canonical,
		EndpointCount: len(endpoints),
		ImportedBy:    &p.UserID,
	}
	diffs := make([]SpecDiff, 0, len(missingInRuntime)+len(missingInSpec))
	for _, key := range missingInRuntime {
		ep := byKey[key]
		detail, _ := json.Marshal(map[string]string{"method": ep.Method, "path": ep.Path})
		diffs = append(diffs, SpecDiff{DiffType: DiffMissingInRuntime, EndpointKey: key, Detail: detail})
	}
	for _, key := range missingInSpec {
		detail, _ := json.Marshal(map[string]string{"endpoint_key": key})
		diffs = append(diffs, SpecDiff{DiffType: DiffMissingInSpec, EndpointKey: key, Detail: detail})
	}
	if err := h.store.ImportSpecWithDiffs(r.Context(), spec, diffs); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "import", "api_import_spec", spec.ID.String(),
		spec.FileName, "",
		fmt.Sprintf("format=%s endpoints=%d missing_in_runtime=%d missing_in_spec=%d",
			spec.Format, spec.EndpointCount, len(missingInRuntime), len(missingInSpec)),
		audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"spec":               spec,
		"missing_in_runtime": len(missingInRuntime),
		"missing_in_spec":    len(missingInSpec),
	})
}

// ListSpecs GET /api/v1/api-security/specs
func (h *Handler) ListSpecs(w http.ResponseWriter, r *http.Request) {
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListSpecs(r.Context(), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// GetSpecDiff GET /api/v1/api-security/specs/{id}/diff
func (h *Handler) GetSpecDiff(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规范ID")
		return
	}
	spec, err := h.store.GetSpec(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规范不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	diffs, err := h.store.ListSpecDiffs(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"spec":  spec,
		"diffs": diffs,
	})
}

// ---------- 51.6 风险与运行时 ----------

// ListFindings GET /api/v1/api-security/findings
func (h *Handler) ListFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListFindings(r.Context(),
		strings.TrimSpace(q.Get("finding_type")),
		strings.ToUpper(strings.TrimSpace(q.Get("severity"))),
		strings.ToUpper(strings.TrimSpace(q.Get("status"))),
		page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// ListViolations GET /api/v1/api-security/violations
func (h *Handler) ListViolations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	endpointID := strings.TrimSpace(q.Get("endpoint_id"))
	if endpointID != "" {
		if _, err := uuid.Parse(endpointID); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的端点ID")
			return
		}
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListViolations(r.Context(), endpointID,
		strings.TrimSpace(q.Get("violation_type")), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// Posture GET /api/v1/api-security/posture
func (h *Handler) Posture(w http.ResponseWriter, r *http.Request) {
	posture, err := h.store.GetPosture(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, posture)
}

// RuntimeStatistics GET /api/v1/api-security/runtime/statistics
func (h *Handler) RuntimeStatistics(w http.ResponseWriter, r *http.Request) {
	st, err := h.store.GetRuntimeStatistics(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, st)
}

// ListRuntimeEvents GET /api/v1/api-security/runtime/events
func (h *Handler) ListRuntimeEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListRuntimeEvents(r.Context(),
		strings.TrimSpace(q.Get("endpoint_key")),
		strings.ToUpper(strings.TrimSpace(q.Get("final_action"))),
		page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// ---------- 通用 ----------

// recordAudit 写操作审计（构造注入 audits.Service；含操作者、动作、对象、前后摘要、风险等级）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName, before, after, result, risk string) {
	_ = h.audits.Record(r.Context(), audits.RecordInput{
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
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
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
