// handler.go 任务书 51.4 分类图谱 / 51.5 规范导入 / 51.6 风险运行时 HTTP 处理器。
package apisecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apigeo"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// specImportMaxBytes 规范导入请求体上限（OpenAPI 文档可能较大）。
const specImportMaxBytes = 16 << 20 // 16 MiB

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// GraphRepository API 调用图谱只读仓储（*Store 自动实现；测试可注入内存实现）。
type GraphRepository interface {
	ListGraphWithFilter(ctx context.Context, f GraphFilter) (*Graph, error)
}

// ServiceRPCGraphReader 后端微服务真实 RPC/服务间调用图谱读接口。
type ServiceRPCGraphReader interface {
	ServiceRPCGraph(ctx context.Context, f ServiceRPCGraphFilter) (*ServiceRPCGraph, error)
}

// Handler API 安全处理器。
type Handler struct {
	store  *Store
	audits auditRecorder
	// 身份轨迹图谱只读仓储（*Store 自动实现；测试可 SetGraphRepository 覆盖）
	graphRepo GraphRepository
	// 后端微服务真实 RPC / 服务间调用图谱只读实现（由 app 层装配 ClickHouse + PG）
	serviceRPCGraph ServiceRPCGraphReader
	// 风险中心仓储（*Store 自动实现；NewHandler 传入非 nil store 时自动接线，
	// 测试可 SetRiskRepository 覆盖为 RiskMemStore；见 risk.go）
	risk RiskRepository
	// 准入防护仓储（*Store 自动实现，接线时机同 risk；测试可 SetAdmissionRepository
	// 覆盖为内存假实现；见 admission.go）
	admission AdmissionRepository
	// 群控观察只读仓储（*Store 自动实现；测试可覆盖为内存实现）
	groupControl GroupControlRepository
	// 策略接口依赖（Setter 注入，保持 app.go 接线简单；见 policy.go）
	policySource   PolicySource
	policySettings PolicySettings
	publishFn      PolicyPublishFunc
	// GeoIP 国家码查询能力（*apigeo.MMDB；Setter 注入。nil = GeoIP 未启用，
	// 态势访问来源 Geo 维度如实返回 geo_enabled=false，与数据出境看板同一降级语义）
	geoLookup apigeo.CountryLookup
	// URL 导入抓取函数（默认带 SSRF 防护的 fetchSpecDocument；单测可注入替换）
	specFetchFn func(ctx context.Context, rawURL string, headers map[string]string) ([]byte, error)
}

// NewHandler 创建处理器。
func NewHandler(store *Store, audit *audits.Service) *Handler {
	h := &Handler{store: store, specFetchFn: fetchSpecDocument}
	if audit != nil {
		h.audits = audit
	}
	if store != nil {
		h.graphRepo = store
		h.risk = store
		h.admission = store
		h.groupControl = store
		h.serviceRPCGraph = NewServiceRPCGraphReader(store.db, nil)
	}
	return h
}

// SetGraphRepository 覆盖图谱只读仓储（测试注入内存实现；生产无需调用）。
func (h *Handler) SetGraphRepository(r GraphRepository) { h.graphRepo = r }

// SetServiceRPCGraphReader 注入后端微服务真实 RPC / 服务间调用图谱读实现（生产由 app 层注入 ClickHouse + PG）。
func (h *Handler) SetServiceRPCGraphReader(r ServiceRPCGraphReader) { h.serviceRPCGraph = r }

// SetRiskRepository 覆盖风险中心仓储（测试注入内存实现；生产无需调用）。
func (h *Handler) SetRiskRepository(r RiskRepository) { h.risk = r }

// SetSpecFetcher 覆盖 URL 导入抓取函数（测试注入以放开 SSRF 防护指向 httptest；生产无需调用）。
func (h *Handler) SetSpecFetcher(fn func(ctx context.Context, rawURL string, headers map[string]string) ([]byte, error)) {
	h.specFetchFn = fn
}

// SetGeoLookup 注入 GeoIP 国家码查询能力（生产由 app 层在加载 country.mmdb 成功后装配；
// 未装配时 /posture/sources 的 Geo 维度降级为 geo_enabled=false，其余维度不受影响）。
func (h *Handler) SetGeoLookup(lookup apigeo.CountryLookup) { h.geoLookup = lookup }

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
// 手动覆盖接口分类维度（source=MANUAL）并锁定 classification_locked，写操作审计。
func (h *Handler) PutEndpointClassification(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	endpointID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的接口ID")
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
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
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
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
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

// parseEdgeFilter 解析图谱/拓扑边过滤参数（W6-A）：start/end（RFC3339，边活跃窗口：
// last_seen_at >= start 且 first_seen_at <= end）与 min_count（最小调用次数）。
// 非法值明确 400，不静默忽略；节点始终全量返回，过滤只作用于边。
func parseEdgeFilter(w http.ResponseWriter, r *http.Request) (EdgeFilter, bool) {
	var f EdgeFilter
	q := r.URL.Query()
	if st := strings.TrimSpace(q.Get("start")); st != "" {
		t, err := time.Parse(time.RFC3339, st)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 start（需 RFC3339 时间）")
			return f, false
		}
		f.Start = &t
	}
	if et := strings.TrimSpace(q.Get("end")); et != "" {
		t, err := time.Parse(time.RFC3339, et)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 end（需 RFC3339 时间）")
			return f, false
		}
		f.End = &t
	}
	if f.Start != nil && f.End != nil && f.Start.After(*f.End) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "start 不能晚于 end")
		return f, false
	}
	if mc := strings.TrimSpace(q.Get("min_count")); mc != "" {
		n, err := strconv.ParseInt(mc, 10, 64)
		if err != nil || n < 0 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 min_count（需非负整数）")
			return f, false
		}
		f.MinCount = n
	}
	return f, true
}

// validGraphStatuses 图谱节点资产状态白名单。
var validGraphStatuses = map[string]bool{
	"DISCOVERED": true,
	"CONFIRMED":  true,
	"IGNORED":    true,
	"DEPRECATED": true,
	"ZOMBIE":     true,
}

func parseOptionalBoolParam(w http.ResponseWriter, r *http.Request, name string) (bool, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return false, true
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, fmt.Sprintf("无效的 %s（需 true 或 false）", name))
		return false, false
	}
	return v, true
}

// parseGraphFilter 解析图谱读接口全部过滤参数（在 EdgeFilter 基础上扩展应用/状态/关键词/降噪开关）。
func parseGraphFilter(w http.ResponseWriter, r *http.Request) (GraphFilter, bool) {
	ef, ok := parseEdgeFilter(w, r)
	if !ok {
		return GraphFilter{}, false
	}
	f := GraphFilter{EdgeFilter: ef}
	q := r.URL.Query()
	if appRaw := strings.TrimSpace(q.Get("application_id")); appRaw != "" {
		id, err := uuid.Parse(appRaw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 application_id（需 UUID）")
			return f, false
		}
		f.ApplicationID = &id
	}
	if st := strings.ToUpper(strings.TrimSpace(q.Get("status"))); st != "" {
		if !validGraphStatuses[st] {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 status（须为 DISCOVERED/CONFIRMED/IGNORED/DEPRECATED/ZOMBIE 之一）")
			return f, false
		}
		f.Status = st
	}
	if kw := strings.TrimSpace(q.Get("keyword")); kw != "" {
		if len([]rune(kw)) > 128 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "keyword 长度不能超过 128 字符")
			return f, false
		}
		f.Keyword = kw
	}
	if v, ok := parseOptionalBoolParam(w, r, "exclude_static"); !ok {
		return f, false
	} else {
		f.ExcludeStatic = v
	}
	if v, ok := parseOptionalBoolParam(w, r, "exclude_ignored"); !ok {
		return f, false
	} else {
		f.ExcludeIgnored = v
	}
	if v, ok := parseOptionalBoolParam(w, r, "only_connected"); !ok {
		return f, false
	} else {
		f.OnlyConnected = v
	}
	return f, true
}

// Graph GET /api/v1/api-security/graph
func (h *Handler) Graph(w http.ResponseWriter, r *http.Request) {
	f, ok := parseGraphFilter(w, r)
	if !ok {
		return
	}
	repo := h.graphRepo
	if repo == nil {
		repo = h.store
	}
	g, err := repo.ListGraphWithFilter(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, g)
}

// Topology GET /api/v1/api-security/topology
func (h *Handler) Topology(w http.ResponseWriter, r *http.Request) {
	f, ok := parseEdgeFilter(w, r)
	if !ok {
		return
	}
	t, err := h.store.ListTopologyFiltered(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, t)
}

// ---------- 51.5 规范导入（W3-C：版本状态机 / URL 导入 / Swagger 2.0 / CHANGED diff / 端点回写） ----------

// decodeSpecImport 解析规范导入请求体：
// 直接文档（JSON / YAML / GraphQL SDL，由 ParseSpecContent 统一入口处理）或
// 兼容包装形式 {"spec": <对象或字符串>, "file_name": "...", "name": "..."}（仅 JSON 外壳）。
// 失败写出 400（原因明确）并返回 ok=false。
func decodeSpecImport(w http.ResponseWriter, r *http.Request, body []byte) (format string, doc map[string]any, ops []SpecOperation, fileName, reqName string, ok bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		if jsonDepthExceeded(trimmed) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "规范文档嵌套深度超出安全限制")
			return "", nil, nil, "", "", false
		}
		var wrap map[string]any
		if err := json.Unmarshal(trimmed, &wrap); err == nil && wrap != nil && detectExtendedSpecFormat(wrap) == "" {
			if raw, has := wrap["spec"]; has {
				if fn, isStr := wrap["file_name"].(string); isStr {
					fileName = strings.TrimSpace(fn)
				}
				if n, isStr := wrap["name"].(string); isStr {
					reqName = strings.TrimSpace(n)
				}
				var err error
				switch inner := raw.(type) {
				case map[string]any:
					format, doc, ops, err = parseSpecJSONDoc(inner)
				case string:
					format, doc, ops, err = ParseSpecContent([]byte(inner))
				default:
					response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "spec 字段必须为 JSON 对象或字符串")
					return "", nil, nil, "", "", false
				}
				if err != nil {
					writeSpecParseError(w, r, err)
					return "", nil, nil, "", "", false
				}
				return format, doc, ops, fileName, reqName, true
			}
		}
	}
	format, doc, ops, err := ParseSpecContent(body)
	if err != nil {
		writeSpecParseError(w, r, err)
		return "", nil, nil, "", "", false
	}
	return format, doc, ops, "", "", true
}

// writeSpecParseError 规范解析错误统一映射为 400（原因明确）；非解析类错误走 500。
func writeSpecParseError(w http.ResponseWriter, r *http.Request, err error) {
	detail := func(sentinel error) string {
		return strings.TrimPrefix(err.Error(), sentinel.Error()+": ")
	}
	switch {
	case errors.Is(err, ErrSpecTooLarge):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "规范文档超过大小上限（16MiB）")
	case errors.Is(err, ErrSpecTooComplex):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "规范文档结构超出安全限制（嵌套深度/节点数）："+detail(ErrSpecTooComplex))
	case errors.Is(err, ErrSpecInvalidJSON):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "JSON 解析失败："+detail(ErrSpecInvalidJSON))
	case errors.Is(err, ErrSpecInvalidYAML):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "YAML 解析失败（不允许自定义标签/别名循环/多文档）："+detail(ErrSpecInvalidYAML))
	case errors.Is(err, ErrSpecExternalRef):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "不允许外部 $ref 引用（仅支持 #/ 文档内引用或 ZIP 包内相对引用）："+detail(ErrSpecExternalRef))
	case errors.Is(err, ErrSpecUnsupportedPostmanVersion):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅支持 Postman Collection v2.1："+detail(ErrSpecUnsupportedPostmanVersion))
	case errors.Is(err, ErrSpecUnsupportedJSONSchemaDraft):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅支持 JSON Schema draft-07 与 2020-12："+detail(ErrSpecUnsupportedJSONSchemaDraft))
	case errors.Is(err, ErrSpecInvalidJSONSchema):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "JSON Schema 无效："+detail(ErrSpecInvalidJSONSchema))
	case errors.Is(err, ErrSpecInvalidGraphQL):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "GraphQL SDL 解析失败："+detail(ErrSpecInvalidGraphQL))
	case errors.Is(err, ErrSpecInvalidProtobuf):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "Protobuf (.proto) 解析失败："+detail(ErrSpecInvalidProtobuf))
	case errors.Is(err, ErrSpecInvalidXML):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "WSDL / XSD XML 解析失败："+detail(ErrSpecInvalidXML))
	case errors.Is(err, ErrSpecInvalidRAML):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "RAML 解析失败："+detail(ErrSpecInvalidRAML))
	case errors.Is(err, ErrSpecInvalidAPIB):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "API Blueprint 解析失败："+detail(ErrSpecInvalidAPIB))
	case errors.Is(err, ErrSpecInvalidHAR):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "HAR 归档解析失败："+detail(ErrSpecInvalidHAR))
	case errors.Is(err, ErrSpecInvalidAsyncAPI):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "AsyncAPI 解析失败："+detail(ErrSpecInvalidAsyncAPI))
	case errors.Is(err, ErrSpecInvalidZip):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ZIP 规范归档解析失败："+detail(ErrSpecInvalidZip))
	case errors.Is(err, ErrSpecNotOpenAPI3):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "OpenAPI 文档缺少 openapi: 3.x 版本声明")
	case errors.Is(err, ErrSpecNoPaths):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "规范文档缺少有效的 paths/请求项定义")
	case errors.Is(err, ErrSpecUnsupportedFormat):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"不支持的规范格式；支持 OpenAPI 3.x / Swagger 2.0 / AsyncAPI 2.x-3.x / Postman v2.1 / JSON Schema / GraphQL SDL / Protobuf (.proto) / WSDL / XSD / RAML / API Blueprint / HAR / ZIP 规范包")
	default:
		response.InternalError(w, r, err)
	}
}

// sanitizeUploadFileName 清洗上传文件名（去路径前缀与控制字符，截断至 255 字符，仅作展示元数据）。
func sanitizeUploadFileName(raw string) string {
	s := strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if s == "" {
		return ""
	}
	base := path.Base(s)
	if base == "." || base == "/" || base == ".." {
		return ""
	}
	cleaned := strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, base)
	return truncateSpecName(cleaned)
}

// decodeSpecMultipart 流式解析 multipart/form-data 规范文件上传（零临时文件落盘）：
// 表单字段 file（规范文件，上限 16MiB）、可选 file_name（覆盖上传文件名）、可选 name（覆盖规范名）。
func decodeSpecMultipart(w http.ResponseWriter, r *http.Request) (format string, doc map[string]any, ops []SpecOperation, fileName, reqName string, ok bool) {
	// 放宽 1MiB 给 multipart 边界和文本字段头，文件内容本身仍严格限制 specImportMaxBytes（16MiB）
	r.Body = http.MaxBytesReader(w, r.Body, specImportMaxBytes+(1<<20))
	mr, err := r.MultipartReader()
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "multipart 表单格式错误")
		return "", nil, nil, "", "", false
	}

	const (
		maxParts     = 16
		maxFieldSize = 4096
	)
	var fileBytes []byte
	var uploadedName string
	var explicitFileName string
	hasFile := false

	for parts := 0; parts < maxParts; parts++ {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体过大或表单读取失败（单文件上限 16MiB）")
			return "", nil, nil, "", "", false
		}
		field := part.FormName()
		switch field {
		case "file":
			if hasFile {
				_ = part.Close()
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅允许上传单个规范文件")
				return "", nil, nil, "", "", false
			}
			hasFile = true
			uploadedName = sanitizeUploadFileName(part.FileName())
			data, readErr := io.ReadAll(io.LimitReader(part, specImportMaxBytes+1))
			_ = part.Close()
			if readErr != nil {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "规范文件读取失败")
				return "", nil, nil, "", "", false
			}
			if len(data) > specImportMaxBytes {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "规范文档超过大小上限（16MiB）")
				return "", nil, nil, "", "", false
			}
			fileBytes = data
		case "file_name":
			b, _ := io.ReadAll(io.LimitReader(part, maxFieldSize))
			_ = part.Close()
			explicitFileName = sanitizeUploadFileName(string(b))
		case "name":
			b, _ := io.ReadAll(io.LimitReader(part, maxFieldSize))
			_ = part.Close()
			reqName = truncateSpecName(string(b))
		default:
			_, _ = io.Copy(io.Discard, io.LimitReader(part, maxFieldSize))
			_ = part.Close()
		}
	}

	if !hasFile || len(fileBytes) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请上传非空规范文件（表单字段 file）")
		return "", nil, nil, "", "", false
	}
	fileName = uploadedName
	if explicitFileName != "" {
		fileName = explicitFileName
	}

	format, doc, ops, err = ParseSpecContent(fileBytes)
	if err != nil {
		writeSpecParseError(w, r, err)
		return "", nil, nil, "", "", false
	}
	return format, doc, ops, fileName, reqName, true
}

// ImportSpec POST /api/v1/api-security/specs/import
// 支持三种提交形态：
//  1. multipart/form-data（字段 file + 可选 file_name / name），适用于各类规范文件及 .zip 归档直传；
//  2. JSON 包装 {"spec": <对象或原始文本>, "file_name": "...", "name": "..."}；
//  3. 原始规范文档正文（OpenAPI 3.x / Swagger 2.0 / AsyncAPI / Postman v2.1 / JSON Schema /
//     GraphQL SDL / Protobuf / WSDL / XSD / RAML / API Blueprint / HAR / ZIP）。
//
// 同名再导入 version_no 自增、旧版降 HISTORICAL，与运行时接口对比生成 MISSING_* 差异，
// 同名跨版本生成 CHANGED 差异，规范端点幂等登记为 api_endpoints 候选。
func (h *Handler) ImportSpec(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType == "multipart/form-data" {
		format, specDoc, ops, fileName, reqName, ok := decodeSpecMultipart(w, r)
		if !ok {
			return
		}
		h.importSpecCore(w, r, p, format, specDoc, ops, fileName, reqName, SpecSourceUpload)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, specImportMaxBytes))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体过大或读取失败（上限16MiB）")
		return
	}
	format, specDoc, ops, fileName, reqName, ok := decodeSpecImport(w, r, body)
	if !ok {
		return
	}
	h.importSpecCore(w, r, p, format, specDoc, ops, fileName, reqName, SpecSourceUpload)
}

// ImportSpecURL POST /api/v1/api-security/specs/import-url
// {"url": "...", "name": "...", "headers": {"Authorization": "..."}}：
// 从 URL 拉取规范文档导入（SSRF 防护：仅 http/https、拒绝内网/保留地址、
// 大小上限 16MiB、超时 10s、重定向再校验），导入语义与粘贴导入一致。
func (h *Handler) ImportSpecURL(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req struct {
		URL     string            `json:"url"`
		Name    string            `json:"name"`
		Headers map[string]string `json:"headers"`
	}
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" || len(req.URL) > 2048 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "url 必填且不超过 2048 字符")
		return
	}
	if len(req.Headers) > 20 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "headers 最多 20 个")
		return
	}
	for k, v := range req.Headers {
		if strings.TrimSpace(k) == "" || len(k) > 128 || len(v) > 2048 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "header 名（1-128字符）与值（≤2048字符）非法")
			return
		}
	}
	body, err := h.specFetchFn(r.Context(), req.URL, req.Headers)
	if err != nil {
		if errors.Is(err, ErrSpecFetchDenied) {
			// 用户可见消息不出现英文 sentinel，仅保留中文原因（空地址/内网保留地址等）
			detail := strings.TrimPrefix(err.Error(), ErrSpecFetchDenied.Error()+": ")
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "URL 不被允许："+detail)
			return
		}
		slog.Warn("拉取规范文档失败", "request_id", response.RequestIDFrom(r), "url", req.URL, "error", err)
		response.Error(w, r, http.StatusBadGateway, response.CodeServiceUnavailable, "拉取规范文档失败，请确认目标地址可访问且返回内容正常")
		return
	}
	format, doc, ops, ok := parseSpecContentResponse(w, r, body)
	if !ok {
		return
	}
	// 文件名取 URL 路径末段（解析失败则留空，由 name/info.title 兜底）
	fileName := ""
	if u, err := url.Parse(req.URL); err == nil {
		fileName = path.Base(u.Path)
		if fileName == "/" || fileName == "." {
			fileName = ""
		}
	}
	h.importSpecCore(w, r, p, format, doc, ops, fileName, strings.TrimSpace(req.Name), SpecSourceURL)
}

// parseSpecContentResponse 调用统一解析入口并把解析错误写成 400 响应。
func parseSpecContentResponse(w http.ResponseWriter, r *http.Request, body []byte) (string, map[string]any, []SpecOperation, bool) {
	format, doc, ops, err := ParseSpecContent(body)
	if err != nil {
		writeSpecParseError(w, r, err)
		return "", nil, nil, false
	}
	return format, doc, ops, true
}

// importSpecCore 粘贴/URL 导入共享流水线：解析产物（格式 + 规范化文档 + 操作清单）→
// 运行时键集对比 + 同名跨版本 CHANGED 对比 → 版本化落库 → 规范端点登记 → 审计。
func (h *Handler) importSpecCore(w http.ResponseWriter, r *http.Request, p *authz.Principal, format string, normalized map[string]any, ops []SpecOperation, fileName, reqName, defaultSource string) {
	// 来源识别（P2-07 源码发现接入）：文档自带标记优先（SOURCE_CODE），否则按入口记缺省来源；
	// 落库前剥离 x-apisrc 采集元数据（含本机扫描路径，不宜入库）
	source := DetectSpecSource(normalized)
	if source == "" {
		source = defaultSource
	}
	normalized = SourceCodeSpecForImport(normalized)
	// 规范化字节（map 序列化键序确定），用于内容哈希与落库
	canonical, err := json.Marshal(normalized)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "规范文档序列化失败")
		return
	}
	contentHash := HashSpecContent(canonical)
	name := resolveSpecName(reqName, fileName, normalized, contentHash)

	// 同名最新版本：内容未变化则拒绝（避免重复版本膨胀）；否则作为 CHANGED 对比基线
	prev, err := h.store.GetLatestSpecByName(r.Context(), name)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if prev != nil && prev.ContentHash == contentHash {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			fmt.Sprintf("同名规范（%s）最新版本 v%d 内容未变化", name, prev.VersionNo))
		return
	}

	runtimeKeys, err := h.store.ListEndpointKeys(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	specKeys := make([]string, 0, len(ops))
	byKey := make(map[string]SpecOperation, len(ops))
	for _, op := range ops {
		specKeys = append(specKeys, op.Key)
		byKey[op.Key] = op
	}
	missingInRuntime, missingInSpec := DiffEndpointKeys(specKeys, runtimeKeys)

	diffs := make([]SpecDiff, 0, len(missingInRuntime)+len(missingInSpec))
	for _, key := range missingInRuntime {
		op := byKey[key]
		detail, _ := json.Marshal(map[string]string{"method": op.Method, "path": op.Path})
		diffs = append(diffs, SpecDiff{DiffType: DiffMissingInRuntime, EndpointKey: key, Detail: detail})
	}
	for _, key := range missingInSpec {
		detail, _ := json.Marshal(map[string]string{"endpoint_key": key})
		diffs = append(diffs, SpecDiff{DiffType: DiffMissingInSpec, EndpointKey: key, Detail: detail})
	}
	// 同名跨版本 CHANGED 级对比（同 path+method 的参数/类型/required 变化）
	changed := []SpecChange{}
	if prev != nil {
		prevOps, err := parseStoredSpecOperations(prev)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		changed = DiffSpecOperations(prevOps, ops)
		for _, c := range changed {
			detail, _ := json.Marshal(c)
			diffs = append(diffs, SpecDiff{DiffType: DiffChanged, EndpointKey: c.EndpointKey, Detail: detail})
		}
	}

	spec := &ImportSpec{
		Name:          name,
		Format:        format,
		FileName:      fileName,
		ContentHash:   contentHash,
		SpecJSON:      canonical,
		EndpointCount: len(ops),
		ImportedBy:    &p.UserID,
		Source:        source,
	}
	// 仅登记运行时缺失的规范端点（MISSING_IN_RUNTIME），冲突不动已有资产
	registerOps := make([]SpecOperation, 0, len(missingInRuntime))
	for _, key := range missingInRuntime {
		registerOps = append(registerOps, byKey[key])
	}
	registered, err := h.store.ImportSpecWithDiffs(r.Context(), spec, diffs, registerOps)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "import", "api_import_spec", spec.ID.String(),
		spec.Name, "",
		fmt.Sprintf("name=%s version=%d format=%s endpoints=%d missing_in_runtime=%d missing_in_spec=%d changed=%d registered=%d",
			spec.Name, spec.VersionNo, spec.Format, spec.EndpointCount,
			len(missingInRuntime), len(missingInSpec), len(changed), registered),
		audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"spec":                 spec,
		"missing_in_runtime":   len(missingInRuntime),
		"missing_in_spec":      len(missingInSpec),
		"changed":              len(changed),
		"registered_endpoints": registered,
	})
}

// ActivateSpec POST /api/v1/api-security/specs/{id}/activate
// 激活指定规范版本：同名当前 ACTIVE 降为 HISTORICAL，目标版本置 ACTIVE，写操作审计。
func (h *Handler) ActivateSpec(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规范ID")
		return
	}
	spec, err := h.store.ActivateSpec(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规范不存在")
		case errors.Is(err, ErrSpecAlreadyActive):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "该版本已是 ACTIVE")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	h.recordAudit(r, p, "activate", "api_import_spec", spec.ID.String(),
		spec.Name, "",
		fmt.Sprintf("name=%s version=%d status=ACTIVE", spec.Name, spec.VersionNo),
		audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"spec": spec})
}

// GetSpecVersionDiff GET /api/v1/api-security/specs/{id}/version-diff?other=<uuid>
// 任意两个规范版本的 CHANGED 级对比（id 为基准旧版，other 为目标新版），只读不落库。
func (h *Handler) GetSpecVersionDiff(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规范ID")
		return
	}
	other, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("other")))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效或缺失的 other 规范ID")
		return
	}
	if id == other {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "两个版本ID相同，无需对比")
		return
	}
	base, err := h.store.GetSpecContent(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "基准规范不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	target, err := h.store.GetSpecContent(r.Context(), other)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "目标规范不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	baseOps, err := parseStoredSpecOperations(base)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	targetOps, err := parseStoredSpecOperations(target)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"base":    map[string]any{"id": base.ID, "name": base.Name, "version_no": base.VersionNo},
		"target":  map[string]any{"id": target.ID, "name": target.Name, "version_no": target.VersionNo},
		"changes": DiffSpecOperations(baseOps, targetOps),
	})
}

// ListSpecs GET /api/v1/api-security/specs（支持 name/status 过滤）
func (h *Handler) ListSpecs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := strings.TrimSpace(q.Get("name"))
	status := strings.ToUpper(strings.TrimSpace(q.Get("status")))
	if status != "" {
		switch status {
		case SpecStatusDraft, SpecStatusActive, SpecStatusHistorical, SpecStatusInvalid, SpecStatusArchived:
		default:
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 status 取值（DRAFT/ACTIVE/HISTORICAL/INVALID/ARCHIVED）")
			return
		}
	}
	page := queryInt(r, "page", 1)
	pageSize := queryPageSize(r, 20)
	list, total, err := h.store.ListSpecs(r.Context(), name, status, page, pageSize)
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
// 过滤参数 finding_type/severity/status 词表校验：非法值明确 400，不静默返回空列表。
func (h *Handler) ListFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	findingType := strings.TrimSpace(q.Get("finding_type"))
	severity := strings.ToUpper(strings.TrimSpace(q.Get("severity")))
	status := strings.ToUpper(strings.TrimSpace(q.Get("status")))
	if findingType != "" && !IsValidRiskFindingType(findingType) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"无效的 finding_type 取值（大写字母/数字/下划线，1-64字符）")
		return
	}
	if severity != "" && !IsValidRiskSeverity(severity) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"无效的 severity 取值（INFO/LOW/MEDIUM/HIGH/CRITICAL）")
		return
	}
	if status != "" && !IsValidRiskStatus(status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"无效的 status 取值（NEW/CONFIRMED/IN_PROGRESS/FALSE_POSITIVE/IGNORED/RESOLVED/ARCHIVED）")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryPageSize(r, 20)
	list, total, err := h.store.ListFindings(r.Context(), findingType, severity, status, page, pageSize)
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
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的接口ID")
			return
		}
	}
	var startTime, endTime *time.Time
	if raw := strings.TrimSpace(q.Get("start_time")); raw != "" {
		t, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 start_time 格式（须为 RFC3339 / ISO 8601）")
			return
		}
		startTime = &t
	}
	if raw := strings.TrimSpace(q.Get("end_time")); raw != "" {
		t, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 end_time 格式（须为 RFC3339 / ISO 8601）")
			return
		}
		endTime = &t
	}
	if startTime != nil && endTime != nil && startTime.After(*endTime) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "start_time 不能晚于 end_time")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryPageSize(r, 20)
	list, total, err := h.store.ListViolations(r.Context(), endpointID,
		strings.TrimSpace(q.Get("violation_type")), startTime, endTime, page, pageSize)
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

// PostureOverview GET /api/v1/api-security/posture/overview
// W9-P101：任务书 §6 顶部核心指标全项真实聚合（口径见 PostureOverview 字段注释）。
func (h *Handler) PostureOverview(w http.ResponseWriter, r *http.Request) {
	o, err := h.store.GetPostureOverview(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, o)
}

// PostureTrends GET /api/v1/api-security/posture/trends?days=N
// W9-P101：六条按天桶曲线（访问/防护/风险/新增/Schema偏离/敏感命中），days 缺省 7、限定 1-30。
func (h *Handler) PostureTrends(w http.ResponseWriter, r *http.Request) {
	days := 7
	if v := strings.TrimSpace(r.URL.Query().Get("days")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 30 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 days 取值（1-30 的整数）")
			return
		}
		days = n
	}
	tr, err := h.store.GetPostureTrends(r.Context(), days)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, tr)
}

// parsePostureDays 解析态势接口 days 查询参数（1-30 的整数，缺省 7；
// 非法值写 400 并返回 ok=false，不静默回落——与 PostureTrends 同一口径）。
func parsePostureDays(w http.ResponseWriter, r *http.Request) (int, bool) {
	days := 7
	if v := strings.TrimSpace(r.URL.Query().Get("days")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 30 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 days 取值（1-30 的整数）")
			return 0, false
		}
		days = n
	}
	return days, true
}

// postureGeoResolver 构建 Geo 判定器（lookup 未装配返回 nil；home_regions 每次请求实时
// 读取 system_settings，设置变更无需重启——与 apigeo 数据出境看板一致）。
func (h *Handler) postureGeoResolver(ctx context.Context) (*apigeo.GeoResolver, error) {
	if h.geoLookup == nil {
		return nil, nil
	}
	raw, err := h.store.getSettingString(ctx, apigeo.SettingsGroup, apigeo.SettingsKeyHomeRegions, apigeo.DefaultHomeRegions)
	if err != nil {
		return nil, err
	}
	return apigeo.NewGeoResolver(h.geoLookup, apigeo.ParseHomeRegions(raw)), nil
}

// PostureSources GET /api/v1/api-security/posture/sources?days=N
// W10-SEC：访问来源聚合——客户端 IP Top（脱敏）/ 地域分桶与国家 Top（GeoIP 降级如实标注）/
// 身份指纹 Top（截断）/ 认证类型分布。
// （api_runtime_events 无 UA 列，User-Agent 族维度按任务书纪律不提供，见 runtime.go 注释。）
func (h *Handler) PostureSources(w http.ResponseWriter, r *http.Request) {
	days, ok := parsePostureDays(w, r)
	if !ok {
		return
	}
	geo, err := h.postureGeoResolver(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	src, err := h.store.GetPostureSources(r.Context(), days, geo)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, src)
}

// PostureTargets GET /api/v1/api-security/posture/targets?days=N
// W10-SEC：访问目标排名——API Top（请求量/风险发现双口径）/ 应用 Top / 涉敏 API Top / 高风险 API Top。
func (h *Handler) PostureTargets(w http.ResponseWriter, r *http.Request) {
	days, ok := parsePostureDays(w, r)
	if !ok {
		return
	}
	tg, err := h.store.GetPostureTargets(r.Context(), days)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, tg)
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
	pageSize := queryPageSize(r, 20)
	list, total, err := h.store.ListRuntimeEvents(r.Context(),
		strings.TrimSpace(q.Get("endpoint_key")),
		strings.ToUpper(strings.TrimSpace(q.Get("final_action"))),
		strings.TrimSpace(q.Get("identity_fingerprint")),
		page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// ListSensitiveFields GET /api/v1/api-security/sensitive-fields
// 过滤 endpoint_id/direction(REQUEST/RESPONSE)/data_type + 分页；数据源 api_sensitive_fields。
func (h *Handler) ListSensitiveFields(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	endpointID := strings.TrimSpace(q.Get("endpoint_id"))
	if endpointID != "" {
		if _, err := uuid.Parse(endpointID); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的接口ID")
			return
		}
	}
	direction := strings.ToUpper(strings.TrimSpace(q.Get("direction")))
	if direction != "" && direction != "REQUEST" && direction != "RESPONSE" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 direction 取值（REQUEST/RESPONSE）")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryPageSize(r, 20)
	list, total, err := h.store.ListSensitiveFields(r.Context(), endpointID, direction,
		strings.TrimSpace(q.Get("data_type")), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// sensitiveFieldsBatchDeleteMax 批量删除单次 ID 上限（防超长请求与长事务）。
const sensitiveFieldsBatchDeleteMax = 500

type batchDeleteSensitiveFieldsRequest struct {
	IDs []string `json:"ids"`
}

// DeleteSensitiveFields POST /api/v1/api-security/sensitive-fields/batch-delete
// 按 ID 批量删除敏感字段识别结果（api_sensitive_fields），写操作审计。
// 部分 ID 不存在不视为错误，如实返回实际删除条数。
func (h *Handler) DeleteSensitiveFields(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req batchDeleteSensitiveFieldsRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if len(req.IDs) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ids 不能为空")
		return
	}
	if len(req.IDs) > sensitiveFieldsBatchDeleteMax {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("单次最多删除 %d 条", sensitiveFieldsBatchDeleteMax))
		return
	}
	ids := make([]uuid.UUID, 0, len(req.IDs))
	for _, raw := range req.IDs {
		id, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ids 含非法 UUID")
			return
		}
		ids = append(ids, id)
	}
	deleted, err := h.store.DeleteSensitiveFieldsByIDs(r.Context(), ids)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", "api_sensitive_field", "", fmt.Sprintf("批量删除敏感字段 %d 条", deleted), "",
		fmt.Sprintf("requested=%d deleted=%d", len(ids), deleted), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"message": fmt.Sprintf("已删除 %d 条敏感字段", deleted),
		"deleted": deleted,
	})
}

// ---------- 通用 ----------

// recordAudit 写操作审计（构造注入 audits.Service；含操作者、动作、对象、前后摘要、风险等级）。
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
