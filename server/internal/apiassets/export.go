package apiassets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/validation"
)

const (
	endpointExportVersion       = 1
	endpointExportModelLimit    = 20
	endpointExportSampleLimit   = 100
	endpointExportEventLimit    = 100
	endpointExportCSVMaxRows    = 10000
	endpointExportCSVPageSize   = 100
	endpointExportFilenameMax   = 80
	endpointExportTimeLayout    = time.RFC3339
	endpointExportCSVDateLayout = "20060102"
	endpointExportCSVUTF8BOM    = "\xef\xbb\xbf"
)

// ExportModelReader 单接口导出所需的模型只读入口（*apimodels.Store 实现）。
type ExportModelReader interface {
	ListByEndpoint(ctx context.Context, endpointID uuid.UUID, page, pageSize int) ([]apimodels.Version, int64, error)
	ListParametersByVersion(ctx context.Context, versionID uuid.UUID) ([]apimodels.Parameter, error)
	ListResponseSchemas(ctx context.Context, endpointKey string) ([]apimodels.ResponseSchema, error)
}

// ExportExtrasProvider 单接口导出所需的扩展安全/来源数据入口（*Store 实现）。
type ExportExtrasProvider interface {
	LoadExportExtras(ctx context.Context, endpointID uuid.UUID) (*ExportExtras, error)
}

// SetExportModelReader 注入模型数据入口；返回 Handler 便于装配链式调用。
func (h *Handler) SetExportModelReader(r ExportModelReader) *Handler {
	h.exportModels = r
	return h
}

// SetExportExtrasProvider 注入扩展数据入口；返回 Handler 便于装配链式调用。
func (h *Handler) SetExportExtrasProvider(p ExportExtrasProvider) *Handler {
	h.exportExtras = p
	return h
}

// ExportClassification 来源观测时的 API 分类证据。
type ExportClassification struct {
	IsAPI        bool      `json:"is_api"`
	Confidence   float64   `json:"confidence"`
	Level        string    `json:"level"`
	Signals      []string  `json:"signals"`
	ClassifiedAt time.Time `json:"classified_at"`
}

// ExportAgentSource Agent HTTP 来源关系与关联状态。
type ExportAgentSource struct {
	AgentID              uuid.UUID             `json:"agent_id"`
	EndpointID           *uuid.UUID            `json:"endpoint_id,omitempty"`
	Host                 string                `json:"host"`
	Method               string                `json:"method"`
	PathTemplate         string                `json:"path_template"`
	SourceType           string                `json:"source_type"`
	SourceInstance       string                `json:"source_instance"`
	SourceEpoch          int64                 `json:"source_epoch"`
	ApplicationBindingID *uuid.UUID            `json:"application_binding_id,omitempty"`
	BindingVersion       *int64                `json:"binding_version,omitempty"`
	AssociationState     string                `json:"association_state"`
	LastError            string                `json:"last_error,omitempty"`
	Classification       *ExportClassification `json:"classification,omitempty"`
	FirstSeenAt          time.Time             `json:"first_seen_at"`
	LastSeenAt           time.Time             `json:"last_seen_at"`
}

// ExportFinding 运行时发现摘要（detail 为既有脱敏 JSON，不含正文）。
type ExportFinding struct {
	ID          uuid.UUID       `json:"id"`
	EndpointID  *uuid.UUID      `json:"endpoint_id,omitempty"`
	RequestID   string          `json:"request_id"`
	FindingType string          `json:"finding_type"`
	Severity    string          `json:"severity"`
	Status      string          `json:"status"`
	Title       string          `json:"title"`
	Detail      json.RawMessage `json:"detail"`
	FirstSeenAt time.Time       `json:"first_seen_at"`
	LastSeenAt  time.Time       `json:"last_seen_at"`
}

// ExportWeakness 弱点摘要（evidence 为既有脱敏 JSON）。
type ExportWeakness struct {
	ID           uuid.UUID       `json:"id"`
	EndpointID   *uuid.UUID      `json:"endpoint_id,omitempty"`
	Code         string          `json:"code"`
	Name         string          `json:"name"`
	Category     string          `json:"category"`
	Severity     string          `json:"severity"`
	Status       string          `json:"status"`
	Evidence     json.RawMessage `json:"evidence"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
	TriggerCount int             `json:"trigger_count"`
	Owner        string          `json:"owner,omitempty"`
}

// ExportSensitiveField 敏感字段摘要（只含路径与类型，不含值）。
type ExportSensitiveField struct {
	ID              uuid.UUID       `json:"id"`
	EndpointID      uuid.UUID       `json:"endpoint_id"`
	Direction       string          `json:"direction"`
	StructuredPath  string          `json:"structured_path"`
	DataType        string          `json:"data_type"`
	Confidence      float64         `json:"confidence"`
	DetectionSource string          `json:"detection_source"`
	FirstSeen       *time.Time      `json:"first_seen,omitempty"`
	LastSeen        *time.Time      `json:"last_seen,omitempty"`
	OccurrenceCount int             `json:"occurrence_count"`
	SourceDetail    json.RawMessage `json:"source_detail,omitempty"`
}

// ExportExtras 详细档案扩展数据。
type ExportExtras struct {
	ClassificationDimensions []ClassificationDimension `json:"classification_dimensions"`
	AgentSources             []ExportAgentSource       `json:"agent_sources"`
	AgentSourcesTotal        int64                     `json:"agent_sources_total"`
	Findings                 []ExportFinding           `json:"findings"`
	FindingsTotal            int64                     `json:"findings_total"`
	Weaknesses               []ExportWeakness          `json:"weaknesses"`
	WeaknessesTotal          int64                     `json:"weaknesses_total"`
	SensitiveFields          []ExportSensitiveField    `json:"sensitive_fields"`
	SensitiveFieldsTotal     int64                     `json:"sensitive_fields_total"`
}

// ExportMeta 导出元数据。
type ExportMeta struct {
	ExportVersion int       `json:"export_version"`
	Kind          string    `json:"kind"`
	GeneratedAt   time.Time `json:"generated_at"`
	GeneratedBy   string    `json:"generated_by"`
	EndpointID    uuid.UUID `json:"endpoint_id"`
	ContentSHA256 string    `json:"content_sha256"`
}

// ExportEndpointClassification 端点当前识别结论与人工分类维度。
type ExportEndpointClassification struct {
	IsAPI      bool                      `json:"is_api"`
	Confidence float64                   `json:"confidence"`
	Dimensions []ClassificationDimension `json:"dimensions"`
}

// ExportModels 模型、参数和响应 Schema。
type ExportModels struct {
	CurrentVersion  *apimodels.Version         `json:"current_version,omitempty"`
	Versions        []apimodels.Version        `json:"versions"`
	VersionsTotal   int64                      `json:"versions_total"`
	Parameters      []apimodels.Parameter      `json:"parameters"`
	ResponseSchemas []apimodels.ResponseSchema `json:"response_schemas"`
}

// ExportLearning 学习状态与脱敏样本元数据。
type ExportLearning struct {
	Job                *LearningJob     `json:"job,omitempty"`
	Stats              SampleStats      `json:"stats"`
	RecentSamples      []LearningSample `json:"recent_samples"`
	RecentSamplesTotal int64            `json:"recent_samples_total"`
}

// ExportSecurity 安全关联数据。
type ExportSecurity struct {
	Findings             []ExportFinding        `json:"findings"`
	FindingsTotal        int64                  `json:"findings_total"`
	Weaknesses           []ExportWeakness       `json:"weaknesses"`
	WeaknessesTotal      int64                  `json:"weaknesses_total"`
	SensitiveFields      []ExportSensitiveField `json:"sensitive_fields"`
	SensitiveFieldsTotal int64                  `json:"sensitive_fields_total"`
}

// EndpointExportBundle 单个 API 详细档案（export_version=1）。
type EndpointExportBundle struct {
	Meta           ExportMeta                   `json:"meta"`
	Endpoint       *Endpoint                    `json:"endpoint"`
	Classification ExportEndpointClassification `json:"classification"`
	Models         ExportModels                 `json:"models"`
	Learning       ExportLearning               `json:"learning"`
	Lifecycle      []LifecycleEvent             `json:"lifecycle"`
	LifecycleTotal int64                        `json:"lifecycle_total"`
	Traffic        map[string]*TrafficTrend     `json:"traffic"`
	Sources        []ExportAgentSource          `json:"sources"`
	SourcesTotal   int64                        `json:"sources_total"`
	Security       ExportSecurity               `json:"security"`
}

// ExportDetail GET /api/v1/api-security/endpoints/{id}/export?format=json。
func (h *Handler) ExportDetail(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	if format != "json" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的导出格式（仅支持 json）")
		return
	}
	if h.exportModels == nil || h.exportExtras == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "API 资产导出数据入口未配置")
		return
	}
	ep, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if err == ErrNotFound {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	asset, err := h.store.GetAsset(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	ep.Asset = asset

	versions, versionsTotal, err := h.exportModels.ListByEndpoint(r.Context(), id, 1, endpointExportModelLimit)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	current := selectExportCurrentVersion(ep, versions)
	var params []apimodels.Parameter
	if current != nil {
		params, err = h.exportModels.ListParametersByVersion(r.Context(), current.ID)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
	}
	responseSchemas, err := h.exportModels.ListResponseSchemas(r.Context(), ep.EndpointKey)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	extras, err := h.exportExtras.LoadExportExtras(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if extras == nil {
		extras = &ExportExtras{}
	}
	job, sampleStats, err := h.store.LearningStatus(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	samples, samplesTotal, err := h.store.ListLearningSamples(r.Context(), id, nil, 1, endpointExportSampleLimit)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	lifecycle, lifecycleTotal, err := h.store.ListLifecycleEvents(r.Context(), id, 1, endpointExportEventLimit)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	traffic, err := h.exportTraffic(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}

	bundle := &EndpointExportBundle{
		Meta: ExportMeta{
			ExportVersion: endpointExportVersion,
			Kind:          "api_endpoint_detail",
			GeneratedAt:   time.Now().UTC(),
			GeneratedBy:   p.Username,
			EndpointID:    id,
		},
		Endpoint: ep,
		Classification: ExportEndpointClassification{
			IsAPI: ep.IsAPI, Confidence: ep.APIConfidence,
			Dimensions: extras.ClassificationDimensions,
		},
		Models: ExportModels{
			CurrentVersion: current, Versions: versions, VersionsTotal: versionsTotal,
			Parameters: params, ResponseSchemas: responseSchemas,
		},
		Learning: ExportLearning{
			Job: job, Stats: sampleStats, RecentSamples: samples, RecentSamplesTotal: samplesTotal,
		},
		Lifecycle: lifecycle, LifecycleTotal: lifecycleTotal,
		Traffic: traffic,
		Sources: extras.AgentSources, SourcesTotal: extras.AgentSourcesTotal,
		Security: ExportSecurity{
			Findings: extras.Findings, FindingsTotal: extras.FindingsTotal,
			Weaknesses: extras.Weaknesses, WeaknessesTotal: extras.WeaknessesTotal,
			SensitiveFields: extras.SensitiveFields, SensitiveFieldsTotal: extras.SensitiveFieldsTotal,
		},
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	sum := sha256.Sum256(raw)
	bundle.Meta.ContentSHA256 = hex.EncodeToString(sum[:])
	h.recordAudit(r, p, "export", id.String(), truncateName(ep.EndpointKey), "",
		summaryJSON(map[string]any{"format": "json", "kind": "api_endpoint_detail"}), audits.RiskMedium)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, safeEndpointExportName(ep)))
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(bundle)
}

// ExportList GET /api/v1/api-security/endpoints/export?format=csv。
func (h *Handler) ExportList(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "csv"
	}
	if format != "csv" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的导出格式（仅支持 csv）")
		return
	}
	q := r.URL.Query()
	ids, err := validation.ParseExportUUIDs(q, "ids")
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	f := ListFilter{
		AssetStatus:     strings.ToUpper(strings.TrimSpace(q.Get("asset_status"))),
		LearningStatus:  strings.ToUpper(strings.TrimSpace(q.Get("learning_status"))),
		Keyword:         strings.TrimSpace(q.Get("keyword")),
		DirectoryPrefix: strings.TrimSpace(q.Get("directory_path")),
		Unassigned:      q.Get("unassigned") == "true",
		IncludeNonAPI:   q.Get("include_non_api") == "true",
		IDs:             ids,
		Page:            1,
		PageSize:        endpointExportCSVPageSize,
	}
	if v := strings.TrimSpace(q.Get("application_id")); v != "" {
		appID, err := uuid.Parse(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的application_id")
			return
		}
		f.ApplicationID = &appID
	}
	if v := strings.TrimSpace(q.Get("business_type")); v != "" {
		bt := NormalizeBusinessType(v)
		if !validBusinessTypes[bt] {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的业务类型")
			return
		}
		f.BusinessType = bt
	}

	var rows []Endpoint
	for {
		list, total, err := h.store.List(r.Context(), f)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		rows = append(rows, list...)
		if int64(len(rows)) >= total || len(rows) >= endpointExportCSVMaxRows || len(list) == 0 {
			break
		}
		f.Page++
	}
	if len(rows) > endpointExportCSVMaxRows {
		rows = rows[:endpointExportCSVMaxRows]
	}
	h.recordAudit(r, p, "export", "", "API资产清单", "",
		summaryJSON(map[string]any{"format": "csv", "count": len(rows)}), audits.RiskMedium)

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="api-endpoints-%s.csv"`, time.Now().Format(endpointExportCSVDateLayout)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(renderEndpointsCSV(rows)))
}

const endpointExportCSVHeader = "所属站点,站点域名,目录路径,请求方法,路径模板,原始路径示例,接口键,协议类型,是否 API,置信度,资产状态,学习状态,业务标签,资产价值,命中次数,首次发现时间,最近访问时间,确认时间,僵尸态起点\n"

// renderEndpointsCSV 渲染 API 资产清单 CSV（含 UTF-8 BOM、中文表头与枚举/布尔中文化、全字符串列防公式注入）。
func renderEndpointsCSV(rows []Endpoint) string {
	var b strings.Builder
	b.WriteString(endpointExportCSVUTF8BOM)
	b.WriteString(endpointExportCSVHeader)
	for _, e := range rows {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%.4f,%s,%s,%s,%s,%d,%s,%s,%s,%s\n",
			exportCSV(e.ApplicationName), exportCSV(e.Host), exportCSV(e.DirectoryPath), exportCSV(e.HTTPMethod),
			exportCSV(e.NormalizedPath), exportCSV(e.RawPathExample), exportCSV(e.EndpointKey),
			exportCSV(exportProtocolLabel(e.ProtocolType)),
			exportCSV(exportBoolLabel(e.IsAPI)),
			e.APIConfidence,
			exportCSV(exportAssetStatusLabel(e.AssetStatus)),
			exportCSV(exportLearningStatusLabel(e.LearningStatus)),
			exportCSV(exportBusinessTypeLabel(e.BusinessType)),
			exportCSV(exportAssetValueLabel(e.AssetValue)),
			e.HitCount,
			e.FirstSeenAt.UTC().Format(endpointExportTimeLayout),
			e.LastSeenAt.UTC().Format(endpointExportTimeLayout),
			exportCSVTimePtr(e.ConfirmedAt),
			exportCSVTimePtr(e.ZombieSince))
	}
	return b.String()
}

var exportProtocolLabels = map[string]string{
	"REST_JSON":           "REST/JSON",
	"REST_XML":            "REST/XML",
	"REST":                "REST",
	"FORM_API":            "Form 表单",
	"SOAP":                "SOAP",
	"GRAPHQL":             "GraphQL",
	"JSON_RPC":            "JSON-RPC",
	"XML_RPC":             "XML-RPC",
	"WEBHOOK":             "Webhook",
	"FILE_UPLOAD":         "文件上传",
	"FILE_DOWNLOAD":       "文件下载",
	"WEBSOCKET_HANDSHAKE": "WebSocket 握手",
	"WEBSOCKET":           "WebSocket",
	"SERVER_SENT_EVENTS":  "SSE",
	"GRPC":                "gRPC",
	"UNKNOWN_HTTP_API":    "未知 HTTP API",
	"UNKNOWN_HTTP":        "未知 HTTP API",
}

func exportProtocolLabel(v string) string {
	key := strings.ToUpper(strings.TrimSpace(v))
	if key == "" {
		return ""
	}
	if label, ok := exportProtocolLabels[key]; ok {
		return label
	}
	return v
}

func exportBoolLabel(v bool) string {
	if v {
		return "是"
	}
	return "否"
}

func exportAssetStatusLabel(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "":
		return ""
	case "DISCOVERED":
		return "已发现"
	case "CONFIRMED":
		return "已确认"
	case "IGNORED":
		return "已忽略"
	case "DEPRECATED":
		return "已废弃"
	case "ZOMBIE":
		return "僵尸接口"
	default:
		return v
	}
}

func exportLearningStatusLabel(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "":
		return ""
	case "NOT_STARTED":
		return "未开始"
	case "LEARNING":
		return "学习中"
	case "PAUSED":
		return "已暂停"
	case "LEARNED":
		return "已完成"
	default:
		return v
	}
}

var exportBusinessTypeLabels = map[string]string{
	"LOGIN":               "登录",
	"REGISTER":            "注册",
	"PASSWORD_RESET":      "找回密码",
	"SMS":                 "短信发送",
	"EMAIL":               "邮件发送",
	"ORDER":               "下单",
	"PAYMENT":             "支付",
	"EXPORT":              "导出",
	"DOWNLOAD":            "下载",
	"SEARCH":              "搜索",
	"QUERY_PERSONAL_DATA": "查询个人数据",
	"AI_INFERENCE":        "AI推理",
	"OTHER":               "其他",
}

func exportBusinessTypeLabel(v string) string {
	key := strings.ToUpper(strings.TrimSpace(v))
	if key == "" {
		return ""
	}
	if label, ok := exportBusinessTypeLabels[key]; ok {
		return label
	}
	return v
}

func exportAssetValueLabel(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "":
		return ""
	case "CRITICAL":
		return "极高"
	case "HIGH":
		return "高"
	case "MEDIUM":
		return "中"
	case "LOW":
		return "低"
	default:
		return v
	}
}

func selectExportCurrentVersion(ep *Endpoint, versions []apimodels.Version) *apimodels.Version {
	if ep.CurrentModelVersionID != nil {
		for i := range versions {
			if versions[i].ID == *ep.CurrentModelVersionID {
				return &versions[i]
			}
		}
	}
	for i := range versions {
		if versions[i].Status == "FORMAL" {
			return &versions[i]
		}
	}
	if len(versions) > 0 {
		return &versions[0]
	}
	return nil
}

func (h *Handler) exportTraffic(ctx context.Context, endpointID uuid.UUID) (map[string]*TrafficTrend, error) {
	now := time.Now().UTC()
	out := make(map[string]*TrafficTrend, 3)
	for _, item := range []struct {
		name string
		dur  time.Duration
	}{
		{"1h", time.Hour}, {"24h", 24 * time.Hour}, {"7d", 7 * 24 * time.Hour},
	} {
		from := now.Add(-item.dur)
		counts, err := h.store.TrafficBuckets(ctx, endpointID, from, TrafficBucketStart(now).Add(TrafficBucketSeconds*time.Second))
		if err != nil {
			return nil, err
		}
		points, total := FillTrafficPoints(from, now, counts)
		out[item.name] = &TrafficTrend{
			EndpointID: endpointID.String(), BucketSeconds: TrafficBucketSeconds,
			Range: item.name, Total: total, Points: points,
		}
	}
	return out, nil
}

func safeEndpointExportName(ep *Endpoint) string {
	raw := strings.ToLower(ep.HTTPMethod + "-" + strings.Trim(ep.NormalizedPath, "/"))
	var b strings.Builder
	lastDash := false
	for _, r := range raw {
		ok := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-'
		if !ok {
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
			continue
		}
		b.WriteRune(r)
		lastDash = false
	}
	name := strings.Trim(b.String(), "-")
	if name == "" {
		name = "api-endpoint"
	}
	if len(name) > endpointExportFilenameMax {
		name = name[:endpointExportFilenameMax]
	}
	return "api-endpoint-" + name
}

func exportCSV(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		s = "'" + s
	}
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func exportCSVTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(endpointExportTimeLayout)
}
