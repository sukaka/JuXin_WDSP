// api_tools.go 阶段8（WDSP）API 动态防护 Tool 组（任务书第四十八章）。
// 全部 READ_ONLY：AI 可解释资产/模型/参数/图谱/运行时/风险/学习/分类，
// 但不得自动确认模型、发布、修改用途、关闭 API 或封禁身份——本组 Tool 不调用任何写路径。
// 装配 gating：仅 cfg.Product.APIDynamicProtectionEnabled() 时由 app.go 挂接。
package aitools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/apisecurity"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// APIEndpointReader api_asset.* / api_learning.status 的只读依赖
// （*apiassets.Store 与 *apiassets.MemStore 均满足，便于单测）。
type APIEndpointReader interface {
	List(ctx context.Context, f apiassets.ListFilter) ([]apiassets.Endpoint, int64, error)
	GetByID(ctx context.Context, id uuid.UUID) (*apiassets.Endpoint, error)
	GetAsset(ctx context.Context, endpointID uuid.UUID) (*apiassets.Asset, error)
	LearningStatus(ctx context.Context, endpointID uuid.UUID) (*apiassets.LearningJob, apiassets.SampleStats, error)
}

// APIModelReader api_model.* / api_parameter.get 的只读依赖（*apimodels.Store 满足）。
type APIModelReader interface {
	GetByID(ctx context.Context, id uuid.UUID) (*apimodels.Version, error)
	ListParametersByVersion(ctx context.Context, versionID uuid.UUID) ([]apimodels.Parameter, error)
}

// APISecurityReader api_graph.query / api_runtime.statistics / api_risk.search /
// api_classification.explain 的只读依赖（*apisecurity.Store 满足）。
type APISecurityReader interface {
	ListGraph(ctx context.Context) (*apisecurity.Graph, error)
	GetRuntimeStatistics(ctx context.Context) (*apisecurity.RuntimeStatistics, error)
	ListFindings(ctx context.Context, findingType, severity, status string, page, pageSize int) ([]apisecurity.RuntimeFinding, int64, error)
	GetEndpointDimensions(ctx context.Context, endpointID uuid.UUID) ([]apisecurity.ClassificationDimension, error)
}

// 编译期保证：生产 SQL Store 与内存实现均满足只读依赖接口（app.go 装配契约）。
var (
	_ APIEndpointReader = (*apiassets.Store)(nil)
	_ APIEndpointReader = (*apiassets.MemStore)(nil)
	_ APIModelReader    = (*apimodels.Store)(nil)
	_ APISecurityReader = (*apisecurity.Store)(nil)
)

// 输入枚举白名单（与迁移 000018/000019 注释口径一致，非法值直接拒绝）。
var (
	apiAssetStatusWhitelist = map[string]bool{
		"DISCOVERED": true, "CONFIRMED": true, "IGNORED": true, "DEPRECATED": true,
	}
	apiLearningStatusWhitelist = map[string]bool{
		"NOT_STARTED": true, "LEARNING": true, "PAUSED": true, "LEARNED": true,
	}
	apiFindingSeverityWhitelist = map[string]bool{
		"INFO": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
	}
	apiFindingStatusWhitelist = map[string]bool{
		"OPEN": true, "ACKNOWLEDGED": true, "RESOLVED": true, "FALSE_POSITIVE": true,
	}
)

// apiTools 阶段8 Tool 组共享依赖。
type apiTools struct {
	endpoints APIEndpointReader
	models    APIModelReader
	security  APISecurityReader
}

// NewAPITools 注册阶段8 API 动态防护 Tool 组（10 个，全部 READ_ONLY）。
// 仅在 cfg.Product.APIDynamicProtectionEnabled() 为真时由装配侧调用。
func NewAPITools(r *Registry, endpoints APIEndpointReader, models APIModelReader, security APISecurityReader) {
	g := &apiTools{endpoints: endpoints, models: models, security: security}
	r.Register(&apiAssetSearch{baseTool: baseTool{meta: toolMeta{
		code: "api_asset.search", name: "API接口搜索", version: "1.0",
		description: "按关键字/资产状态/学习状态搜索API接口",
		risk:        RiskReadOnly, permission: "api_asset.read", timeout: 15, maxResults: 50,
		schema: obj(map[string]interface{}{
			"keyword":         sch("string", "归一化路径关键字（可选）"),
			"asset_status":    sch("string", "资产状态 DISCOVERED/CONFIRMED/IGNORED/DEPRECATED（可选）"),
			"learning_status": sch("string", "学习状态 NOT_STARTED/LEARNING/PAUSED/LEARNED（可选）"),
			"page":            sch("integer", "页码"),
			"limit":           sch("integer", "每页数量（默认20，上限50）"),
		})}}, g: g})
	r.Register(&apiAssetGet{baseTool: baseTool{meta: toolMeta{
		code: "api_asset.get", name: "API接口详情", version: "1.0",
		description: "按接口ID获取详情（含业务维度扩展与当前模型版本号）",
		risk:        RiskReadOnly, permission: "api_asset.read", timeout: 10, maxResults: 1,
		schema: obj(map[string]interface{}{
			"endpoint_id": sch("string", "接口ID"),
		})}}, g: g})
	r.Register(&apiModelGet{baseTool: baseTool{meta: toolMeta{
		code: "api_model.get", name: "API模型版本详情", version: "1.0",
		description: "按模型版本ID获取状态/版本号/schema/变更摘要",
		risk:        RiskReadOnly, permission: "api_model.read", timeout: 10, maxResults: 1,
		schema: obj(map[string]interface{}{
			"model_version_id": sch("string", "模型版本ID"),
		})}}, g: g})
	r.Register(&apiModelDiff{baseTool: baseTool{meta: toolMeta{
		code: "api_model.diff", name: "API模型版本差异", version: "1.0",
		description: "比较两个模型版本的字段级差异（纯计算，不落库）",
		risk:        RiskReadOnly, permission: "api_model.read", timeout: 15, maxResults: 1,
		schema: obj(map[string]interface{}{
			"id":       sch("string", "目标模型版本ID"),
			"other_id": sch("string", "对比基准模型版本ID"),
		})}}, g: g})
	r.Register(&apiParameterGet{baseTool: baseTool{meta: toolMeta{
		code: "api_parameter.get", name: "API参数模型列表", version: "1.0",
		description: "按模型版本ID获取参数模型列表（方向/位置/类型/约束/敏感级别）",
		risk:        RiskReadOnly, permission: "api_parameter.read", timeout: 15, maxResults: 200,
		schema: obj(map[string]interface{}{
			"model_version_id": sch("string", "模型版本ID"),
		})}}, g: g})
	r.Register(&apiGraphQuery{baseTool: baseTool{meta: toolMeta{
		code: "api_graph.query", name: "API调用图谱查询", version: "1.0",
		description: "查询API调用图谱节点与调用边（可按应用过滤）",
		risk:        RiskReadOnly, permission: "api_graph.read", timeout: 20, maxResults: 500,
		schema: obj(map[string]interface{}{
			"application_id": sch("string", "应用ID（可选，按应用过滤节点与相关调用边）"),
		})}}, g: g})
	r.Register(&apiRuntimeStatistics{baseTool: baseTool{meta: toolMeta{
		code: "api_runtime.statistics", name: "API运行时统计", version: "1.0",
		description: "API运行时事件总量、最终动作/风险级别分布与Top接口",
		risk:        RiskReadOnly, permission: "api_runtime.read", timeout: 20, maxResults: 1,
		schema: obj(map[string]interface{}{})}}, g: g})
	r.Register(&apiRiskSearch{baseTool: baseTool{meta: toolMeta{
		code: "api_risk.search", name: "API风险发现搜索", version: "1.0",
		description: "按发现类型/严重级别/状态搜索风险发现（Shadow/Zombie/越权/偏离等）",
		risk:        RiskReadOnly, permission: "api_runtime.read", timeout: 20, maxResults: 50,
		schema: obj(map[string]interface{}{
			"finding_type": sch("string", "发现类型 SHADOW/ZOMBIE/BOLA/BFLA/SCHEMA_DEVIATION/SENSITIVE_LEAK 等（可选）"),
			"severity":     sch("string", "严重级别 INFO/LOW/MEDIUM/HIGH/CRITICAL（可选）"),
			"status":       sch("string", "状态 OPEN/ACKNOWLEDGED/RESOLVED/FALSE_POSITIVE（可选）"),
			"page":         sch("integer", "页码"),
			"limit":        sch("integer", "每页数量（默认20，上限50）"),
		})}}, g: g})
	r.Register(&apiLearningStatus{baseTool: baseTool{meta: toolMeta{
		code: "api_learning.status", name: "API学习状态", version: "1.0",
		description: "按接口ID查询学习状态、最近学习任务与样本统计",
		risk:        RiskReadOnly, permission: "api_learning.read", timeout: 10, maxResults: 1,
		schema: obj(map[string]interface{}{
			"endpoint_id": sch("string", "接口ID"),
		})}}, g: g})
	r.Register(&apiClassificationExplain{baseTool: baseTool{meta: toolMeta{
		code: "api_classification.explain", name: "API分类解释", version: "1.0",
		description: "按接口ID返回分类维度及来源/置信度（解释API用途）",
		risk:        RiskReadOnly, permission: "api_classification.read", timeout: 10, maxResults: 50,
		schema: obj(map[string]interface{}{
			"endpoint_id": sch("string", "接口ID"),
		})}}, g: g})
}

// parseUUIDField 解析必填 UUID 入参。
func parseUUIDField(m map[string]interface{}, key string) (uuid.UUID, error) {
	id, err := uuid.Parse(StrField(m, key, 64))
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: invalid %s", ErrInvalidInput, key)
	}
	return id, nil
}

// pageLimit 解析分页入参：page 从 1 起，limit  clamp 到 [1, maxLimit]。
func pageLimit(m map[string]interface{}, defLimit, maxLimit int) (page, limit int) {
	page = IntField(m, "page", 1)
	if page < 1 {
		page = 1
	}
	limit = IntField(m, "limit", defLimit)
	if limit <= 0 {
		limit = defLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	return page, limit
}

// endpointSummary 接口列表项摘要。
func endpointSummary(e apiassets.Endpoint) map[string]interface{} {
	return map[string]interface{}{
		"endpoint_id":              e.ID,
		"endpoint_key":             e.EndpointKey,
		"http_method":              e.HTTPMethod,
		"normalized_path":          e.NormalizedPath,
		"application_id":           e.ApplicationID,
		"asset_status":             e.AssetStatus,
		"learning_status":          e.LearningStatus,
		"api_confidence":           e.APIConfidence,
		"protocol_type":            e.ProtocolType,
		"is_api":                   e.IsAPI,
		"hit_count":                e.HitCount,
		"current_model_version_id": e.CurrentModelVersionID,
		"first_seen_at":            e.FirstSeenAt,
		"last_seen_at":             e.LastSeenAt,
	}
}

// ---------- 1. api_asset.search ----------

type apiAssetSearch struct {
	baseTool
	g *apiTools
}

func (t *apiAssetSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	page, limit := pageLimit(m, 20, 50)
	f := apiassets.ListFilter{Page: page, PageSize: limit}
	if v := strings.ToUpper(StrField(m, "asset_status", 20)); v != "" {
		if !apiAssetStatusWhitelist[v] {
			return nil, fmt.Errorf("%w: invalid asset_status", ErrInvalidInput)
		}
		f.AssetStatus = v
	}
	if v := strings.ToUpper(StrField(m, "learning_status", 20)); v != "" {
		if !apiLearningStatusWhitelist[v] {
			return nil, fmt.Errorf("%w: invalid learning_status", ErrInvalidInput)
		}
		f.LearningStatus = v
	}
	f.Keyword = StrField(m, "keyword", 128)
	items, total, err := t.g.endpoints.List(ctx, f)
	if err != nil {
		return nil, err
	}
	out := []map[string]interface{}{}
	for _, e := range items {
		out = append(out, endpointSummary(e))
	}
	return map[string]interface{}{"total": total, "page": page, "limit": limit, "items": out}, nil
}

// ---------- 2. api_asset.get ----------

type apiAssetGet struct {
	baseTool
	g *apiTools
}

func (t *apiAssetGet) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	id, err := parseUUIDField(m, "endpoint_id")
	if err != nil {
		return nil, err
	}
	e, err := t.g.endpoints.GetByID(ctx, id)
	if errors.Is(err, apiassets.ErrNotFound) {
		return nil, fmt.Errorf("api endpoint not found")
	}
	if err != nil {
		return nil, err
	}
	asset, err := t.g.endpoints.GetAsset(ctx, id)
	if err != nil {
		return nil, err
	}
	out := endpointSummary(*e)
	out["raw_path_example"] = e.RawPathExample
	out["classification_locked"] = e.ClassificationLocked
	out["confirmed_at"] = e.ConfirmedAt
	// asset 可能为 (nil, nil)：显式转为无类型 nil，避免 typed-nil 污染输出
	var assetOut interface{}
	if asset != nil {
		assetOut = asset
	}
	out["asset"] = assetOut
	// 当前模型版本号（api_endpoints.current_model_version_id → api_model_versions）
	out["current_model"] = nil
	if e.CurrentModelVersionID != nil && t.g.models != nil {
		if v, err := t.g.models.GetByID(ctx, *e.CurrentModelVersionID); err == nil {
			out["current_model"] = map[string]interface{}{
				"model_version_id": v.ID,
				"version_number":   v.VersionNumber,
				"status":           v.Status,
				"confidence":       v.Confidence,
			}
		}
	}
	return out, nil
}

// ---------- 3. api_model.get ----------

type apiModelGet struct {
	baseTool
	g *apiTools
}

func (t *apiModelGet) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	id, err := parseUUIDField(m, "model_version_id")
	if err != nil {
		return nil, err
	}
	v, err := t.g.models.GetByID(ctx, id)
	if errors.Is(err, apimodels.ErrNotFound) {
		return nil, fmt.Errorf("model version not found")
	}
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"model_version_id":      v.ID,
		"endpoint_id":           v.EndpointID,
		"endpoint_key":          v.EndpointKey,
		"version_number":        v.VersionNumber,
		"status":                v.Status,
		"schema":                v.Schema,
		"content_hash":          v.ContentHash,
		"change_summary":        v.ChangeSummary,
		"sample_count":          v.SampleCount,
		"valid_sample_count":    v.ValidSampleCount,
		"excluded_sample_count": v.ExcludedSampleCount,
		"confidence":            v.Confidence,
		"created_reason":        v.CreatedReason,
		"created_at":            v.CreatedAt,
		"confirmed_at":          v.ConfirmedAt,
		"activated_at":          v.ActivatedAt,
	}, nil
}

// ---------- 4. api_model.diff ----------

type apiModelDiff struct {
	baseTool
	g *apiTools
}

func (t *apiModelDiff) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	id, err := parseUUIDField(m, "id")
	if err != nil {
		return nil, err
	}
	otherID, err := parseUUIDField(m, "other_id")
	if err != nil {
		return nil, err
	}
	if id == otherID {
		return nil, fmt.Errorf("%w: id and other_id must differ", ErrInvalidInput)
	}
	v, err := t.g.models.GetByID(ctx, id)
	if errors.Is(err, apimodels.ErrNotFound) {
		return nil, fmt.Errorf("model version not found")
	}
	if err != nil {
		return nil, err
	}
	other, err := t.g.models.GetByID(ctx, otherID)
	if errors.Is(err, apimodels.ErrNotFound) {
		return nil, fmt.Errorf("other model version not found")
	}
	if err != nil {
		return nil, err
	}
	// READ_ONLY：复用 apimodels 的字段级差异纯计算，不写 api_model_diffs。
	d := apimodels.ComputeSchemaDiff(other.Schema, v.Schema)
	return map[string]interface{}{
		"model_version_id": id,
		"other_version_id": otherID,
		"from": map[string]interface{}{
			"version_number": other.VersionNumber, "status": other.Status, "content_hash": other.ContentHash,
		},
		"to": map[string]interface{}{
			"version_number": v.VersionNumber, "status": v.Status, "content_hash": v.ContentHash,
		},
		"diff": d,
	}, nil
}

// ---------- 5. api_parameter.get ----------

type apiParameterGet struct {
	baseTool
	g *apiTools
}

// apiParameterMax 参数列表返回上限（超出截断并标记）。
const apiParameterMax = 200

func (t *apiParameterGet) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	versionID, err := parseUUIDField(m, "model_version_id")
	if err != nil {
		return nil, err
	}
	// 先校验模型版本存在，避免对不存在的版本返回空列表造成歧义
	if _, err := t.g.models.GetByID(ctx, versionID); errors.Is(err, apimodels.ErrNotFound) {
		return nil, fmt.Errorf("model version not found")
	} else if err != nil {
		return nil, err
	}
	params, err := t.g.models.ListParametersByVersion(ctx, versionID)
	if err != nil {
		return nil, err
	}
	truncated := false
	if len(params) > apiParameterMax {
		params = params[:apiParameterMax]
		truncated = true
	}
	return map[string]interface{}{
		"model_version_id": versionID,
		"count":            len(params),
		"truncated":        truncated,
		"items":            params,
	}, nil
}

// ---------- 6. api_graph.query ----------

type apiGraphQuery struct {
	baseTool
	g *apiTools
}

// 图谱返回上限（超出截断并标记）。
const (
	apiGraphMaxNodes = 500
	apiGraphMaxEdges = 1000
)

func (t *apiGraphQuery) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	var appID *uuid.UUID
	if v := StrField(m, "application_id", 64); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid application_id", ErrInvalidInput)
		}
		appID = &id
	}
	graph, err := t.g.security.ListGraph(ctx)
	if err != nil {
		return nil, err
	}
	nodes := graph.Nodes
	edges := graph.Edges
	if appID != nil {
		kept := map[uuid.UUID]bool{}
		filtered := []apisecurity.GraphNode{}
		for _, n := range nodes {
			if n.ApplicationID != nil && *n.ApplicationID == *appID {
				filtered = append(filtered, n)
				kept[n.ID] = true
			}
		}
		// 保留目标接口在过滤结果内的调用边（谁调用了该应用的接口）
		filteredEdges := []apisecurity.GraphEdge{}
		for _, e := range edges {
			if kept[e.TargetEndpointID] {
				filteredEdges = append(filteredEdges, e)
			}
		}
		nodes, edges = filtered, filteredEdges
	}
	nodesTruncated, edgesTruncated := false, false
	if len(nodes) > apiGraphMaxNodes {
		nodes = nodes[:apiGraphMaxNodes]
		nodesTruncated = true
	}
	if len(edges) > apiGraphMaxEdges {
		edges = edges[:apiGraphMaxEdges]
		edgesTruncated = true
	}
	return map[string]interface{}{
		"application_id":  appID,
		"node_count":      len(nodes),
		"edge_count":      len(edges),
		"nodes_truncated": nodesTruncated,
		"edges_truncated": edgesTruncated,
		"nodes":           nodes,
		"edges":           edges,
	}, nil
}

// ---------- 7. api_runtime.statistics ----------

type apiRuntimeStatistics struct {
	baseTool
	g *apiTools
}

func (t *apiRuntimeStatistics) Run(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	st, err := t.g.security.GetRuntimeStatistics(ctx)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// ---------- 8. api_risk.search ----------

type apiRiskSearch struct {
	baseTool
	g *apiTools
}

func (t *apiRiskSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	page, limit := pageLimit(m, 20, 50)
	findingType := strings.ToUpper(StrField(m, "finding_type", 64))
	severity := strings.ToUpper(StrField(m, "severity", 20))
	if severity != "" && !apiFindingSeverityWhitelist[severity] {
		return nil, fmt.Errorf("%w: invalid severity", ErrInvalidInput)
	}
	status := strings.ToUpper(StrField(m, "status", 20))
	if status != "" && !apiFindingStatusWhitelist[status] {
		return nil, fmt.Errorf("%w: invalid status", ErrInvalidInput)
	}
	findings, total, err := t.g.security.ListFindings(ctx, findingType, severity, status, page, limit)
	if err != nil {
		return nil, err
	}
	items := []map[string]interface{}{}
	for _, f := range findings {
		items = append(items, map[string]interface{}{
			"finding_id":    f.ID,
			"endpoint_id":   f.EndpointID,
			"request_id":    f.RequestID,
			"finding_type":  f.FindingType,
			"severity":      f.Severity,
			"status":        f.Status,
			"title":         f.Title,
			"detail":        audits.MaskSensitiveJSON(string(f.Detail)),
			"first_seen_at": f.FirstSeenAt,
			"last_seen_at":  f.LastSeenAt,
		})
	}
	return map[string]interface{}{"total": total, "page": page, "limit": limit, "items": items}, nil
}

// ---------- 9. api_learning.status ----------

type apiLearningStatus struct {
	baseTool
	g *apiTools
}

func (t *apiLearningStatus) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	id, err := parseUUIDField(m, "endpoint_id")
	if err != nil {
		return nil, err
	}
	e, err := t.g.endpoints.GetByID(ctx, id)
	if errors.Is(err, apiassets.ErrNotFound) {
		return nil, fmt.Errorf("api endpoint not found")
	}
	if err != nil {
		return nil, err
	}
	job, stats, err := t.g.endpoints.LearningStatus(ctx, id)
	if err != nil {
		return nil, err
	}
	// 从未学习时 job 为 nil：显式转为无类型 nil，避免 typed-nil 污染输出
	var jobOut interface{}
	if job != nil {
		jobOut = job
	}
	return map[string]interface{}{
		"endpoint_id":     id,
		"endpoint_key":    e.EndpointKey,
		"learning_status": e.LearningStatus,
		"latest_job":      jobOut,
		"samples": map[string]interface{}{
			"total":    stats.Total,
			"accepted": stats.Accepted,
			"excluded": stats.Excluded,
		},
	}, nil
}

// ---------- 10. api_classification.explain ----------

type apiClassificationExplain struct {
	baseTool
	g *apiTools
}

func (t *apiClassificationExplain) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	id, err := parseUUIDField(m, "endpoint_id")
	if err != nil {
		return nil, err
	}
	e, err := t.g.endpoints.GetByID(ctx, id)
	if errors.Is(err, apiassets.ErrNotFound) {
		return nil, fmt.Errorf("api endpoint not found")
	}
	if err != nil {
		return nil, err
	}
	dims, err := t.g.security.GetEndpointDimensions(ctx, id)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"endpoint_id":           id,
		"endpoint_key":          e.EndpointKey,
		"classification_locked": e.ClassificationLocked,
		"dimensions":            dims,
		"note":                  "source 标识分类来源（AUTO 自动启发式 / MANUAL 人工 / AI），confidence 为来源置信度（0-1），仅供解释，AI 不得据此自动修改分类",
	}, nil
}
