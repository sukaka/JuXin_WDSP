// api_tools_test.go 阶段8 API 动态防护 Tool 组测试：
// 注册元数据、权限拒绝、管理面禁用拒绝、输入校验，以及内存/假 store 的 happy path。
package aitools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/apisecurity"
)

// fakeModelReader 内存 APIModelReader。
type fakeModelReader struct {
	versions map[uuid.UUID]*apimodels.Version
	params   map[uuid.UUID][]apimodels.Parameter
}

func (f *fakeModelReader) GetByID(_ context.Context, id uuid.UUID) (*apimodels.Version, error) {
	v, ok := f.versions[id]
	if !ok {
		return nil, apimodels.ErrNotFound
	}
	return v, nil
}

func (f *fakeModelReader) ListParametersByVersion(_ context.Context, versionID uuid.UUID) ([]apimodels.Parameter, error) {
	out := f.params[versionID]
	if out == nil {
		out = []apimodels.Parameter{}
	}
	return out, nil
}

// fakeSecurityReader 内存 APISecurityReader。
type fakeSecurityReader struct {
	graph    *apisecurity.Graph
	stats    *apisecurity.RuntimeStatistics
	findings []apisecurity.RuntimeFinding
	dims     []apisecurity.ClassificationDimension
}

func (f *fakeSecurityReader) ListGraph(context.Context) (*apisecurity.Graph, error) {
	if f.graph == nil {
		return &apisecurity.Graph{Nodes: []apisecurity.GraphNode{}, Edges: []apisecurity.GraphEdge{}}, nil
	}
	return f.graph, nil
}

func (f *fakeSecurityReader) GetRuntimeStatistics(context.Context) (*apisecurity.RuntimeStatistics, error) {
	if f.stats == nil {
		return &apisecurity.RuntimeStatistics{}, nil
	}
	return f.stats, nil
}

func (f *fakeSecurityReader) ListFindings(_ context.Context, findingType, severity, status string, _, _ int) ([]apisecurity.RuntimeFinding, int64, error) {
	out := []apisecurity.RuntimeFinding{}
	for _, x := range f.findings {
		if findingType != "" && x.FindingType != findingType {
			continue
		}
		if severity != "" && x.Severity != severity {
			continue
		}
		if status != "" && x.Status != status {
			continue
		}
		out = append(out, x)
	}
	return out, int64(len(out)), nil
}

func (f *fakeSecurityReader) GetEndpointDimensions(context.Context, uuid.UUID) ([]apisecurity.ClassificationDimension, error) {
	return f.dims, nil
}

// newAPIRegistry 注册全部阶段8 Tool 的测试注册中心。
func newAPIRegistry(endpoints APIEndpointReader, models APIModelReader, security APISecurityReader) *Registry {
	r := NewRegistry()
	NewAPITools(r, endpoints, models, security)
	return r
}

// TestNewAPIToolsMetadata 十个 Tool 全部注册，READ_ONLY 且权限点正确。
func TestNewAPIToolsMetadata(t *testing.T) {
	r := newAPIRegistry(apiassets.NewMemStore(), &fakeModelReader{}, &fakeSecurityReader{})
	want := map[string]string{
		"api_asset.search":           "api_asset.read",
		"api_asset.get":              "api_asset.read",
		"api_model.get":              "api_model.read",
		"api_model.diff":             "api_model.read",
		"api_parameter.get":          "api_parameter.read",
		"api_graph.query":            "api_graph.read",
		"api_runtime.statistics":     "api_runtime.read",
		"api_risk.search":            "api_runtime.read",
		"api_learning.status":        "api_learning.read",
		"api_classification.explain": "api_classification.read",
	}
	if got := len(r.List()); got != len(want) {
		t.Fatalf("注册 Tool 数 = %d, want %d", got, len(want))
	}
	for code, perm := range want {
		tl, ok := r.Get(code)
		if !ok {
			t.Errorf("缺少 Tool %s", code)
			continue
		}
		if tl.RiskLevel() != RiskReadOnly {
			t.Errorf("Tool %s risk = %s, want READ_ONLY（任务书禁止 AI 写操作）", code, tl.RiskLevel())
		}
		if tl.RequiredPermission() != perm {
			t.Errorf("Tool %s permission = %s, want %s", code, tl.RequiredPermission(), perm)
		}
		if tl.TimeoutSeconds() <= 0 || tl.MaxResults() <= 0 {
			t.Errorf("Tool %s timeout/maxResults 未设置", code)
		}
	}
}

// TestAPIToolPermissionDenied 无对应权限点拒绝执行并审计 DENIED。
func TestAPIToolPermissionDenied(t *testing.T) {
	r := newAPIRegistry(apiassets.NewMemStore(), &fakeModelReader{}, &fakeSecurityReader{})
	aud := &fakeAuditor{}
	_, _, err := r.Execute(context.Background(), adminPrincipal("security_events.read"), uuid.New(), nil,
		"api_asset.search", json.RawMessage(`{}`), aud)
	if !errors.Is(err, ErrPermission) {
		t.Fatalf("err = %v, want ErrPermission", err)
	}
	if len(aud.records) != 1 || aud.records[0].Status != "DENIED" {
		t.Fatalf("DENIED 审计记录缺失: %+v", aud.records)
	}
	// nil Principal 同样拒绝
	if _, _, err := r.Execute(context.Background(), nil, uuid.New(), nil,
		"api_risk.search", json.RawMessage(`{}`), nil); !errors.Is(err, ErrPermission) {
		t.Errorf("nil Principal err = %v, want ErrPermission", err)
	}
}

// TestAPIToolDisabled 管理面禁用的 Tool 拒绝执行。
func TestAPIToolDisabled(t *testing.T) {
	r := newAPIRegistry(apiassets.NewMemStore(), &fakeModelReader{}, &fakeSecurityReader{})
	r.SetEnabledChecker(func(context.Context, string) bool { return false })
	_, _, err := r.Execute(context.Background(), adminPrincipal("api_runtime.read"), uuid.New(), nil,
		"api_runtime.statistics", nil, nil)
	if !errors.Is(err, ErrToolDisabled) {
		t.Fatalf("err = %v, want ErrToolDisabled", err)
	}
}

// TestAPIToolInputValidation 入参校验：非法枚举 / 非法 UUID / 自比差异。
func TestAPIToolInputValidation(t *testing.T) {
	r := newAPIRegistry(apiassets.NewMemStore(), &fakeModelReader{}, &fakeSecurityReader{})
	ctx := context.Background()
	cases := []struct {
		code  string
		perm  string
		input string
	}{
		{"api_asset.search", "api_asset.read", `{"asset_status":"HACKED"}`},
		{"api_asset.search", "api_asset.read", `{"learning_status":"DONE"}`},
		{"api_asset.get", "api_asset.read", `{"endpoint_id":"not-a-uuid"}`},
		{"api_model.get", "api_model.read", `{"model_version_id":""}`},
		{"api_model.diff", "api_model.read", `{"id":"` + uuid.NewString() + `"`},
		{"api_model.diff", "api_model.read", `{"id":"x","other_id":"y"}`},
		{"api_parameter.get", "api_parameter.read", `{"model_version_id":"zzz"}`},
		{"api_graph.query", "api_graph.read", `{"application_id":"bad"}`},
		{"api_risk.search", "api_runtime.read", `{"severity":"EXTREME"}`},
		{"api_risk.search", "api_runtime.read", `{"status":"CLOSED"}`},
		{"api_learning.status", "api_learning.read", `{}`},
		{"api_classification.explain", "api_classification.read", `{"endpoint_id":"1"}`},
	}
	for _, c := range cases {
		_, _, err := r.Execute(ctx, adminPrincipal(c.perm), uuid.New(), nil, c.code, json.RawMessage(c.input), nil)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s input %s: err = %v, want ErrInvalidInput", c.code, c.input, err)
		}
	}
	// id 与 other_id 相同
	same := uuid.NewString()
	_, _, err := r.Execute(ctx, adminPrincipal("api_model.read"), uuid.New(), nil,
		"api_model.diff", json.RawMessage(`{"id":"`+same+`","other_id":"`+same+`"}`), nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("api_model.diff 自比: err = %v, want ErrInvalidInput", err)
	}
}

// seedEndpoints 内存仓储造两个端点：e1 CONFIRMED + 业务扩展，e2 DISCOVERED。
func seedEndpoints(t *testing.T) (*apiassets.MemStore, *apiassets.Endpoint, *apiassets.Endpoint) {
	t.Helper()
	ctx := context.Background()
	mem := apiassets.NewMemStore()
	e1, err := mem.UpsertDiscovery(ctx, "GET", "/api/users/{id}", 0.9, true)
	if err != nil {
		t.Fatalf("UpsertDiscovery e1: %v", err)
	}
	e2, err := mem.UpsertDiscovery(ctx, "POST", "/api/orders", 0.8, true)
	if err != nil {
		t.Fatalf("UpsertDiscovery e2: %v", err)
	}
	if _, err := mem.Confirm(ctx, e1.ID); err != nil {
		t.Fatalf("Confirm e1: %v", err)
	}
	if _, err := mem.UpsertAsset(ctx, e1.ID, "用户管理", "PUBLIC", "team-a", []string{"pii"}); err != nil {
		t.Fatalf("UpsertAsset e1: %v", err)
	}
	return mem, e1, e2
}

// TestAPIAssetSearchAndGetHappyPath api_asset.search / api_asset.get 走通（MemStore 真实语义）。
func TestAPIAssetSearchAndGetHappyPath(t *testing.T) {
	mem, e1, e2 := seedEndpoints(t)
	r := newAPIRegistry(mem, &fakeModelReader{}, &fakeSecurityReader{})
	ctx := context.Background()
	p := adminPrincipal("api_asset.read")

	// 资产状态过滤（小写输入归一为大写）
	res, _, err := r.Execute(ctx, p, uuid.New(), nil, "api_asset.search",
		json.RawMessage(`{"asset_status":"confirmed","limit":50}`), nil)
	if err != nil {
		t.Fatalf("api_asset.search: %v", err)
	}
	got := res.(map[string]interface{})
	if got["total"].(int64) != 1 {
		t.Fatalf("CONFIRMED total = %v, want 1", got["total"])
	}
	items := got["items"].([]map[string]interface{})
	if items[0]["endpoint_key"] != e1.EndpointKey {
		t.Errorf("命中端点 = %v, want %s", items[0]["endpoint_key"], e1.EndpointKey)
	}

	// 关键字过滤命中 e2
	res, _, err = r.Execute(ctx, p, uuid.New(), nil, "api_asset.search",
		json.RawMessage(`{"keyword":"orders"}`), nil)
	if err != nil {
		t.Fatalf("api_asset.search keyword: %v", err)
	}
	if res.(map[string]interface{})["total"].(int64) != 1 {
		t.Errorf("keyword total = %v, want 1", res.(map[string]interface{})["total"])
	}
	_ = e2

	// 详情：含 api_assets 扩展，无当前模型时 current_model 为 nil
	res, _, err = r.Execute(ctx, p, uuid.New(), nil, "api_asset.get",
		json.RawMessage(`{"endpoint_id":"`+e1.ID.String()+`"}`), nil)
	if err != nil {
		t.Fatalf("api_asset.get: %v", err)
	}
	detail := res.(map[string]interface{})
	if detail["endpoint_key"] != e1.EndpointKey || detail["asset_status"] != "CONFIRMED" {
		t.Errorf("详情字段错误: %v", detail)
	}
	asset, ok := detail["asset"].(*apiassets.Asset)
	if !ok || asset.Purpose != "用户管理" || asset.Exposure != "PUBLIC" {
		t.Errorf("asset 扩展缺失或错误: %+v", detail["asset"])
	}
	if detail["current_model"] != nil {
		t.Errorf("无当前模型时 current_model 应为 nil, got %v", detail["current_model"])
	}

	// 不存在的端点
	_, _, err = r.Execute(ctx, p, uuid.New(), nil, "api_asset.get",
		json.RawMessage(`{"endpoint_id":"`+uuid.NewString()+`"}`), nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("缺失端点 err = %v, want not found", err)
	}
}

// TestAPIModelDiffHappyPath api_model.diff 复用纯计算返回字段级差异。
func TestAPIModelDiffHappyPath(t *testing.T) {
	idV2, idV1 := uuid.New(), uuid.New()
	fm := &fakeModelReader{versions: map[uuid.UUID]*apimodels.Version{
		idV2: {ID: idV2, EndpointKey: "GET /a", VersionNumber: 2, Status: apimodels.StatusFormal,
			Schema: map[string]string{"id": "integer", "email": "string", "age": "integer"}, ContentHash: "h2"},
		idV1: {ID: idV1, EndpointKey: "GET /a", VersionNumber: 1, Status: apimodels.StatusSuperseded,
			Schema: map[string]string{"id": "integer", "name": "string", "age": "string"}, ContentHash: "h1"},
	}}
	r := newAPIRegistry(apiassets.NewMemStore(), fm, &fakeSecurityReader{})
	res, _, err := r.Execute(context.Background(), adminPrincipal("api_model.read"), uuid.New(), nil,
		"api_model.diff", json.RawMessage(`{"id":"`+idV2.String()+`","other_id":"`+idV1.String()+`"}`), nil)
	if err != nil {
		t.Fatalf("api_model.diff: %v", err)
	}
	got := res.(map[string]interface{})
	d, ok := got["diff"].(apimodels.SchemaDiff)
	if !ok {
		t.Fatalf("diff 类型 = %T", got["diff"])
	}
	if len(d.Added) != 1 || d.Added[0] != "email" {
		t.Errorf("Added = %v, want [email]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0] != "name" {
		t.Errorf("Removed = %v, want [name]", d.Removed)
	}
	if len(d.TypeChanged) != 1 || d.TypeChanged[0] != (apimodels.TypeChange{Field: "age", From: "string", To: "integer"}) {
		t.Errorf("TypeChanged = %+v", d.TypeChanged)
	}

	// 版本不存在
	_, _, err = r.Execute(context.Background(), adminPrincipal("api_model.read"), uuid.New(), nil,
		"api_model.diff", json.RawMessage(`{"id":"`+uuid.NewString()+`","other_id":"`+idV1.String()+`"}`), nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("缺失版本 err = %v, want not found", err)
	}
}

// TestAPIParameterGetHappyPath api_parameter.get 返回参数列表。
func TestAPIParameterGetHappyPath(t *testing.T) {
	idV := uuid.New()
	fm := &fakeModelReader{
		versions: map[uuid.UUID]*apimodels.Version{
			idV: {ID: idV, EndpointKey: "GET /a", VersionNumber: 1, Status: apimodels.StatusFormal},
		},
		params: map[uuid.UUID][]apimodels.Parameter{
			idV: {
				{ID: uuid.New(), ModelVersionID: idV, Direction: "REQUEST", Location: "QUERY",
					ParameterName: "page", BaseType: "integer", SensitivityLevel: "UNKNOWN"},
			},
		},
	}
	r := newAPIRegistry(apiassets.NewMemStore(), fm, &fakeSecurityReader{})
	res, _, err := r.Execute(context.Background(), adminPrincipal("api_parameter.read"), uuid.New(), nil,
		"api_parameter.get", json.RawMessage(`{"model_version_id":"`+idV.String()+`"}`), nil)
	if err != nil {
		t.Fatalf("api_parameter.get: %v", err)
	}
	got := res.(map[string]interface{})
	if got["count"].(int) != 1 || got["truncated"].(bool) {
		t.Errorf("count/truncated = %v/%v", got["count"], got["truncated"])
	}
	// 版本不存在 → 明确报错而非空列表
	_, _, err = r.Execute(context.Background(), adminPrincipal("api_parameter.read"), uuid.New(), nil,
		"api_parameter.get", json.RawMessage(`{"model_version_id":"`+uuid.NewString()+`"}`), nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("缺失版本 err = %v, want not found", err)
	}
}

// TestAPIGraphQueryHappyPath api_graph.query 全量与按应用过滤。
func TestAPIGraphQueryHappyPath(t *testing.T) {
	appID := uuid.New()
	nodeIn := apisecurity.GraphNode{ID: uuid.New(), EndpointKey: "GET /a", ApplicationID: &appID}
	nodeOut := apisecurity.GraphNode{ID: uuid.New(), EndpointKey: "GET /b"}
	edge := apisecurity.GraphEdge{ID: uuid.New(), TargetEndpointID: nodeIn.ID, CallCount: 5}
	fs := &fakeSecurityReader{graph: &apisecurity.Graph{
		Nodes: []apisecurity.GraphNode{nodeIn, nodeOut},
		Edges: []apisecurity.GraphEdge{edge},
	}}
	r := newAPIRegistry(apiassets.NewMemStore(), &fakeModelReader{}, fs)
	ctx := context.Background()
	p := adminPrincipal("api_graph.read")

	res, _, err := r.Execute(ctx, p, uuid.New(), nil, "api_graph.query", json.RawMessage(`{}`), nil)
	if err != nil {
		t.Fatalf("api_graph.query: %v", err)
	}
	if got := res.(map[string]interface{}); got["node_count"].(int) != 2 || got["edge_count"].(int) != 1 {
		t.Errorf("全量 node/edge = %v/%v, want 2/1", got["node_count"], got["edge_count"])
	}

	res, _, err = r.Execute(ctx, p, uuid.New(), nil, "api_graph.query",
		json.RawMessage(`{"application_id":"`+appID.String()+`"}`), nil)
	if err != nil {
		t.Fatalf("api_graph.query filtered: %v", err)
	}
	got := res.(map[string]interface{})
	if got["node_count"].(int) != 1 || got["edge_count"].(int) != 1 {
		t.Errorf("过滤后 node/edge = %v/%v, want 1/1", got["node_count"], got["edge_count"])
	}
}

// TestAPIRuntimeStatisticsHappyPath api_runtime.statistics 透传聚合结果。
func TestAPIRuntimeStatisticsHappyPath(t *testing.T) {
	fs := &fakeSecurityReader{stats: &apisecurity.RuntimeStatistics{
		Total:         7,
		ByFinalAction: map[string]int{"BLOCK": 2, "PASS": 5},
		ByRiskLevel:   map[string]int{"HIGH": 2},
		TopEndpoints:  []apisecurity.EndpointEventCount{{EndpointKey: "GET /a", Count: 4}},
	}}
	r := newAPIRegistry(apiassets.NewMemStore(), &fakeModelReader{}, fs)
	res, _, err := r.Execute(context.Background(), adminPrincipal("api_runtime.read"), uuid.New(), nil,
		"api_runtime.statistics", nil, nil)
	if err != nil {
		t.Fatalf("api_runtime.statistics: %v", err)
	}
	st, ok := res.(*apisecurity.RuntimeStatistics)
	if !ok || st.Total != 7 || st.ByFinalAction["BLOCK"] != 2 {
		t.Errorf("statistics = %+v", res)
	}
}

// TestAPIRiskSearchHappyPath api_risk.search 过滤与 detail 脱敏。
func TestAPIRiskSearchHappyPath(t *testing.T) {
	fs := &fakeSecurityReader{findings: []apisecurity.RuntimeFinding{
		{ID: uuid.New(), FindingType: "BOLA", Severity: "HIGH", Status: "OPEN",
			Title: "疑似越权", Detail: json.RawMessage(`{"password":"x123","field":"body.id"}`)},
		{ID: uuid.New(), FindingType: "SHADOW", Severity: "LOW", Status: "OPEN", Title: "影子API"},
	}}
	r := newAPIRegistry(apiassets.NewMemStore(), &fakeModelReader{}, fs)
	res, _, err := r.Execute(context.Background(), adminPrincipal("api_runtime.read"), uuid.New(), nil,
		"api_risk.search", json.RawMessage(`{"severity":"high","limit":50}`), nil)
	if err != nil {
		t.Fatalf("api_risk.search: %v", err)
	}
	got := res.(map[string]interface{})
	if got["total"].(int64) != 1 {
		t.Fatalf("HIGH total = %v, want 1", got["total"])
	}
	detail := got["items"].([]map[string]interface{})[0]["detail"].(string)
	if strings.Contains(detail, "x123") || !strings.Contains(detail, "********") {
		t.Errorf("detail 未脱敏: %s", detail)
	}
}

// TestAPILearningStatusHappyPath api_learning.status 返回学习状态与样本统计。
func TestAPILearningStatusHappyPath(t *testing.T) {
	mem, e1, _ := seedEndpoints(t)
	r := newAPIRegistry(mem, &fakeModelReader{}, &fakeSecurityReader{})
	ctx := context.Background()
	p := adminPrincipal("api_learning.read")

	res, _, err := r.Execute(ctx, p, uuid.New(), nil, "api_learning.status",
		json.RawMessage(`{"endpoint_id":"`+e1.ID.String()+`"}`), nil)
	if err != nil {
		t.Fatalf("api_learning.status: %v", err)
	}
	got := res.(map[string]interface{})
	if got["learning_status"] != "NOT_STARTED" {
		t.Errorf("learning_status = %v, want NOT_STARTED", got["learning_status"])
	}
	if got["latest_job"] != nil {
		t.Errorf("未学习时 latest_job 应为 nil, got %v", got["latest_job"])
	}
	samples := got["samples"].(map[string]interface{})
	if samples["total"].(int64) != 0 {
		t.Errorf("samples.total = %v, want 0", samples["total"])
	}

	_, _, err = r.Execute(ctx, p, uuid.New(), nil, "api_learning.status",
		json.RawMessage(`{"endpoint_id":"`+uuid.NewString()+`"}`), nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("缺失端点 err = %v, want not found", err)
	}
}

// TestAPIClassificationExplainHappyPath api_classification.explain 返回维度来源与置信度。
func TestAPIClassificationExplainHappyPath(t *testing.T) {
	mem, e1, _ := seedEndpoints(t)
	fs := &fakeSecurityReader{dims: []apisecurity.ClassificationDimension{
		{Dimension: "PURPOSE", Value: "USER_MGMT", Source: "AUTO", Confidence: 0.6},
		{Dimension: "EXPOSURE", Value: "PUBLIC", Source: "MANUAL", Confidence: 1},
	}}
	r := newAPIRegistry(mem, &fakeModelReader{}, fs)
	res, _, err := r.Execute(context.Background(), adminPrincipal("api_classification.read"), uuid.New(), nil,
		"api_classification.explain", json.RawMessage(`{"endpoint_id":"`+e1.ID.String()+`"}`), nil)
	if err != nil {
		t.Fatalf("api_classification.explain: %v", err)
	}
	got := res.(map[string]interface{})
	dims := got["dimensions"].([]apisecurity.ClassificationDimension)
	if len(dims) != 2 || dims[0].Source != "AUTO" || dims[1].Confidence != 1 {
		t.Errorf("dimensions = %+v", dims)
	}
	if got["classification_locked"].(bool) {
		t.Errorf("classification_locked 应为 false")
	}
	if got["note"] == "" {
		t.Errorf("缺少解释说明 note")
	}
}
