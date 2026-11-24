package apisecurity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apm"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// ---------- Fake ClickHouse rows/querier ----------

type fakeCHRows struct {
	rows [][]any
	idx  int
	err  error
}

func (r *fakeCHRows) Next() bool {
	if r.idx >= len(r.rows) {
		return false
	}
	r.idx++
	return true
}

func (r *fakeCHRows) Scan(dest ...any) error {
	row := r.rows[r.idx-1]
	if len(dest) != len(row) {
		return errors.New("column count mismatch")
	}
	for i := range dest {
		switch d := dest[i].(type) {
		case *string:
			*d = row[i].(string)
		case *uint64:
			*d = row[i].(uint64)
		case *float64:
			*d = row[i].(float64)
		case *[]string:
			*d = append([]string(nil), row[i].([]string)...)
		case *time.Time:
			*d = row[i].(time.Time)
		default:
			return errors.New("unsupported scan type")
		}
	}
	return nil
}

func (r *fakeCHRows) Close() error { return nil }
func (r *fakeCHRows) Err() error   { return r.err }

type fakeCHQuerier struct {
	otelRows     [][]any
	otelErr      error
	dataflowRows [][]any
	dataflowErr  error
	queries      []string
}

func (q *fakeCHQuerier) Query(_ context.Context, query string, _ ...any) (apm.CHRows, error) {
	q.queries = append(q.queries, query)
	if strings.Contains(query, "apm.otel_traces") {
		if q.otelErr != nil {
			return nil, q.otelErr
		}
		return &fakeCHRows{rows: q.otelRows}, nil
	}
	if strings.Contains(query, "wdsp.data_flow_contributions") {
		if q.dataflowErr != nil {
			return nil, q.dataflowErr
		}
		return &fakeCHRows{rows: q.dataflowRows}, nil
	}
	return &fakeCHRows{}, nil
}

// ---------- Identity Graph Filter Tests ----------

func TestApplyGraphFilterExcludesStaticIgnoredAndIsolated(t *testing.T) {
	appA := uuid.New()
	appB := uuid.New()
	epOrders := GraphNode{
		ID: uuid.New(), EndpointKey: "POST /api/v1/orders", HTTPMethod: "POST",
		NormalizedPath: "/api/v1/orders", ApplicationID: &appA, ApplicationName: "订单系统",
		Host: "api.example.com", IsAPI: true, AssetStatus: "DISCOVERED",
	}
	epPay := GraphNode{
		ID: uuid.New(), EndpointKey: "POST /api/v1/pay", HTTPMethod: "POST",
		NormalizedPath: "/api/v1/pay", ApplicationID: &appA, ApplicationName: "订单系统",
		Host: "api.example.com", IsAPI: true, AssetStatus: "CONFIRMED",
	}
	epFavicon := GraphNode{
		ID: uuid.New(), EndpointKey: "GET /favicon_128x128.ico", HTTPMethod: "GET",
		NormalizedPath: "/favicon_128x128.ico", ApplicationID: &appA, ApplicationName: "订单系统",
		Host: "api.example.com", IsAPI: true, AssetStatus: "DISCOVERED",
	}
	epConfirmedPNG := GraphNode{
		ID: uuid.New(), EndpointKey: "GET /static/badge.png", HTTPMethod: "GET",
		NormalizedPath: "/static/badge.png", ApplicationID: &appA, ApplicationName: "订单系统",
		IsAPI: false, AssetStatus: "CONFIRMED",
	}
	epIgnored := GraphNode{
		ID: uuid.New(), EndpointKey: "GET /api/v1/old", HTTPMethod: "GET",
		NormalizedPath: "/api/v1/old", ApplicationID: &appA, ApplicationName: "订单系统",
		IsAPI: true, AssetStatus: "IGNORED",
	}
	epIsolated := GraphNode{
		ID: uuid.New(), EndpointKey: "GET /api/v1/health", HTTPMethod: "GET",
		NormalizedPath: "/api/v1/health", ApplicationID: &appB, ApplicationName: "网关系统",
		IsAPI: true, AssetStatus: "DISCOVERED",
	}

	raw := &Graph{
		Nodes: []GraphNode{epOrders, epPay, epFavicon, epConfirmedPNG, epIgnored, epIsolated},
		Edges: []GraphEdge{
			{ID: uuid.New(), CallerFingerprint: "u1", SourceEndpointID: &epOrders.ID, TargetEndpointID: epPay.ID, CallCount: 12},
			{ID: uuid.New(), CallerFingerprint: "u1", SourceEndpointID: &epOrders.ID, TargetEndpointID: epFavicon.ID, CallCount: 5},
			{ID: uuid.New(), CallerFingerprint: "u1", SourceEndpointID: &epIgnored.ID, TargetEndpointID: epPay.ID, CallCount: 3},
		},
	}

	// 开启 exclude_static + exclude_ignored + only_connected：
	// favicon 被按静态排除，ignored 被排除，epConfirmedPNG 虽受 CONFIRMED 保护但不含边被 only_connected 隐藏，epIsolated 孤立隐藏。
	got := applyGraphFilter(raw, GraphFilter{
		ExcludeStatic:  true,
		ExcludeIgnored: true,
		OnlyConnected:  true,
	})
	if len(got.Nodes) != 2 || len(got.Edges) != 1 {
		t.Fatalf("filtered nodes/edges = %d/%d, want 2/1: %+v", len(got.Nodes), len(got.Edges), got)
	}
	if got.Summary == nil || got.Summary.StaticNoiseNodes != 1 || got.Summary.IgnoredNodes != 1 || got.Summary.IsolatedNodes != 2 {
		t.Fatalf("summary = %+v, want static=1 ignored=1 isolated=2", got.Summary)
	}

	// 未开启 only_connected 但开启 exclude_static 时，CONFIRMED 静态端点仍被保护保留
	gotProtected := applyGraphFilter(raw, GraphFilter{ExcludeStatic: true, ExcludeIgnored: true})
	foundConfirmedPNG := false
	for _, n := range gotProtected.Nodes {
		if n.ID == epConfirmedPNG.ID {
			foundConfirmedPNG = true
		}
		if n.ID == epFavicon.ID {
			t.Errorf("unconfirmed favicon should be excluded")
		}
	}
	if !foundConfirmedPNG {
		t.Errorf("CONFIRMED endpoint must never be filtered out by exclude_static")
	}

	// 按应用 + 关键词过滤
	gotApp := applyGraphFilter(raw, GraphFilter{ApplicationID: &appB, Keyword: "网关"})
	if len(gotApp.Nodes) != 1 || gotApp.Nodes[0].ID != epIsolated.ID {
		t.Fatalf("app+keyword filter got %+v, want epIsolated only", gotApp.Nodes)
	}
}

type stubGraphRepo struct {
	lastFilter GraphFilter
	result     *Graph
}

func (s *stubGraphRepo) ListGraphWithFilter(_ context.Context, f GraphFilter) (*Graph, error) {
	s.lastFilter = f
	if s.result != nil {
		return s.result, nil
	}
	return &Graph{Nodes: []GraphNode{}, Edges: []GraphEdge{}, Summary: &GraphSummary{}}, nil
}

func TestHandlerGraphQueryValidation(t *testing.T) {
	repo := &stubGraphRepo{}
	h := NewHandler(nil, nil)
	h.SetGraphRepository(repo)

	badURLs := []string{
		"/api/v1/api-security/graph?application_id=not-uuid",
		"/api/v1/api-security/graph?status=INVALID",
		"/api/v1/api-security/graph?exclude_static=maybe",
		"/api/v1/api-security/graph?only_connected=2",
		"/api/v1/api-security/graph?keyword=" + strings.Repeat("a", 129),
	}
	for _, u := range badURLs {
		req := httptest.NewRequest(http.MethodGet, u, nil)
		rec := httptest.NewRecorder()
		h.Graph(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s status = %d, want 400 (body=%s)", u, rec.Code, rec.Body.String())
		}
	}

	appID := uuid.New()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/api-security/graph?application_id="+appID.String()+"&status=confirmed&exclude_static=true&exclude_ignored=true&only_connected=true&min_count=3&keyword=orders",
		nil)
	rec := httptest.NewRecorder()
	h.Graph(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid GET /graph status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if repo.lastFilter.ApplicationID == nil || *repo.lastFilter.ApplicationID != appID ||
		repo.lastFilter.Status != "CONFIRMED" || !repo.lastFilter.ExcludeStatic ||
		!repo.lastFilter.ExcludeIgnored || !repo.lastFilter.OnlyConnected ||
		repo.lastFilter.MinCount != 3 || repo.lastFilter.Keyword != "orders" {
		t.Fatalf("unexpected parsed GraphFilter: %+v", repo.lastFilter)
	}
}

// ---------- Backend Microservice RPC Graph Tests ----------

func TestBuildServiceRPCGraphMergeAndFilters(t *testing.T) {
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	raw := []ServiceRPCEdge{
		{
			Source: "order-svc", Target: "inventory-svc", TargetType: "SERVICE",
			Protocol: "grpc", EvidenceType: "OTEL_SPAN_PAIRED", Paired: true, DataSource: "otel_traces",
			Calls: 80, ErrorCount: 2, AvgMS: 12.0, P95MS: 30.0,
			Operations:     []string{"inventory.StockService/Reserve"},
			SampleTraceIDs: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			FirstSeenAt:    now.Add(-20 * time.Minute), LastSeenAt: now.Add(-2 * time.Minute),
		},
		// 同一服务对同协议由另一路单侧观测补入：应合并且保留双端配对证据
		{
			Source: "order-svc", Target: "inventory-svc", TargetType: "SERVICE",
			Protocol: "GRPC", EvidenceType: "AGENT_GRPC_OBSERVED", Paired: false, DataSource: "agent_grpc",
			Calls: 20, ErrorCount: 3, AvgMS: 22.0, P95MS: 45.0,
			Operations:     []string{"inventory.StockService/Release"},
			SampleTraceIDs: []string{},
			FirstSeenAt:    now.Add(-30 * time.Minute), LastSeenAt: now.Add(-1 * time.Minute),
		},
		// 微服务间 HTTP 调用（双端配对）
		{
			Source: "order-svc", Target: "payment-svc", TargetType: "SERVICE",
			Protocol: "HTTP", EvidenceType: "AGENT_TRACE_PAIRED", Paired: true, DataSource: "agent_dataflow",
			Calls: 50, ErrorCount: 5, AvgMS: 25.0, P95MS: 60.0,
			Operations:     []string{"POST /internal/pay"},
			SampleTraceIDs: []string{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			FirstSeenAt:    now.Add(-15 * time.Minute), LastSeenAt: now,
		},
		// 未配对外部调用
		{
			Source: "payment-svc", Target: "api.stripe.com", TargetType: "EXTERNAL",
			Protocol: "HTTP", EvidenceType: "OTEL_CLIENT_SPAN", Paired: false, DataSource: "otel_traces",
			Calls: 15, ErrorCount: 0, AvgMS: 180.0, P95MS: 240.0,
			Operations:  []string{"POST /v1/charges"},
			FirstSeenAt: now.Add(-10 * time.Minute), LastSeenAt: now,
		},
	}

	// 1) 默认：不包含 EXTERNAL，保留全部内部服务间调用（RPC + HTTP），同键合并
	g := buildServiceRPCGraph(raw, nil, ServiceRPCGraphFilter{
		Start: now.Add(-time.Hour), End: now, Protocol: "ALL",
	})
	if len(g.Edges) != 2 || len(g.Nodes) != 3 {
		t.Fatalf("default graph edges/nodes = %d/%d, want 2/3", len(g.Edges), len(g.Nodes))
	}
	inv := g.Edges[0]
	if inv.Source != "order-svc" || inv.Target != "inventory-svc" || inv.Protocol != "GRPC" {
		t.Fatalf("top edge = %+v, want order-svc->inventory-svc GRPC", inv)
	}
	if inv.Calls != 100 || inv.ErrorCount != 5 || inv.ErrorRate != 0.05 || inv.AvgMS != 14.0 || inv.P95MS != 45.0 {
		t.Fatalf("merged metrics = calls=%d err=%d rate=%v avg=%v p95=%v",
			inv.Calls, inv.ErrorCount, inv.ErrorRate, inv.AvgMS, inv.P95MS)
	}
	if !inv.Paired || inv.EvidenceType != "OTEL_SPAN_PAIRED" || len(inv.Operations) != 2 {
		t.Fatalf("merged evidence/ops = paired=%v ev=%s ops=%v", inv.Paired, inv.EvidenceType, inv.Operations)
	}
	if g.Summary.RPCEdges != 1 || g.Summary.HTTPEdges != 1 || g.Summary.PairedEdges != 2 || g.Summary.ErrorEdges != 2 {
		t.Fatalf("summary = %+v", g.Summary)
	}

	// 2) 仅看 RPC 协议（过滤掉 HTTP）
	gRPCOnly := buildServiceRPCGraph(raw, nil, ServiceRPCGraphFilter{
		Start: now.Add(-time.Hour), End: now, Protocol: "RPC",
	})
	if len(gRPCOnly.Edges) != 1 || gRPCOnly.Edges[0].Protocol != "GRPC" {
		t.Fatalf("RPC-only edges = %+v, want 1 GRPC edge", gRPCOnly.Edges)
	}

	// 3) 仅双端配对：在合并前过滤掉单侧 20 次，只保留双端配对 80 次
	gPaired := buildServiceRPCGraph(raw, nil, ServiceRPCGraphFilter{
		Start: now.Add(-time.Hour), End: now, Protocol: "RPC", PairedOnly: true,
	})
	if len(gPaired.Edges) != 1 || gPaired.Edges[0].Calls != 80 {
		t.Fatalf("paired-only edges = %+v, want 1 edge with calls=80", gPaired.Edges)
	}

	// 4) 开启 IncludeExternal
	gExt := buildServiceRPCGraph(raw, nil, ServiceRPCGraphFilter{
		Start: now.Add(-time.Hour), End: now, Protocol: "ALL", IncludeExternal: true,
	})
	if len(gExt.Edges) != 3 || gExt.Summary.ExternalNodes != 1 {
		t.Fatalf("include external edges=%d extNodes=%d, want 3/1", len(gExt.Edges), gExt.Summary.ExternalNodes)
	}
}

func TestDefaultServiceRPCGraphReaderCHIntegrationAndDegradation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	f := ServiceRPCGraphFilter{Start: now.Add(-time.Hour), End: now, Protocol: "ALL", Limit: 200}

	// 1) ClickHouse 未配置 + db=nil：优雅降级，不报错、不造假数据
	degraded := NewServiceRPCGraphReader(nil, func(context.Context) apm.CHQuerier { return nil })
	gEmpty, err := degraded.ServiceRPCGraph(context.Background(), f)
	if err != nil {
		t.Fatalf("degraded ServiceRPCGraph err: %v", err)
	}
	if len(gEmpty.Nodes) != 0 || len(gEmpty.Edges) != 0 || len(gEmpty.Sources) != 3 {
		t.Fatalf("degraded graph = nodes:%d edges:%d sources:%d", len(gEmpty.Nodes), len(gEmpty.Edges), len(gEmpty.Sources))
	}
	if gEmpty.Sources[0].Status != "NOT_CONFIGURED" {
		t.Errorf("otel status = %s, want NOT_CONFIGURED", gEmpty.Sources[0].Status)
	}

	// 2) OTel 有真实双端配对数据，Dataflow 报错降级：OTel 结果完好返回、Dataflow 标 UNAVAILABLE
	fq := &fakeCHQuerier{
		otelRows: [][]any{
			{
				"gateway-bff", "user-service", "SERVICE", "GRPC", "OTEL_SPAN_PAIRED",
				uint64(42), uint64(1), float64(8.4), float64(19.2),
				[]string{"user.UserService/GetProfile"},
				[]string{"11111111111111111111111111111111"},
				now.Add(-10 * time.Minute), now,
			},
		},
		dataflowErr: errors.New("table wdsp.data_flow_contributions does not exist"),
	}
	reader := NewServiceRPCGraphReader(nil, func(context.Context) apm.CHQuerier { return fq })
	g, err := reader.ServiceRPCGraph(context.Background(), f)
	if err != nil {
		t.Fatalf("ServiceRPCGraph err: %v", err)
	}
	if len(g.Edges) != 1 || g.Edges[0].Source != "gateway-bff" || g.Edges[0].Target != "user-service" || !g.Edges[0].Paired {
		t.Fatalf("unexpected OTel edge: %+v", g.Edges)
	}
	if g.Sources[0].Status != "READY" || g.Sources[1].Status != "UNAVAILABLE" {
		t.Fatalf("sources status = %+v, want otel=READY dataflow=UNAVAILABLE", g.Sources)
	}
}

func TestHandlerServiceRPCGraphValidationAndRBAC(t *testing.T) {
	h := NewHandler(nil, nil)
	h.SetServiceRPCGraphReader(NewServiceRPCGraphReader(nil, nil))

	badURLs := []string{
		"/api/v1/api-security/service-rpc-graph?start=bad",
		"/api/v1/api-security/service-rpc-graph?end=bad",
		"/api/v1/api-security/service-rpc-graph?start=2026-11-24T10:00:00Z&end=2026-11-24T09:00:00Z",
		"/api/v1/api-security/service-rpc-graph?start=2026-11-22T00:00:00Z&end=2026-11-24T00:00:00Z", // >24h
		"/api/v1/api-security/service-rpc-graph?protocol=UNKNOWN_PROTO",
		"/api/v1/api-security/service-rpc-graph?paired_only=invalid",
		"/api/v1/api-security/service-rpc-graph?min_calls=-1",
		"/api/v1/api-security/service-rpc-graph?limit=999",
	}
	for _, u := range badURLs {
		req := httptest.NewRequest(http.MethodGet, u, nil)
		rec := httptest.NewRecorder()
		h.ServiceRPCGraph(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s status = %d, want 400 (body=%s)", u, rec.Code, rec.Body.String())
		}
	}

	// 权限校验：路由层必须要求 api_graph.read
	mux := http.NewServeMux()
	passAuthz := func(next http.Handler) http.Handler { return next }
	RegisterRoutes(mux, passAuthz, h)

	reqNoPerm := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/service-rpc-graph", nil)
	reqNoPerm = reqNoPerm.WithContext(authz.WithPrincipal(reqNoPerm.Context(), &authz.Principal{
		UserID: uuid.New(), Username: "viewer",
		Permissions: []string{"api_policy.read"},
		PermsSet:    map[string]bool{"api_policy.read": true},
	}))
	recNoPerm := httptest.NewRecorder()
	mux.ServeHTTP(recNoPerm, reqNoPerm)
	if recNoPerm.Code != http.StatusForbidden {
		t.Fatalf("missing api_graph.read status = %d, want 403", recNoPerm.Code)
	}

	reqOK := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/service-rpc-graph?protocol=RPC&paired_only=true", nil)
	reqOK = reqOK.WithContext(authz.WithPrincipal(reqOK.Context(), &authz.Principal{
		UserID: uuid.New(), Username: "secadmin",
		Permissions: []string{"api_graph.read"},
		PermsSet:    map[string]bool{"api_graph.read": true},
	}))
	recOK := httptest.NewRecorder()
	mux.ServeHTTP(recOK, reqOK)
	if recOK.Code != http.StatusOK {
		t.Fatalf("authorized GET /service-rpc-graph status = %d, want 200 (body=%s)", recOK.Code, recOK.Body.String())
	}
	var env struct {
		Data ServiceRPCGraph `json:"data"`
	}
	if err := json.Unmarshal(recOK.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(env.Data.Sources) != 3 {
		t.Fatalf("response sources = %d, want 3", len(env.Data.Sources))
	}
}
