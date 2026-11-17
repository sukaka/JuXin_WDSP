package apidataflow

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

type fakeReader struct {
	graph      *Graph
	evidence   []EvidenceRecord
	quality    DataQuality
	err        error
	lastFilter GraphFilter
}

func (f *fakeReader) Graph(_ context.Context, filter GraphFilter) (*Graph, error) {
	f.lastFilter = filter
	if f.err != nil {
		return nil, f.err
	}
	return f.graph, nil
}
func (f *fakeReader) Evidence(_ context.Context, _ string, filter GraphFilter, _ int) ([]EvidenceRecord, error) {
	f.lastFilter = filter
	return f.evidence, f.err
}
func (f *fakeReader) Quality(_ context.Context, _ GraphFilter) (DataQuality, error) {
	return f.quality, f.err
}

func TestDataflowHandlers(t *testing.T) {
	now := time.Now().UTC()
	reader := &fakeReader{
		graph: &Graph{
			Nodes: []Node{{ID: "service:orders", Name: "orders", Type: "SERVICE", Calls: 2, APICount: 1, Health: "HEALTHY"}},
			Edges: []Edge{{ID: "service:orders->service:profile|HTTP", SourceID: "service:orders", TargetID: "service:profile", SourceName: "orders", TargetName: "profile", Protocol: "HTTP", Calls: 2, DataTypes: []string{"PHONE"}, FirstSeenAt: now, LastSeenAt: now}},
		},
		quality: DataQuality{Observations: 2, TraceLinked: 2, TraceCoverage: 1, DataSource: "clickhouse"},
		evidence: []EvidenceRecord{{
			AgentID: uuid.New(), EventID: "ev-1", EdgeID: "edge-1", EvidenceType: "OBSERVED",
			PeerAddress: "10.0.0.8", ClientAddress: "8.8.8.8", ClientAddressSource: "TRUSTED_PROXY", ServerAddress: "10.20.0.30",
			SourceZone: "PUBLIC", TargetZone: "INTERNAL", BoundaryType: "PUBLIC_TO_INTERNAL", BoundaryEvidence: "TRUSTED_PROXY",
		}},
	}
	mux := http.NewServeMux()
	RegisterRoutes(mux, func(handler http.Handler) http.Handler { return handler }, NewHandler(reader))
	authenticatedMux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: map[string]bool{
			PermDataFlowRead: true, PermDataFlowEvidenceRead: true,
		}}
		mux.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), principal)))
	})

	t.Run("graph", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/data-flow/graph?max_edges=10&view=network", nil)
		authenticatedMux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "PHONE") || !strings.Contains(rr.Body.String(), "trace_coverage") {
			t.Fatalf("unexpected graph response: %d %s", rr.Code, rr.Body.String())
		}
		if reader.lastFilter.MaxEdges != 10 || reader.lastFilter.View != "network" {
			t.Fatalf("max_edges not passed: %+v", reader.lastFilter)
		}
	})

	t.Run("boundary graph", func(t *testing.T) {
		reader.graph.View = "boundary"
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/data-flow/graph?view=BOUNDARY&max_edges=25&method=get&data_type=PHONE&application_id=7abf5de5-8c6f-4ea6-9420-f6d1b87c4215", nil)
		authenticatedMux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"view":"boundary"`) {
			t.Fatalf("unexpected boundary graph response: %d %s", rr.Code, rr.Body.String())
		}
		filter := reader.lastFilter
		if filter.View != "boundary" || filter.MaxEdges != 25 || filter.Method != "GET" || filter.DataType != "PHONE" || filter.ApplicationID == nil || filter.ApplicationID.String() != "7abf5de5-8c6f-4ea6-9420-f6d1b87c4215" {
			t.Fatalf("boundary filters not passed: %+v", filter)
		}
	})

	t.Run("node dependencies", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/data-flow/nodes/service:orders", nil)
		authenticatedMux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "dependencies") || !strings.Contains(rr.Body.String(), "profile") {
			t.Fatalf("unexpected node response: %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("evidence", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/data-flow/evidence?edge_id=service:orders-%3Eservice:profile%7CHTTP&view=boundary", nil)
		authenticatedMux.ServeHTTP(rr, req)
		body := rr.Body.String()
		if rr.Code != http.StatusOK || !strings.Contains(body, "ev-1") {
			t.Fatalf("unexpected evidence response: %d %s", rr.Code, body)
		}
		for _, value := range []string{`"peer_address":"10.0.0.8"`, `"client_address":"8.8.8.8"`, `"client_address_source":"TRUSTED_PROXY"`, `"server_address":"10.20.0.30"`, `"source_zone":"PUBLIC"`, `"target_zone":"INTERNAL"`, `"boundary_type":"PUBLIC_TO_INTERNAL"`, `"boundary_evidence":"TRUSTED_PROXY"`} {
			if !strings.Contains(body, value) {
				t.Errorf("evidence response missing %s: %s", value, body)
			}
		}
		if reader.lastFilter.View != "boundary" {
			t.Fatalf("evidence view not passed: %+v", reader.lastFilter)
		}
	})

	t.Run("invalid time and unavailable", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/data-flow/graph?start=bad", nil)
		authenticatedMux.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
		reader.err = ErrObservationDataPlane
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/api/v1/api-security/data-flow/graph", nil)
		authenticatedMux.ServeHTTP(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d body=%s", rr.Code, rr.Body.String())
		}
		reader.err = nil
	})

	t.Run("internal error", func(t *testing.T) {
		reader.err = errors.New("query failed")
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/data-flow/graph", nil)
		authenticatedMux.ServeHTTP(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rr.Code)
		}
	})
}

func TestDataflowGraphHandlerMergesRuntimeFieldWarning(t *testing.T) {
	reader := &fakeReader{
		graph: &Graph{
			Nodes: []Node{}, Edges: []Edge{}, Truncated: true,
			RuntimeFieldsWarning: "网关敏感字段未完整关联，请缩小时间窗/稍后重试",
		},
		quality: DataQuality{Observations: 2, TraceLinked: 2, TraceCoverage: 1, DataSource: "clickhouse", Message: "观测数据完整度以当前采集覆盖率为准"},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/data-flow/graph", nil)
	NewHandler(reader).Graph(rr, req)
	body := rr.Body.String()
	if rr.Code != http.StatusOK || !strings.Contains(body, `"partial":true`) ||
		!strings.Contains(body, `"message":"网关敏感字段未完整关联，请缩小时间窗/稍后重试"`) || !strings.Contains(body, `"truncated":true`) {
		t.Fatalf("runtime field degradation was not visible in final quality: %d %s", rr.Code, body)
	}
	if strings.Contains(body, "RuntimeFieldsWarning") || strings.Contains(body, "runtime_fields_warning") {
		t.Fatalf("internal warning leaked as an unnecessary API field: %s", body)
	}
}
