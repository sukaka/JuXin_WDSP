package apiassets

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apimodels"
)

type fakeExportModelReader struct {
	versions []apimodels.Version
	params   []apimodels.Parameter
	schemas  []apimodels.ResponseSchema
	err      error
}

func (f *fakeExportModelReader) ListByEndpoint(_ context.Context, _ uuid.UUID, _, _ int) ([]apimodels.Version, int64, error) {
	return f.versions, int64(len(f.versions)), f.err
}

func (f *fakeExportModelReader) ListParametersByVersion(_ context.Context, _ uuid.UUID) ([]apimodels.Parameter, error) {
	return f.params, f.err
}

func (f *fakeExportModelReader) ListResponseSchemas(_ context.Context, _ string) ([]apimodels.ResponseSchema, error) {
	return f.schemas, f.err
}

type fakeExportExtrasProvider struct {
	extras *ExportExtras
	err    error
}

func (f *fakeExportExtrasProvider) LoadExportExtras(_ context.Context, _ uuid.UUID) (*ExportExtras, error) {
	return f.extras, f.err
}

func TestEndpointExportDetailHTTP(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	ep, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		Method: "GET", PathTemplate: "/v1/users/{id}", Host: "api.example.com",
		Confidence: 0.8, IsAPI: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertAsset(ctx, ep.ID, AssetProfile{Purpose: "用户查询", Exposure: "PARTNER", Owner: "security", Tags: []string{"user", "pii"}, BusinessType: "QUERY_PERSONAL_DATA"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StartLearning(ctx, ep.ID, 10, nil); err != nil {
		t.Fatal(err)
	}
	store.AddLearningSample(LearningSample{EndpointID: ep.ID, RequestID: "req-1", SampleHash: "hash-1", Accepted: true, CollectedAt: time.Now().UTC()})
	if err := store.RecordTrafficBucket(ctx, ep.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	currentVersionID := uuid.New()
	modelReader := &fakeExportModelReader{
		versions: []apimodels.Version{{
			ID: currentVersionID, EndpointID: ep.ID, EndpointKey: ep.EndpointKey, VersionNumber: 2,
			Status: "FORMAL", Schema: map[string]string{"id": "number"}, ContentHash: "model-hash", Confidence: 0.9,
		}},
		params: []apimodels.Parameter{{
			ID: uuid.New(), ModelVersionID: currentVersionID, Direction: "REQUEST", Location: "PATH",
			StructuredPath: "id", ParameterName: "id", BaseType: "number", Required: true,
		}},
		schemas: []apimodels.ResponseSchema{{
			ID: uuid.New(), EndpointKey: ep.EndpointKey, StatusCode: 200,
			Fields: map[string]string{"id": "number", "name": "string"}, ContentHash: "resp-hash", SampleCount: 8,
		}},
	}
	extras := &ExportExtras{
		ClassificationDimensions: []ClassificationDimension{{EndpointID: ep.ID, Dimension: "PURPOSE", Value: "USER", Source: "MANUAL", Confidence: 1}},
		AgentSources: []ExportAgentSource{{
			AgentID: uuid.New(), EndpointID: &ep.ID, Host: "api.example.com", Method: "GET", PathTemplate: ep.NormalizedPath,
			SourceType: "ENVOY_TAP", SourceInstance: "envoy-a", AssociationState: "LINKED",
			Classification: &ExportClassification{
				IsAPI: true, Confidence: 0.85, Level: "CONFIRMED_API", Signals: []string{"content_type_json", "response_json"},
				ClassifiedAt: time.Now().UTC(),
			},
		}},
		Findings: []ExportFinding{{
			ID: uuid.New(), EndpointID: &ep.ID, RequestID: "req-risk", FindingType: "BOLA", Severity: "HIGH",
			Status: "NEW", Title: "对象越权风险", Detail: json.RawMessage(`{"reason":"test"}`),
		}},
		Weaknesses: []ExportWeakness{{
			ID: uuid.New(), EndpointID: &ep.ID, Code: "SENSITIVE_IN_QUERY", Name: "查询参数敏感", Category: "SENSITIVE",
			Severity: "MEDIUM", Status: "NEW", Evidence: json.RawMessage(`{"count":2}`), TriggerCount: 2,
		}},
		SensitiveFields: []ExportSensitiveField{{
			ID: uuid.New(), EndpointID: ep.ID, Direction: "RESPONSE", StructuredPath: "data.phone",
			DataType: "phone", Confidence: 0.9, DetectionSource: "RUNTIME", OccurrenceCount: 3,
		}},
	}
	h := NewHandler(store, nil).SetExportModelReader(modelReader).SetExportExtrasProvider(&fakeExportExtrasProvider{extras: extras})
	mux := newTestMux(h)

	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/export?format=json", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("detail export status=%d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type=%q", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".json") {
		t.Fatalf("Content-Disposition=%q", cd)
	}
	var bundle EndpointExportBundle
	if err := json.Unmarshal(rr.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode bundle: %v body=%s", err, rr.Body.String())
	}
	if bundle.Meta.ExportVersion != 1 || bundle.Meta.GeneratedBy != "tester" || bundle.Meta.EndpointID != ep.ID || bundle.Meta.ContentSHA256 == "" {
		t.Fatalf("bad meta: %+v", bundle.Meta)
	}
	if bundle.Endpoint == nil || bundle.Endpoint.ID != ep.ID || bundle.Endpoint.Asset == nil || bundle.Endpoint.Asset.Owner != "security" {
		t.Fatalf("bad endpoint section: %+v", bundle.Endpoint)
	}
	if !bundle.Classification.IsAPI || len(bundle.Classification.Dimensions) != 1 {
		t.Fatalf("bad classification section: %+v", bundle.Classification)
	}
	if bundle.Models.CurrentVersion == nil || bundle.Models.CurrentVersion.ID != currentVersionID ||
		len(bundle.Models.Parameters) != 1 || len(bundle.Models.ResponseSchemas) != 1 {
		t.Fatalf("bad models section: %+v", bundle.Models)
	}
	if bundle.Learning.Job == nil || len(bundle.Learning.RecentSamples) != 1 {
		t.Fatalf("bad learning section: %+v", bundle.Learning)
	}
	if bundle.Traffic["24h"] == nil || bundle.Traffic["24h"].Total != 1 {
		t.Fatalf("bad traffic section: %+v", bundle.Traffic)
	}
	if len(bundle.Sources) != 1 || bundle.Sources[0].Classification == nil ||
		bundle.Sources[0].Classification.Signals[1] != "response_json" {
		t.Fatalf("bad sources section: %+v", bundle.Sources)
	}
	if len(bundle.Security.Findings) != 1 || len(bundle.Security.Weaknesses) != 1 || len(bundle.Security.SensitiveFields) != 1 {
		t.Fatalf("bad security section: %+v", bundle.Security)
	}

	for _, tc := range []struct {
		name, url string
		want      int
	}{
		{"非法 ID", "/api/v1/api-security/endpoints/not-a-uuid/export", http.StatusBadRequest},
		{"不存在", "/api/v1/api-security/endpoints/" + uuid.NewString() + "/export", http.StatusNotFound},
		{"非法格式", "/api/v1/api-security/endpoints/" + ep.ID.String() + "/export?format=pdf", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := doJSON(t, mux, http.MethodGet, tc.url, nil)
			if got.Code != tc.want {
				t.Fatalf("status=%d want %d body=%s", got.Code, tc.want, got.Body.String())
			}
		})
	}

	unwired := NewHandler(store, nil)
	unwiredMux := newTestMux(unwired)
	rr = doJSON(t, unwiredMux, http.MethodGet, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/export", nil)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired provider status=%d want 503 body=%s", rr.Code, rr.Body.String())
	}
}

func TestEndpointExportCSV(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	ep, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		Method: "POST", PathTemplate: "/api/export/{id}", Host: "api.example.com",
		Confidence: 0.9, IsAPI: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertAsset(ctx, ep.ID, AssetProfile{Purpose: "数据导出", Exposure: "INTERNAL", Owner: "owner-a", BusinessType: "EXPORT"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/docs/{id}", Confidence: 0.1, IsAPI: false}); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(store, nil)
	mux := newTestMux(h)

	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/export?format=csv&asset_status=DISCOVERED&keyword=export", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("csv export status=%d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "text/csv") {
		t.Fatalf("Content-Type=%q", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".csv") {
		t.Fatalf("Content-Disposition=%q", cd)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "application_name,host,directory_path,http_method,normalized_path") {
		t.Fatalf("csv header missing: %s", body)
	}
	if !strings.Contains(body, "/api/export/{id}") || !strings.Contains(body, "EXPORT") {
		t.Fatalf("csv row missing endpoint/business fields: %s", body)
	}
	if strings.Contains(body, "/docs/{id}") {
		t.Fatalf("csv did not apply filters: %s", body)
	}

	if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		Method: "GET", PathTemplate: "/api/cmd/{id}", Host: "=cmd.example.com",
		Confidence: 0.5, IsAPI: true,
	}); err != nil {
		t.Fatal(err)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/export?keyword=cmd", nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "'=cmd.example.com") {
		t.Fatalf("formula host not escaped: status=%d body=%s", rr.Code, rr.Body.String())
	}
}
