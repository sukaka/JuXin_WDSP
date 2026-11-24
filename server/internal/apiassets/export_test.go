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
	wantHeader := "\xef\xbb\xbf所属站点,站点域名,目录路径,请求方法,路径模板,原始路径示例,接口键,协议类型,是否 API,置信度,资产状态,学习状态,业务标签,资产价值,命中次数,首次发现时间,最近访问时间,确认时间,僵尸态起点\n"
	if !strings.HasPrefix(body, wantHeader) {
		t.Fatalf("csv header/BOM mismatch: got prefix %q, want %q", body[:min(len(body), len(wantHeader)+20)], wantHeader)
	}
	if !strings.Contains(body, "/api/export/{id}") || !strings.Contains(body, ",是,") || !strings.Contains(body, ",已发现,") || !strings.Contains(body, ",导出,") {
		t.Fatalf("csv row missing localized endpoint/business fields: %s", body)
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

func TestRenderEndpointsCSVLocalizationAndSecurity(t *testing.T) {
	now := time.Date(2026, 11, 24, 8, 30, 0, 0, time.UTC)
	confirmed := now.Add(time.Minute)
	zombie := now.Add(2 * time.Minute)

	rows := []Endpoint{
		{
			ApplicationName: "电商门户",
			Host:            "api.shop.local",
			DirectoryPath:   "/v1/orders",
			HTTPMethod:      "POST",
			NormalizedPath:  "/v1/orders/{id}",
			RawPathExample:  "/v1/orders/42",
			EndpointKey:     "POST /v1/orders/{id}",
			ProtocolType:    "REST_JSON",
			IsAPI:           true,
			APIConfidence:   0.9525,
			AssetStatus:     "CONFIRMED",
			LearningStatus:  "LEARNED",
			BusinessType:    "ORDER",
			AssetValue:      "CRITICAL",
			HitCount:        128,
			FirstSeenAt:     now,
			LastSeenAt:      now,
			ConfirmedAt:     &confirmed,
			ZombieSince:     &zombie,
		},
		{
			ApplicationName: "\t=SUM(A1)",
			Host:            "legacy.local",
			DirectoryPath:   "/old",
			HTTPMethod:      "GET",
			NormalizedPath:  "/old/item",
			RawPathExample:  "/old/item",
			EndpointKey:     "GET /old/item",
			ProtocolType:    "UNKNOWN_HTTP",
			IsAPI:           false,
			APIConfidence:   0.2,
			AssetStatus:     "ZOMBIE",
			LearningStatus:  "NOT_STARTED",
			BusinessType:    "OTHER",
			AssetValue:      "",
			HitCount:        3,
			FirstSeenAt:     now,
			LastSeenAt:      now,
		},
		{
			ApplicationName: "未知回退站",
			Host:            "\r+1+1",
			DirectoryPath:   "/custom",
			HTTPMethod:      "PATCH",
			NormalizedPath:  "/custom/x",
			RawPathExample:  "/custom/x",
			EndpointKey:     "PATCH /custom/x",
			ProtocolType:    "FUTURE_PROTO",
			IsAPI:           true,
			APIConfidence:   0.5,
			AssetStatus:     "CUSTOM_STATUS",
			LearningStatus:  "CUSTOM_LEARN",
			BusinessType:    "CUSTOM_BIZ",
			AssetValue:      "CUSTOM_VAL",
			HitCount:        1,
			FirstSeenAt:     now,
			LastSeenAt:      now,
		},
	}

	out := renderEndpointsCSV(rows)
	if !strings.HasPrefix(out, "\xef\xbb\xbf"+endpointExportCSVHeader) {
		t.Fatalf("missing UTF-8 BOM or Chinese header: %q", out[:min(len(out), 120)])
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("line count=%d want 4, out=%q", len(lines), out)
	}
	wantRow1 := "电商门户,api.shop.local,/v1/orders,POST,/v1/orders/{id},/v1/orders/42,POST /v1/orders/{id},REST/JSON,是,0.9525,已确认,已完成,下单,极高,128,2026-11-24T08:30:00Z,2026-11-24T08:30:00Z,2026-11-24T08:31:00Z,2026-11-24T08:32:00Z"
	if lines[1] != wantRow1 {
		t.Fatalf("row1 mismatch:\n got: %s\nwant: %s", lines[1], wantRow1)
	}
	if !strings.HasPrefix(lines[2], "'\t=SUM(A1),legacy.local,") ||
		!strings.Contains(lines[2], ",未知 HTTP API,否,0.2000,僵尸接口,未开始,其他,,3,") {
		t.Fatalf("row2 mismatch: %s", lines[2])
	}
	if !strings.Contains(lines[3], "\"'\r+1+1\"") ||
		!strings.Contains(lines[3], ",FUTURE_PROTO,是,0.5000,CUSTOM_STATUS,CUSTOM_LEARN,CUSTOM_BIZ,CUSTOM_VAL,") {
		t.Fatalf("row3 fallback/escape mismatch: %s", lines[3])
	}

	// 覆盖全量枚举映射字典
	for raw, want := range map[string]string{
		"REST_JSON": "REST/JSON", "REST_XML": "REST/XML", "REST": "REST",
		"FORM_API": "Form 表单", "SOAP": "SOAP", "GRAPHQL": "GraphQL",
		"JSON_RPC": "JSON-RPC", "XML_RPC": "XML-RPC", "WEBHOOK": "Webhook",
		"FILE_UPLOAD": "文件上传", "FILE_DOWNLOAD": "文件下载",
		"WEBSOCKET_HANDSHAKE": "WebSocket 握手", "WEBSOCKET": "WebSocket",
		"SERVER_SENT_EVENTS": "SSE", "GRPC": "gRPC",
		"UNKNOWN_HTTP_API": "未知 HTTP API", "UNKNOWN_HTTP": "未知 HTTP API",
		"": "",
	} {
		if got := exportProtocolLabel(raw); got != want {
			t.Errorf("exportProtocolLabel(%q) = %q, want %q", raw, got, want)
		}
	}
	for raw, want := range map[string]string{
		"DISCOVERED": "已发现", "CONFIRMED": "已确认", "IGNORED": "已忽略",
		"DEPRECATED": "已废弃", "ZOMBIE": "僵尸接口", "": "",
	} {
		if got := exportAssetStatusLabel(raw); got != want {
			t.Errorf("exportAssetStatusLabel(%q) = %q, want %q", raw, got, want)
		}
	}
	for raw, want := range map[string]string{
		"NOT_STARTED": "未开始", "LEARNING": "学习中", "PAUSED": "已暂停", "LEARNED": "已完成", "": "",
	} {
		if got := exportLearningStatusLabel(raw); got != want {
			t.Errorf("exportLearningStatusLabel(%q) = %q, want %q", raw, got, want)
		}
	}
	for bt := range validBusinessTypes {
		got := exportBusinessTypeLabel(bt)
		if got == bt {
			t.Errorf("business_type %q missing Chinese label", bt)
		}
	}
	for raw, want := range map[string]string{
		"CRITICAL": "极高", "HIGH": "高", "MEDIUM": "中", "LOW": "低", "": "",
	} {
		if got := exportAssetValueLabel(raw); got != want {
			t.Errorf("exportAssetValueLabel(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestEndpointExportCSVSelectedIDs(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	ep1, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		Method: "GET", PathTemplate: "/api/v1/orders/{id}", Host: "shop.example.com", Confidence: 0.9, IsAPI: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ep2, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		Method: "POST", PathTemplate: "/api/v1/payments/{id}", Host: "shop.example.com", Confidence: 0.9, IsAPI: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		Method: "DELETE", PathTemplate: "/api/v1/unselected/{id}", Host: "shop.example.com", Confidence: 0.9, IsAPI: true,
	}); err != nil {
		t.Fatal(err)
	}

	h := NewHandler(store, nil)
	mux := newTestMux(h)

	// 仅导出选中的 ep1 与 ep2，未勾选的 ep3 不得出现
	rr := doJSON(t, mux, http.MethodGet,
		"/api/v1/api-security/endpoints/export?format=csv&ids="+ep1.ID.String()+","+ep2.ID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("selected export status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "/api/v1/orders/{id}") || !strings.Contains(body, "/api/v1/payments/{id}") {
		t.Fatalf("selected rows missing: %s", body)
	}
	if strings.Contains(body, "/api/v1/unselected/{id}") {
		t.Fatalf("unselected row leaked into export: %s", body)
	}

	// 空 ids 参数与非法 UUID 必须被 400 拒绝，不得退化为全量导出
	for _, q := range []string{"ids=", "ids=not-a-uuid"} {
		rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/export?format=csv&"+q, nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("query %q: status=%d, want 400, body=%s", q, rr.Code, rr.Body.String())
		}
	}
}
