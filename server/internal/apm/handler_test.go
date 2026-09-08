// handler_test.go APM 接口参数校验与降级分支测试（httptest + fake Repository，
// 不依赖数据库；权限在路由层由 middleware.RequirePermission 强制，经注入主体验证）。
package apm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// fakeRepo 内存版 Repository（记录调用入参，可注入错误）。
type fakeRepo struct {
	overviewArgs struct {
		start, end time.Time
		enabled    bool
	}
	servicesFilter   *ServicesFilter
	endpointsFilter  *EndpointsFilter
	searchFilter     *TraceSearchFilter
	sqlFilter        *SQLFilter
	exceptionsFilter *ExceptionsFilter
	depsFilter       *DependenciesFilter
	runtimeFilter    *RuntimeFilter
	traceArgs        struct {
		traceID            string
		start, end         *time.Time
		accessLogEnabled   bool
		ingestLagThreshold time.Duration
	}
	appCodeID    uuid.UUID
	overview     *OverviewData
	services     []ServiceRow
	detail       *ServiceDetailData
	endpoints    []EndpointRow
	trace        *TraceViewData
	search       *TraceSearchData
	sql          *SQLData
	exceptions   *ExceptionsData
	dependencies *DependenciesData
	runtime      *RuntimeData
	appCode      string
	err          error // 统一错误注入（优先级最高）
	notFound     bool  // ServiceDetail/AppCodeByID 返回 ErrNotFound
}

func (f *fakeRepo) Overview(_ context.Context, start, end time.Time, enabled bool) (*OverviewData, error) {
	f.overviewArgs.start, f.overviewArgs.end, f.overviewArgs.enabled = start, end, enabled
	if f.err != nil {
		return nil, f.err
	}
	if f.overview != nil {
		return f.overview, nil
	}
	return &OverviewData{DataSource: "agentless", AccessLogEnabled: enabled,
		StartTime: start, EndTime: end, Trend: []TrendBucket{},
		TopSlowApplications: []AppRankItem{}, TopErrorApplications: []AppRankItem{},
		TopSlowEndpoints: []EndpointStat{}}, nil
}

func (f *fakeRepo) ListServices(_ context.Context, q ServicesFilter) ([]ServiceRow, int64, error) {
	qCopy := q
	f.servicesFilter = &qCopy
	if f.err != nil {
		return nil, 0, f.err
	}
	return f.services, int64(len(f.services)), nil
}

func (f *fakeRepo) ServiceDetail(_ context.Context, id uuid.UUID, _, _ time.Time, _ bool) (*ServiceDetailData, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.notFound {
		return nil, ErrNotFound
	}
	if f.detail != nil {
		return f.detail, nil
	}
	return &ServiceDetailData{ApplicationID: id, Trend: []TrendBucket{},
		StatusClasses: []StatusClassCount{}, Actions: []ActionCount{}, TopEndpoints: []EndpointStat{}}, nil
}

func (f *fakeRepo) ListEndpoints(_ context.Context, q EndpointsFilter) ([]EndpointRow, int64, error) {
	qCopy := q
	f.endpointsFilter = &qCopy
	if f.err != nil {
		return nil, 0, f.err
	}
	return f.endpoints, int64(len(f.endpoints)), nil
}

func (f *fakeRepo) AppCodeByID(_ context.Context, id uuid.UUID) (string, error) {
	f.appCodeID = id
	if f.err != nil {
		return "", f.err
	}
	if f.notFound {
		return "", ErrNotFound
	}
	return f.appCode, nil
}

func (f *fakeRepo) TraceView(_ context.Context, traceID string, start, end *time.Time, accessLogEnabled bool, ingestLagThreshold time.Duration) (*TraceViewData, error) {
	f.traceArgs.traceID, f.traceArgs.start, f.traceArgs.end = traceID, start, end
	f.traceArgs.accessLogEnabled, f.traceArgs.ingestLagThreshold = accessLogEnabled, ingestLagThreshold
	if f.err != nil {
		return nil, f.err
	}
	if f.trace != nil {
		return f.trace, nil
	}
	return &TraceViewData{TraceID: traceID, AccessLogs: []TraceAccessLog{},
		SecurityEvents: []TraceSecurityEvent{}, OTelSpans: []OTelSpan{},
		DataSource: "agentless", Partial: true, Note: "agentless"}, nil
}

func (f *fakeRepo) SearchTraces(_ context.Context, q TraceSearchFilter) (*TraceSearchData, error) {
	qCopy := q
	f.searchFilter = &qCopy
	if f.err != nil {
		return nil, f.err
	}
	if f.search != nil {
		return f.search, nil
	}
	return &TraceSearchData{List: []TraceSearchItem{}, Page: q.Page, PageSize: q.PageSize,
		DataSource: "agentless", Message: "APM_CLICKHOUSE_DSN 未配置"}, nil
}

// ---------- 阶段3 第一批：SQL/异常/依赖 ----------

func (f *fakeRepo) ListSQLFingerprints(_ context.Context, q SQLFilter) (*SQLData, error) {
	qCopy := q
	f.sqlFilter = &qCopy
	if f.err != nil {
		return nil, f.err
	}
	if f.sql != nil {
		return f.sql, nil
	}
	return &SQLData{List: []SQLRow{}, Page: q.Page, PageSize: q.PageSize,
		DataSource: "agentless", Message: "APM_CLICKHOUSE_DSN 未配置"}, nil
}

func (f *fakeRepo) ListExceptions(_ context.Context, q ExceptionsFilter) (*ExceptionsData, error) {
	qCopy := q
	f.exceptionsFilter = &qCopy
	if f.err != nil {
		return nil, f.err
	}
	if f.exceptions != nil {
		return f.exceptions, nil
	}
	return &ExceptionsData{List: []ExceptionRow{}, Page: q.Page, PageSize: q.PageSize,
		DataSource: "agentless", Message: "APM_CLICKHOUSE_DSN 未配置"}, nil
}

func (f *fakeRepo) ListDependencies(_ context.Context, q DependenciesFilter) (*DependenciesData, error) {
	qCopy := q
	f.depsFilter = &qCopy
	if f.err != nil {
		return nil, f.err
	}
	if f.dependencies != nil {
		return f.dependencies, nil
	}
	return &DependenciesData{Edges: []DependencyEdge{},
		DataSource: "agentless", Note: "APM_CLICKHOUSE_DSN 未配置"}, nil
}

// ---------- 阶段3 第二批：运行时指标 ----------

func (f *fakeRepo) ListRuntimeMetrics(_ context.Context, q RuntimeFilter) (*RuntimeData, error) {
	qCopy := q
	f.runtimeFilter = &qCopy
	if f.err != nil {
		return nil, f.err
	}
	if f.runtime != nil {
		return f.runtime, nil
	}
	return &RuntimeData{Instances: []RuntimeInstance{},
		DataSource: "agentless", Note: "APM_CLICKHOUSE_DSN 未配置"}, nil
}

// fakeSettings 内存版 SettingsReader。
type fakeSettings struct {
	accessLogEnabled bool
	ingestLagSeconds int // 0 = 回退默认
}

func (f fakeSettings) GetBool(_ context.Context, group, key string, def bool) bool {
	if group == "logging" && key == "access_log_enabled" {
		return f.accessLogEnabled
	}
	return def
}

func (f fakeSettings) GetInt(_ context.Context, group, key string, def int) int {
	if group == "apm_alert" && key == "ingest_lag_seconds" && f.ingestLagSeconds != 0 {
		return f.ingestLagSeconds
	}
	return def
}

// injectPrincipal 模拟认证链：注入持有给定权限点的主体与 Request ID。
func injectPrincipal(perms ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			set := map[string]bool{}
			for _, p := range perms {
				set[p] = true
			}
			p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: set}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
}

func newTestMux(h *Handler, perms ...string) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPrincipal(perms...), h)
	return mux
}

func doGet(t *testing.T, mux http.Handler, path string, query url.Values) *httptest.ResponseRecorder {
	t.Helper()
	u := path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req := httptest.NewRequest(http.MethodGet, u, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func decodeBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v, raw: %s", err, rr.Body.String())
	}
	return body
}

func dataOf(t *testing.T, rr *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	data, ok := decodeBody(t, rr)["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("data missing or not an object: %s", rr.Body.String())
	}
	return data
}

// TestOverviewWindowParsing 时间窗解析：缺省最近 1 小时；非法格式/超 31 天/起点不早于终点 → 400。
func TestOverviewWindowParsing(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.overview.read")

	rr := doGet(t, mux, "/api/v1/apm/overview", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("default window status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if d := repo.overviewArgs.end.Sub(repo.overviewArgs.start); d != time.Hour {
		t.Errorf("default window = %v, want 1h", d)
	}

	now := time.Now().UTC()
	cases := []struct {
		name  string
		query url.Values
	}{
		{"bad start_time", url.Values{"start_time": {"not-a-time"}}},
		{"bad end_time", url.Values{"end_time": {"2026-13-01T00:00:00Z"}}},
		{"window over 31d", url.Values{
			"start_time": {now.Add(-32 * 24 * time.Hour).Format(time.RFC3339)},
			"end_time":   {now.Format(time.RFC3339)},
		}},
		{"start not before end", url.Values{
			"start_time": {now.Format(time.RFC3339)},
			"end_time":   {now.Add(-time.Hour).Format(time.RFC3339)},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := doGet(t, mux, "/api/v1/apm/overview", c.query)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400, body: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestOverviewPermission 权限在路由层强制：无权限点 403，未注入主体 401。
func TestOverviewPermission(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, fakeSettings{}, 10*time.Minute)

	mux := newTestMux(h, "apm.services.read") // 有别的权限但没有 apm.overview.read
	rr := doGet(t, mux, "/api/v1/apm/overview", nil)
	if rr.Code != http.StatusForbidden {
		t.Errorf("no permission status = %d, want 403", rr.Code)
	}

	noAuth := http.NewServeMux()
	RegisterRoutes(noAuth, func(next http.Handler) http.Handler { return next }, h)
	rr = doGet(t, noAuth, "/api/v1/apm/overview", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no principal status = %d, want 401", rr.Code)
	}
}

// TestListServicesPagination 分页夹紧：page_size 超上限夹到 100，page 非法回到 1。
func TestListServicesPagination(t *testing.T) {
	repo := &fakeRepo{services: []ServiceRow{}}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.services.read")

	rr := doGet(t, mux, "/api/v1/apm/services", url.Values{"page": {"0"}, "page_size": {"500"}})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo.servicesFilter == nil {
		t.Fatal("store not called")
	}
	if repo.servicesFilter.Page != 1 || repo.servicesFilter.PageSize != maxPageSize {
		t.Errorf("filter page=%d page_size=%d, want 1/%d",
			repo.servicesFilter.Page, repo.servicesFilter.PageSize, maxPageSize)
	}
	data := dataOf(t, rr)
	if data["page"] != float64(1) || data["page_size"] != float64(maxPageSize) {
		t.Errorf("response page/page_size = %v/%v", data["page"], data["page_size"])
	}
	if _, ok := data["items"]; !ok {
		t.Errorf("services list must use unified page envelope (items), got: %v", data)
	}

	// 非法分页值回落默认
	rr = doGet(t, mux, "/api/v1/apm/services", url.Values{"page": {"abc"}, "page_size": {"x"}})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if repo.servicesFilter.Page != defaultPage || repo.servicesFilter.PageSize != defaultPageSize {
		t.Errorf("invalid page params must fall back to defaults, got %d/%d",
			repo.servicesFilter.Page, repo.servicesFilter.PageSize)
	}
}

// TestServiceDetailBranches 400（非法 UUID）/404（不存在）/200 分支。
func TestServiceDetailBranches(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.services.read")

	rr := doGet(t, mux, "/api/v1/apm/services/not-a-uuid", nil)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad id status = %d, want 400", rr.Code)
	}

	repo.notFound = true
	rr = doGet(t, mux, "/api/v1/apm/services/"+uuid.NewString(), nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("missing app status = %d, want 404, body: %s", rr.Code, rr.Body.String())
	}

	repo.notFound = false
	rr = doGet(t, mux, "/api/v1/apm/services/"+uuid.NewString(), nil)
	if rr.Code != http.StatusOK {
		t.Errorf("ok status = %d, body: %s", rr.Code, rr.Body.String())
	}
}

// TestEndpointsValidation sort 白名单与 application_id 校验。
func TestEndpointsValidation(t *testing.T) {
	repo := &fakeRepo{appCode: "shop"}
	mux := newTestMux(NewHandler(repo, fakeSettings{accessLogEnabled: true}, 10*time.Minute), "apm.services.read")

	rr := doGet(t, mux, "/api/v1/apm/endpoints", url.Values{"sort": {"drop table"}})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad sort status = %d, want 400", rr.Code)
	}
	if repo.endpointsFilter != nil {
		t.Error("store must not be called on invalid sort")
	}

	rr = doGet(t, mux, "/api/v1/apm/endpoints", url.Values{"application_id": {"bad"}})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad application_id status = %d, want 400", rr.Code)
	}

	// 过滤条件指向不存在的应用：空页 200 而非 5xx
	repo.notFound = true
	rr = doGet(t, mux, "/api/v1/apm/endpoints", url.Values{"application_id": {uuid.NewString()}})
	if rr.Code != http.StatusOK {
		t.Fatalf("unknown app filter status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	if data["total"] != float64(0) {
		t.Errorf("unknown app filter total = %v, want 0", data["total"])
	}
	repo.notFound = false

	// 正常过滤：application_id 反解为 code 后下传
	appID := uuid.New()
	rr = doGet(t, mux, "/api/v1/apm/endpoints", url.Values{"application_id": {appID.String()}, "sort": {"requests"}})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo.appCodeID != appID {
		t.Errorf("AppCodeByID got %v, want %v", repo.appCodeID, appID)
	}
	if repo.endpointsFilter == nil || repo.endpointsFilter.AppCode == nil || *repo.endpointsFilter.AppCode != "shop" {
		t.Errorf("endpoints filter app code not propagated: %+v", repo.endpointsFilter)
	}
	if repo.endpointsFilter != nil && repo.endpointsFilter.Sort != "requests" {
		t.Errorf("sort = %q, want requests", repo.endpointsFilter.Sort)
	}
}

// TestEndpointsAccessLogDegraded access_log 关闭时端点列表为空且不触达存取层（ADR D9 如实降级）。
func TestEndpointsAccessLogDegraded(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{accessLogEnabled: false}, 10*time.Minute), "apm.services.read")

	rr := doGet(t, mux, "/api/v1/apm/endpoints", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	if data["access_log_enabled"] != false {
		t.Errorf("access_log_enabled = %v, want false", data["access_log_enabled"])
	}
	if list, ok := data["list"].([]interface{}); !ok || len(list) != 0 {
		t.Errorf("list = %v, want empty array", data["list"])
	}
	if repo.endpointsFilter != nil {
		t.Error("store must not be called when access log disabled")
	}
}

// TestTraceValidation trace_id 格式校验（32 hex）与可选窗口校验。
func TestTraceValidation(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.traces.read")
	valid := strings.Repeat("ab", 16)

	cases := []struct {
		name    string
		traceID string
	}{
		{"too short", "abc123"},
		{"not hex", strings.Repeat("zz", 16)},
		{"64 chars", strings.Repeat("ab", 32)},
		{"sql injection", "'; DROP TABLE access_logs;--"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := doGet(t, mux, "/api/v1/apm/traces/"+url.PathEscape(c.traceID), nil)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400, body: %s", rr.Code, rr.Body.String())
			}
		})
	}
	if repo.traceArgs.traceID != "" {
		t.Error("store must not be called on invalid trace_id")
	}

	// 大写 hex 合法并统一转小写
	rr := doGet(t, mux, "/api/v1/apm/traces/"+strings.ToUpper(valid), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("uppercase trace status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo.traceArgs.traceID != valid {
		t.Errorf("trace_id = %q, want lowercased %q", repo.traceArgs.traceID, valid)
	}
	if repo.traceArgs.start != nil || repo.traceArgs.end != nil {
		t.Error("no window params must yield nil window (point lookup)")
	}

	// 只给一个时间边界 → 400
	rr = doGet(t, mux, "/api/v1/apm/traces/"+valid, url.Values{"start_time": {time.Now().UTC().Format(time.RFC3339)}})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("half window status = %d, want 400", rr.Code)
	}

	// 合法窗口透传
	now := time.Now().UTC()
	rr = doGet(t, mux, "/api/v1/apm/traces/"+valid, url.Values{
		"start_time": {now.Add(-2 * time.Hour).Format(time.RFC3339)},
		"end_time":   {now.Format(time.RFC3339)},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("windowed trace status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo.traceArgs.start == nil || repo.traceArgs.end == nil {
		t.Fatal("window must be propagated")
	}
}

// TestTraceEmptyHit 无命中返回空数组而非 404（合同固定）。
func TestTraceEmptyHit(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.traces.read")
	rr := doGet(t, mux, "/api/v1/apm/traces/"+strings.Repeat("00", 16), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	if logs, ok := data["access_logs"].([]interface{}); !ok || len(logs) != 0 {
		t.Errorf("access_logs = %v, want empty array", data["access_logs"])
	}
	if evs, ok := data["security_events"].([]interface{}); !ok || len(evs) != 0 {
		t.Errorf("security_events = %v, want empty array", data["security_events"])
	}
	if data["partial"] != true || data["note"] != "agentless" {
		t.Errorf("partial/note = %v/%v", data["partial"], data["note"])
	}
}

// TestStoreError 存取层错误 → 500（不泄露细节）。
func TestStoreError(t *testing.T) {
	repo := &fakeRepo{err: errors.New("db down")}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.overview.read", "apm.services.read", "apm.traces.read")

	for _, path := range []string{
		"/api/v1/apm/overview",
		"/api/v1/apm/services",
		"/api/v1/apm/services/" + uuid.NewString(),
		"/api/v1/apm/traces/" + strings.Repeat("ab", 16),
		"/api/v1/apm/trace-search",
	} {
		rr := doGet(t, mux, path, nil)
		if rr.Code != http.StatusInternalServerError {
			t.Errorf("%s status = %d, want 500", path, rr.Code)
		}
		if strings.Contains(rr.Body.String(), "db down") {
			t.Errorf("%s leaks internal error detail", path)
		}
	}
}

// ---------- 阶段2 下半：trace-search（OTel 数据面检索） ----------

// TestTraceSearchWindow 窗口口径：缺省最近 1 小时；上限 24 小时（超窗 400，严于通用列表）。
func TestTraceSearchWindow(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.traces.read")

	rr := doGet(t, mux, "/api/v1/apm/trace-search", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("default window status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo.searchFilter == nil {
		t.Fatal("store not called")
	}
	if d := repo.searchFilter.End.Sub(repo.searchFilter.Start); d != time.Hour {
		t.Errorf("default window = %v, want 1h", d)
	}

	now := time.Now().UTC()
	// 24h 边界合法
	rr = doGet(t, mux, "/api/v1/apm/trace-search", url.Values{
		"start_time": {now.Add(-24 * time.Hour).Format(time.RFC3339)},
		"end_time":   {now.Format(time.RFC3339)},
	})
	if rr.Code != http.StatusOK {
		t.Errorf("24h window status = %d, want 200, body: %s", rr.Code, rr.Body.String())
	}
	// 超 24h → 400
	rr = doGet(t, mux, "/api/v1/apm/trace-search", url.Values{
		"start_time": {now.Add(-24*time.Hour - time.Minute).Format(time.RFC3339)},
		"end_time":   {now.Format(time.RFC3339)},
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("over 24h status = %d, want 400", rr.Code)
	}
}

// TestTraceSearchValidation 过滤参数校验（非法值 400 且不触达存取层）。
func TestTraceSearchValidation(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.traces.read")
	valid := strings.Repeat("ab", 16)

	cases := []struct {
		name  string
		query url.Values
	}{
		{"bad trace_id", url.Values{"trace_id": {"xyz"}}},
		{"trace_id 64 chars", url.Values{"trace_id": {strings.Repeat("ab", 32)}}},
		{"sql injection trace_id", url.Values{"trace_id": {"' OR 1=1 --"}}},
		{"long request_id", url.Values{"request_id": {strings.Repeat("r", 129)}}},
		{"long service", url.Values{"service": {strings.Repeat("s", 129)}}},
		{"bad min_duration_ms", url.Values{"min_duration_ms": {"abc"}}},
		{"negative min_duration_ms", url.Values{"min_duration_ms": {"-5"}}},
		{"bad error", url.Values{"error": {"yes"}}},
		{"bad start_time", url.Values{"start_time": {"not-a-time"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo.searchFilter = nil
			rr := doGet(t, mux, "/api/v1/apm/trace-search", c.query)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400, body: %s", rr.Code, rr.Body.String())
			}
			if repo.searchFilter != nil {
				t.Error("store must not be called on invalid params")
			}
		})
	}

	// 合法组合透传：trace_id 小写化直达 + 全过滤项 + 分页夹紧
	repo.searchFilter = nil
	rr := doGet(t, mux, "/api/v1/apm/trace-search", url.Values{
		"trace_id":        {strings.ToUpper(valid)},
		"request_id":      {"req-1"},
		"service":         {"order-svc"},
		"min_duration_ms": {"12.5"},
		"error":           {"true"},
		"page":            {"2"},
		"page_size":       {"500"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	f := repo.searchFilter
	if f == nil || len(f.TraceIDs) != 1 || f.TraceIDs[0] != valid {
		t.Fatalf("trace_id not lowercased/propagated: %+v", f)
	}
	if f.RequestID != "req-1" || f.Service != "order-svc" || f.MinDurationMS != 12.5 || !f.ErrorOnly {
		t.Errorf("filters not propagated: %+v", f)
	}
	if f.Page != 2 || f.PageSize != maxPageSize {
		t.Errorf("page clamp = %d/%d, want 2/%d", f.Page, f.PageSize, maxPageSize)
	}
}

// TestTraceSearchDegraded DSN 未配置降级：空页 + data_source=agentless + message，不报 500。
func TestTraceSearchDegraded(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.traces.read")
	rr := doGet(t, mux, "/api/v1/apm/trace-search", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	if data["data_source"] != "agentless" {
		t.Errorf("data_source = %v, want agentless", data["data_source"])
	}
	if list, ok := data["list"].([]interface{}); !ok || len(list) != 0 {
		t.Errorf("list = %v, want empty array", data["list"])
	}
	if data["total"] != float64(0) || data["page"] != float64(1) {
		t.Errorf("total/page = %v/%v", data["total"], data["page"])
	}
	if msg, _ := data["message"].(string); msg == "" {
		t.Error("degraded response must carry explanatory message")
	}
}

// TestTraceSearchPermission trace-search 权限点：apm.traces.read。
func TestTraceSearchPermission(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.services.read")
	rr := doGet(t, mux, "/api/v1/apm/trace-search", nil)
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

// TestNewHandlerOfflineClamp 离线阈值夹紧（越界回退 10 分钟，与 Agent 控制面口径一致）。
func TestNewHandlerOfflineClamp(t *testing.T) {
	if h := NewHandler(&fakeRepo{}, fakeSettings{}, 0); h.agentOfflineAfter != 10*time.Minute {
		t.Errorf("zero offlineAfter = %v, want 10m", h.agentOfflineAfter)
	}
	if h := NewHandler(&fakeRepo{}, fakeSettings{}, 48*time.Hour); h.agentOfflineAfter != 10*time.Minute {
		t.Errorf("48h offlineAfter = %v, want 10m", h.agentOfflineAfter)
	}
	if h := NewHandler(&fakeRepo{}, fakeSettings{}, 5*time.Minute); h.agentOfflineAfter != 5*time.Minute {
		t.Errorf("5m offlineAfter = %v, want 5m", h.agentOfflineAfter)
	}
}
