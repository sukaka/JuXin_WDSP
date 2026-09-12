// handler_aggregates_test.go 阶段3 第一批接口（/apm/sql、/apm/exceptions、/apm/dependencies）
// 参数校验、分页夹紧、权限注册（403/401）与过滤器透传测试（httptest + fakeRepo，
// 不依赖数据库/ClickHouse）。
package apm

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestListSQLParams 参数校验：sort 白名单、db_system/service 长度上限、窗口 24h 上限 → 400；
// 缺省 sort=p95_ms；分页超限夹紧。
func TestListSQLParams(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.sql.read")

	// 缺省：窗口 1h、sort=p95_ms
	rr := doGet(t, mux, "/api/v1/apm/sql", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo.sqlFilter == nil {
		t.Fatal("store not called")
	}
	if repo.sqlFilter.Sort != "p95_ms" {
		t.Errorf("default sort = %q, want p95_ms", repo.sqlFilter.Sort)
	}
	if d := repo.sqlFilter.End.Sub(repo.sqlFilter.Start); d != time.Hour {
		t.Errorf("default window = %v, want 1h", d)
	}
	data := dataOf(t, rr)
	if data["data_source"] != "agentless" || data["message"] == "" {
		t.Errorf("degraded payload = %v", data)
	}

	// 合法组合透传
	rr = doGet(t, mux, "/api/v1/apm/sql", url.Values{
		"service": {"order-svc"}, "db_system": {"postgresql"}, "sort": {"calls"},
		"page": {"2"}, "page_size": {"500"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	f := repo.sqlFilter
	if f.Service != "order-svc" || f.DBSystem != "postgresql" || f.Sort != "calls" {
		t.Errorf("filter = %+v", f)
	}
	if f.PageSize != maxPageSize {
		t.Errorf("page_size = %d, want clamped %d", f.PageSize, maxPageSize)
	}

	// 非法参数 → 400
	now := time.Now().UTC()
	cases := []struct {
		name  string
		query url.Values
	}{
		{"bad sort", url.Values{"sort": {"duration"}}},
		{"db_system too long", url.Values{"db_system": {strings.Repeat("x", 65)}}},
		{"service too long", url.Values{"service": {strings.Repeat("x", 129)}}},
		{"window over 24h", url.Values{
			"start_time": {now.Add(-25 * time.Hour).Format(time.RFC3339)},
			"end_time":   {now.Format(time.RFC3339)},
		}},
		{"bad start_time", url.Values{"start_time": {"not-a-time"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := doGet(t, mux, "/api/v1/apm/sql", c.query)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400, body: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestListExceptionsParams 参数校验与透传（service 过滤、分页夹紧、窗口上限）。
func TestListExceptionsParams(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.traces.read")

	rr := doGet(t, mux, "/api/v1/apm/exceptions", url.Values{"service": {"order-svc"}, "page_size": {"1000"}})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo.exceptionsFilter == nil || repo.exceptionsFilter.Service != "order-svc" {
		t.Fatalf("filter = %+v", repo.exceptionsFilter)
	}
	if repo.exceptionsFilter.PageSize != maxPageSize {
		t.Errorf("page_size = %d, want clamped %d", repo.exceptionsFilter.PageSize, maxPageSize)
	}

	rr = doGet(t, mux, "/api/v1/apm/exceptions", url.Values{"service": {strings.Repeat("x", 129)}})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("service too long status = %d, want 400", rr.Code)
	}
	now := time.Now().UTC()
	rr = doGet(t, mux, "/api/v1/apm/exceptions", url.Values{
		"start_time": {now.Add(-48 * time.Hour).Format(time.RFC3339)},
		"end_time":   {now.Format(time.RFC3339)},
	})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("window over 24h status = %d, want 400", rr.Code)
	}
}

// TestListDependenciesParams 参数校验与透传（无分页参数；窗口上限 24h）。
func TestListDependenciesParams(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.services.read")

	rr := doGet(t, mux, "/api/v1/apm/dependencies", url.Values{"service": {"order-svc"}})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo.depsFilter == nil || repo.depsFilter.Service != "order-svc" {
		t.Fatalf("filter = %+v", repo.depsFilter)
	}
	data := dataOf(t, rr)
	if data["data_source"] != "agentless" || data["note"] == "" {
		t.Errorf("degraded payload = %v", data)
	}
	edges, ok := data["edges"].([]interface{})
	if !ok || edges == nil {
		t.Errorf("edges must be an array, got %v", data["edges"])
	}

	rr = doGet(t, mux, "/api/v1/apm/dependencies", url.Values{"service": {strings.Repeat("x", 129)}})
	if rr.Code != http.StatusBadRequest {
		t.Errorf("service too long status = %d, want 400", rr.Code)
	}
}

// TestStage3Permissions 权限注册：各路由独立权限点 403；未注入主体 401
// （含第二批 /apm/runtime 的 apm.runtime.read，迁移 000091）。
func TestStage3Permissions(t *testing.T) {
	repo := &fakeRepo{}
	h := NewHandler(repo, fakeSettings{}, 10*time.Minute)

	cases := []struct {
		path    string
		perm    string   // 该路由要求的权限点
		haveAny []string // 持有其他权限（不含目标权限点）
	}{
		{"/api/v1/apm/sql", "apm.sql.read", []string{"apm.traces.read", "apm.services.read"}},
		{"/api/v1/apm/exceptions", "apm.traces.read", []string{"apm.sql.read", "apm.services.read"}},
		{"/api/v1/apm/dependencies", "apm.services.read", []string{"apm.sql.read", "apm.traces.read"}},
		{"/api/v1/apm/runtime", "apm.runtime.read", []string{"apm.sql.read", "apm.services.read"}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			// 持有其他 APM 权限但缺目标权限 → 403
			mux := newTestMux(h, c.haveAny...)
			rr := doGet(t, mux, c.path, nil)
			if rr.Code != http.StatusForbidden {
				t.Errorf("wrong-perm status = %d, want 403", rr.Code)
			}
			// 持有目标权限 → 200
			mux = newTestMux(h, c.perm)
			rr = doGet(t, mux, c.path, nil)
			if rr.Code != http.StatusOK {
				t.Errorf("with-perm status = %d, want 200, body: %s", rr.Code, rr.Body.String())
			}
			// 未注入主体 → 401
			noAuth := http.NewServeMux()
			RegisterRoutes(noAuth, func(next http.Handler) http.Handler { return next }, h)
			rr = doGet(t, noAuth, c.path, nil)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("no-principal status = %d, want 401", rr.Code)
			}
		})
	}
}
