// admission_test.go API 准入防护接口测试：窗口参数校验（1/168 缺省/2160 合法；
// 2161/0/负数/非数字 400）、application_id 校验、coverage/denied 响应形态与
// denied 分页透传（内存 fake 驱动真实 Handler，不依赖数据库——与 risk_handler_test 同一纪律）。
package apisecurity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeAdmissionRepo 准入仓储内存假实现。
type fakeAdmissionRepo struct {
	coverage      *AdmissionCoverageReport
	coverageErr   error
	denied        []AdmissionDeniedItem
	deniedTotal   int64
	deniedErr     error
	gotAppID      uuid.UUID
	gotWindow     int
	gotPage       int
	gotPageSize   int
	coverageCalls int
}

func (f *fakeAdmissionRepo) AdmissionCoverage(_ context.Context, appID uuid.UUID, window int) (*AdmissionCoverageReport, error) {
	f.coverageCalls++
	f.gotAppID = appID
	f.gotWindow = window
	if f.coverageErr != nil {
		return nil, f.coverageErr
	}
	return f.coverage, nil
}

func (f *fakeAdmissionRepo) AdmissionDenied(_ context.Context, appID uuid.UUID, window, page, pageSize int) ([]AdmissionDeniedItem, int64, error) {
	f.gotAppID = appID
	f.gotWindow = window
	f.gotPage = page
	f.gotPageSize = pageSize
	if f.deniedErr != nil {
		return nil, 0, f.deniedErr
	}
	return f.denied, f.deniedTotal, nil
}

func newAdmissionTestMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectRiskPrincipal("api_asset.read"), h)
	return mux
}

func getAdmission(t *testing.T, mux http.Handler, url string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// decodeData 解统一响应信封的 data 字段。
func decodeData(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	var body struct {
		Code string          `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应非 JSON: %v body=%s", err, rec.Body.String())
	}
	if body.Code != "SUCCESS" {
		t.Fatalf("业务码非 SUCCESS: %s body=%s", body.Code, rec.Body.String())
	}
	if err := json.Unmarshal(body.Data, v); err != nil {
		t.Fatalf("data 解析失败: %v body=%s", err, rec.Body.String())
	}
}

func TestAdmissionCoverageWindowValidation(t *testing.T) {
	repo := &fakeAdmissionRepo{coverage: &AdmissionCoverageReport{UnconfirmedHot: []AdmissionHotEndpoint{}}}
	h := NewHandler(nil, nil)
	h.SetAdmissionRepository(repo)
	mux := newAdmissionTestMux(h)
	appID := uuid.New().String()

	// 缺省 → 168
	rec := getAdmission(t, mux, "/api/v1/api-security/admission/coverage?application_id="+appID)
	if rec.Code != http.StatusOK {
		t.Fatalf("缺省窗口应 200，got %d body=%s", rec.Code, rec.Body.String())
	}
	if repo.gotWindow != AdmissionDefaultHitsWindowHours {
		t.Fatalf("缺省窗口应为 %d，got %d", AdmissionDefaultHitsWindowHours, repo.gotWindow)
	}
	// 边界 1 与 2160 合法
	for _, w := range []string{"1", "2160"} {
		rec := getAdmission(t, mux, "/api/v1/api-security/admission/coverage?application_id="+appID+"&hits_window="+w)
		if rec.Code != http.StatusOK {
			t.Fatalf("hits_window=%s 应 200，got %d body=%s", w, rec.Code, rec.Body.String())
		}
	}
	// 越界/零/负/非数字 → 400
	for _, w := range []string{"2161", "0", "-5", "abc", "1.5"} {
		rec := getAdmission(t, mux, "/api/v1/api-security/admission/coverage?application_id="+appID+"&hits_window="+w)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("hits_window=%q 应 400，got %d body=%s", w, rec.Code, rec.Body.String())
		}
	}
	// 非法窗口不得触达仓储
	if repo.coverageCalls != 3 {
		t.Fatalf("非法窗口不应调用仓储，calls=%d", repo.coverageCalls)
	}
}

func TestAdmissionCoverageAppIDValidation(t *testing.T) {
	repo := &fakeAdmissionRepo{coverage: &AdmissionCoverageReport{}}
	h := NewHandler(nil, nil)
	h.SetAdmissionRepository(repo)
	mux := newAdmissionTestMux(h)

	for _, q := range []string{"", "application_id=", "application_id=not-a-uuid"} {
		rec := getAdmission(t, mux, "/api/v1/api-security/admission/coverage?"+q)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("application_id %q 应 400，got %d", q, rec.Code)
		}
	}
	if repo.coverageCalls != 0 {
		t.Fatalf("非法 application_id 不应调用仓储，calls=%d", repo.coverageCalls)
	}
}

func TestAdmissionCoverageNotFound(t *testing.T) {
	repo := &fakeAdmissionRepo{coverageErr: ErrNotFound}
	h := NewHandler(nil, nil)
	h.SetAdmissionRepository(repo)
	mux := newAdmissionTestMux(h)
	rec := getAdmission(t, mux, "/api/v1/api-security/admission/coverage?application_id="+uuid.New().String())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("应用不存在应 404，got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdmissionCoverageResponseShape(t *testing.T) {
	appID := uuid.New()
	repo := &fakeAdmissionRepo{coverage: &AdmissionCoverageReport{
		ApplicationID:   appID,
		Mode:            "OBSERVE",
		HitsWindowHours: 24,
		Endpoints:       AdmissionEndpointCounts{Confirmed: 4, Discovered: 1, Ignored: 1},
		ConfirmRate:     0.8,
		UnconfirmedHot: []AdmissionHotEndpoint{{
			EndpointKey: "GET /v1/coupon", HTTPMethod: "GET", NormalizedPath: "/v1/coupon",
			AssetStatus: "DISCOVERED", Hits: 1320, LastSeenAt: time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC),
		}},
		Blocked: 0,
	}}
	h := NewHandler(nil, nil)
	h.SetAdmissionRepository(repo)
	mux := newAdmissionTestMux(h)

	rec := getAdmission(t, mux, "/api/v1/api-security/admission/coverage?application_id="+appID.String()+"&hits_window=24")
	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，got %d body=%s", rec.Code, rec.Body.String())
	}
	var rep AdmissionCoverageReport
	decodeData(t, rec, &rep)
	if rep.Mode != "OBSERVE" || rep.HitsWindowHours != 24 || rep.ConfirmRate != 0.8 || rep.Blocked != 0 {
		t.Fatalf("覆盖率字段不符: %+v", rep)
	}
	if rep.Endpoints.Confirmed != 4 || rep.Endpoints.Discovered != 1 || rep.Endpoints.Ignored != 1 {
		t.Fatalf("状态计数不符: %+v", rep.Endpoints)
	}
	if len(rep.UnconfirmedHot) != 1 || rep.UnconfirmedHot[0].Hits != 1320 ||
		rep.UnconfirmedHot[0].EndpointKey != "GET /v1/coupon" || rep.UnconfirmedHot[0].AssetStatus != "DISCOVERED" {
		t.Fatalf("命中榜不符: %+v", rep.UnconfirmedHot)
	}
	if repo.gotAppID != appID {
		t.Fatalf("application_id 透传不符: %s", repo.gotAppID)
	}
}

func TestAdmissionCoverageStoreError(t *testing.T) {
	repo := &fakeAdmissionRepo{coverageErr: errors.New("db down")}
	h := NewHandler(nil, nil)
	h.SetAdmissionRepository(repo)
	mux := newAdmissionTestMux(h)
	rec := getAdmission(t, mux, "/api/v1/api-security/admission/coverage?application_id="+uuid.New().String())
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("仓储错误应 500，got %d", rec.Code)
	}
}

func TestAdmissionDeniedPaginationAndShape(t *testing.T) {
	appID := uuid.New()
	repo := &fakeAdmissionRepo{
		denied: []AdmissionDeniedItem{{
			EndpointKey: "POST /v1/login", HTTPMethod: "POST", NormalizedPath: "/v1/login",
			AssetStatus: "DISCOVERED", DeniedCount: 3,
			LastDeniedAt:    time.Date(2026, 9, 20, 2, 0, 0, 0, time.UTC),
			SampleClientIPs: []string{"198.51.100.7"},
			FirstSeenAt:     time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		}},
		deniedTotal: 1,
	}
	h := NewHandler(nil, nil)
	h.SetAdmissionRepository(repo)
	mux := newAdmissionTestMux(h)

	rec := getAdmission(t, mux, "/api/v1/api-security/admission/denied?application_id="+appID.String()+
		"&hits_window=720&page=2&page_size=10")
	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，got %d body=%s", rec.Code, rec.Body.String())
	}
	// 分页与窗口参数透传
	if repo.gotWindow != 720 || repo.gotPage != 2 || repo.gotPageSize != 10 {
		t.Fatalf("参数透传不符: window=%d page=%d size=%d", repo.gotWindow, repo.gotPage, repo.gotPageSize)
	}
	var page struct {
		Items    []AdmissionDeniedItem `json:"items"`
		Total    int64                 `json:"total"`
		Page     int                   `json:"page"`
		PageSize int                   `json:"page_size"`
	}
	decodeData(t, rec, &page)
	if page.Total != 1 || page.Page != 2 || page.PageSize != 10 || len(page.Items) != 1 {
		t.Fatalf("分页结构不符: %+v", page)
	}
	it := page.Items[0]
	if it.EndpointKey != "POST /v1/login" || it.DeniedCount != 3 || len(it.SampleClientIPs) != 1 ||
		it.SampleClientIPs[0] != "198.51.100.7" || it.AssetStatus != "DISCOVERED" {
		t.Fatalf("拦截行字段不符: %+v", it)
	}
}

func TestAdmissionDeniedWindowValidation(t *testing.T) {
	repo := &fakeAdmissionRepo{}
	h := NewHandler(nil, nil)
	h.SetAdmissionRepository(repo)
	mux := newAdmissionTestMux(h)
	appID := uuid.New().String()

	for _, w := range []string{"2161", "0", "abc"} {
		rec := getAdmission(t, mux, "/api/v1/api-security/admission/denied?application_id="+appID+"&hits_window="+w)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("hits_window=%q 应 400，got %d", w, rec.Code)
		}
	}
	rec := getAdmission(t, mux, "/api/v1/api-security/admission/denied?application_id="+appID)
	if rec.Code != http.StatusOK {
		t.Fatalf("缺省窗口应 200，got %d", rec.Code)
	}
	if repo.gotWindow != AdmissionDefaultHitsWindowHours {
		t.Fatalf("缺省窗口应为 %d，got %d", AdmissionDefaultHitsWindowHours, repo.gotWindow)
	}
}

func TestAdmissionPermissionEnforced(t *testing.T) {
	// 无 api_asset.read 权限点：两接口均 403（路由层 RequirePermission）
	h := NewHandler(nil, nil)
	h.SetAdmissionRepository(&fakeAdmissionRepo{coverage: &AdmissionCoverageReport{}})
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectRiskPrincipal("api_runtime.read"), h) // 注入无关权限
	for _, path := range []string{"/api/v1/api-security/admission/coverage", "/api/v1/api-security/admission/denied"} {
		rec := getAdmission(t, mux, path+"?application_id="+uuid.New().String())
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s 无权限应 403，got %d body=%s", path, rec.Code, rec.Body.String())
		}
	}
}
