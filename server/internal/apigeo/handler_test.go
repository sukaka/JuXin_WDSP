// handler_test.go 数据出境看板 HTTP 入口测试：权限矩阵 / 参数校验 /
// 看板聚合 / 明细过滤分页 / geo_enabled 元信息（内存仓储驱动真实 Handler 与路由）。
package apigeo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apidata"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// injectPrincipal 模拟认证链：注入持有给定权限点集合的主体。
func injectPrincipal(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "w7xb-tester", PermsSet: set}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "w7xb-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// noPrincipal 模拟未注入主体的认证链（权限中间件应 401）。
func noPrincipal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// newTestMux 装配看板路由（内存仓储 + 假 GeoIP + 假设置）。
func newTestMux(store *MemStore, lookup CountryLookup, settings SettingsReader, authzFn func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, authzFn, NewHandler(store, lookup, settings))
	return mux
}

// crossBorderRespBody 响应解码结构（仅需断言字段）。
type crossBorderRespBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    struct {
		GeoEnabled  bool     `json:"geo_enabled"`
		HomeRegions []string `json:"home_regions"`
		Dashboard   struct {
			Days    int `json:"days"`
			Summary struct {
				TotalEvents   int64 `json:"total_events"`
				CountryCount  int64 `json:"country_count"`
				EndpointCount int64 `json:"endpoint_count"`
				HighRiskCount int64 `json:"high_risk_count"`
			} `json:"summary"`
			ByCountry []struct {
				Country       string   `json:"country"`
				EventCount    int64    `json:"event_count"`
				EndpointCount int64    `json:"endpoint_count"`
				DataTypes     []string `json:"data_types"`
			} `json:"by_country"`
			ByCountryType []struct {
				Country    string `json:"country"`
				DataType   string `json:"data_type"`
				EventCount int64  `json:"event_count"`
			} `json:"by_country_type"`
			ByEndpoint []struct {
				EndpointKey  string `json:"endpoint_key"`
				EventCount   int64  `json:"event_count"`
				CountryCount int64  `json:"country_count"`
			} `json:"by_endpoint"`
			Trend []struct {
				Date       string `json:"date"`
				EventCount int64  `json:"event_count"`
			} `json:"trend"`
		} `json:"dashboard"`
		Events struct {
			Items []struct {
				Country   string   `json:"country"`
				Direction string   `json:"direction"`
				RiskLevel string   `json:"risk_level"`
				DataTypes []string `json:"data_types"`
			} `json:"items"`
			Total    int64 `json:"total"`
			Page     int   `json:"page"`
			PageSize int   `json:"page_size"`
		} `json:"events"`
	} `json:"data"`
}

// doGet 执行 GET 并解码响应。
func doGet(t *testing.T, mux http.Handler, url string) (int, crossBorderRespBody) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	var body crossBorderRespBody
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rr.Body.String())
	}
	return rr.Code, body
}

// seedCrossBorder 经真实 SweepOnce 生产看板数据（US 境外 3 事件跨 2 端点 2 类型，JP 1 事件）。
func seedCrossBorder(t *testing.T, store *MemStore, lookup CountryLookup) {
	t.Helper()
	store.setDataTypeLevels(map[string]string{"id_card": "IMPORTANT", "phone": "SENSITIVE", "email": "GENERAL"})
	base := time.Now().UTC().Add(-2 * time.Hour)
	store.addRuntimeEvent("GET /users/{id}", "8.8.8.8", "fp-1", base,
		sensitiveDetails(t, []map[string]any{sensHit("id_card", "RESPONSE")}))
	store.addRuntimeEvent("GET /users/{id}", "8.8.8.8", "fp-1", base.Add(time.Minute),
		sensitiveDetails(t, []map[string]any{sensHit("phone", "REQUEST")}))
	store.addRuntimeEvent("POST /orders", "1.1.1.1", "fp-2", base.Add(2*time.Minute),
		sensitiveDetails(t, []map[string]any{sensHit("email", "RESPONSE")}))
	sweeper := NewSweeper(store, lookup, fakeSettings{})
	if _, err := sweeper.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
}

var handlerLookup = fakeLookup{byIP: map[string]string{"8.8.8.8": "US", "1.1.1.1": "AU"}}

// TestCrossBorderPermission 权限矩阵：未登录 401 / 无权限 403 / api_data.read 200。
func TestCrossBorderPermission(t *testing.T) {
	store := NewMemStore()
	seedCrossBorder(t, store, handlerLookup)

	// 未注入主体 → 401
	code, _ := doGet(t, newTestMux(store, handlerLookup, fakeSettings{}, noPrincipal), "/api/v1/api-security/cross-border")
	if code != http.StatusUnauthorized {
		t.Fatalf("no principal: status=%d, want 401", code)
	}
	// 主体无 api_data.read → 403
	code, _ = doGet(t, newTestMux(store, handlerLookup, fakeSettings{}, injectPrincipal(apidata.PermDataManage)),
		"/api/v1/api-security/cross-border")
	if code != http.StatusForbidden {
		t.Fatalf("no permission: status=%d, want 403", code)
	}
	// 持 api_data.read → 200
	code, _ = doGet(t, newTestMux(store, handlerLookup, fakeSettings{}, injectPrincipal(apidata.PermDataRead)),
		"/api/v1/api-security/cross-border")
	if code != http.StatusOK {
		t.Fatalf("with permission: status=%d, want 200", code)
	}
}

// TestCrossBorderDashboard 看板聚合断言：汇总 / 国家×类型 / 端点 / 趋势零值补齐 /
// geo_enabled 与 home_regions 元信息。
func TestCrossBorderDashboard(t *testing.T) {
	store := NewMemStore()
	seedCrossBorder(t, store, handlerLookup)
	mux := newTestMux(store, handlerLookup, fakeSettings{"api_data:home_regions": "CN"}, injectPrincipal(apidata.PermDataRead))

	code, body := doGet(t, mux, "/api/v1/api-security/cross-border?days=7")
	if code != http.StatusOK {
		t.Fatalf("status=%d", code)
	}
	if !body.Data.GeoEnabled {
		t.Fatal("geo_enabled should be true")
	}
	if len(body.Data.HomeRegions) != 1 || body.Data.HomeRegions[0] != "CN" {
		t.Fatalf("home_regions=%v", body.Data.HomeRegions)
	}
	sum := body.Data.Dashboard.Summary
	if sum.TotalEvents != 3 || sum.CountryCount != 2 || sum.EndpointCount != 2 || sum.HighRiskCount != 1 {
		t.Fatalf("summary=%+v", sum)
	}
	// by_country：US 2 次居首，AU 1 次
	if len(body.Data.Dashboard.ByCountry) != 2 {
		t.Fatalf("by_country=%+v", body.Data.Dashboard.ByCountry)
	}
	us := body.Data.Dashboard.ByCountry[0]
	if us.Country != "US" || us.EventCount != 2 || us.EndpointCount != 1 {
		t.Fatalf("us=%+v", us)
	}
	if len(us.DataTypes) != 2 || us.DataTypes[0] != "id_card" || us.DataTypes[1] != "phone" {
		t.Fatalf("us.DataTypes=%v", us.DataTypes)
	}
	// by_country_type：US×id_card / US×phone / AU×email 各 1
	if len(body.Data.Dashboard.ByCountryType) != 3 {
		t.Fatalf("by_country_type=%+v", body.Data.Dashboard.ByCountryType)
	}
	// by_endpoint：GET /users/{id} 2 次 1 国，POST /orders 1 次 1 国
	if len(body.Data.Dashboard.ByEndpoint) != 2 || body.Data.Dashboard.ByEndpoint[0].EndpointKey != "GET /users/{id}" {
		t.Fatalf("by_endpoint=%+v", body.Data.Dashboard.ByEndpoint)
	}
	// 趋势：固定 7 天、今日 3 次、零值日补齐
	if len(body.Data.Dashboard.Trend) != 7 {
		t.Fatalf("trend len=%d", len(body.Data.Dashboard.Trend))
	}
	if body.Data.Dashboard.Trend[6].EventCount != 3 {
		t.Fatalf("trend=%+v", body.Data.Dashboard.Trend)
	}
	for _, p := range body.Data.Dashboard.Trend[:6] {
		if p.EventCount != 0 {
			t.Fatalf("trend day %s should be 0, got %d", p.Date, p.EventCount)
		}
	}
}

// TestCrossBorderEventFilter 明细过滤与分页：country/direction/risk_level 白名单过滤。
func TestCrossBorderEventFilter(t *testing.T) {
	store := NewMemStore()
	seedCrossBorder(t, store, handlerLookup)
	mux := newTestMux(store, handlerLookup, fakeSettings{}, injectPrincipal(apidata.PermDataRead))

	// country=US → 2 条
	code, body := doGet(t, mux, "/api/v1/api-security/cross-border?country=us")
	if code != http.StatusOK || body.Data.Events.Total != 2 {
		t.Fatalf("country filter: status=%d total=%d", code, body.Data.Events.Total)
	}
	// direction=OUT → 2 条（US id_card + AU email）
	_, body = doGet(t, mux, "/api/v1/api-security/cross-border?direction=OUT")
	if body.Data.Events.Total != 2 {
		t.Fatalf("direction filter: total=%d", body.Data.Events.Total)
	}
	// risk_level=HIGH → 1 条
	_, body = doGet(t, mux, "/api/v1/api-security/cross-border?risk_level=HIGH")
	if body.Data.Events.Total != 1 || body.Data.Events.Items[0].RiskLevel != RiskHigh {
		t.Fatalf("risk filter: %+v", body.Data.Events)
	}
	// endpoint_key 精确过滤 → 1 条
	_, body = doGet(t, mux, "/api/v1/api-security/cross-border?endpoint_key="+
		urlQueryEscape("POST /orders"))
	if body.Data.Events.Total != 1 {
		t.Fatalf("endpoint filter: total=%d", body.Data.Events.Total)
	}
	// 分页：page_size=2 第一页 2 条，第二页 1 条
	_, body = doGet(t, mux, "/api/v1/api-security/cross-border?page_size=2&page=1")
	if body.Data.Events.Total != 3 || len(body.Data.Events.Items) != 2 || body.Data.Events.PageSize != 2 {
		t.Fatalf("page1: %+v", body.Data.Events)
	}
	_, body = doGet(t, mux, "/api/v1/api-security/cross-border?page_size=2&page=2")
	if len(body.Data.Events.Items) != 1 {
		t.Fatalf("page2: %+v", body.Data.Events)
	}
}

// TestCrossBorderBadQuery 参数校验矩阵：非法枚举/格式 400。
func TestCrossBorderBadQuery(t *testing.T) {
	store := NewMemStore()
	mux := newTestMux(store, handlerLookup, fakeSettings{}, injectPrincipal(apidata.PermDataRead))
	bad := []string{
		"/api/v1/api-security/cross-border?direction=SIDEWAYS",
		"/api/v1/api-security/cross-border?risk_level=CRITICAL",
		"/api/v1/api-security/cross-border?country=USA",
		"/api/v1/api-security/cross-border?country=1S",
		"/api/v1/api-security/cross-border?endpoint_key=" + strings.Repeat("a", 561),
	}
	for _, url := range bad {
		if code, _ := doGet(t, mux, url); code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d, want 400", url, code)
		}
	}
}

// TestCrossBorderGeoDisabled 数据源未启用：geo_enabled=false 如实标注，
// 既有数据（可能为空）仍返回，不伪造判定。
func TestCrossBorderGeoDisabled(t *testing.T) {
	store := NewMemStore()
	mux := newTestMux(store, nil, fakeSettings{}, injectPrincipal(apidata.PermDataRead))
	code, body := doGet(t, mux, "/api/v1/api-security/cross-border")
	if code != http.StatusOK {
		t.Fatalf("status=%d", code)
	}
	if body.Data.GeoEnabled {
		t.Fatal("geo_enabled should be false when lookup is nil")
	}
	if body.Data.Dashboard.Summary.TotalEvents != 0 || len(body.Data.Dashboard.Trend) != 7 {
		t.Fatalf("dashboard=%+v", body.Data.Dashboard)
	}
	if body.Data.Events.Total != 0 {
		t.Fatalf("events=%+v", body.Data.Events)
	}
}

// urlQueryEscape 查询串转义（空格）。
func urlQueryEscape(s string) string {
	out := ""
	for _, b := range []byte(s) {
		if b == ' ' {
			out += "%20"
		} else {
			out += string(b)
		}
	}
	return out
}
