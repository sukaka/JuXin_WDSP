package tests

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// satInsertApp 直接写库创建应用（返回应用 ID）。
func satInsertApp(t *testing.T, env *testEnv, code, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := env.db.QueryRow(context.Background(),
		`INSERT INTO applications (code, name, status) VALUES ($1, $2, 'ACTIVE') RETURNING id`,
		code, name).Scan(&id)
	if err != nil {
		t.Fatalf("insert application: %v", err)
	}
	return id
}

// satInsertLog 直接写库插入访问日志（access_logs 无 HTTP 写入口，采集器入库）。
func satInsertLog(t *testing.T, env *testEnv, appID uuid.UUID, domain string, occurredAt time.Time) {
	t.Helper()
	_, err := env.db.Exec(context.Background(),
		`INSERT INTO access_logs (occurred_at, application_id, domain) VALUES ($1, $2, $3)`,
		occurredAt, appID, domain)
	if err != nil {
		t.Fatalf("insert access log: %v", err)
	}
}

// satSeriesSum 汇总 series 各桶 requests。
func satSeriesSum(t *testing.T, item map[string]interface{}) float64 {
	t.Helper()
	series, ok := item["series"].([]interface{})
	if !ok {
		t.Fatalf("series missing or not an array: %+v", item)
	}
	var sum float64
	for _, p := range series {
		pt, ok := p.(map[string]interface{})
		if !ok {
			t.Fatalf("series point not an object: %+v", p)
		}
		if _, err := time.Parse(time.RFC3339, fmt.Sprintf("%v", pt["t"])); err != nil {
			t.Fatalf("series point t not RFC3339: %+v", pt)
		}
		sum += pt["requests"].(float64)
	}
	return sum
}

// TestSiteAccessTrends 网站访问趋势（应用维度）：聚合正确性、零流量应用、参数校验、权限边界。
func TestSiteAccessTrends(t *testing.T) {
	env := setupTestEnv(t)
	secCookies, _ := env.s5Login(t, "sat_sec", "SECURITY_ADMIN")
	audCookies, _ := env.s5Login(t, "sat_aud", "AUDIT_ADMIN")

	now := time.Now().UTC()
	appA := satInsertApp(t, env, "sat-app-a", "趋势应用A")
	appB := satInsertApp(t, env, "sat-app-b", "趋势应用B") // 零流量应用
	satInsertLog(t, env, appA, "www.example.com", now.Add(-10*time.Minute))
	satInsertLog(t, env, appA, "www.example.com", now.Add(-20*time.Minute))
	satInsertLog(t, env, appA, "api.example.com", now.Add(-70*time.Minute))

	start := now.Add(-2 * time.Hour).Format(time.RFC3339)
	end := now.Format(time.RFC3339)

	// 应用维度：200 + 聚合正确
	resp := env.get(t, fmt.Sprintf("/api/v1/analytics/site-access-trends?start_time=%s&end_time=%s", start, end), secCookies)
	result := s5OK(t, resp, "site access trends")
	if g, _ := result.Data["granularity"].(string); g != "hour" {
		t.Errorf("granularity = %q, want hour", g)
	}
	items, ok := result.Data["items"].([]interface{})
	if !ok || len(items) != 2 {
		t.Fatalf("items len = %d, want 2: %+v", len(items), result.Data)
	}
	first := items[0].(map[string]interface{})
	second := items[1].(map[string]interface{})
	// 按 total_requests 降序：应用A（3 次）在前
	if first["app_code"] != "sat-app-a" || first["application_id"] != appA.String() {
		t.Errorf("first item: %+v", first)
	}
	if got := s5Num(t, first, "total_requests"); got != 3 {
		t.Errorf("app-a total_requests = %v, want 3", got)
	}
	if got := satSeriesSum(t, first); got != 3 {
		t.Errorf("app-a series sum = %v, want 3", got)
	}
	// 零流量应用也在结果中，series 为完整时间轴且全 0
	if second["app_code"] != "sat-app-b" || second["application_id"] != appB.String() {
		t.Errorf("second item: %+v", second)
	}
	if got := s5Num(t, second, "total_requests"); got != 0 {
		t.Errorf("app-b total_requests = %v, want 0", got)
	}
	if got := satSeriesSum(t, second); got != 0 {
		t.Errorf("app-b series sum = %v, want 0", got)
	}
	if len(first["series"].([]interface{})) != len(second["series"].([]interface{})) {
		t.Errorf("两应用 series 长度不一致（时间轴不完整）: %d vs %d",
			len(first["series"].([]interface{})), len(second["series"].([]interface{})))
	}
	// 缺省参数（最近 24 小时）也可查询
	resp = env.get(t, "/api/v1/analytics/site-access-trends", secCookies)
	s5Expect(t, resp, http.StatusOK, "site access trends default range")

	// 域名维度：200 + 按域名分组降序
	resp = env.get(t, fmt.Sprintf("/api/v1/analytics/site-access-trends/domains?application_id=%s&start_time=%s&end_time=%s", appA, start, end), secCookies)
	result = s5OK(t, resp, "site access trend domains")
	items, ok = result.Data["items"].([]interface{})
	if !ok || len(items) != 2 {
		t.Fatalf("domain items len = %d, want 2: %+v", len(items), result.Data)
	}
	d0 := items[0].(map[string]interface{})
	d1 := items[1].(map[string]interface{})
	if d0["domain"] != "www.example.com" || s5Num(t, d0, "total_requests") != 2 {
		t.Errorf("domain[0]: %+v", d0)
	}
	if d1["domain"] != "api.example.com" || s5Num(t, d1, "total_requests") != 1 {
		t.Errorf("domain[1]: %+v", d1)
	}
	if got := satSeriesSum(t, d0); got != 2 {
		t.Errorf("www series sum = %v, want 2", got)
	}

	// 参数错误 400
	badCases := []string{
		"/api/v1/analytics/site-access-trends?start_time=" + now.Add(-8*24*time.Hour).Format(time.RFC3339) + "&end_time=" + end, // 超过 7 天
		"/api/v1/analytics/site-access-trends?start_time=" + end + "&end_time=" + start,                                         // 倒置
		"/api/v1/analytics/site-access-trends?start_time=not-a-time",
		"/api/v1/analytics/site-access-trends/domains",                                                                                                                        // 缺 application_id
		"/api/v1/analytics/site-access-trends/domains?application_id=not-a-uuid",                                                                                              // 非法 application_id
		"/api/v1/analytics/site-access-trends/domains?application_id=" + appA.String() + "&start_time=" + now.Add(-30*24*time.Hour).Format(time.RFC3339) + "&end_time=" + end, // 超过 7 天
	}
	for _, p := range badCases {
		resp := env.get(t, p, secCookies)
		s5Expect(t, resp, http.StatusBadRequest, "bad params "+p)
	}

	// 审计管理员无 analytics.security.read 权限 → 403
	resp = env.get(t, "/api/v1/analytics/site-access-trends", audCookies)
	s5Expect(t, resp, http.StatusForbidden, "audit site-access-trends")
	resp = env.get(t, "/api/v1/analytics/site-access-trends/domains?application_id="+appA.String(), audCookies)
	s5Expect(t, resp, http.StatusForbidden, "audit site-access-trends/domains")
}
