// sitetraffic_test.go 站点流量分析：参数校验（400 先于 DB）、数据源路由与
// 响应组装纯逻辑单测（补桶/排序/零流量应用/summary 口径，不依赖数据库）。
package analytics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// stRow 构造单应用单桶查询行。
func stRow(id uuid.UUID, code, name string, bucket *time.Time, reqs, bin, bout, uips, blocked int64) siteTrafficRow {
	return siteTrafficRow{
		appID: id, code: code, name: name, bucket: bucket,
		m: siteTrafficBucket{requests: reqs, bytesIn: bin, bytesOut: bout, uniqueIPs: uips, blocked: blocked},
	}
}

func stTime(t time.Time) *time.Time { return &t }

func TestSiteTrafficRejectsOver31Days(t *testing.T) {
	h := NewHandler(nil, nil) // 校验先于任何 DB 访问
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/analytics/site-traffic?start_time=2026-08-01T00:00:00Z&end_time=2026-09-02T00:00:01Z", nil)
	rec := httptest.NewRecorder()
	h.SiteTraffic(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "INVALID_ARGUMENT") || !strings.Contains(rec.Body.String(), "31 天") {
		t.Errorf("body: %s", rec.Body.String())
	}
}

func TestSiteTrafficRejectsBadRange(t *testing.T) {
	h := NewHandler(nil, nil)
	cases := []string{
		"/api/v1/analytics/site-traffic?start_time=bad",
		"/api/v1/analytics/site-traffic?start_time=2026-09-10T00:00:00Z&end_time=2026-09-09T00:00:00Z", // 倒置
		"/api/v1/analytics/site-traffic?start_time=2026-09-10T00:00:00Z&end_time=2026-09-10T00:00:00Z", // 相等
	}
	for _, u := range cases {
		req := httptest.NewRequest(http.MethodGet, u, nil)
		rec := httptest.NewRecorder()
		h.SiteTraffic(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, body: %s", u, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "INVALID_ARGUMENT") {
			t.Errorf("%s body: %s", u, rec.Body.String())
		}
	}
}

func TestSiteTrafficRejectsBadApplicationID(t *testing.T) {
	h := NewHandler(nil, nil)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/analytics/site-traffic?application_id=not-a-uuid&start_time=2026-09-18T00:00:00Z&end_time=2026-09-19T00:00:00Z", nil)
	rec := httptest.NewRecorder()
	h.SiteTraffic(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "INVALID_ARGUMENT") {
		t.Errorf("body: %s", rec.Body.String())
	}
}

func TestSiteTrafficSourceRouting(t *testing.T) {
	end := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		d    time.Duration
		want string
	}{
		{time.Hour, siteTrafficSourceAccessLogs},
		{7 * 24 * time.Hour, siteTrafficSourceAccessLogs},      // 边界：≤7d 直查
		{7*24*time.Hour + time.Second, siteTrafficSourceDaily}, // >7d 走日聚合表
		{30 * 24 * time.Hour, siteTrafficSourceDaily},
		{31 * 24 * time.Hour, siteTrafficSourceDaily},
	}
	for _, c := range cases {
		r := Range{Start: end.Add(-c.d), End: end}
		if got := siteTrafficSource(r); got != c.want {
			t.Errorf("d=%v: source = %s, want %s", c.d, got, c.want)
		}
	}
}

// TestAssembleSiteTrafficAccessLogs 直查数据源：零流量应用出现、补桶、排序、
// summary 各字段合计且 unique_ips 非 nil。
func TestAssembleSiteTrafficAccessLogs(t *testing.T) {
	end := time.Date(2026, 9, 19, 3, 0, 0, 0, time.UTC)
	r := Range{Start: end.Add(-3 * time.Hour), End: end} // hour 桶，3 桶
	appA, appB, appC := uuid.New(), uuid.New(), uuid.New()
	b0, b1 := end.Add(-3*time.Hour), end.Add(-2*time.Hour)
	rows := []siteTrafficRow{
		stRow(appB, "b-app", "应用B", stTime(b0), 2, 100, 200, 1, 0),
		stRow(appA, "a-app", "应用A", stTime(b0), 5, 500, 600, 3, 1),
		stRow(appA, "a-app", "应用A", stTime(b1), 7, 700, 800, 2, 2),
		stRow(appC, "c-app", "应用C", nil, 0, 0, 0, 0, 0), // 零流量应用（LEFT JOIN 空侧）
	}
	data := assembleSiteTraffic(r, siteTrafficSourceAccessLogs, rows)
	if data.Source != siteTrafficSourceAccessLogs || data.Granularity != "hour" {
		t.Errorf("meta: source=%s granularity=%s", data.Source, data.Granularity)
	}
	if len(data.Items) != 3 {
		t.Fatalf("items = %d, want 3（含零流量应用）", len(data.Items))
	}
	// 排序：total_requests 降序 → a-app(12) 在最前；b/c 同 2/0... b-app(2) 次之，c-app(0) 最后
	if data.Items[0].AppCode != "a-app" || data.Items[1].AppCode != "b-app" || data.Items[2].AppCode != "c-app" {
		t.Errorf("order: %s %s %s", data.Items[0].AppCode, data.Items[1].AppCode, data.Items[2].AppCode)
	}
	a := data.Items[0]
	if a.TotalRequests != 12 || a.TotalBytesIn != 1200 || a.TotalBytesOut != 1400 || a.UniqueIPs != 5 || a.BlockedRequests != 3 {
		t.Errorf("a-app totals: %+v", a)
	}
	if len(a.Series) != 3 || a.Series[0].Requests != 5 || a.Series[1].Requests != 7 || a.Series[2].Requests != 0 {
		t.Errorf("a-app series（末桶补 0）: %+v", a.Series)
	}
	c := data.Items[2]
	if c.TotalRequests != 0 || len(c.Series) != 3 {
		t.Errorf("c-app 零流量项: %+v", c)
	}
	for _, p := range c.Series {
		if p.Requests != 0 || p.BytesIn != 0 || p.UniqueIPs != 0 {
			t.Errorf("零流量应用桶应全 0: %+v", p)
		}
	}
	// summary：合计 + peak 为 items 汇总序列单桶最大值（b0 桶 5+2=7，b1 桶 7 → peak=7）
	s := data.Summary
	if s.TotalRequests != 14 || s.TotalBytesIn != 1300 || s.TotalBytesOut != 1600 || s.BlockedRequests != 3 {
		t.Errorf("summary: %+v", s)
	}
	if s.UniqueIPs == nil || *s.UniqueIPs != 6 {
		t.Errorf("summary.unique_ips 应为 6（直查可加和）: %+v", s.UniqueIPs)
	}
	if s.PeakBucketRequests != 7 {
		t.Errorf("peak_bucket_requests = %d, want 7", s.PeakBucketRequests)
	}
}

// TestAssembleSiteTrafficDailySummary 日聚合数据源：summary.unique_ips 为 null
// （跨天去重不可加和），blocked 照常加和，series 点用表中值。
func TestAssembleSiteTrafficDailySummary(t *testing.T) {
	end := time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC)
	r := Range{Start: end.AddDate(0, 0, -30), End: end} // 30 天，day 桶
	appA := uuid.New()
	d1 := end.AddDate(0, 0, -2)
	d2 := end.AddDate(0, 0, -1)
	rows := []siteTrafficRow{
		stRow(appA, "a-app", "应用A", stTime(d1), 10, 1000, 2000, 4, 1),
		stRow(appA, "a-app", "应用A", stTime(d2), 20, 3000, 4000, 6, 2),
	}
	data := assembleSiteTraffic(r, siteTrafficSourceDaily, rows)
	if data.Source != siteTrafficSourceDaily || data.Granularity != "day" {
		t.Errorf("meta: source=%s granularity=%s", data.Source, data.Granularity)
	}
	if len(data.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(data.Items))
	}
	item := data.Items[0]
	if len(item.Series) != 30 {
		t.Fatalf("series len = %d, want 30（空天补 0）", len(item.Series))
	}
	if item.Series[28].Requests != 10 || item.Series[29].Requests != 20 {
		t.Errorf("series 末两桶: %+v %+v", item.Series[28], item.Series[29])
	}
	if item.Series[28].UniqueIPs != 4 || item.Series[29].BlockedRequests != 2 {
		t.Errorf("series 点应带表中 unique/blocked 值: %+v %+v", item.Series[28], item.Series[29])
	}
	if item.TotalRequests != 30 || item.UniqueIPs != 10 { // item 级为逐日值加和
		t.Errorf("item totals: %+v", item)
	}
	if data.Summary.UniqueIPs != nil {
		t.Errorf(">7 天 summary.unique_ips 必须为 null, got %v", *data.Summary.UniqueIPs)
	}
	if data.Summary.BlockedRequests != 3 || data.Summary.TotalRequests != 30 {
		t.Errorf("summary: %+v", data.Summary)
	}
	if data.Summary.PeakBucketRequests != 20 {
		t.Errorf("peak = %d, want 20", data.Summary.PeakBucketRequests)
	}
}

// TestAssembleSiteTrafficSingleApp 指定 application_id 时查询行只含该站点：
// items 仅一项，summary 同该项。
func TestAssembleSiteTrafficSingleApp(t *testing.T) {
	end := time.Date(2026, 9, 19, 2, 0, 0, 0, time.UTC)
	r := Range{Start: end.Add(-time.Hour), End: end} // minute 桶
	appA := uuid.New()
	b := end.Add(-time.Minute)
	rows := []siteTrafficRow{stRow(appA, "a-app", "应用A", stTime(b), 3, 30, 40, 2, 1)}
	data := assembleSiteTraffic(r, siteTrafficSourceAccessLogs, rows)
	if data.Granularity != "minute" {
		t.Errorf("granularity = %s, want minute", data.Granularity)
	}
	if len(data.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(data.Items))
	}
	if data.Summary.TotalRequests != 3 || data.Summary.PeakBucketRequests != 3 {
		t.Errorf("summary 应同唯一 item: %+v", data.Summary)
	}
	// 未知 id：查询无行 → items 空、summary 全 0（不报错）
	empty := assembleSiteTraffic(r, siteTrafficSourceAccessLogs, nil)
	if len(empty.Items) != 0 || empty.Summary.TotalRequests != 0 {
		t.Errorf("未知应用应返回空 items: %+v", empty)
	}
	if empty.Summary.UniqueIPs == nil || *empty.Summary.UniqueIPs != 0 {
		t.Errorf("空结果 summary.unique_ips 应为 0: %+v", empty.Summary.UniqueIPs)
	}
}

// TestAssembleSiteTrafficTieBreak 同请求数按应用编码升序。
func TestAssembleSiteTrafficTieBreak(t *testing.T) {
	end := time.Date(2026, 9, 19, 1, 0, 0, 0, time.UTC)
	r := Range{Start: end.Add(-time.Hour), End: end}
	id1, id2 := uuid.New(), uuid.New()
	b := end.Add(-30 * time.Minute)
	rows := []siteTrafficRow{
		stRow(id1, "b-app", "应用B", stTime(b), 5, 0, 0, 0, 0),
		stRow(id2, "a-app", "应用A", stTime(b), 5, 0, 0, 0, 0),
	}
	data := assembleSiteTraffic(r, siteTrafficSourceAccessLogs, rows)
	if data.Items[0].AppCode != "a-app" || data.Items[1].AppCode != "b-app" {
		t.Errorf("tie-break order: %s %s", data.Items[0].AppCode, data.Items[1].AppCode)
	}
}
