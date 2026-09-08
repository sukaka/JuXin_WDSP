package analytics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBucketFloor(t *testing.T) {
	tm := time.Date(2026, 7, 21, 12, 34, 56, 0, time.UTC)
	if got := bucketFloor(tm, "minute"); !got.Equal(time.Date(2026, 7, 21, 12, 34, 0, 0, time.UTC)) {
		t.Errorf("minute floor: %v", got)
	}
	if got := bucketFloor(tm, "hour"); !got.Equal(time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("hour floor: %v", got)
	}
	if got := bucketFloor(tm, "day"); !got.Equal(time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("day floor: %v", got)
	}
}

func TestFillBucketsHourAxis(t *testing.T) {
	end := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	r := Range{Start: end.Add(-3 * time.Hour), End: end}
	counts := map[time.Time]int64{
		end.Add(-2 * time.Hour): 7,
	}
	series := fillBuckets(r, counts)
	// 完整时间轴：[10,11,12) 共 3 个小时桶
	if len(series) != 3 {
		t.Fatalf("len = %d, want 3", len(series))
	}
	for i, p := range series {
		wantT := r.Start.Add(time.Duration(i) * time.Hour)
		if !p.T.Equal(wantT) {
			t.Errorf("series[%d].t = %v, want %v", i, p.T, wantT)
		}
	}
	if series[1].Requests != 7 {
		t.Errorf("series[1].requests = %d, want 7", series[1].Requests)
	}
	if series[0].Requests != 0 || series[2].Requests != 0 {
		t.Errorf("空桶应补 0: %+v", series)
	}
}

func TestFillBucketsMinuteAxisAndUnalignedStart(t *testing.T) {
	// 起点未对齐分钟边界时，首桶向下取整到分钟，轴覆盖 [floor(start), end)
	end := time.Date(2026, 7, 21, 12, 2, 30, 0, time.UTC)
	r := Range{Start: end.Add(-3 * time.Minute), End: end} // 11:59:30 ~ 12:02:30
	series := fillBuckets(r, nil)
	if len(series) != 4 { // 11:59 12:00 12:01 12:02
		t.Fatalf("len = %d, want 4", len(series))
	}
	if !series[0].T.Equal(time.Date(2026, 7, 21, 11, 59, 0, 0, time.UTC)) {
		t.Errorf("first bucket: %v", series[0].T)
	}
	for i, p := range series {
		if p.Requests != 0 {
			t.Errorf("series[%d].requests = %d, want 0（空结果补零）", i, p.Requests)
		}
	}
}

func TestFillBucketsEmptyCounts(t *testing.T) {
	end := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	r := Range{Start: end.Add(-24 * time.Hour), End: end}
	series := fillBuckets(r, map[time.Time]int64{})
	if len(series) != 24 {
		t.Fatalf("len = %d, want 24", len(series))
	}
	var sum int64
	for _, p := range series {
		sum += p.Requests
	}
	if sum != 0 {
		t.Errorf("sum = %d, want 0", sum)
	}
}

func TestSortSiteTrendItems(t *testing.T) {
	id1, id2, id3 := uuid.New(), uuid.New(), uuid.New()
	items := []SiteAccessTrendItem{
		{ApplicationID: id1, AppCode: "b-app", TotalRequests: 3},
		{ApplicationID: id2, AppCode: "a-app", TotalRequests: 3},
		{ApplicationID: id3, AppCode: "c-app", TotalRequests: 9},
	}
	sortSiteTrendItems(items)
	if items[0].AppCode != "c-app" || items[1].AppCode != "a-app" || items[2].AppCode != "b-app" {
		t.Errorf("order: %+v", items)
	}
}

func TestSortDomainTrendItems(t *testing.T) {
	items := []DomainAccessTrendItem{
		{Domain: "b.example.com", TotalRequests: 1},
		{Domain: "a.example.com", TotalRequests: 5},
		{Domain: "c.example.com", TotalRequests: 5},
	}
	sortDomainTrendItems(items)
	if items[0].Domain != "a.example.com" || items[1].Domain != "c.example.com" || items[2].Domain != "b.example.com" {
		t.Errorf("order: %+v", items)
	}
}

func TestSiteTrendsRejectsOver7Days(t *testing.T) {
	h := NewHandler(nil, nil) // 校验先于任何 DB 访问
	cases := []string{
		"/api/v1/analytics/site-access-trends?start_time=2026-07-01T00:00:00Z&end_time=2026-07-09T00:00:00Z",                                                 // 8 天
		"/api/v1/analytics/site-access-trends/domains?application_id=" + uuid.NewString() + "&start_time=2026-07-01T00:00:00Z&end_time=2026-07-08T00:00:01Z", // >7 天
	}
	for _, u := range cases {
		req := httptest.NewRequest(http.MethodGet, u, nil)
		rec := httptest.NewRecorder()
		if strings.Contains(u, "/domains") {
			h.SiteAccessTrendDomains(rec, req)
		} else {
			h.SiteAccessTrends(rec, req)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, body: %s", u, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "7 天") || !strings.Contains(rec.Body.String(), "保留期") {
			t.Errorf("%s 应提示数据保留期限制: %s", u, rec.Body.String())
		}
	}
}

func TestSiteTrendsRejectsBadRange(t *testing.T) {
	h := NewHandler(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/site-access-trends?start_time=bad", nil)
	rec := httptest.NewRecorder()
	h.SiteAccessTrends(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "INVALID_ARGUMENT") {
		t.Errorf("body: %s", rec.Body.String())
	}
}

func TestSiteTrendDomainsRequiresApplicationID(t *testing.T) {
	h := NewHandler(nil, nil)
	// 缺失 application_id
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/site-access-trends/domains", nil)
	rec := httptest.NewRecorder()
	h.SiteAccessTrendDomains(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing application_id status = %d, body: %s", rec.Code, rec.Body.String())
	}
	// 非法 application_id
	req = httptest.NewRequest(http.MethodGet, "/api/v1/analytics/site-access-trends/domains?application_id=xyz", nil)
	rec = httptest.NewRecorder()
	h.SiteAccessTrendDomains(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid application_id status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "INVALID_ARGUMENT") {
		t.Errorf("body: %s", rec.Body.String())
	}
}
