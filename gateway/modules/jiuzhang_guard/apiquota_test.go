package jiuzhang_guard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// api_quota_per_hour 等 §36 限流键发布字段反序列化；旧版配置无此键时为零值
// （对应检测不启用，零行为变化）；负数装配期 Validate 显式拒绝。
func TestGuardConfigAPIRateLimitKeysJSON(t *testing.T) {
	raw := `{
		"app_id": "app-1",
		"events_log": "/var/log/caddy/guard-events.log",
		"api_dynamic_protection": true,
		"api_protection_mode": "OBSERVE",
		"api_quota_per_hour": 3600,
		"api_quota_per_day": 50000,
		"object_rate_per_minute": 60,
		"max_page_size": 500,
		"max_batch_size": 200
	}`
	var g Guard
	if err := json.Unmarshal([]byte(raw), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if g.APIQuotaPerHour != 3600 || g.APIQuotaPerDay != 50000 || g.ObjectRatePerMinute != 60 ||
		g.MaxPageSize != 500 || g.MaxBatchSize != 200 {
		t.Fatalf("rate limit keys = %+v", g)
	}

	// 旧配置（无该组键）：全部零值，检测不启用
	var legacy Guard
	if err := json.Unmarshal([]byte(`{"app_id":"a","events_log":"/tmp/e.log"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.APIQuotaPerHour != 0 || legacy.APIQuotaPerDay != 0 || legacy.ObjectRatePerMinute != 0 ||
		legacy.MaxPageSize != 0 || legacy.MaxBatchSize != 0 {
		t.Fatalf("legacy config must leave rate limit keys zero: %+v", legacy)
	}

	// 负数非法（0 = 不启用），装配期显式拒绝
	bad := Guard{EventsLog: "/tmp/e.log", APIDynamicProtection: true, MaxPageSize: -1}
	if err := bad.Validate(); err == nil {
		t.Fatal("negative max_page_size must fail validation")
	}
}

// §36 限流下发面接线：max_page_size / max_batch_size 透传管线，
// 超限 query 参数命中 OBSERVE 信号；未配置（零值）时无对应明细。
func TestServeNext_PageAndBatchSizeLimits(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	g.MaxPageSize = 100
	g.MaxBatchSize = 3

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	req := httptest.NewRequest(http.MethodGet, "/v1/orders?page_size=999&ids=1,2,3,4", nil)
	req.Header.Set("Accept", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d: %+v", len(recs), recs)
	}
	want := map[string]bool{
		"ratelimit.page_size_exceeded":  false,
		"ratelimit.batch_size_exceeded": false,
	}
	for _, d := range recs[0].Details {
		if _, ok := want[d.RuleID]; ok {
			want[d.RuleID] = true
			// RATE_LIMIT 类只 AddMatch 不定案：OBSERVE 下明细保留检测器类别且请求放行
			if d.Category != "RATE_LIMIT" {
				t.Fatalf("%s category = %q, want RATE_LIMIT", d.RuleID, d.Category)
			}
		}
	}
	for id, found := range want {
		if !found {
			t.Fatalf("%s detail missing: %+v", id, recs[0].Details)
		}
	}

	// 零值（未下发）：同形态请求无 §36 明细
	g2, logPath2 := newAPITestGuard(t, "OBSERVE", nil)
	req2 := httptest.NewRequest(http.MethodGet, "/v1/orders?page_size=999&ids=1,2,3,4", nil)
	req2.Header.Set("Accept", "application/json")
	if err := g2.serveNext(httptest.NewRecorder(), req2, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	for _, rec := range readAPIRecords(t, logPath2) {
		for _, d := range rec.Details {
			if strings.HasPrefix(d.RuleID, "ratelimit.") {
				t.Fatalf("zero config must not emit §36 detail: %+v", d)
			}
		}
	}
}

// api_quota_per_hour 接线：身份+端点定窗计数，第二请求超阈命中 OBSERVE 信号。
func TestServeNext_APIQuotaPerHour(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	g.APIQuotaPerHour = 1

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	mk := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer quota-hourly-wiring-token")
		req.RemoteAddr = "203.0.113.70:1001"
		return req
	}
	if err := g.serveNext(httptest.NewRecorder(), mk(), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if err := g.serveNext(httptest.NewRecorder(), mk(), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("want 2 api events, got %d: %+v", len(recs), recs)
	}
	for _, d := range recs[0].Details {
		if d.RuleID == "ratelimit.api_hourly_quota" {
			t.Fatalf("first request below quota must not match: %+v", recs[0].Details)
		}
	}
	found := false
	for _, d := range recs[1].Details {
		if d.RuleID == "ratelimit.api_hourly_quota" {
			found = true
			if d.Category != "RATE_LIMIT" {
				t.Fatalf("quota detail category = %q, want RATE_LIMIT", d.Category)
			}
		}
	}
	if !found {
		t.Fatalf("api_hourly_quota detail missing: %+v", recs[1].Details)
	}
}

// object_rate_per_minute 接线：同身份对同对象（路径位置参数）第二请求命中 OBSERVE 信号。
func TestServeNext_ObjectRatePerMinute(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	g.ObjectRatePerMinute = 1

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	mk := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/v1/orders/987654", nil)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer object-rate-wiring-token")
		req.RemoteAddr = "203.0.113.71:1001"
		return req
	}
	if err := g.serveNext(httptest.NewRecorder(), mk(), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if err := g.serveNext(httptest.NewRecorder(), mk(), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("want 2 api events, got %d: %+v", len(recs), recs)
	}
	found := false
	for _, d := range recs[1].Details {
		if d.RuleID == "ratelimit.object_rate" {
			found = true
			if d.Category != "RATE_LIMIT" {
				t.Fatalf("object rate detail category = %q, want RATE_LIMIT", d.Category)
			}
			// 对象原始值不出证据（仅结构维度）
			for _, v := range d.Evidence {
				if strings.Contains(v, "987654") {
					t.Fatalf("object raw value leaked into evidence: %+v", d.Evidence)
				}
			}
		}
	}
	if !found {
		t.Fatalf("object_rate detail missing: %+v", recs[1].Details)
	}
}
