// overview_test.go 敏感数据态势聚合测试（内存仓储）。
package apidata

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestSensitiveOverview 涉敏 API 数、类型分布、近 7 天趋势（零值日补齐）。
func TestSensitiveOverview(t *testing.T) {
	store := NewMemStore()
	ctx := context.Background()
	ep1 := "GET /orders/{id}"
	ep2 := "POST /users"
	store.addEndpoint(ep1)
	store.addEndpoint(ep2)

	now := time.Now().UTC()
	yesterday := now.Add(-24 * time.Hour)
	// ep1：今天 query.phone 命中两次；ep2：昨天 json.id_card 命中一次
	store.addRuntimeEvent(ep1, now.Add(-time.Hour), sensitiveDetails(t, []map[string]any{
		queryPhoneHit("phone"),
	}))
	store.addRuntimeEvent(ep1, now.Add(-30*time.Minute), sensitiveDetails(t, []map[string]any{
		queryPhoneHit("phone"), jsonEmailHit("email"),
	}))
	store.addRuntimeEvent(ep2, yesterday, sensitiveDetails(t, []map[string]any{
		{
			"detector": "sensitive_data",
			"rule_id":  "sensitive.field",
			"evidence": map[string]string{"field": "id_card", "data_type": "id_card", "location": "json"},
		},
	}))
	// 8 天前的事件不计入 7 天趋势
	store.addRuntimeEvent(ep1, now.Add(-8*24*time.Hour), sensitiveDetails(t, []map[string]any{
		queryPhoneHit("phone"),
	}))

	if _, err := store.SweepOnce(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	overview, err := store.SensitiveOverview(ctx, 7)
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if overview.SensitiveEndpointCount != 2 || overview.SensitiveFieldCount != 3 {
		t.Fatalf("summary=%+v", overview)
	}
	if len(overview.TypeDistribution) != 3 {
		t.Fatalf("distribution=%+v", overview.TypeDistribution)
	}
	// phone/email/id_card 各 1 个字段行（同端点同路径去重），分布按字段数并列、名称升序；
	// phone 累计命中 3 次（今天 2 次 + 8 天前 1 次，sweep 无水位全量回填）
	byType := map[string]TypeDistItem{}
	for _, it := range overview.TypeDistribution {
		byType[it.DataType] = it
		if it.FieldCount != 1 || it.EndpointCount != 1 {
			t.Fatalf("dist item=%+v", it)
		}
	}
	if byType["phone"].OccurrenceCount != 3 || byType["email"].OccurrenceCount != 1 || byType["id_card"].OccurrenceCount != 1 {
		t.Fatalf("distribution=%+v", overview.TypeDistribution)
	}
	// 趋势：7 天零值补齐
	if len(overview.Trend) != 7 {
		t.Fatalf("trend len=%d", len(overview.Trend))
	}
	today := now.Format("2006-01-02")
	yday := yesterday.Format("2006-01-02")
	var todayPoint, ydayPoint *TrendPoint
	for i := range overview.Trend {
		switch overview.Trend[i].Date {
		case today:
			todayPoint = &overview.Trend[i]
		case yday:
			ydayPoint = &overview.Trend[i]
		}
	}
	if todayPoint == nil || todayPoint.EventCount != 2 || todayPoint.HitCount != 3 {
		t.Fatalf("today=%+v", todayPoint)
	}
	if ydayPoint == nil || ydayPoint.EventCount != 1 || ydayPoint.HitCount != 1 {
		t.Fatalf("yesterday=%+v", ydayPoint)
	}
	// 8 天前命中不进 7 天窗口（事件总数已在上面断言：今天 2 + 昨天 1）
	var totalEvents int64
	for _, p := range overview.Trend {
		totalEvents += p.EventCount
	}
	if totalEvents != 3 {
		t.Fatalf("trend total=%d", totalEvents)
	}

	// days 参数：默认/上限收敛
	ov3, err := store.SensitiveOverview(ctx, 3)
	if err != nil || len(ov3.Trend) != 3 {
		t.Fatalf("days=3 trend=%d err=%v", len(ov3.Trend), err)
	}
	ovMax, err := store.SensitiveOverview(ctx, 365)
	if err != nil || len(ovMax.Trend) != OverviewMaxDays {
		t.Fatalf("days clamp=%d err=%v", len(ovMax.Trend), err)
	}
}

// TestSensitiveOverviewEmpty 空态势安全（全零 + 趋势零值补齐）。
func TestSensitiveOverviewEmpty(t *testing.T) {
	store := NewMemStore()
	overview, err := store.SensitiveOverview(context.Background(), 0) // 0 → 默认 7
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if overview.SensitiveEndpointCount != 0 || overview.SensitiveFieldCount != 0 ||
		len(overview.TypeDistribution) != 0 || len(overview.Trend) != 7 || overview.Days != 7 {
		t.Fatalf("overview=%+v", overview)
	}
	for _, p := range overview.Trend {
		if p.EventCount != 0 || p.HitCount != 0 {
			t.Fatalf("empty trend point=%+v", p)
		}
	}
}

// TestSensitiveOverviewHTTP 接口层（含 days 查询参数透传）。
func TestSensitiveOverviewHTTP(t *testing.T) {
	mux := newTestMux(NewHandler(NewMemStore(), nil))
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/sensitive/overview", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var overview SensitiveOverview
	decodeData(t, rr, &overview)
	if overview.Days != 7 || len(overview.Trend) != 7 {
		t.Fatalf("overview=%+v", overview)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/sensitive/overview?days=3", nil)
	decodeData(t, rr, &overview)
	if overview.Days != 3 || len(overview.Trend) != 3 {
		t.Fatalf("overview days=3: %+v", overview)
	}
}
