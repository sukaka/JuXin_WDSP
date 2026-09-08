// sweep_test.go SweepOnce 跨境清扫测试（内存仓储 + 假 GeoIP 查询，语义同 SQL）。
package apigeo

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// fakeSettings 假设置读取（group:key → value）。
type fakeSettings map[string]string

func (f fakeSettings) GetString(_ context.Context, group, key, def string) string {
	if v, ok := f[group+":"+key]; ok {
		return v
	}
	return def
}

// sensitiveDetails 构造运行时事件检测明细（镜像 dsctx.DetectorMatch JSON 形状）。
func sensitiveDetails(t *testing.T, details []map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// sensHit 构造一条敏感命中明细（direction 空 = 网关当前请求侧缺省口径）。
func sensHit(dataType, direction string) map[string]any {
	ev := map[string]string{"field": "f1", "data_type": dataType, "location": "query"}
	if direction != "" {
		ev["direction"] = direction
	}
	return map[string]any{"detector": "sensitive_data", "rule_id": "sensitive.in_query", "evidence": ev}
}

// newTestSweeper 装配内存仓储 + 假 GeoIP（CN 本土；byIP 为归属表）。
func newTestSweeper(store *MemStore, byIP map[string]string, settings SettingsReader) *Sweeper {
	return NewSweeper(store, fakeLookup{byIP: byIP}, settings)
}

// TestSweepOnceClassifyAndInsert 首次全量回填：仅境外来源落库；
// 本土/内网/未知/非法 IP 逐一跳过并计数。
func TestSweepOnceClassifyAndInsert(t *testing.T) {
	store := NewMemStore()
	store.setDataTypeLevels(map[string]string{"id_card": "IMPORTANT", "phone": "SENSITIVE", "email": "GENERAL"})
	byIP := map[string]string{"8.8.8.8": "US", "114.114.114.114": "CN"}
	sweeper := newTestSweeper(store, byIP, fakeSettings{})
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)

	// 境外（US）请求侧命中 id_card+phone
	store.addRuntimeEvent("GET /users/{id}", "8.8.8.8", "fp-1", base,
		sensitiveDetails(t, []map[string]any{sensHit("id_card", ""), sensHit("phone", "")}))
	// 本土（CN）命中敏感 → 跳过
	store.addRuntimeEvent("GET /users/{id}", "114.114.114.114", "fp-2", base.Add(time.Minute),
		sensitiveDetails(t, []map[string]any{sensHit("id_card", "")}))
	// 内网 → 跳过
	store.addRuntimeEvent("GET /users/{id}", "10.0.0.9", "fp-3", base.Add(2*time.Minute),
		sensitiveDetails(t, []map[string]any{sensHit("phone", "")}))
	// 公网但库未收录 → 跳过
	store.addRuntimeEvent("GET /users/{id}", "9.9.9.9", "fp-4", base.Add(3*time.Minute),
		sensitiveDetails(t, []map[string]any{sensHit("phone", "")}))
	// 非法 IP → 跳过
	store.addRuntimeEvent("GET /users/{id}", "not-an-ip", "fp-5", base.Add(4*time.Minute),
		sensitiveDetails(t, []map[string]any{sensHit("phone", "")}))
	// 无 client_ip（SQL 层已过滤，内存实现同口径）→ 根本不进扫描集
	store.addRuntimeEvent("GET /users/{id}", "", "fp-6", base.Add(5*time.Minute),
		sensitiveDetails(t, []map[string]any{sensHit("phone", "")}))

	res, err := sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if !res.GeoEnabled || res.EventsScanned != 5 || res.EventsInserted != 1 {
		t.Fatalf("result=%+v", res)
	}
	if res.SkippedHome != 1 || res.SkippedInternal != 1 || res.SkippedUnknown != 1 || res.SkippedBadIP != 1 {
		t.Fatalf("skips=%+v", res)
	}
	if len(res.HomeRegions) != 1 || res.HomeRegions[0] != "CN" {
		t.Fatalf("home=%v", res.HomeRegions)
	}
	rows := store.crossBorderRows()
	if len(rows) != 1 {
		t.Fatalf("rows=%d %+v", len(rows), rows)
	}
	row := rows[0]
	if row.Country != "US" || row.Direction != DirectionIn || row.RiskLevel != RiskHigh {
		t.Fatalf("row=%+v", row)
	}
	if row.ClientIP != "8.8.8.8" || row.IdentityFingerprint != "fp-1" || row.EndpointKey != "GET /users/{id}" {
		t.Fatalf("row=%+v", row)
	}
	if len(row.DataTypes) != 2 || row.DataTypes[0] != "id_card" || row.DataTypes[1] != "phone" {
		t.Fatalf("data_types=%v", row.DataTypes)
	}
	if res.Watermark == nil || !res.Watermark.Equal(base.Add(4*time.Minute)) {
		t.Fatalf("watermark=%v", res.Watermark)
	}
}

// TestSweepOnceIdempotent 水位幂等：连续两次 SweepOnce 不重复落库；
// 新事件到达后增量产生；境外重复源事件（同 event_id 同方向）冲突跳过。
func TestSweepOnceIdempotent(t *testing.T) {
	store := NewMemStore()
	store.setDataTypeLevels(map[string]string{"phone": "SENSITIVE"})
	sweeper := newTestSweeper(store, map[string]string{"8.8.8.8": "US"}, fakeSettings{})
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)

	store.addRuntimeEvent("GET /a", "8.8.8.8", "", base,
		sensitiveDetails(t, []map[string]any{sensHit("phone", "")}))
	res1, err := sweeper.SweepOnce(ctx)
	if err != nil || res1.EventsInserted != 1 {
		t.Fatalf("sweep1=%+v err=%v", res1, err)
	}
	// 第二次：无新事件 → 全零（水位幂等）
	res2, err := sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep2: %v", err)
	}
	if res2.EventsScanned != 0 || res2.EventsInserted != 0 || len(store.crossBorderRows()) != 1 {
		t.Fatalf("sweep2=%+v rows=%d", res2, len(store.crossBorderRows()))
	}
	// 新事件增量落库
	store.addRuntimeEvent("GET /b", "8.8.8.8", "", base.Add(time.Minute),
		sensitiveDetails(t, []map[string]any{sensHit("phone", "")}))
	res3, err := sweeper.SweepOnce(ctx)
	if err != nil || res3.EventsScanned != 1 || res3.EventsInserted != 1 {
		t.Fatalf("sweep3=%+v err=%v", res3, err)
	}
	if len(store.crossBorderRows()) != 2 {
		t.Fatalf("rows=%d", len(store.crossBorderRows()))
	}
}

// TestSweepOnceDirections 双方向拆行：REQUEST 命中 → IN，RESPONSE 命中 → OUT；
// 同事件双侧命中各产一行，数据类型按方向归集。
func TestSweepOnceDirections(t *testing.T) {
	store := NewMemStore()
	store.setDataTypeLevels(map[string]string{"id_card": "IMPORTANT", "email": "GENERAL"})
	sweeper := newTestSweeper(store, map[string]string{"8.8.8.8": "US"}, fakeSettings{})
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)

	store.addRuntimeEvent("POST /profile", "8.8.8.8", "fp-x", base,
		sensitiveDetails(t, []map[string]any{
			sensHit("id_card", "REQUEST"),
			sensHit("email", "RESPONSE"),
		}))
	res, err := sweeper.SweepOnce(ctx)
	if err != nil || res.EventsInserted != 2 {
		t.Fatalf("sweep=%+v err=%v", res, err)
	}
	rows := store.crossBorderRows()
	if len(rows) != 2 {
		t.Fatalf("rows=%d", len(rows))
	}
	byDir := map[string]CrossBorderEvent{}
	for _, r := range rows {
		byDir[r.Direction] = r
	}
	in := byDir[DirectionIn]
	if in.RiskLevel != RiskHigh || len(in.DataTypes) != 1 || in.DataTypes[0] != "id_card" {
		t.Fatalf("in=%+v", in)
	}
	out := byDir[DirectionOut]
	if out.RiskLevel != RiskLow || len(out.DataTypes) != 1 || out.DataTypes[0] != "email" {
		t.Fatalf("out=%+v", out)
	}
	if in.SourceEventID != out.SourceEventID {
		t.Fatalf("source ids differ: %v vs %v", in.SourceEventID, out.SourceEventID)
	}
}

// TestRiskOf 风险推导矩阵（纯函数）：CORE/IMPORTANT→HIGH，SENSITIVE/字典外→MEDIUM，
// GENERAL/空→LOW。
func TestRiskOf(t *testing.T) {
	levels := map[string]string{"password": "CORE", "id_card": "IMPORTANT", "phone": "SENSITIVE", "email": "GENERAL"}
	cases := []struct {
		types []string
		want  string
	}{
		{[]string{"password"}, RiskHigh},
		{[]string{"id_card"}, RiskHigh},
		{[]string{"email", "id_card"}, RiskHigh},
		{[]string{"phone"}, RiskMedium},
		{[]string{"custom_type"}, RiskMedium}, // 字典外保守 MEDIUM
		{[]string{"email"}, RiskLow},
		{[]string{}, RiskLow},
	}
	for _, c := range cases {
		if got := riskOf(c.types, levels); got != c.want {
			t.Fatalf("riskOf(%v) = %s, want %s", c.types, got, c.want)
		}
	}
}

// TestSweepOnceGeoDisabled GeoIP 未启用：空转且如实标注，水位不推进
// （数据源就位后全量回填）。
func TestSweepOnceGeoDisabled(t *testing.T) {
	store := NewMemStore()
	base := time.Now().UTC().Add(-time.Hour)
	store.addRuntimeEvent("GET /a", "8.8.8.8", "", base,
		sensitiveDetails(t, []map[string]any{sensHit("phone", "")}))

	sweeper := NewSweeper(store, nil, fakeSettings{})
	res, err := sweeper.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.GeoEnabled || res.EventsScanned != 0 || res.EventsInserted != 0 || res.Watermark != nil {
		t.Fatalf("res=%+v", res)
	}
	if len(store.crossBorderRows()) != 0 {
		t.Fatalf("rows=%d", len(store.crossBorderRows()))
	}
	// 数据源就位（同库注入 lookup）后回填历史事件
	sweeper2 := NewSweeper(store, fakeLookup{byIP: map[string]string{"8.8.8.8": "US"}}, fakeSettings{})
	store.setDataTypeLevels(map[string]string{"phone": "SENSITIVE"})
	res2, err := sweeper2.SweepOnce(context.Background())
	if err != nil || res2.EventsInserted != 1 {
		t.Fatalf("backfill=%+v err=%v", res2, err)
	}
}

// TestSweepOnceHomeRegionsSetting home_regions 设置即时生效：US 纳入本土后不再落库。
func TestSweepOnceHomeRegionsSetting(t *testing.T) {
	store := NewMemStore()
	store.setDataTypeLevels(map[string]string{"phone": "SENSITIVE"})
	settings := fakeSettings{"api_data:home_regions": "CN,US"}
	sweeper := newTestSweeper(store, map[string]string{"8.8.8.8": "US"}, settings)
	base := time.Now().UTC().Add(-time.Hour)
	store.addRuntimeEvent("GET /a", "8.8.8.8", "", base,
		sensitiveDetails(t, []map[string]any{sensHit("phone", "")}))

	res, err := sweeper.SweepOnce(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.EventsInserted != 0 || res.SkippedHome != 1 {
		t.Fatalf("res=%+v", res)
	}
	if len(res.HomeRegions) != 2 || res.HomeRegions[0] != "CN" || res.HomeRegions[1] != "US" {
		t.Fatalf("home=%v", res.HomeRegions)
	}
}
