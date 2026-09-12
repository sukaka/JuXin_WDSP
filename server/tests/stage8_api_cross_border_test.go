// stage8_api_cross_border_test.go 数据出境基础（W7-XB / P1-03）集成测试。
// 覆盖：迁移 000058 两表 + CHECK + 唯一索引 + home_regions 种子落位；
// SQL Store 的 SweepOnce 生产（境外落库/本土内网跳过/水位幂等/双方向拆行）；
// Dashboard 与 ListEvents 聚合过滤；HTTP 接线与权限点 api_data.read；
// 真实 GeoIP 库（仓库归档 country.mmdb，缺失跳过）端到端判定。
package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/apigeo"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/settings"
)

// xbGeoLookup 假国家码查询（map 驱动，实现 apigeo.CountryLookup）。
type xbGeoLookup map[string]string

func (f xbGeoLookup) LookupCountry(ip netip.Addr) (string, error) { return f[ip.String()], nil }

// xbInjectNoPerm 注入无 api_data.read 权限的主体（403 断言用）。
func xbInjectNoPerm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "w7xb-noperm", PermsSet: map[string]bool{}}
		next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
	})
}

// xbInjectAnon 不注入主体（401 断言用）。
func xbInjectAnon(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r) })
}

// xbSaveEvent 落一条带 client_ip 的运行时事件（经真实 SavePrimary 序列化 details_json）。
func xbSaveEvent(t *testing.T, env *testEnv, endpointKey, requestID, clientIP, identity string, at time.Time, details []dsctx.DetectorMatch) {
	t.Helper()
	rt := apiruntime.NewStore(env.db)
	err := rt.SavePrimary(context.Background(), &apiruntime.PrimaryEvent{
		PrimaryEvent: events.PrimaryEvent{
			RequestID: requestID, EndpointKey: endpointKey, OccurredAt: at,
			RiskScore: 40, RiskLevel: "MEDIUM", FinalAction: "OBSERVE", Details: details,
		},
		ClientIP:            clientIP,
		IdentityFingerprint: identity,
	})
	if err != nil {
		t.Fatalf("SavePrimary: %v", err)
	}
}

// xbSensHit 构造敏感命中明细（direction 空 = 请求侧缺省口径）。
func xbSensHit(dataType, direction string) dsctx.DetectorMatch {
	ev := map[string]string{"field": "f1", "data_type": dataType, "location": "query"}
	if direction != "" {
		ev["direction"] = direction
	}
	return dsctx.DetectorMatch{
		Detector: "sensitive_data", RuleID: "sensitive.in_query", Category: "BLOCK", Severity: "HIGH",
		Evidence: ev,
	}
}

// TestStage8CrossBorderMigration 迁移 000058 落位：表结构 / CHECK 约束 / 唯一索引 / 设置种子。
func TestStage8CrossBorderMigration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	// 两张表存在
	for _, table := range []string{"api_cross_border_events", "api_cross_border_state"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables WHERE table_name=$1`, table); n != 1 {
			t.Fatalf("table %s missing", table)
		}
	}
	// 契约列
	for _, col := range []string{"id", "occurred_at", "client_ip", "country", "asn", "endpoint_key",
		"identity_fingerprint", "data_types", "direction", "risk_level", "source_event_id", "created_at"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_cross_border_events' AND column_name=$1`, col); n != 1 {
			t.Fatalf("api_cross_border_events column %s missing", col)
		}
	}
	// 水位单行种子
	if n := s8Count(t, env, `SELECT count(*) FROM api_cross_border_state WHERE id = TRUE`); n != 1 {
		t.Fatalf("state seed = %d, want 1", n)
	}
	// home_regions 设置种子（默认 CN）
	if n := s8Count(t, env, `SELECT count(*) FROM system_settings
		WHERE setting_group='api_data' AND setting_key='home_regions' AND setting_value='"CN"'::jsonb`); n != 1 {
		t.Fatalf("home_regions seed missing")
	}

	// CHECK 约束：非法 direction / risk_level 拒绝
	badInserts := []string{
		`INSERT INTO api_cross_border_events (occurred_at, direction, source_event_id)
		 VALUES (now(), 'SIDEWAYS', gen_random_uuid())`,
		`INSERT INTO api_cross_border_events (occurred_at, direction, risk_level, source_event_id)
		 VALUES (now(), 'OUT', 'CRITICAL', gen_random_uuid())`,
	}
	for i, sql := range badInserts {
		if _, err := env.db.Exec(ctx, sql); err == nil {
			t.Fatalf("bad insert %d unexpectedly succeeded", i)
		}
	}
	// 唯一索引：同 (source_event_id, direction) 重复拒绝；不同方向放行
	src := uuid.New()
	if _, err := env.db.Exec(ctx, `INSERT INTO api_cross_border_events
		(occurred_at, direction, source_event_id) VALUES (now(), 'OUT', $1)`, src); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if _, err := env.db.Exec(ctx, `INSERT INTO api_cross_border_events
		(occurred_at, direction, source_event_id) VALUES (now(), 'OUT', $1)`, src); err == nil {
		t.Fatalf("duplicate (source_event_id, direction) should fail")
	}
	if _, err := env.db.Exec(ctx, `INSERT INTO api_cross_border_events
		(occurred_at, direction, source_event_id) VALUES (now(), 'IN', $1)`, src); err != nil {
		t.Fatalf("different direction should pass: %v", err)
	}
}

// TestStage8CrossBorderSweepOnce SQL Store 全链路：境外落库 / 本土内网未知跳过 /
// 水位幂等 / 双方向拆行 / 风险推导（真实 api_runtime_events + api_sensitive_data_types 种子等级）。
func TestStage8CrossBorderSweepOnce(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apigeo.NewStore(env.db)
	settingsSvc := settings.NewService(env.db)
	lookup := xbGeoLookup{"8.8.8.8": "US", "114.114.114.114": "CN"}
	sweeper := apigeo.NewSweeper(store, lookup, settingsSvc)
	base := time.Now().UTC().Add(-time.Hour)
	rid := s5Rand()

	// 境外（US）双侧命中：REQUEST id_card（IMPORTANT 种子等级）+ RESPONSE email（GENERAL）
	xbSaveEvent(t, env, "GET /xb/"+rid, "req-"+rid+"-1", "8.8.8.8", "fp-"+rid, base,
		[]dsctx.DetectorMatch{xbSensHit("id_card", "REQUEST"), xbSensHit("email", "RESPONSE")})
	// 本土（CN）命中 → 跳过
	xbSaveEvent(t, env, "GET /xb/"+rid, "req-"+rid+"-2", "114.114.114.114", "", base.Add(time.Minute),
		[]dsctx.DetectorMatch{xbSensHit("id_card", "")})
	// 内网 → 跳过
	xbSaveEvent(t, env, "GET /xb/"+rid, "req-"+rid+"-3", "10.1.2.3", "", base.Add(2*time.Minute),
		[]dsctx.DetectorMatch{xbSensHit("id_card", "")})
	// 公网未收录 → 跳过
	xbSaveEvent(t, env, "GET /xb/"+rid, "req-"+rid+"-4", "9.9.9.9", "", base.Add(3*time.Minute),
		[]dsctx.DetectorMatch{xbSensHit("id_card", "")})
	// 无 client_ip → 不进扫描集
	xbSaveEvent(t, env, "GET /xb/"+rid, "req-"+rid+"-5", "", "", base.Add(4*time.Minute),
		[]dsctx.DetectorMatch{xbSensHit("id_card", "")})

	res, err := sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if !res.GeoEnabled || res.EventsScanned != 4 || res.EventsInserted != 2 {
		t.Fatalf("result=%+v", res)
	}
	if res.SkippedHome != 1 || res.SkippedInternal != 1 || res.SkippedUnknown != 1 {
		t.Fatalf("skips=%+v", res)
	}
	if len(res.HomeRegions) != 1 || res.HomeRegions[0] != "CN" {
		t.Fatalf("home=%v", res.HomeRegions)
	}

	// 行内容断言（IN=id_card HIGH；OUT=email LOW；同 source_event_id 双方向）
	rows, total, err := store.ListEvents(ctx, apigeo.EventFilter{Days: 7, Page: 1, PageSize: 20})
	if err != nil || total != 2 || len(rows) != 2 {
		t.Fatalf("list=%d/%d err=%v", len(rows), total, err)
	}
	byDir := map[string]apigeo.CrossBorderEvent{}
	for _, r := range rows {
		byDir[r.Direction] = r
		if r.Country != "US" || r.ClientIP != "8.8.8.8" || r.IdentityFingerprint != "fp-"+rid {
			t.Fatalf("row=%+v", r)
		}
		if r.Asn != nil {
			t.Fatalf("asn should be NULL, got %v", *r.Asn)
		}
	}
	in, out := byDir["IN"], byDir["OUT"]
	if in.RiskLevel != "HIGH" || len(in.DataTypes) != 1 || in.DataTypes[0] != "id_card" {
		t.Fatalf("in=%+v", in)
	}
	if out.RiskLevel != "LOW" || len(out.DataTypes) != 1 || out.DataTypes[0] != "email" {
		t.Fatalf("out=%+v", out)
	}
	if in.SourceEventID != out.SourceEventID || in.EndpointKey != "GET /xb/"+rid {
		t.Fatalf("in=%+v out=%+v", in, out)
	}

	// 幂等：连续第二次零新增；新事件增量落库
	res2, err := sweeper.SweepOnce(ctx)
	if err != nil || res2.EventsScanned != 0 || res2.EventsInserted != 0 {
		t.Fatalf("sweep2=%+v err=%v", res2, err)
	}
	xbSaveEvent(t, env, "GET /xb/"+rid, "req-"+rid+"-6", "8.8.8.8", "", base.Add(5*time.Minute),
		[]dsctx.DetectorMatch{xbSensHit("phone", "")})
	res3, err := sweeper.SweepOnce(ctx)
	if err != nil || res3.EventsScanned != 1 || res3.EventsInserted != 1 {
		t.Fatalf("sweep3=%+v err=%v", res3, err)
	}
	if _, total, _ := store.ListEvents(ctx, apigeo.EventFilter{Days: 7, Page: 1, PageSize: 20}); total != 3 {
		t.Fatalf("total=%d, want 3", total)
	}

	// 看板聚合（SQL）：汇总 / 国家×类型 / 趋势
	dash, err := store.Dashboard(ctx, 7)
	if err != nil {
		t.Fatalf("dashboard: %v", err)
	}
	if dash.Summary.TotalEvents != 3 || dash.Summary.CountryCount != 1 ||
		dash.Summary.EndpointCount != 1 || dash.Summary.HighRiskCount != 1 {
		t.Fatalf("summary=%+v", dash.Summary)
	}
	if len(dash.ByCountry) != 1 || dash.ByCountry[0].Country != "US" || dash.ByCountry[0].EventCount != 3 {
		t.Fatalf("by_country=%+v", dash.ByCountry)
	}
	if len(dash.ByCountryType) != 3 { // id_card / email / phone 各 1
		t.Fatalf("by_country_type=%+v", dash.ByCountryType)
	}
	if len(dash.Trend) != 7 {
		t.Fatalf("trend=%+v", dash.Trend)
	}
	// 趋势按 UTC 日期分桶：base=now-1h 在 UTC 零点后一小时内运行会落在昨日桶，
	// 故断言总量与允许日期而非固定"今天"桶。
	var trendTotal int64
	wantDates := map[string]bool{
		base.UTC().Format("2006-01-02"):                      true,
		base.Add(6 * time.Minute).UTC().Format("2006-01-02"): true,
	}
	for _, d := range dash.Trend {
		trendTotal += d.EventCount
		if d.EventCount > 0 && !wantDates[d.Date] {
			t.Fatalf("trend date %s unexpected: %+v", d.Date, dash.Trend)
		}
	}
	if trendTotal != 3 {
		t.Fatalf("trend=%+v", dash.Trend)
	}
	// 明细过滤（SQL 白名单拼接路径）
	_, total, err = store.ListEvents(ctx, apigeo.EventFilter{Days: 7, Direction: "OUT", Page: 1, PageSize: 20})
	if err != nil || total != 1 {
		t.Fatalf("direction filter total=%d err=%v", total, err)
	}
	_, total, err = store.ListEvents(ctx, apigeo.EventFilter{Days: 7, RiskLevel: "HIGH", Page: 1, PageSize: 20})
	if err != nil || total != 1 {
		t.Fatalf("risk filter total=%d err=%v", total, err)
	}
}

// TestStage8CrossBorderHTTP 路由接线与权限点：401/403/200 + 参数校验 400 + geo_enabled 元信息。
func TestStage8CrossBorderHTTP(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apigeo.NewStore(env.db)
	settingsSvc := settings.NewService(env.db)
	lookup := xbGeoLookup{"8.8.8.8": "US"}
	rid := s5Rand()
	xbSaveEvent(t, env, "GET /xb-http/"+rid, "req-"+rid, "8.8.8.8", "", time.Now().UTC(),
		[]dsctx.DetectorMatch{xbSensHit("bank_card", "RESPONSE")})
	if _, err := apigeo.NewSweeper(store, lookup, settingsSvc).SweepOnce(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	newMux := func(authzFn func(http.Handler) http.Handler) *http.ServeMux {
		mux := http.NewServeMux()
		apigeo.RegisterRoutes(mux, authzFn, apigeo.NewHandler(store, lookup, settingsSvc))
		return mux
	}

	// 未登录 401 / 无权限 403 / 持 api_data.read 200
	if rr := apidataDo(t, newMux(xbInjectAnon), http.MethodGet, "/api/v1/api-security/cross-border", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anon: status=%d, want 401", rr.Code)
	}
	if rr := apidataDo(t, newMux(xbInjectNoPerm), http.MethodGet, "/api/v1/api-security/cross-border", nil); rr.Code != http.StatusForbidden {
		t.Fatalf("noperm: status=%d, want 403", rr.Code)
	}
	rr := apidataDo(t, newMux(apidataInjectPrincipal), http.MethodGet, "/api/v1/api-security/cross-border?days=7", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("authorized: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Data struct {
			GeoEnabled  bool     `json:"geo_enabled"`
			HomeRegions []string `json:"home_regions"`
			Dashboard   struct {
				Summary struct {
					TotalEvents   int64 `json:"total_events"`
					HighRiskCount int64 `json:"high_risk_count"`
				} `json:"summary"`
			} `json:"dashboard"`
			Events struct {
				Total int64 `json:"total"`
				Items []struct {
					Country   string `json:"country"`
					Direction string `json:"direction"`
					RiskLevel string `json:"risk_level"`
				} `json:"items"`
			} `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rr.Body.String())
	}
	if !body.Data.GeoEnabled || len(body.Data.HomeRegions) != 1 || body.Data.HomeRegions[0] != "CN" {
		t.Fatalf("meta=%+v", body.Data)
	}
	if body.Data.Dashboard.Summary.TotalEvents != 1 || body.Data.Dashboard.Summary.HighRiskCount != 1 {
		t.Fatalf("summary=%+v", body.Data.Dashboard.Summary)
	}
	if body.Data.Events.Total != 1 || body.Data.Events.Items[0].Country != "US" ||
		body.Data.Events.Items[0].Direction != "OUT" || body.Data.Events.Items[0].RiskLevel != "HIGH" {
		t.Fatalf("events=%+v", body.Data.Events)
	}
	// 参数校验 400
	for _, url := range []string{
		"/api/v1/api-security/cross-border?direction=X",
		"/api/v1/api-security/cross-border?risk_level=X",
		"/api/v1/api-security/cross-border?country=USA",
	} {
		if rr := apidataDo(t, newMux(apidataInjectPrincipal), http.MethodGet, url, nil); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d, want 400", url, rr.Code)
		}
	}
}

// TestStage8CrossBorderRealMMDB 真实 GeoIP 库端到端：仓库归档 country.mmdb
// （web 静态资产，CC0 数据集；缺失环境跳过）驱动完整 SweepOnce 判定。
func TestStage8CrossBorderRealMMDB(t *testing.T) {
	const mmdbPath = "../../web/public/assets/geo/country.mmdb"
	if _, err := os.Stat(mmdbPath); err != nil {
		t.Skipf("real mmdb not present: %v", err)
	}
	db, err := apigeo.OpenMMDB(mmdbPath)
	if err != nil {
		t.Fatalf("OpenMMDB: %v", err)
	}
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apigeo.NewStore(env.db)
	settingsSvc := settings.NewService(env.db)
	rid := s5Rand()
	// 8.8.8.8=US（境外）/ 114.114.114.114=CN（本土），真实库判定
	xbSaveEvent(t, env, "GET /xb-mmdb/"+rid, "req-"+rid+"-us", "8.8.8.8", "", time.Now().UTC(),
		[]dsctx.DetectorMatch{xbSensHit("id_card", "RESPONSE")})
	xbSaveEvent(t, env, "GET /xb-mmdb/"+rid, "req-"+rid+"-cn", "114.114.114.114", "", time.Now().UTC(),
		[]dsctx.DetectorMatch{xbSensHit("id_card", "RESPONSE")})
	res, err := apigeo.NewSweeper(store, db, settingsSvc).SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.EventsInserted != 1 || res.SkippedHome != 1 {
		t.Fatalf("result=%+v", res)
	}
	rows, total, err := store.ListEvents(ctx, apigeo.EventFilter{Days: 7, Page: 1, PageSize: 20})
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("list=%d/%d err=%v", len(rows), total, err)
	}
	if rows[0].Country != "US" || rows[0].Direction != "OUT" || rows[0].RiskLevel != "HIGH" {
		t.Fatalf("row=%+v", rows[0])
	}
}
