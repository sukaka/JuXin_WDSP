// APM 阶段1 接口集成测试（WP4；决策 docs/APM_STAGE0_ADR.md D9/D11/D12）。
//
// 覆盖：/api/v1/apm/overview、/apm/services、/apm/services/{id}、/apm/endpoints、
// /apm/traces/{trace_id} 五个接口的真实 HTTP 全链路（聚合表读模型 + access_logs/
// security_events trace 关联）、apm.* 权限点三权口径（SYSTEM_ADMIN 不含）、
// APM_ENABLED=false 时 503 降级 stub 与 /product/edition 的 apm_enabled 下发。
// 阶段3 第一批（/apm/sql、/apm/exceptions、/apm/dependencies）：CH 未配置时
// 如实降级空数据 + agentless（不 500）、三权口径（含迁移 000090 的 apm.sql.read）、
// 关闭形态 503 stub。CH 数据面正路径由 internal/apm 的 CH 集成测试覆盖。
//
// 运行方式（与既有集成测试一致）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestAPM -count=1
//
// 无 POSTGRES_PASSWORD/VALKEY_PASSWORD 环境变量时遵循仓库既有约定 t.Skip；
// 不得 mock，数据落真实 PostgreSQL/Valkey（独立测试库重建 + 全量迁移，含 000088）。
package tests

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// setupAPMEnv 以 APM_ENABLED=true 装配测试环境（纪律同 setupTestEnv：真实库重建、
// 全量迁移、真实应用 + httptest.Server、setup 阶段导入公共测试授权）。
func setupAPMEnv(t *testing.T) *testEnv {
	t.Helper()
	cfg := baseTestCfg()
	cfg.APM.Enabled = true
	env := newTestEnv(t, cfg)
	env.importBaseLicense(t)
	return env
}

// apmSeed 写入 APM 测试数据：应用、窗口内分钟聚合行（应用级 + 端点级，指标名/标签
// 口径与 aggregations 采集器产出一致）、trace 关联的 access_logs/security_events，
// 并开启 logging.access_log_enabled（端点级数据可用性前置）。返回应用 ID 与 trace_id。
func apmSeed(t *testing.T, env *testEnv) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	bucket := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)

	var appID uuid.UUID
	if err := env.db.QueryRow(ctx,
		`INSERT INTO applications (code, name) VALUES ('apmappshop', 'APM测试商城') RETURNING id`).Scan(&appID); err != nil {
		t.Fatalf("insert application: %v", err)
	}

	type metricRow struct {
		metric string
		labels string
		value  float64
		extra  string
	}
	rows := []metricRow{
		// 应用级（管道 B 口径）：requests 115（2xx 100 / 4xx 10 / 5xx 5）、blocks 3、observes 2
		{"http_requests_total", `{"app":"apmappshop","status_class":"2xx"}`, 100, `{}`},
		{"http_requests_total", `{"app":"apmappshop","status_class":"4xx"}`, 10, `{}`},
		{"http_requests_total", `{"app":"apmappshop","status_class":"5xx"}`, 5, `{}`},
		{"http_request_duration_ms", `{"app":"apmappshop"}`, 115, `{"buckets":[0,10,20,30,30,20,5,0,0,0,0]}`},
		{"waf_blocks_total", `{"app":"apmappshop"}`, 3, `{}`},
		{"waf_observes_total", `{"app":"apmappshop"}`, 2, `{}`},
		// 端点级（管道 A 口径）：GET /orders/{id} 共 68（allow 65 含 5xx 5 + block 3）
		{"http_endpoint_requests_total", `{"app":"apmappshop","endpoint":"GET /orders/{id}","status_class":"2xx","action":"allow"}`, 60, `{}`},
		{"http_endpoint_requests_total", `{"app":"apmappshop","endpoint":"GET /orders/{id}","status_class":"5xx","action":"allow"}`, 5, `{}`},
		{"http_endpoint_requests_total", `{"app":"apmappshop","endpoint":"GET /orders/{id}","status_class":"2xx","action":"block"}`, 3, `{}`},
		{"http_endpoint_duration_ms", `{"app":"apmappshop","endpoint":"GET /orders/{id}","status_class":"2xx","action":"allow"}`, 60, `{"buckets":[0,5,10,20,15,10,0,0,0,0,0]}`},
		{"http_endpoint_duration_ms", `{"app":"apmappshop","endpoint":"GET /orders/{id}","status_class":"5xx","action":"allow"}`, 5, `{"buckets":[0,0,0,0,0,5,0,0,0,0,0]}`},
		{"http_endpoint_duration_ms", `{"app":"apmappshop","endpoint":"GET /orders/{id}","status_class":"2xx","action":"block"}`, 3, `{"buckets":[3,0,0,0,0,0,0,0,0,0,0]}`},
		// 未归类治理桶（__UNCLASSIFIED__ 原样返回并计入 unclassified_requests）
		{"http_endpoint_requests_total", `{"app":"apmappshop","endpoint":"__UNCLASSIFIED__","status_class":"2xx","action":"allow"}`, 7, `{}`},
	}
	for _, m := range rows {
		if _, err := env.db.Exec(ctx, `
INSERT INTO metric_minute_aggregates (bucket_start, metric, labels, value, extra)
VALUES ($1, $2, $3::jsonb, $4, $5::jsonb)`, bucket, m.metric, m.labels, m.value, m.extra); err != nil {
			t.Fatalf("insert metric %s: %v", m.metric, err)
		}
	}

	if _, err := env.db.Exec(ctx, `
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type)
VALUES ('logging', 'access_log_enabled', 'true'::jsonb, 'boolean')
ON CONFLICT (setting_group, setting_key) DO UPDATE SET setting_value = 'true'::jsonb`); err != nil {
		t.Fatalf("enable access log setting: %v", err)
	}

	traceID := strings.Repeat("ab", 16)
	occurred := time.Now().UTC().Add(-3 * time.Minute)
	if _, err := env.db.Exec(ctx, `
INSERT INTO access_logs (occurred_at, request_id, application_id, domain, request_method,
  request_uri, request_path, response_status, duration_ms, waf_action,
  trace_id, span_id, endpoint_key, path_template, ttfb_ms)
VALUES ($1, 'req-apm-1', $2, 'shop.example.com', 'GET', '/orders/123?x=1', '/orders/123',
  200, 42, 'ALLOW', $3, '0123456789abcdef', 'GET /orders/{id}', '/orders/{id}', 40)`,
		occurred, appID, traceID); err != nil {
		t.Fatalf("insert access log: %v", err)
	}
	if _, err := env.db.Exec(ctx, `
INSERT INTO security_events (request_id, occurred_at, application_id, attack_type, severity,
  action, response_status, request_method, request_uri, rule_match_count)
VALUES ('req-apm-1', $1, $2, 'SQLI', 'HIGH', 'BLOCK', 403, 'GET', '/orders/123', 2)`,
		occurred, appID); err != nil {
		t.Fatalf("insert security event: %v", err)
	}
	return appID, traceID
}

// TestAPMIntegration APM 开启形态全链路（共享一个测试环境，子用例顺序执行）。
func TestAPMIntegration(t *testing.T) {
	env := setupAPMEnv(t)
	appID, traceID := apmSeed(t, env)
	cookies, _ := env.s5Login(t, "apmsec", "SECURITY_ADMIN")

	t.Run("overview", func(t *testing.T) {
		r := s5OK(t, env.get(t, "/api/v1/apm/overview", cookies), "apm overview")
		data := r.Data
		if data["data_source"] != "agentless" {
			t.Errorf("data_source = %v", data["data_source"])
		}
		if data["access_log_enabled"] != true {
			t.Errorf("access_log_enabled = %v", data["access_log_enabled"])
		}
		if data["requests_total"] != float64(115) {
			t.Errorf("requests_total = %v, want 115", data["requests_total"])
		}
		if data["error_5xx_total"] != float64(5) || data["error_4xx_total"] != float64(10) {
			t.Errorf("error totals = %v/%v", data["error_5xx_total"], data["error_4xx_total"])
		}
		if data["blocked_total"] != float64(3) {
			t.Errorf("blocked_total = %v, want 3", data["blocked_total"])
		}
		if er, ok := data["error_rate"].(float64); !ok || er <= 0 || er >= 1 {
			t.Errorf("error_rate = %v", data["error_rate"])
		}
		lat, _ := data["latency"].(map[string]interface{})
		if p95, _ := lat["p95"].(float64); p95 <= 0 {
			t.Errorf("latency.p95 = %v", lat["p95"])
		}
		trend, _ := data["trend"].([]interface{})
		if len(trend) == 0 {
			t.Error("trend must be non-empty (zero-filled buckets)")
		}
		if data["unclassified_requests"] != float64(7) {
			t.Errorf("unclassified_requests = %v, want 7", data["unclassified_requests"])
		}
		slowApps, _ := data["top_slow_applications"].([]interface{})
		if len(slowApps) == 0 {
			t.Fatal("top_slow_applications empty")
		}
		first, _ := slowApps[0].(map[string]interface{})
		if first["app"] != "apmappshop" || first["application_id"] != appID.String() || first["name"] != "APM测试商城" {
			t.Errorf("top slow app = %v", first)
		}
		slowEps, _ := data["top_slow_endpoints"].([]interface{})
		if len(slowEps) == 0 {
			t.Fatal("top_slow_endpoints empty (access log enabled)")
		}
		ep, _ := slowEps[0].(map[string]interface{})
		if ep["endpoint"] != "GET /orders/{id}" || ep["app"] != "apmappshop" {
			t.Errorf("top slow endpoint = %v", ep)
		}
	})

	t.Run("services", func(t *testing.T) {
		r := s5OK(t, env.get(t, "/api/v1/apm/services", cookies), "apm services")
		data := r.Data
		items, _ := data["items"].([]interface{})
		if len(items) == 0 {
			t.Fatal("services empty")
		}
		row, _ := items[0].(map[string]interface{})
		if row["app"] != "apmappshop" || row["observation_mode"] != "agentless" {
			t.Errorf("service row = %v", row)
		}
		if row["requests"] != float64(115) || row["blocked"] != float64(3) {
			t.Errorf("service requests/blocked = %v/%v", row["requests"], row["blocked"])
		}
		if p95, _ := row["p95"].(float64); p95 <= 0 {
			t.Errorf("service p95 = %v", row["p95"])
		}
		if row["last_seen_at"] == nil {
			t.Error("service last_seen_at must be non-null with traffic in window")
		}

		// keyword 模糊匹配（name/code）
		r = s5OK(t, env.get(t, "/api/v1/apm/services?keyword="+url.QueryEscape("商城"), cookies), "apm services keyword")
		if r.Data["total"] != float64(1) {
			t.Errorf("keyword 商城 total = %v", r.Data["total"])
		}
		r = s5OK(t, env.get(t, "/api/v1/apm/services?keyword=no-such-app", cookies), "apm services keyword miss")
		if r.Data["total"] != float64(0) {
			t.Errorf("keyword miss total = %v", r.Data["total"])
		}
	})

	t.Run("service detail", func(t *testing.T) {
		r := s5OK(t, env.get(t, "/api/v1/apm/services/"+appID.String(), cookies), "apm service detail")
		data := r.Data
		if data["application_id"] != appID.String() || data["app"] != "apmappshop" {
			t.Errorf("detail identity = %v/%v", data["application_id"], data["app"])
		}
		if data["requests_total"] != float64(115) {
			t.Errorf("requests_total = %v", data["requests_total"])
		}
		classes, _ := data["status_classes"].([]interface{})
		found5xx := false
		for _, c := range classes {
			m, _ := c.(map[string]interface{})
			if m["status_class"] == "5xx" && m["count"] == float64(5) {
				found5xx = true
			}
		}
		if !found5xx {
			t.Errorf("status_classes missing 5xx=5: %v", classes)
		}
		actions, _ := data["actions"].([]interface{})
		foundBlock := false
		for _, a := range actions {
			m, _ := a.(map[string]interface{})
			if m["action"] == "block" && m["count"] == float64(3) {
				foundBlock = true
			}
		}
		if !foundBlock {
			t.Errorf("actions missing block=3: %v", actions)
		}
		eps, _ := data["top_endpoints"].([]interface{})
		if len(eps) == 0 {
			t.Fatal("top_endpoints empty")
		}
		if m, _ := eps[0].(map[string]interface{}); m["endpoint"] != "GET /orders/{id}" {
			t.Errorf("top endpoint = %v", m)
		}

		// 404 / 400 分支
		s5Expect(t, env.get(t, "/api/v1/apm/services/"+uuid.NewString(), cookies), 404, "missing app")
		s5Expect(t, env.get(t, "/api/v1/apm/services/bad-id", cookies), 400, "bad app id")
	})

	t.Run("endpoints", func(t *testing.T) {
		r := s5OK(t, env.get(t, "/api/v1/apm/endpoints", cookies), "apm endpoints")
		data := r.Data
		if data["access_log_enabled"] != true {
			t.Errorf("access_log_enabled = %v", data["access_log_enabled"])
		}
		if data["total"] != float64(2) {
			t.Fatalf("endpoints total = %v, want 2", data["total"])
		}
		list, _ := data["list"].([]interface{})
		var orders, unclassified map[string]interface{}
		for _, it := range list {
			m, _ := it.(map[string]interface{})
			switch m["endpoint"] {
			case "GET /orders/{id}":
				orders = m
			case "__UNCLASSIFIED__":
				unclassified = m
			}
		}
		if orders == nil || unclassified == nil {
			t.Fatalf("endpoint rows missing: %v", list)
		}
		if orders["method"] != "GET" || orders["path_template"] != "/orders/{id}" {
			t.Errorf("endpoint split = %v/%v", orders["method"], orders["path_template"])
		}
		if orders["requests"] != float64(68) || orders["blocked"] != float64(3) {
			t.Errorf("endpoint requests/blocked = %v/%v", orders["requests"], orders["blocked"])
		}
		if orders["application_id"] != appID.String() {
			t.Errorf("endpoint application_id = %v", orders["application_id"])
		}
		// 保留桶原样返回，method/path_template 为空串（前端负责标注）
		if unclassified["method"] != "" || unclassified["path_template"] != "" {
			t.Errorf("unclassified split = %v/%v", unclassified["method"], unclassified["path_template"])
		}

		// application_id 过滤与非法参数
		r = s5OK(t, env.get(t, "/api/v1/apm/endpoints?application_id="+appID.String(), cookies), "endpoints app filter")
		if r.Data["total"] != float64(2) {
			t.Errorf("app filter total = %v", r.Data["total"])
		}
		r = s5OK(t, env.get(t, "/api/v1/apm/endpoints?application_id="+uuid.NewString(), cookies), "endpoints unknown app")
		if r.Data["total"] != float64(0) {
			t.Errorf("unknown app total = %v", r.Data["total"])
		}
		s5Expect(t, env.get(t, "/api/v1/apm/endpoints?sort=bogus", cookies), 400, "bad sort")
		s5Expect(t, env.get(t, "/api/v1/apm/endpoints?application_id=bad", cookies), 400, "bad application_id")
	})

	t.Run("trace", func(t *testing.T) {
		r := s5OK(t, env.get(t, "/api/v1/apm/traces/"+traceID, cookies), "apm trace")
		data := r.Data
		if data["trace_id"] != traceID || data["partial"] != true || data["note"] != "agentless" {
			t.Errorf("trace meta = %v/%v/%v", data["trace_id"], data["partial"], data["note"])
		}
		logs, _ := data["access_logs"].([]interface{})
		if len(logs) != 1 {
			t.Fatalf("access_logs len = %d, want 1", len(logs))
		}
		l, _ := logs[0].(map[string]interface{})
		if l["request_id"] != "req-apm-1" || l["waf_action"] != "ALLOW" {
			t.Errorf("access log = %v", l)
		}
		if l["ttfb_ms"] != float64(40) || l["endpoint_key"] != "GET /orders/{id}" {
			t.Errorf("access log apm fields = %v/%v", l["ttfb_ms"], l["endpoint_key"])
		}
		evs, _ := data["security_events"].([]interface{})
		if len(evs) != 1 {
			t.Fatalf("security_events len = %d, want 1", len(evs))
		}
		ev, _ := evs[0].(map[string]interface{})
		if ev["attack_type"] != "SQLI" || ev["action"] != "BLOCK" || ev["request_id"] != "req-apm-1" {
			t.Errorf("security event = %v", ev)
		}
		// 安全子集：不回传请求/响应头体留痕
		if _, ok := ev["request_headers"]; ok {
			t.Error("security event must not carry request_headers")
		}

		// 无命中 → 空数组而非 404；非法 trace_id → 400
		r = s5OK(t, env.get(t, "/api/v1/apm/traces/"+strings.Repeat("cd", 16), cookies), "trace miss")
		miss := r.Data
		if logs, _ := miss["access_logs"].([]interface{}); len(logs) != 0 {
			t.Errorf("miss access_logs = %v", logs)
		}
		s5Expect(t, env.get(t, "/api/v1/apm/traces/nothex", cookies), 400, "bad trace id")
	})

	t.Run("permission", func(t *testing.T) {
		// D12 三权口径：SYSTEM_ADMIN 不含业务观测权限
		sysCookies, _ := env.login(t, "test_sysadmin", env.adminPwd)
		s5Expect(t, env.get(t, "/api/v1/apm/overview", sysCookies), 403, "sysadmin overview")
		s5Expect(t, env.get(t, "/api/v1/apm/traces/"+traceID, sysCookies), 403, "sysadmin trace")
		// 阶段3 第一批：apm.sql.read（000090）/apm.traces.read/apm.services.read 同样不授 SYSTEM_ADMIN
		s5Expect(t, env.get(t, "/api/v1/apm/sql", sysCookies), 403, "sysadmin sql")
		s5Expect(t, env.get(t, "/api/v1/apm/exceptions", sysCookies), 403, "sysadmin exceptions")
		s5Expect(t, env.get(t, "/api/v1/apm/dependencies", sysCookies), 403, "sysadmin dependencies")
		// AUDIT_ADMIN（000100 收紧为纯审计角色）：APM 读权限点全部移除 → 403
		auditCookies, _ := env.s5Login(t, "apmaudit", "AUDIT_ADMIN")
		s5Expect(t, env.get(t, "/api/v1/apm/sql", auditCookies), 403, "audit sql")
		s5Expect(t, env.get(t, "/api/v1/apm/exceptions", auditCookies), 403, "audit exceptions")
		s5Expect(t, env.get(t, "/api/v1/apm/dependencies", auditCookies), 403, "audit dependencies")
		// 未登录 401
		s5Expect(t, env.get(t, "/api/v1/apm/overview", nil), 401, "anonymous overview")
	})

	// 阶段3 第一批（SQL/异常/依赖）：测试环境不配置 APM_CLICKHOUSE_DSN，
	// 三接口如实降级为空数据 + data_source=agentless + 提示，不 500。
	t.Run("stage3 ch-backed queries degrade without clickhouse", func(t *testing.T) {
		r := s5OK(t, env.get(t, "/api/v1/apm/sql", cookies), "apm sql degraded")
		if r.Data["data_source"] != "agentless" || r.Data["message"] == "" {
			t.Errorf("sql degraded = %v", r.Data)
		}
		if list, _ := r.Data["list"].([]interface{}); len(list) != 0 {
			t.Errorf("sql list = %v, want empty", list)
		}
		s5Expect(t, env.get(t, "/api/v1/apm/sql?sort=bogus", cookies), 400, "sql bad sort")

		r = s5OK(t, env.get(t, "/api/v1/apm/exceptions", cookies), "apm exceptions degraded")
		if r.Data["data_source"] != "agentless" || r.Data["message"] == "" {
			t.Errorf("exceptions degraded = %v", r.Data)
		}

		r = s5OK(t, env.get(t, "/api/v1/apm/dependencies", cookies), "apm dependencies degraded")
		if r.Data["data_source"] != "agentless" || r.Data["note"] == "" {
			t.Errorf("dependencies degraded = %v", r.Data)
		}
		if edges, _ := r.Data["edges"].([]interface{}); len(edges) != 0 {
			t.Errorf("dependencies edges = %v, want empty", edges)
		}
	})

	t.Run("edition exposes apm_enabled", func(t *testing.T) {
		r := s5OK(t, env.get(t, "/api/v1/product/edition", cookies), "product edition")
		if r.Data["apm_enabled"] != true {
			t.Errorf("apm_enabled = %v, want true", r.Data["apm_enabled"])
		}
	})
}

// TestAPMDisabledIntegration APM_ENABLED=false（默认）：/api/v1/apm/* 统一 503 降级
// （仿 AI 先例，不 404），edition 如实下发 apm_enabled=false。
func TestAPMDisabledIntegration(t *testing.T) {
	env := newTestEnv(t, baseTestCfg())
	env.importBaseLicense(t)
	cookies, _ := env.s5Login(t, "apmoff", "SECURITY_ADMIN")

	s5Expect(t, env.get(t, "/api/v1/apm/overview", cookies), 503, "disabled overview")
	s5Expect(t, env.get(t, "/api/v1/apm/services", cookies), 503, "disabled services")
	s5Expect(t, env.get(t, "/api/v1/apm/traces/"+strings.Repeat("ab", 16), cookies), 503, "disabled trace")
	// 阶段3 第一批同样经降级 stub
	s5Expect(t, env.get(t, "/api/v1/apm/sql", cookies), 503, "disabled sql")
	s5Expect(t, env.get(t, "/api/v1/apm/exceptions", cookies), 503, "disabled exceptions")
	s5Expect(t, env.get(t, "/api/v1/apm/dependencies", cookies), 503, "disabled dependencies")

	r := s5OK(t, env.get(t, "/api/v1/product/edition", cookies), "product edition")
	if r.Data["apm_enabled"] != false {
		t.Errorf("apm_enabled = %v, want false", r.Data["apm_enabled"])
	}
}
