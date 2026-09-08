// APM SLO 目标管理集成测试（迁移 000092 + 五接口真实 HTTP 全链路 + 小时聚合表评估
// + 审计落库 + 三权口径 + APM_SLO_BREACH 告警触发/恢复）。
//
// 覆盖：
//   - 迁移 up/down 幂等（down 后表消失、重 up 恢复）；
//   - CRUD：创建（创建即评估一次）/详情（含 trend）/全量更新/删除；400/404/409 语义；
//   - 评估口径：availability 只把 5xx 计失败（current_value = 1 − 5xx/总量）、
//     latency_p95 直方图估算、错误预算剩余夹紧 [−1,1]、BREACHED/AT_RISK/OK 状态机、
//     无数据 current_value=null + OK + note；
//   - 窗口源纪律：7d/30d 窗口只读 metric_hour_aggregates（分钟表埋入反证数据不误读）；
//   - 审计：create/update/delete 落 operation_audits（module=apm、object_type=apm_slo、
//     risk MEDIUM）；纯 GET 不审计；
//   - 三权：SECURITY_ADMIN 可写、AUDIT_ADMIN 000100 后读/写均 403、SYSTEM_ADMIN 读也 403、匿名 401；
//   - 告警：BREACHED 经 EvaluateSLOBreach 触发 APM_SLO_BREACH（MEDIUM），删除 SLO 后
//     下一轮评估自动恢复（RESOLVED/RECOVERED）。
//
// 运行方式与既有 APM 集成测试一致（POSTGRES_PASSWORD/VALKEY_PASSWORD 环境变量；
// 数据落真实 PostgreSQL/Valkey，不 mock）。
package tests

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// sloSeed 写入 SLO 评估测试数据（小时聚合表；返回时不含任何 SLO 定义）。
//
//   - sloshop：2xx 980 / 4xx 10 / 5xx 10（total 1000，availability 0.99；target 0.999 → BREACHED）；
//   - slolat：耗时直方图全部落 (2500,5000]ms 桶（p95≈4875ms；target 500ms → BREACHED，达标占比 0）；
//   - sloshop 分钟表反证：metric_minute_aggregates 埋 2xx 100 万行干净流量——
//     SLO 评估若误读分钟表 availability 将≈1（OK），断言 BREACHED 即证明窗口源为小时表。
func sloSeed(t *testing.T, env *testEnv) {
	t.Helper()
	ctx := context.Background()
	bucket := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)

	type metricRow struct {
		metric string
		labels string
		value  float64
		extra  string
	}
	rows := []metricRow{
		{"http_requests_total", `{"app":"sloshop","status_class":"2xx"}`, 980, `{}`},
		{"http_requests_total", `{"app":"sloshop","status_class":"4xx"}`, 10, `{}`},
		{"http_requests_total", `{"app":"sloshop","status_class":"5xx"}`, 10, `{}`},
		{"http_request_duration_ms", `{"app":"slolat"}`, 100, `{"buckets":[0,0,0,0,0,0,0,0,0,100,0]}`},
	}
	for _, m := range rows {
		if _, err := env.db.Exec(ctx, `
INSERT INTO metric_hour_aggregates (bucket_start, metric, labels, value, extra)
VALUES ($1, $2, $3::jsonb, $4, $5::jsonb)`, bucket, m.metric, m.labels, m.value, m.extra); err != nil {
			t.Fatalf("insert hour metric %s: %v", m.metric, err)
		}
	}

	// 分钟表反证（窗口源纪律）：同服务全干净 2xx 大流量
	minuteBucket := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	if _, err := env.db.Exec(ctx, `
INSERT INTO metric_minute_aggregates (bucket_start, metric, labels, value, extra)
VALUES ($1, 'http_requests_total', '{"app":"sloshop","status_class":"2xx"}'::jsonb, 1000000, '{}'::jsonb)`,
		minuteBucket); err != nil {
		t.Fatalf("insert minute trap metric: %v", err)
	}
}

// TestAPMSLOMigration 迁移 000092 up/down 幂等：down 后 apm_slos 消失、重 up 恢复。
func TestAPMSLOMigration(t *testing.T) {
	env := setupAPMEnv(t)
	ctx := context.Background()

	tableExists := func() bool {
		var n int
		if err := env.db.QueryRow(ctx,
			`SELECT count(*) FROM information_schema.tables WHERE table_name = 'apm_slos'`).Scan(&n); err != nil {
			t.Fatalf("check table: %v", err)
		}
		return n == 1
	}
	if !tableExists() {
		t.Fatal("apm_slos missing after migrate up")
	}

	execFile := func(path string) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if _, err := env.db.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("exec %s: %v", path, err)
		}
	}
	execFile("../migrations/000092_apm_slos.down.sql")
	if tableExists() {
		t.Fatal("apm_slos still exists after down")
	}
	execFile("../migrations/000092_apm_slos.up.sql")
	if !tableExists() {
		t.Fatal("apm_slos missing after re-up")
	}

	// 唯一约束（service+metric_type+window）落库兜底（window 为 PG 保留字，需引号）
	if _, err := env.db.Exec(ctx, `
INSERT INTO apm_slos (name, service, metric_type, target, "window")
VALUES ('a', 'slodup', 'availability', 0.99, '7d')`); err != nil {
		t.Fatalf("insert first slo: %v", err)
	}
	if _, err := env.db.Exec(ctx, `
INSERT INTO apm_slos (name, service, metric_type, target, "window")
VALUES ('b', 'slodup', 'availability', 0.999, '7d')`); err == nil {
		t.Fatal("duplicate service+metric_type+window must violate unique constraint")
	}
}

// TestAPMSLOIntegration SLO 管理全链路（共享一个测试环境，子用例顺序执行）。
func TestAPMSLOIntegration(t *testing.T) {
	env := setupAPMEnv(t)
	sloSeed(t, env)
	cookies, csrf := env.s5Login(t, "apmSLOsec", "SECURITY_ADMIN")

	var availID, latID string

	t.Run("create evaluates immediately", func(t *testing.T) {
		// availability：创建即评估——sloshop availability 0.99 < target 0.999 → BREACHED
		r := s5OK(t, env.post(t, "/api/v1/apm/slos",
			`{"name":"可用性SLO","service":"sloshop","metric_type":"availability","target":0.999,"window":"7d"}`,
			cookies, csrf), "create availability slo")
		d := r.Data
		availID, _ = d["id"].(string)
		if availID == "" {
			t.Fatalf("create response missing id: %v", d)
		}
		if d["status"] != "BREACHED" {
			t.Errorf("status = %v, want BREACHED（分钟表反证未被误读）", d["status"])
		}
		// current_value = 1 − 10/1000 = 0.99（4xx 不计失败）
		if v, _ := d["current_value"].(float64); v < 0.989 || v > 0.991 {
			t.Errorf("current_value = %v, want ≈0.99", v)
		}
		if v, _ := d["error_budget_remaining"].(float64); v != -1 {
			t.Errorf("error_budget_remaining = %v, want -1（夹紧下界）", v)
		}
		if d["compliance_ratio"] != d["current_value"] {
			t.Errorf("availability compliance_ratio 应等于 current_value: %v/%v",
				d["compliance_ratio"], d["current_value"])
		}

		// latency_p95：p95≈4875ms > target 500ms → BREACHED，达标占比 0
		r = s5OK(t, env.post(t, "/api/v1/apm/slos",
			`{"name":"时延SLO","service":"slolat","metric_type":"latency_p95","target":500,"window":"30d"}`,
			cookies, csrf), "create latency slo")
		d = r.Data
		latID, _ = d["id"].(string)
		if d["status"] != "BREACHED" {
			t.Errorf("latency status = %v, want BREACHED", d["status"])
		}
		if v, _ := d["current_value"].(float64); v < 4000 || v > 5000 {
			t.Errorf("latency current_value = %v, want ≈4875ms", v)
		}
		if v, _ := d["compliance_ratio"].(float64); v != 0 {
			t.Errorf("latency compliance_ratio = %v, want 0", v)
		}
	})

	t.Run("create validation and conflict", func(t *testing.T) {
		bad := []string{
			`{"name":"x","service":"s","metric_type":"availability","target":1.5,"window":"7d"}`,
			`{"name":"x","service":"s","metric_type":"availability","target":0.99,"window":"1d"}`,
			`{"name":"x","service":"s","metric_type":"latency_p95","target":-1,"window":"7d"}`,
			`{"name":"","service":"s","metric_type":"availability","target":0.99,"window":"7d"}`,
			`{"name":"x","service":"","metric_type":"availability","target":0.99,"window":"7d"}`,
		}
		for _, b := range bad {
			s5Expect(t, env.post(t, "/api/v1/apm/slos", b, cookies, csrf), 400, "create invalid "+b)
		}
		// 唯一约束：同 service+metric_type+window 重复定义 → 409
		s5Expect(t, env.post(t, "/api/v1/apm/slos",
			`{"name":"重复定义","service":"sloshop","metric_type":"availability","target":0.99,"window":"7d"}`,
			cookies, csrf), 409, "create duplicate")
	})

	t.Run("list and detail", func(t *testing.T) {
		r := s5OK(t, env.get(t, "/api/v1/apm/slos", cookies), "list slos")
		if r.Data["total"] != float64(2) {
			t.Fatalf("total = %v, want 2", r.Data["total"])
		}
		list, _ := r.Data["list"].([]interface{})
		if len(list) != 2 {
			t.Fatalf("list len = %d", len(list))
		}

		// 详情：trend 存在且按小时桶（7d 窗口 ≥168 桶；种子桶达标率 0.99）
		r = s5OK(t, env.get(t, "/api/v1/apm/slos/"+availID, cookies), "slo detail")
		d := r.Data
		if d["id"] != availID || d["status"] != "BREACHED" {
			t.Errorf("detail = %v/%v", d["id"], d["status"])
		}
		trend, _ := d["trend"].([]interface{})
		if len(trend) < 168 {
			t.Fatalf("7d trend buckets = %d, want >= 168", len(trend))
		}
		foundSeeded := false
		for _, b := range trend {
			m, _ := b.(map[string]interface{})
			if v, _ := m["compliance_ratio"].(float64); v > 0.989 && v < 0.991 {
				foundSeeded = true
			}
		}
		if !foundSeeded {
			t.Error("trend must contain seeded hour bucket with compliance_ratio ≈ 0.99")
		}

		// 30d 窗口趋势按天桶（30~31 桶）
		r = s5OK(t, env.get(t, "/api/v1/apm/slos/"+latID, cookies), "latency slo detail")
		trend, _ = r.Data["trend"].([]interface{})
		if len(trend) < 30 || len(trend) > 31 {
			t.Errorf("30d trend buckets = %d, want 30~31", len(trend))
		}

		// 404 / 400
		s5Expect(t, env.get(t, "/api/v1/apm/slos/"+uuid.NewString(), cookies), 404, "missing slo")
		s5Expect(t, env.get(t, "/api/v1/apm/slos/bad-id", cookies), 400, "bad slo id")
	})

	t.Run("no data slo stays ok", func(t *testing.T) {
		r := s5OK(t, env.post(t, "/api/v1/apm/slos",
			`{"name":"无流量","service":"slonodata","metric_type":"availability","target":0.99,"window":"7d"}`,
			cookies, csrf), "create no-data slo")
		d := r.Data
		if d["current_value"] != nil {
			t.Errorf("no-data current_value = %v, want null", d["current_value"])
		}
		if d["status"] != "OK" || d["note"] == "" {
			t.Errorf("no-data status/note = %v/%v", d["status"], d["note"])
		}
		if v, _ := d["error_budget_remaining"].(float64); v != 1 {
			t.Errorf("no-data error_budget_remaining = %v, want 1", v)
		}
		// 清理（不影响后续 total 断言口径——后续用例不依赖 total）
		noDataID, _ := d["id"].(string)
		s5OK(t, env.do(t, "DELETE", "/api/v1/apm/slos/"+noDataID, "", cookies, csrf), "delete no-data slo")
	})

	t.Run("update", func(t *testing.T) {
		// 放宽 target 至 0.98：availability 0.99 ≥ target → remaining (0.02−0.01)/0.02 = 0.5 → OK
		r := s5OK(t, env.do(t, "PUT", "/api/v1/apm/slos/"+availID,
			`{"name":"可用性SLO","service":"sloshop","metric_type":"availability","target":0.98,"window":"7d"}`,
			cookies, csrf), "update slo")
		if r.Data["status"] != "OK" {
			t.Errorf("updated status = %v, want OK", r.Data["status"])
		}
		if v, _ := r.Data["error_budget_remaining"].(float64); v < 0.49 || v > 0.51 {
			t.Errorf("updated remaining = %v, want ≈0.5", v)
		}
		s5Expect(t, env.do(t, "PUT", "/api/v1/apm/slos/"+uuid.NewString(),
			`{"name":"x","service":"s","metric_type":"availability","target":0.99,"window":"7d"}`,
			cookies, csrf), 404, "update missing")
	})

	t.Run("alert breach and recover", func(t *testing.T) {
		ctx := context.Background()
		// 恢复 update 用例的 target（0.98 → OK 无告警）；先把可用性 SLO 改回违约态
		s5OK(t, env.do(t, "PUT", "/api/v1/apm/slos/"+availID,
			`{"name":"可用性SLO","service":"sloshop","metric_type":"availability","target":0.999,"window":"7d"}`,
			cookies, csrf), "restore breached slo")

		if err := env.app.AlertEngine().EvaluateSLOBreach(ctx); err != nil {
			t.Fatalf("evaluate slo breach: %v", err)
		}
		var severity, status string
		err := env.db.QueryRow(ctx, `
SELECT severity, status FROM system_alerts
WHERE alert_type = 'APM_SLO_BREACH' AND component = 'sloshop/可用性SLO'`).Scan(&severity, &status)
		if err != nil {
			t.Fatalf("query slo alert: %v", err)
		}
		if severity != "MEDIUM" || status != "OPEN" {
			t.Errorf("alert severity/status = %s/%s, want MEDIUM/OPEN", severity, status)
		}
		// latency SLO 同样违约 → 各自组件告警
		var n int
		if err := env.db.QueryRow(ctx,
			`SELECT count(*) FROM system_alerts WHERE alert_type = 'APM_SLO_BREACH' AND status = 'OPEN'`).Scan(&n); err != nil {
			t.Fatalf("count slo alerts: %v", err)
		}
		if n != 2 {
			t.Errorf("open APM_SLO_BREACH = %d, want 2（两条违约 SLO 各一条）", n)
		}

		// 删除 SLO → 下一轮评估自动恢复（定义消失视为恢复收口）
		s5OK(t, env.do(t, "DELETE", "/api/v1/apm/slos/"+latID, "", cookies, csrf), "delete latency slo")
		if err := env.app.AlertEngine().EvaluateSLOBreach(ctx); err != nil {
			t.Fatalf("evaluate after delete: %v", err)
		}
		var resolveType string
		err = env.db.QueryRow(ctx, `
SELECT COALESCE(resolve_type, '') FROM system_alerts
WHERE alert_type = 'APM_SLO_BREACH' AND component = 'slolat/时延SLO'`).Scan(&resolveType)
		if err != nil {
			t.Fatalf("query recovered alert: %v", err)
		}
		if resolveType != "RECOVERED" {
			t.Errorf("resolve_type = %s, want RECOVERED", resolveType)
		}
		s5Expect(t, env.get(t, "/api/v1/apm/slos/"+latID, cookies), 404, "get deleted slo")
	})

	t.Run("medium risk audits recorded", func(t *testing.T) {
		ctx := context.Background()
		var n int
		if err := env.db.QueryRow(ctx, `
SELECT count(*) FROM operation_audits
WHERE module = 'apm' AND object_type = 'apm_slo' AND risk_level = 'MEDIUM'
  AND action IN ('create', 'update', 'delete')`).Scan(&n); err != nil {
			t.Fatalf("query audits: %v", err)
		}
		// create ×4（含 no-data 与 update 用例恢复）+ update ×3 + delete ×2 = ≥5
		if n < 5 {
			t.Errorf("apm_slo medium-risk audit count = %d, want >= 5", n)
		}
		// 纯 GET 不审计：apm_slo 对象不存在 read 类审计动作
		var reads int
		if err := env.db.QueryRow(ctx, `
SELECT count(*) FROM operation_audits
WHERE module = 'apm' AND object_type = 'apm_slo' AND action NOT IN ('create', 'update', 'delete')`).Scan(&reads); err != nil {
			t.Fatalf("query read audits: %v", err)
		}
		if reads != 0 {
			t.Errorf("pure GET must not audit, got %d rows", reads)
		}
	})

	t.Run("permission", func(t *testing.T) {
		// AUDIT_ADMIN（000100 收紧为纯审计角色）：读/写均 403（apm.* 权限点全部移除）
		auditCookies, auditCSRF := env.s5Login(t, "apmsloaudit", "AUDIT_ADMIN")
		s5Expect(t, env.get(t, "/api/v1/apm/slos", auditCookies), 403, "audit_admin list slos")
		s5Expect(t, env.post(t, "/api/v1/apm/slos",
			`{"name":"x","service":"s","metric_type":"availability","target":0.99,"window":"7d"}`,
			auditCookies, auditCSRF), 403, "audit_admin create slo")
		s5Expect(t, env.do(t, "DELETE", "/api/v1/apm/slos/"+availID, "", auditCookies, auditCSRF), 403, "audit_admin delete slo")

		// SYSTEM_ADMIN：不含业务观测权限（读也 403）
		sysCookies, sysCSRF := env.login(t, "test_sysadmin", env.adminPwd)
		s5Expect(t, env.get(t, "/api/v1/apm/slos", sysCookies), 403, "sysadmin list slos")
		s5Expect(t, env.post(t, "/api/v1/apm/slos",
			`{"name":"x","service":"s","metric_type":"availability","target":0.99,"window":"7d"}`,
			sysCookies, sysCSRF), 403, "sysadmin create slo")

		// 匿名 401
		s5Expect(t, env.get(t, "/api/v1/apm/slos", nil), 401, "anonymous list slos")
	})
}

// TestAPMSLODisabledIntegration APM_ENABLED=false 时 SLO 接口同样 503 降级。
func TestAPMSLODisabledIntegration(t *testing.T) {
	env := newTestEnv(t, baseTestCfg())
	env.importBaseLicense(t)
	cookies, csrf := env.s5Login(t, "apmslooff", "SECURITY_ADMIN")

	s5Expect(t, env.get(t, "/api/v1/apm/slos", cookies), 503, "disabled list slos")
	s5Expect(t, env.post(t, "/api/v1/apm/slos",
		`{"name":"x","service":"s","metric_type":"availability","target":0.99,"window":"7d"}`,
		cookies, csrf), 503, "disabled create slo")
	// 关闭形态下周期评估空转（评估源未注入）：直接调用引擎不报错、不产生告警
	if err := env.app.AlertEngine().EvaluateSLOBreach(context.Background()); err != nil {
		t.Fatalf("disabled evaluate: %v", err)
	}
	var n int
	if err := env.db.QueryRow(context.Background(),
		`SELECT count(*) FROM system_alerts WHERE alert_type = 'APM_SLO_BREACH'`).Scan(&n); err != nil {
		t.Fatalf("count slo alerts: %v", err)
	}
	if n != 0 {
		t.Errorf("disabled form must not raise APM_SLO_BREACH, got %d", n)
	}
}
