// apm_diagnostics_test.go APM 阶段4 深度诊断会话控制面集成测试（真实 PostgreSQL/Valkey，
// 运行方式同既有 APM 集成测试：POSTGRES_PASSWORD/VALKEY_PASSWORD 环境变量，缺失则 Skip）。
//
// 覆盖：
//   - 迁移 000093 落位与 up/down 幂等（会话表 + apm.diagnostics.manage 权限种子 +
//     apm_diagnostics.kill_switch 设置种子）；
//   - 创建纪律：dry_run 预估（不落库）→ confirm 缺失 400 → 校验/夹紧/开销护栏
//     （422/400 语义）→ 无匹配在线 Agent 422 → 同应用并发会话 409；
//   - 策略机制：创建即发布应用级更高版本签名诊断叠加（版本单调递增、信封
//     expires_at=会话硬截止、签名可验），Agent 拉取即生效，匹配 Agent 置 DIAGNOSING；
//   - 停止：STOPPED 终态 + 基线恢复策略新版本（叠加剥除）+ Agent 回基线 + 重复停止 409；
//   - 自动到期：直接改库 expires_at 后 SweepOnce → EXPIRED + 基线恢复 + baseline_restored；
//   - kill switch：enable=true 全量 KILLED + 恢复基线 + 新建 422 + 列表响应级
//     kill_switch_enabled；审计 HIGH（create/stop/kill）与 CRITICAL（kill_switch）；
//   - 详情按对象关联 operation_audits；
//   - 三权：SECURITY_ADMIN 全量 / AUDIT_ADMIN·SYSTEM_ADMIN 403 / 匿名 401；
//   - kill switch 键经系统设置 Update API 可改（白名单登记生效）。
package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apm"
)

// TestAPMDiagnosticsMigration 迁移 000093 up/down 幂等与种子落位。
func TestAPMDiagnosticsMigration(t *testing.T) {
	env := setupAPMAgentEnv(t)
	ctx := context.Background()

	var tableExists bool
	if err := env.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'apm_diagnostic_sessions')`).Scan(&tableExists); err != nil || !tableExists {
		t.Fatalf("apm_diagnostic_sessions missing: exists=%v err=%v", tableExists, err)
	}
	var permExists bool
	if err := env.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM permissions WHERE code = 'apm.diagnostics.manage')`).Scan(&permExists); err != nil || !permExists {
		t.Fatalf("permission seed missing: exists=%v err=%v", permExists, err)
	}
	// 权限仅授 SECURITY_ADMIN（manage 类三权口径）
	var grantCount int
	if err := env.db.QueryRow(ctx, `
SELECT count(*) FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
WHERE p.code = 'apm.diagnostics.manage'`).Scan(&grantCount); err != nil || grantCount != 1 {
		t.Errorf("role grant count = %d, want 1（仅 SECURITY_ADMIN）, err=%v", grantCount, err)
	}
	var ksValue bool
	if err := env.db.QueryRow(ctx,
		`SELECT (setting_value)::boolean FROM system_settings
		 WHERE setting_group = 'apm_diagnostics' AND setting_key = 'kill_switch'`).Scan(&ksValue); err != nil || ksValue {
		t.Errorf("kill_switch seed = %v, want false, err=%v", ksValue, err)
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
	execFile("../migrations/000093_apm_diagnostics.down.sql")
	if err := env.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'apm_diagnostic_sessions')`).Scan(&tableExists); err != nil || tableExists {
		t.Fatal("apm_diagnostic_sessions still exists after down")
	}
	execFile("../migrations/000093_apm_diagnostics.up.sql")
	if err := env.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'apm_diagnostic_sessions')`).Scan(&tableExists); err != nil || !tableExists {
		t.Fatal("apm_diagnostic_sessions missing after re-up")
	}
}

// TestAPMDiagnosticSessions 诊断会话全链路（单环境共享，子用例顺序执行）。
func TestAPMDiagnosticSessions(t *testing.T) {
	env := setupAPMAgentEnv(t)
	ctx := context.Background()

	// 应用行（会话 scope 目标）
	var appID uuid.UUID
	if err := env.db.QueryRow(ctx,
		`INSERT INTO applications (code, name) VALUES ('apmdiagapp', 'APM诊断测试应用') RETURNING id`).Scan(&appID); err != nil {
		t.Fatalf("insert application: %v", err)
	}

	secCookies, secCSRF := env.s5Login(t, "apmdiagsec", "SECURITY_ADMIN")

	// 注册一个在线 Agent（绑定该应用；registered_at 新鲜即在线）
	var agentID string
	var agentIdentity *apmAgentIdentity
	var caPubKey string
	t.Run("register online agent", func(t *testing.T) {
		resp := env.post(t, "/api/v1/apm/agents/enrollment-tokens",
			fmt.Sprintf(`{"application_id":%q,"environment":"prod","expires_in_minutes":30}`, appID), secCookies, secCSRF)
		token, _ := s5OK(t, resp, "create enrollment token").Data["token"].(string)
		var data map[string]interface{}
		agentIdentity, data = apmRegister(t, env, token, "shop-diag", "host-d1", "java")
		agentID = data["agent_id"].(string)
		caPubKey, _ = data["ca_public_key"].(string)
		// 注册响应携带全局基线 v1（惰性创建）
		if data["policy"].(map[string]interface{})["scope"] != "global" {
			t.Errorf("register policy = %v", data["policy"])
		}
	})

	createBody := func(extra string) string {
		return fmt.Sprintf(`{"scope":{"application_id":%q,"service":"shop-diag","environment":"prod"},"capabilities":["sql_detail"],"sampling_rate":0.5,"duration_minutes":30%s}`,
			appID, extra)
	}

	var sessionID string

	t.Run("dry run then confirm required", func(t *testing.T) {
		// dry_run：预估返回，不落库
		r := s5OK(t, env.post(t, "/api/v1/apm/diagnostic-sessions", createBody(`,"dry_run":true`), secCookies, secCSRF), "dry run")
		est, _ := r.Data["estimated_overhead"].(map[string]interface{})
		if est == nil || est["cpu_hint"] == "" || est["spans_per_s_hint"] == "" || est["data_volume_hint"] == "" {
			t.Fatalf("estimated_overhead = %v", r.Data)
		}
		if notes, _ := est["risk_notes"].([]interface{}); len(notes) == 0 {
			t.Error("risk_notes 不能为空")
		}
		if r.Data["matched_instances"] != float64(1) {
			t.Errorf("matched_instances = %v", r.Data["matched_instances"])
		}
		var n int
		if err := env.db.QueryRow(ctx, `SELECT count(*) FROM apm_diagnostic_sessions`).Scan(&n); err != nil || n != 0 {
			t.Errorf("dry_run 落库了会话: n=%d err=%v", n, err)
		}
		// 无确认标志 → 400
		s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions", createBody(""), secCookies, secCSRF), 400, "create without confirm")
	})

	t.Run("validation and overhead guards", func(t *testing.T) {
		// 未知能力 → 400
		s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions",
			fmt.Sprintf(`{"scope":{"application_id":%q},"capabilities":["heap_dump"],"confirm":true}`, appID), secCookies, secCSRF), 400, "unknown capability")
		// 坏 scope → 400
		s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions",
			`{"scope":{"application_id":"bad"},"capabilities":["sql_detail"],"confirm":true}`, secCookies, secCSRF), 400, "bad application_id")
		// 函数探针大范围 → 422
		s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions",
			fmt.Sprintf(`{"scope":{"application_id":%q},"capabilities":["function_probe"],"sampling_rate":0.3,"confirm":true}`, appID), secCookies, secCSRF), 422, "function_probe wide scope")
		// 函数探针超分级采样上限 → 422
		s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions",
			fmt.Sprintf(`{"scope":{"application_id":%q,"service":"shop-diag"},"capabilities":["function_probe"],"sampling_rate":0.8,"confirm":true}`, appID), secCookies, secCSRF), 422, "function_probe rate 0.8")
		// 采样率超总上限 → 422
		s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions",
			fmt.Sprintf(`{"scope":{"application_id":%q},"capabilities":["sql_detail"],"sampling_rate":2.0,"confirm":true}`, appID), secCookies, secCSRF), 422, "rate 2.0")
		// 时长超上限 → 422
		s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions",
			fmt.Sprintf(`{"scope":{"application_id":%q},"capabilities":["sql_detail"],"duration_minutes":300,"confirm":true}`, appID), secCookies, secCSRF), 422, "duration 300")
		// 无匹配在线 Agent（其他应用）→ 422
		s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions",
			fmt.Sprintf(`{"scope":{"application_id":%q},"capabilities":["sql_detail"],"confirm":true}`, uuid.New()), secCookies, secCSRF), 422, "no matched agents")
	})

	t.Run("create publishes signed diagnostic policy", func(t *testing.T) {
		r := s5OK(t, env.post(t, "/api/v1/apm/diagnostic-sessions", createBody(`,"confirm":true`), secCookies, secCSRF), "create session")
		sessionID, _ = r.Data["id"].(string)
		if sessionID == "" || r.Data["status"] != "ACTIVE" {
			t.Fatalf("create response = %v", r.Data)
		}
		// 会话行：夹紧后生效值与硬截止
		var status string
		var rate float64
		var duration int
		var expiresAt time.Time
		if err := env.db.QueryRow(ctx,
			`SELECT status, sampling_rate, duration_minutes, expires_at FROM apm_diagnostic_sessions WHERE id = $1`,
			sessionID).Scan(&status, &rate, &duration, &expiresAt); err != nil {
			t.Fatalf("query session: %v", err)
		}
		if status != "ACTIVE" || rate != 0.5 || duration != 30 {
			t.Errorf("session row = %s/%v/%d", status, rate, duration)
		}
		// 应用级策略 v1：诊断叠加 + 信封 expires_at = 会话硬截止
		var version int64
		var policyExpires time.Time
		var policyRaw []byte
		if err := env.db.QueryRow(ctx, `
SELECT version, expires_at, policy FROM apm_agent_policies
WHERE scope = $1 ORDER BY version DESC LIMIT 1`,
			"application:"+appID.String()).Scan(&version, &policyExpires, &policyRaw); err != nil {
			t.Fatalf("query policy: %v", err)
		}
		if version != 1 {
			t.Errorf("policy version = %d, want 1", version)
		}
		if !policyExpires.Equal(expiresAt) {
			t.Errorf("信封 expires_at = %v, 会话硬截止 = %v（须一致）", policyExpires, expiresAt)
		}
		var policy map[string]interface{}
		if err := json.Unmarshal(policyRaw, &policy); err != nil {
			t.Fatalf("decode policy: %v", err)
		}
		diag, _ := policy["diagnostics"].(map[string]interface{})
		if diag["enabled"] != true {
			t.Errorf("overlay diagnostics.enabled = %v", diag["enabled"])
		}
		sess, _ := diag["session"].(map[string]interface{})
		if sess["id"] != sessionID || sess["sampling_rate"] != 0.5 {
			t.Errorf("overlay session = %v", sess)
		}
		// Agent 置 DIAGNOSING；Agent 拉取即得诊断叠加
		var agentStatus string
		if err := env.db.QueryRow(ctx, `SELECT status FROM apm_agents WHERE id = $1`, agentID).Scan(&agentStatus); err != nil {
			t.Fatalf("query agent: %v", err)
		}
		if agentStatus != "DIAGNOSING" {
			t.Errorf("agent status = %s, want DIAGNOSING", agentStatus)
		}
		resp := env.apmAgentDo(t, "GET", "/api/v1/apm/agent/policy", "",
			apmPoPHeaders(t, agentIdentity, "GET", "/api/v1/apm/agent/policy", nil))
		rp := s5OK(t, resp, "agent pull policy")
		if rp.Data["version"] != float64(1) || rp.Data["scope"] != "application:"+appID.String() {
			t.Errorf("agent policy = scope %v version %v", rp.Data["scope"], rp.Data["version"])
		}
		// Agent 侧视角验签：用注册响应下发的 CA 公钥验证拉取到的信封
		raw, _ := json.Marshal(rp.Data)
		var env2 apm.PolicyEnvelope
		if err := json.Unmarshal(raw, &env2); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		if err := apm.VerifyPolicySignature(caPubKey, &env2); err != nil {
			t.Errorf("Agent 拉取信封验签失败: %v", err)
		}
		// 同应用第二个 ACTIVE 会话 → 409
		s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions",
			fmt.Sprintf(`{"scope":{"application_id":%q},"capabilities":["gc_detail"],"confirm":true}`, appID), secCookies, secCSRF), 409, "scope busy")
	})

	t.Run("detail carries related audits", func(t *testing.T) {
		r := s5OK(t, env.get(t, "/api/v1/apm/diagnostic-sessions/"+sessionID, secCookies), "session detail")
		if r.Data["id"] != sessionID || r.Data["status"] != "ACTIVE" {
			t.Errorf("detail = %v", r.Data)
		}
		entries, _ := r.Data["audits"].([]interface{})
		foundCreate := false
		for _, e := range entries {
			m, _ := e.(map[string]interface{})
			if m["action"] == "create" && m["risk_level"] == "HIGH" && m["object_id"] == sessionID {
				foundCreate = true
			}
		}
		if !foundCreate {
			t.Errorf("关联审计缺 create HIGH 条目: %v", entries)
		}
	})

	t.Run("stop restores baseline policy", func(t *testing.T) {
		r := s5OK(t, env.post(t, "/api/v1/apm/diagnostic-sessions/"+sessionID+"/stop",
			`{"reason":"定位完成"}`, secCookies, secCSRF), "stop session")
		if r.Data["status"] != "STOPPED" || r.Data["baseline_restored"] != true {
			t.Errorf("stop response = %v", r.Data)
		}
		// 基线恢复 v2：叠加剥除；Agent 回 CONNECTED_BASELINE 并拉到 v2
		var version int64
		var diagEnabled bool
		if err := env.db.QueryRow(ctx, `
SELECT version, (policy->'diagnostics'->>'enabled')::boolean FROM apm_agent_policies
WHERE scope = $1 ORDER BY version DESC LIMIT 1`,
			"application:"+appID.String()).Scan(&version, &diagEnabled); err != nil {
			t.Fatalf("query policy: %v", err)
		}
		if version != 2 || diagEnabled {
			t.Errorf("restored policy = v%d enabled=%v", version, diagEnabled)
		}
		var agentStatus string
		if err := env.db.QueryRow(ctx, `SELECT status FROM apm_agents WHERE id = $1`, agentID).Scan(&agentStatus); err != nil {
			t.Fatalf("query agent: %v", err)
		}
		if agentStatus != "CONNECTED_BASELINE" {
			t.Errorf("agent status = %s, want CONNECTED_BASELINE", agentStatus)
		}
		resp := env.apmAgentDo(t, "GET", "/api/v1/apm/agent/policy", "",
			apmPoPHeaders(t, agentIdentity, "GET", "/api/v1/apm/agent/policy", nil))
		if rp := s5OK(t, resp, "agent pull restored policy"); rp.Data["version"] != float64(2) {
			t.Errorf("agent policy version = %v, want 2", rp.Data["version"])
		}
		// 重复停止 → 409
		s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions/"+sessionID+"/stop", "", secCookies, secCSRF), 409, "re-stop")
		// 不存在 → 404
		s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions/"+uuid.NewString()+"/stop", "", secCookies, secCSRF), 404, "stop missing")
	})

	var session2ID string
	t.Run("auto expiry via sweeper", func(t *testing.T) {
		r := s5OK(t, env.post(t, "/api/v1/apm/diagnostic-sessions", createBody(`,"confirm":true`), secCookies, secCSRF), "create session 2")
		session2ID, _ = r.Data["id"].(string)
		// 直接改库把硬截止拨到过去（等价于时间流逝），驱动扫描任务
		if _, err := env.db.Exec(ctx,
			`UPDATE apm_diagnostic_sessions SET expires_at = now() - interval '1 minute' WHERE id = $1`, session2ID); err != nil {
			t.Fatalf("backdate expires_at: %v", err)
		}
		sweeper := env.app.APMDiagnosticsSweeper()
		if sweeper == nil {
			t.Fatal("APM_ENABLED 开启时 sweeper 必须装配")
		}
		expired, restored, err := sweeper.SweepOnce(ctx, time.Now())
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
		if expired != 1 || restored != 1 {
			t.Errorf("expired=%d restored=%d, want 1/1", expired, restored)
		}
		var status string
		var baselineRestored bool
		var stopReason string
		if err := env.db.QueryRow(ctx,
			`SELECT status, baseline_restored, stop_reason FROM apm_diagnostic_sessions WHERE id = $1`,
			session2ID).Scan(&status, &baselineRestored, &stopReason); err != nil {
			t.Fatalf("query session 2: %v", err)
		}
		if status != "EXPIRED" || !baselineRestored || stopReason != "expired" {
			t.Errorf("session 2 = %s/%v/%s", status, baselineRestored, stopReason)
		}
		// 恢复策略 v4（v1 叠加→v2 恢复→v3 叠加→v4 恢复）叠加剥除
		var version int64
		var diagEnabled bool
		if err := env.db.QueryRow(ctx, `
SELECT version, (policy->'diagnostics'->>'enabled')::boolean FROM apm_agent_policies
WHERE scope = $1 ORDER BY version DESC LIMIT 1`,
			"application:"+appID.String()).Scan(&version, &diagEnabled); err != nil {
			t.Fatalf("query policy: %v", err)
		}
		if version != 4 || diagEnabled {
			t.Errorf("post-expiry policy = v%d enabled=%v, want v4 disabled", version, diagEnabled)
		}
		// 幂等：再次扫描空转
		expired, restored, err = sweeper.SweepOnce(ctx, time.Now())
		if err != nil || expired != 0 || restored != 0 {
			t.Errorf("re-sweep = %d/%d/%v, want 0/0/nil", expired, restored, err)
		}
	})

	t.Run("kill switch", func(t *testing.T) {
		// 先建一个 ACTIVE 会话
		r := s5OK(t, env.post(t, "/api/v1/apm/diagnostic-sessions", createBody(`,"confirm":true`), secCookies, secCSRF), "create session 3")
		session3ID, _ := r.Data["id"].(string)
		// enable=true：全量 KILLED + 恢复基线
		r = s5OK(t, env.post(t, "/api/v1/apm/diagnostics/kill-switch", `{"enable":true}`, secCookies, secCSRF), "kill switch on")
		if r.Data["kill_switch_enabled"] != true || r.Data["killed_sessions"] != float64(1) {
			t.Errorf("kill switch response = %v", r.Data)
		}
		var status string
		var baselineRestored bool
		if err := env.db.QueryRow(ctx,
			`SELECT status, baseline_restored FROM apm_diagnostic_sessions WHERE id = $1`,
			session3ID).Scan(&status, &baselineRestored); err != nil {
			t.Fatalf("query session 3: %v", err)
		}
		if status != "KILLED" || !baselineRestored {
			t.Errorf("session 3 = %s/%v, want KILLED/true", status, baselineRestored)
		}
		// 开启中拒绝新建 → 422；列表响应级 kill_switch_enabled
		s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions", createBody(`,"confirm":true`), secCookies, secCSRF), 422, "create while kill switch on")
		r = s5OK(t, env.get(t, "/api/v1/apm/diagnostic-sessions", secCookies), "list sessions")
		if r.Data["kill_switch_enabled"] != true {
			t.Errorf("kill_switch_enabled = %v", r.Data["kill_switch_enabled"])
		}
		if r.Data["total"] != float64(3) {
			t.Errorf("total = %v, want 3", r.Data["total"])
		}
		// 状态过滤
		r = s5OK(t, env.get(t, "/api/v1/apm/diagnostic-sessions?status=KILLED", secCookies), "list killed")
		if r.Data["total"] != float64(1) {
			t.Errorf("killed total = %v", r.Data["total"])
		}
		s5Expect(t, env.get(t, "/api/v1/apm/diagnostic-sessions?status=BOGUS", secCookies), 400, "bad status filter")
		// 审计：kill HIGH + kill_switch CRITICAL
		var highKills, criticalSwitches int
		if err := env.db.QueryRow(ctx, `
SELECT count(*) FILTER (WHERE action = 'kill' AND risk_level = 'HIGH' AND object_id = $1),
       count(*) FILTER (WHERE action = 'kill_switch' AND risk_level = 'CRITICAL')
FROM operation_audits WHERE module = 'apm'`, session3ID).Scan(&highKills, &criticalSwitches); err != nil {
			t.Fatalf("query audits: %v", err)
		}
		if highKills != 1 || criticalSwitches != 1 {
			t.Errorf("audits kill=%d kill_switch=%d, want 1/1", highKills, criticalSwitches)
		}
		// enable=false 解除封锁
		r = s5OK(t, env.post(t, "/api/v1/apm/diagnostics/kill-switch", `{"enable":false}`, secCookies, secCSRF), "kill switch off")
		if r.Data["kill_switch_enabled"] != false {
			t.Errorf("disable response = %v", r.Data)
		}
	})

	t.Run("kill switch updatable via settings API", func(t *testing.T) {
		sysCookies, sysCSRF := env.login(t, "test_sysadmin", env.adminPwd)
		r := s5OK(t, env.get(t, "/api/v1/system-settings?group=apm_diagnostics", sysCookies), "list apm_diagnostics settings")
		items, _ := r.Data["items"].([]interface{})
		if len(items) != 1 {
			t.Fatalf("apm_diagnostics settings count = %d, want 1", len(items))
		}
		m, _ := items[0].(map[string]interface{})
		version, _ := m["version"].(float64)
		// 白名单登记后 Update API 可改
		body := fmt.Sprintf(`{"setting_group":"apm_diagnostics","setting_key":"kill_switch","setting_value":true,"version":%d}`, int(version))
		s5OK(t, env.request(t, http.MethodPut, "/api/v1/system-settings", body, sysCookies, sysCSRF), "update kill switch via settings API")
		var stored bool
		if err := env.db.QueryRow(ctx,
			`SELECT (setting_value)::boolean FROM system_settings WHERE setting_group='apm_diagnostics' AND setting_key='kill_switch'`).Scan(&stored); err != nil || !stored {
			t.Errorf("updated kill_switch = %v, err=%v", stored, err)
		}
		// 还原（不干扰其他用例）
		body = fmt.Sprintf(`{"setting_group":"apm_diagnostics","setting_key":"kill_switch","setting_value":false,"version":%d}`, int(version)+1)
		s5OK(t, env.request(t, http.MethodPut, "/api/v1/system-settings", body, sysCookies, sysCSRF), "restore kill switch")
	})

	t.Run("permission triad", func(t *testing.T) {
		auditCookies, auditCSRF := env.s5Login(t, "apmdiagaudit", "AUDIT_ADMIN")
		sysCookies, sysCSRF := env.login(t, "test_sysadmin", env.adminPwd)
		checkForbidden := func(cookies []*http.Cookie, csrf, who string) {
			t.Helper()
			s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions", createBody(`,"confirm":true`), cookies, csrf), 403, who+" create")
			s5Expect(t, env.get(t, "/api/v1/apm/diagnostic-sessions", cookies), 403, who+" list")
			s5Expect(t, env.get(t, "/api/v1/apm/diagnostic-sessions/"+sessionID, cookies), 403, who+" detail")
			s5Expect(t, env.post(t, "/api/v1/apm/diagnostic-sessions/"+sessionID+"/stop", "", cookies, csrf), 403, who+" stop")
			s5Expect(t, env.post(t, "/api/v1/apm/diagnostics/kill-switch", `{"enable":true}`, cookies, csrf), 403, who+" kill switch")
		}
		checkForbidden(auditCookies, auditCSRF, "audit_admin")
		checkForbidden(sysCookies, sysCSRF, "system_admin")
		// 匿名 → 401
		s5Expect(t, env.get(t, "/api/v1/apm/diagnostic-sessions", nil), 401, "anonymous list")
	})
}
