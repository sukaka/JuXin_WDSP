// stage_risk_policy_test.go 身份风险处置策略 + 风险处置事件采集集成测试
// （WDSP AI 自动化渗透防护增强 阶段3；真实 PG/Valkey，未设置环境或 -short 即 skip）。
// 覆盖：迁移建表（含 access_control_events.details 列）与权限/策略种子；
// risk-policy GET/PUT（字段校验 400、乐观锁 409、权限 403、成功 200+version+1+审计，
// OBSERVE→PROTECT 升级高风险审计）；风险处置事件（RISK_POLICY_BLOCK /
// RISK_POLICY_RATE_LIMIT）经 guard 事件通道采集落库——details 证据载荷完整、
// 不错标 temporary_blocks、不进 CC 运行汇总。
// 角色口径：risk_policy.read 授 SYSTEM_ADMIN/SECURITY_ADMIN，000122 撤销
// AUDIT_ADMIN 超出审计职责的只读权；edit 仅 SECURITY_ADMIN。
package tests

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/accesscontrolevents"
)

// TestRiskPolicyMigrations 迁移后表/列/权限/策略种子存在。
func TestRiskPolicyMigrations(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	var n int
	if err := env.db.QueryRow(ctx, "SELECT count(*) FROM security_risk_policy").Scan(&n); err != nil {
		t.Fatalf("table security_risk_policy missing: %v", err)
	}

	// access_control_events.details 列（风险处置事件证据载荷落点）
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
WHERE table_name='access_control_events' AND column_name='details'`).Scan(&n); err != nil {
		t.Fatalf("query details column: %v", err)
	}
	if n != 1 {
		t.Errorf("access_control_events.details column count = %d, want 1", n)
	}

	// 权限种子（2 个权限点）
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM permissions
WHERE code IN ('risk_policy.read','risk_policy.edit')`).Scan(&n); err != nil {
		t.Fatalf("query permissions: %v", err)
	}
	if n != 2 {
		t.Errorf("risk policy permissions = %d, want 2", n)
	}

	// 000232 后：risk_policy.read / risk_policy.edit 均仅授予运维管理员（SECURITY_ADMIN）
	if err := env.db.QueryRow(ctx, `SELECT count(DISTINCT r.code) FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
WHERE p.code = 'risk_policy.read' AND r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN','AUDIT_ADMIN')`).Scan(&n); err != nil {
		t.Fatalf("query read grants: %v", err)
	}
	if n != 1 {
		t.Errorf("risk_policy.read granted roles = %d, want 1 (SECURITY_ADMIN only)", n)
	}
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
WHERE r.code = 'AUDIT_ADMIN'
  AND p.code IN ('risk_policy.read','attack_sessions.read','traffic.agents.view','license.read')`).Scan(&n); err != nil {
		t.Fatalf("query AUDIT_ADMIN non-audit grants: %v", err)
	}
	if n != 0 {
		t.Errorf("AUDIT_ADMIN non-audit grants = %d, want 0", n)
	}
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
WHERE p.code = 'risk_policy.edit' AND r.code = 'SECURITY_ADMIN'`).Scan(&n); err != nil {
		t.Fatalf("query edit grant: %v", err)
	}
	if n != 1 {
		t.Errorf("risk_policy.edit SECURITY_ADMIN grant = %d, want 1", n)
	}
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM role_permissions rp
JOIN permissions p ON p.id = rp.permission_id
WHERE p.code = 'risk_policy.edit' AND rp.role_id NOT IN (SELECT id FROM roles WHERE code = 'SECURITY_ADMIN')`).Scan(&n); err != nil {
		t.Fatalf("query edit non-grants: %v", err)
	}
	if n != 0 {
		t.Errorf("risk_policy.edit granted beyond SECURITY_ADMIN: %d, want 0", n)
	}

	// GLOBAL 策略种子行（version=1, mode=OBSERVE, enabled=true，阈值默认值）
	var version, blockThreshold, rateThreshold, rateRPS, windowSec int
	var mode string
	var enabled bool
	if err := env.db.QueryRow(ctx,
		`SELECT version, mode, enabled, block_threshold, rate_limit_threshold, rate_limit_rps, signal_window_seconds
FROM security_risk_policy WHERE scope='GLOBAL'`).
		Scan(&version, &mode, &enabled, &blockThreshold, &rateThreshold, &rateRPS, &windowSec); err != nil {
		t.Fatalf("risk policy seed row missing: %v", err)
	}
	if version != 1 || mode != "OBSERVE" || !enabled {
		t.Errorf("seed policy version=%d mode=%s enabled=%v, want 1/OBSERVE/true", version, mode, enabled)
	}
	if blockThreshold != 80 || rateThreshold != 40 || rateRPS != 10 || windowSec != 86400 {
		t.Errorf("seed thresholds = %d/%d/%d/%d, want 80/40/10/86400", blockThreshold, rateThreshold, rateRPS, windowSec)
	}
}

// TestRiskPolicyAPI risk-policy GET 种子行 + PUT 全生命周期。
func TestRiskPolicyAPI(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "rp_sec", "SECURITY_ADMIN")

	// GET 种子行
	resp := env.get(t, "/api/v1/security/risk-policy", cookies)
	result := s5OK(t, resp, "get risk policy")
	policy := s5Obj(t, result, "policy")
	if policy["scope"] != "GLOBAL" || policy["mode"] != "OBSERVE" || policy["enabled"] != true {
		t.Fatalf("default policy unexpected: %+v", policy)
	}
	if int(s5Num(t, policy, "version")) != 1 {
		t.Fatalf("default policy version = %v, want 1", policy["version"])
	}
	if int(s5Num(t, policy, "block_threshold")) != 80 || int(s5Num(t, policy, "rate_limit_threshold")) != 40 ||
		int(s5Num(t, policy, "challenge_threshold")) != 0 {
		t.Fatalf("default thresholds = %v/%v/%v, want 80/40/0", policy["block_threshold"], policy["rate_limit_threshold"], policy["challenge_threshold"])
	}
	levels, _ := policy["risk_levels"].(map[string]interface{})
	if levels["medium"] != float64(20) || levels["high"] != float64(40) || levels["critical"] != float64(70) {
		t.Fatalf("default risk_levels = %+v, want 20/40/70", levels)
	}

	// PUT 阻断阈值越界 → 400
	resp = env.do(t, http.MethodPut, "/api/v1/security/risk-policy",
		`{"enabled":true,"mode":"OBSERVE","version":1,"block_threshold":0}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "put risk policy with block_threshold 0")

	// PUT 限速阈值 ≥ 阻断阈值 → 400
	resp = env.do(t, http.MethodPut, "/api/v1/security/risk-policy",
		`{"enabled":true,"mode":"OBSERVE","version":1,"block_threshold":80,"rate_limit_threshold":80}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "put risk policy with rate_limit >= block")

	// PUT 非法 mode → 400
	resp = env.do(t, http.MethodPut, "/api/v1/security/risk-policy",
		`{"enabled":true,"mode":"ENFORCE","version":1,"block_threshold":80,"rate_limit_threshold":40,"rate_limit_rps":10,"signal_window_seconds":86400}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "put risk policy with bad mode")

	// PUT 非法信号键 / risk_levels 缺键 → 400
	resp = env.do(t, http.MethodPut, "/api/v1/security/risk-policy",
		`{"enabled":true,"mode":"OBSERVE","version":1,"block_threshold":80,"rate_limit_threshold":40,"rate_limit_rps":10,"signal_window_seconds":86400,"scores":{"lower_case":10}}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "put risk policy with bad score key")
	resp = env.do(t, http.MethodPut, "/api/v1/security/risk-policy",
		`{"enabled":true,"mode":"OBSERVE","version":1,"block_threshold":80,"rate_limit_threshold":40,"rate_limit_rps":10,"signal_window_seconds":86400,"risk_levels":{"medium":20,"high":40}}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "put risk policy with incomplete risk_levels")

	// PUT version 冲突 → 409
	resp = env.do(t, http.MethodPut, "/api/v1/security/risk-policy",
		`{"enabled":true,"mode":"OBSERVE","version":999,"block_threshold":80,"rate_limit_threshold":40,"rate_limit_rps":10,"signal_window_seconds":86400}`, cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "put risk policy with stale version")

	// 000122 收紧后 AUDIT_ADMIN 无 risk_policy.* 权限：GET 403 / PUT 403
	auditCookies, auditCSRF := env.s5Login(t, "rp_audit", "AUDIT_ADMIN")
	resp = env.get(t, "/api/v1/security/risk-policy", auditCookies)
	s5Expect(t, resp, http.StatusForbidden, "audit admin get risk policy")
	resp = env.do(t, http.MethodPut, "/api/v1/security/risk-policy",
		`{"enabled":true,"mode":"OBSERVE","version":1,"block_threshold":80,"rate_limit_threshold":40,"rate_limit_rps":10,"signal_window_seconds":86400}`, auditCookies, auditCSRF)
	s5Expect(t, resp, http.StatusForbidden, "audit admin put risk policy")

	// 000232 后 SYSTEM_ADMIN 剥离应用防护策略（risk_policy.read）：GET 403 / PUT 403
	sysCookies, sysCSRF := env.s5Login(t, "rp_sys", "SYSTEM_ADMIN")
	resp = env.get(t, "/api/v1/security/risk-policy", sysCookies)
	s5Expect(t, resp, http.StatusForbidden, "system admin get risk policy")
	resp = env.do(t, http.MethodPut, "/api/v1/security/risk-policy",
		`{"enabled":true,"mode":"OBSERVE","version":1,"block_threshold":80,"rate_limit_threshold":40,"rate_limit_rps":10,"signal_window_seconds":86400}`, sysCookies, sysCSRF)
	s5Expect(t, resp, http.StatusForbidden, "system admin put risk policy")

	// PUT 成功 → 200 + version+1（PUT 会异步触发发布任务，无网关时任务失败不影响响应）
	resp = env.do(t, http.MethodPut, "/api/v1/security/risk-policy",
		`{"enabled":true,"mode":"OBSERVE","version":1,"block_threshold":75,"rate_limit_threshold":35,"challenge_threshold":55,"rate_limit_rps":5,
"signal_window_seconds":43200,"scores":{"URI_ENUMERATION":25,"SQLI":50},"risk_levels":{"medium":20,"high":40,"critical":70}}`, cookies, csrf)
	result = s5OK(t, resp, "put risk policy")
	policy = s5Obj(t, result, "policy")
	if int(s5Num(t, policy, "version")) != 2 {
		t.Errorf("policy version after update = %v, want 2", policy["version"])
	}
	if int(s5Num(t, policy, "block_threshold")) != 75 || int(s5Num(t, policy, "challenge_threshold")) != 55 ||
		int(s5Num(t, policy, "signal_window_seconds")) != 43200 {
		t.Errorf("updated thresholds = %v/%v/%v, want 75/55/43200", policy["block_threshold"], policy["challenge_threshold"], policy["signal_window_seconds"])
	}
	scores, _ := policy["scores"].(map[string]interface{})
	if scores["SQLI"] != float64(50) {
		t.Errorf("scores.SQLI = %v, want 50", scores["SQLI"])
	}

	// 审计记录存在（module=security, object_type=risk_policy, action=update, 中风险）
	var auditCount int
	if err := env.db.QueryRow(context.Background(), `SELECT count(*) FROM operation_audits
WHERE module='security' AND object_type='risk_policy' AND action='update' AND risk_level='MEDIUM'`).Scan(&auditCount); err != nil {
		t.Fatalf("query audits: %v", err)
	}
	if auditCount < 1 {
		t.Errorf("risk policy update audit missing")
	}

	// 旧客户端 PUT 省略 challenge_threshold：保留已启用值；OBSERVE→PROTECT 仍记高风险审计。
	resp = env.do(t, http.MethodPut, "/api/v1/security/risk-policy",
		`{"enabled":true,"mode":"PROTECT","version":2,"block_threshold":75,"rate_limit_threshold":35,"rate_limit_rps":5,
"signal_window_seconds":43200,"scores":{"URI_ENUMERATION":25,"SQLI":50},"risk_levels":{"medium":20,"high":40,"critical":70}}`, cookies, csrf)
	result = s5OK(t, resp, "put risk policy to PROTECT")
	policy = s5Obj(t, result, "policy")
	if policy["mode"] != "PROTECT" || int(s5Num(t, policy, "version")) != 3 || int(s5Num(t, policy, "challenge_threshold")) != 55 {
		t.Errorf("policy after legacy PROTECT update = %+v, want PROTECT/version 3/challenge 55", policy)
	}
	if err := env.db.QueryRow(context.Background(), `SELECT count(*) FROM operation_audits
WHERE module='security' AND object_type='risk_policy' AND action='update' AND risk_level='HIGH'`).Scan(&auditCount); err != nil {
		t.Fatalf("query high risk audits: %v", err)
	}
	if auditCount < 1 {
		t.Errorf("risk policy OBSERVE→PROTECT high-risk audit missing")
	}

	// 显式 0 关闭挑战，响应与数据库均不得吞掉该值。
	resp = env.do(t, http.MethodPut, "/api/v1/security/risk-policy",
		`{"enabled":true,"mode":"PROTECT","version":3,"block_threshold":75,"rate_limit_threshold":35,"challenge_threshold":0,"rate_limit_rps":5,
"signal_window_seconds":43200,"scores":{"URI_ENUMERATION":25,"SQLI":50},"risk_levels":{"medium":20,"high":40,"critical":70}}`, cookies, csrf)
	result = s5OK(t, resp, "disable risk challenge")
	policy = s5Obj(t, result, "policy")
	if int(s5Num(t, policy, "version")) != 4 || int(s5Num(t, policy, "challenge_threshold")) != 0 {
		t.Errorf("policy after explicit zero = %+v, want version 4/challenge 0", policy)
	}
}

// TestRiskPolicyEventCollection 风险处置事件经 guard 事件通道采集落库：
// 阻断/限速/挑战入库 + details 证据载荷 + action 映射；挑战不计 REJECT，
// 不错标 temporary_blocks、不进 CC 运行汇总。
func TestRiskPolicyEventCollection(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "guard-events.log")
	ts := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)

	lines := []string{
		// PROTECT 模式阻断（blocked → REJECT；risk 证据嵌套对象，与网关线格式同形）
		fmt.Sprintf(`{"request_id":"r-rp-1","occurred_at":%q,"gateway_node_id":"gw-rp-01","client_ip":"203.0.113.10","connection_ip":"10.0.0.2","domain":"shop.example.com","request_method":"GET","request_path":"/api/orders","event_type":"RISK_POLICY_BLOCK","action":"blocked","risk":{"identity_key":"ik-rp-1","score":85,"risk_level":"CRITICAL","threshold":80,"signals":[{"type":"URI_ENUMERATION","score":15},{"type":"SQLI","score":50}],"mode":"PROTECT","policy_version":3,"action_taken":"blocked","reason":"identity_risk_policy"},"response_status":403}`, ts),
		// OBSERVE 模式限速（would_rate_limit → OBSERVE）
		fmt.Sprintf(`{"request_id":"r-rp-2","occurred_at":%q,"gateway_node_id":"gw-rp-01","client_ip":"203.0.113.11","domain":"shop.example.com","request_method":"POST","request_path":"/api/login","event_type":"RISK_POLICY_RATE_LIMIT","action":"would_rate_limit","risk":{"identity_key":"ik-rp-2","score":45,"risk_level":"HIGH","threshold":40,"signals":[{"type":"AUTH_FAIL_PROBE","score":15}],"mode":"OBSERVE","policy_version":3,"action_taken":"would_rate_limit","reason":"identity_risk_policy"},"response_status":429}`, ts),
		// PROTECT 身份挑战（challenged → CHALLENGE，不计 REJECT）
		fmt.Sprintf(`{"request_id":"r-rp-3","occurred_at":%q,"gateway_node_id":"gw-rp-01","client_ip":"203.0.113.12","domain":"shop.example.com","request_method":"GET","request_path":"/api/orders","event_type":"RISK_POLICY_CHALLENGE","action":"challenged","risk":{"identity_key":"ik-rp-3","score":60,"risk_level":"HIGH","threshold":55,"signals":[],"mode":"PROTECT","policy_version":3,"action_taken":"challenged","reason":"identity_risk_policy"},"response_status":403}`, ts),
		// OBSERVE 身份挑战（would_challenge → OBSERVE）
		fmt.Sprintf(`{"request_id":"r-rp-4","occurred_at":%q,"gateway_node_id":"gw-rp-01","client_ip":"203.0.113.13","domain":"shop.example.com","request_method":"GET","request_path":"/api/orders","event_type":"RISK_POLICY_CHALLENGE","action":"would_challenge","risk":{"identity_key":"ik-rp-4","score":60,"risk_level":"HIGH","threshold":55,"signals":[],"mode":"OBSERVE","policy_version":3,"action_taken":"would_challenge","reason":"identity_risk_policy"},"response_status":200}`, ts),
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	store := accesscontrolevents.NewStore(env.db)
	coll := accesscontrolevents.NewCollector(store, "risk-events-01",
		logPath, filepath.Join(dir, "guard-events.checkpoint"), "gw-rp-01")
	n, err := coll.CollectOnce(ctx)
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 4 {
		t.Fatalf("processed = %d, want 4", n)
	}

	// RISK_POLICY_BLOCK：action=REJECT + details 证据载荷完整
	var action, idKey, riskLevel, mode, actionTaken, reason string
	var score, threshold, policyVersion int
	var signals string
	if err := env.db.QueryRow(ctx, `SELECT action,
details->>'identity_key', (details->>'score')::int, details->>'risk_level',
(details->>'threshold')::int, details->>'mode', (details->>'policy_version')::int,
details->>'action_taken', details->>'reason', details->>'signals'
FROM access_control_events WHERE request_id='r-rp-1'`).
		Scan(&action, &idKey, &score, &riskLevel, &threshold, &mode, &policyVersion, &actionTaken, &reason, &signals); err != nil {
		t.Fatalf("query risk block event: %v", err)
	}
	if action != "REJECT" {
		t.Errorf("block event action = %s, want REJECT", action)
	}
	if idKey != "ik-rp-1" || score != 85 || riskLevel != "CRITICAL" || threshold != 80 ||
		mode != "PROTECT" || policyVersion != 3 || actionTaken != "blocked" || reason != "identity_risk_policy" {
		t.Errorf("block event details = key %s score %d level %s th %d mode %s pv %d at %s reason %s",
			idKey, score, riskLevel, threshold, mode, policyVersion, actionTaken, reason)
	}
	if !strings.Contains(signals, "URI_ENUMERATION") || !strings.Contains(signals, "SQLI") {
		t.Errorf("block event signals = %s, want 2 signal items", signals)
	}

	// RISK_POLICY_RATE_LIMIT：action=OBSERVE（would_rate_limit）
	if err := env.db.QueryRow(ctx, `SELECT action, details->>'action_taken', details->>'mode'
FROM access_control_events WHERE request_id='r-rp-2'`).Scan(&action, &actionTaken, &mode); err != nil {
		t.Fatalf("query risk rate limit event: %v", err)
	}
	if action != "OBSERVE" || actionTaken != "would_rate_limit" || mode != "OBSERVE" {
		t.Errorf("rate limit event = action %s taken %s mode %s, want OBSERVE/would_rate_limit/OBSERVE", action, actionTaken, mode)
	}

	// RISK_POLICY_CHALLENGE：实际挑战为 CHALLENGE，观察挑战为 OBSERVE，均不映射 REJECT。
	for _, tc := range []struct {
		requestID, wantAction, wantTaken string
	}{
		{requestID: "r-rp-3", wantAction: "CHALLENGE", wantTaken: "challenged"},
		{requestID: "r-rp-4", wantAction: "OBSERVE", wantTaken: "would_challenge"},
	} {
		if err := env.db.QueryRow(ctx, `SELECT action, details->>'action_taken'
FROM access_control_events WHERE request_id=$1`, tc.requestID).Scan(&action, &actionTaken); err != nil {
			t.Fatalf("query risk challenge event %s: %v", tc.requestID, err)
		}
		if action != tc.wantAction || actionTaken != tc.wantTaken {
			t.Errorf("challenge event %s = action %s taken %s, want %s/%s", tc.requestID, action, actionTaken, tc.wantAction, tc.wantTaken)
		}
	}

	// 不错标 temporary_blocks（风险处置不产 CC_AUTO 封禁记录）
	var cnt int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM temporary_blocks`).Scan(&cnt); err != nil {
		t.Fatalf("query temporary_blocks: %v", err)
	}
	if cnt != 0 {
		t.Errorf("temporary_blocks = %d, want 0 (risk events must not create CC_AUTO blocks)", cnt)
	}

	// 不进 CC 运行汇总（policy_id 空，无策略聚合）
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM rate_limit_runtime_summaries`).Scan(&cnt); err != nil {
		t.Fatalf("query runtime summaries: %v", err)
	}
	if cnt != 0 {
		t.Errorf("rate_limit_runtime_summaries = %d, want 0 (risk events must not pollute CC stats)", cnt)
	}

	// 事件列表 API 可按 event_type 筛出（access_control_events.read 权限）
	cookies, _ := env.s5Login(t, "rpe_sec", "SECURITY_ADMIN")
	resp := env.get(t, "/api/v1/access-control-events?event_type=RISK_POLICY_BLOCK", cookies)
	func() {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list risk events status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
		}
		var page apiRespPage5
		readJSON(t, resp, &page)
		if page.Data.Total != 1 || len(page.Data.Items) != 1 {
			t.Fatalf("risk block events total = %d, want 1", page.Data.Total)
		}
		item := page.Data.Items[0]
		if item["event_type"] != "RISK_POLICY_BLOCK" || item["action"] != "REJECT" {
			t.Errorf("list item = %+v", item)
		}
		details, _ := item["details"].(map[string]interface{})
		if details["identity_key"] != "ik-rp-1" || details["reason"] != "identity_risk_policy" {
			t.Errorf("list item details = %+v", details)
		}
	}()
}
