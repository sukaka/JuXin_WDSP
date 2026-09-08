// stage_identity_security_test.go client_identity 体系 + 行为事件采集 + 行为策略
// 集成测试（WDSP AI 自动化渗透防护增强 阶段1；真实 PG/Valkey，未设置环境或 -short 即 skip）。
// 覆盖：迁移建表与权限/策略种子；behavior-policy GET/PUT（校验 400、乐观锁 409、
// 权限 403、成功 200+version+1+审计）；identities 空列表分页结构；identity-events
// 采集器三种记录入库（UPSERT 幂等、risk_score/level 重算 CRITICAL、坏行入失败队列）
// 及 identities API 列表/详情/行为序列/事件分页。
// 角色说明：000099 将本组权限点授予三内置角色，其后的 000100_role_perm_rebalance
// 将 security_identities.*/behavior_policy.* 划归 SECURITY_ADMIN（SYSTEM_ADMIN 移交、
// AUDIT_ADMIN 收紧为纯审计角色），故正向用例一律以 SECURITY_ADMIN 登录。
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

	"github.com/jiuzhang-waf/server/internal/identityevents"
)

// TestIdentitySecurityMigrations 迁移后表/权限/策略种子存在。
func TestIdentitySecurityMigrations(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	for _, table := range []string{
		"client_identity", "identity_ip_history", "identity_credential",
		"behavior_statistics", "identity_behavior_events", "security_behavior_policy",
	} {
		var n int
		if err := env.db.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}

	// 权限种子（3 个权限点）
	var permCount int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM permissions
WHERE code IN ('security_identities.read','behavior_policy.read','behavior_policy.edit')`).Scan(&permCount); err != nil {
		t.Fatalf("query permissions: %v", err)
	}
	if permCount != 3 {
		t.Errorf("identity security permissions = %d, want 3", permCount)
	}

	// GLOBAL 策略种子行（version=1, mode=OBSERVE, enabled=true）
	var version int
	var mode string
	var enabled bool
	if err := env.db.QueryRow(ctx,
		`SELECT version, mode, enabled FROM security_behavior_policy WHERE scope='GLOBAL'`).Scan(&version, &mode, &enabled); err != nil {
		t.Fatalf("behavior policy seed row missing: %v", err)
	}
	if version != 1 || mode != "OBSERVE" || !enabled {
		t.Errorf("seed policy version=%d mode=%s enabled=%v, want 1/OBSERVE/true", version, mode, enabled)
	}
}

// TestBehaviorPolicyAPI behavior-policy GET 默认行 + PUT 全生命周期。
func TestBehaviorPolicyAPI(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "bp_sec", "SECURITY_ADMIN")

	// GET 默认行
	resp := env.get(t, "/api/v1/security/behavior-policy", cookies)
	result := s5OK(t, resp, "get behavior policy")
	policy := s5Obj(t, result, "policy")
	if policy["scope"] != "GLOBAL" || policy["mode"] != "OBSERVE" || policy["enabled"] != true {
		t.Fatalf("default policy unexpected: %+v", policy)
	}
	if int(s5Num(t, policy, "version")) != 1 {
		t.Fatalf("default policy version = %v, want 1", policy["version"])
	}
	paths, _ := policy["sensitive_paths"].([]interface{})
	if len(paths) == 0 {
		t.Fatalf("default sensitive_paths empty")
	}

	// PUT 非法比率 → 400
	resp = env.do(t, http.MethodPut, "/api/v1/security/behavior-policy",
		`{"enabled":true,"mode":"OBSERVE","version":1,"uri_enum_new_ratio_threshold":1.5}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "put behavior policy with ratio > 1")

	// PUT 非法白名单 IP → 400
	resp = env.do(t, http.MethodPut, "/api/v1/security/behavior-policy",
		`{"enabled":true,"mode":"OBSERVE","version":1,"whitelist_ips":["not-an-ip"]}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "put behavior policy with bad whitelist ip")

	// PUT version 冲突 → 409
	resp = env.do(t, http.MethodPut, "/api/v1/security/behavior-policy",
		`{"enabled":true,"mode":"OBSERVE","version":999}`, cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "put behavior policy with stale version")

	// AUDIT_ADMIN 无本组权限（000100 收紧为纯审计角色）：GET 403 / PUT 403
	auditCookies, auditCSRF := env.s5Login(t, "bp_audit", "AUDIT_ADMIN")
	resp = env.get(t, "/api/v1/security/behavior-policy", auditCookies)
	s5Expect(t, resp, http.StatusForbidden, "audit admin get behavior policy")
	resp = env.do(t, http.MethodPut, "/api/v1/security/behavior-policy",
		`{"enabled":true,"mode":"OBSERVE","version":1}`, auditCookies, auditCSRF)
	s5Expect(t, resp, http.StatusForbidden, "audit admin put behavior policy")

	// PUT 成功 → 200 + version+1（PUT 会异步触发发布任务，无网关时任务失败不影响响应）
	resp = env.do(t, http.MethodPut, "/api/v1/security/behavior-policy",
		`{"enabled":true,"mode":"OBSERVE","version":1,"uri_enum_unique_threshold":77,
"uri_enum_new_ratio_threshold":0.8,"not_found_ratio_threshold":0.7,"not_found_min_requests":30,
"method_enum_threshold":4,"param_mutation_threshold":30,"auth_fail_threshold":10,"low_slow_sensitive_min_hits":10,
"sensitive_paths":["/.git","/.env"],"scores":{"URI_ENUMERATION":25,"AUTH_FAIL_PROBE":15},
"whitelist_ips":["10.0.0.0/8"],"whitelist_uas":["internal-monitor"]}`, cookies, csrf)
	result = s5OK(t, resp, "put behavior policy")
	policy = s5Obj(t, result, "policy")
	if int(s5Num(t, policy, "version")) != 2 {
		t.Errorf("policy version after update = %v, want 2", policy["version"])
	}
	if int(s5Num(t, policy, "uri_enum_unique_threshold")) != 77 {
		t.Errorf("uri_enum_unique_threshold = %v, want 77", policy["uri_enum_unique_threshold"])
	}
	scores, _ := policy["scores"].(map[string]interface{})
	if scores["URI_ENUMERATION"] != float64(25) {
		t.Errorf("scores.URI_ENUMERATION = %v, want 25", scores["URI_ENUMERATION"])
	}

	// 审计记录存在（module=security, object_type=behavior_policy, action=update）
	var auditCount int
	if err := env.db.QueryRow(context.Background(), `SELECT count(*) FROM operation_audits
WHERE module='security' AND object_type='behavior_policy' AND action='update'`).Scan(&auditCount); err != nil {
		t.Fatalf("query audits: %v", err)
	}
	if auditCount < 1 {
		t.Errorf("behavior policy update audit missing")
	}
}

// TestSecurityIdentitiesEmptyList identities 空列表分页结构 + 不存在身份 404。
func TestSecurityIdentitiesEmptyList(t *testing.T) {
	env := setupTestEnv(t)
	cookies, _ := env.s5Login(t, "id_sec", "SECURITY_ADMIN")

	resp := env.get(t, "/api/v1/security/identities", cookies)
	var page apiRespPage5
	func() {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list identities status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
		}
		readJSON(t, resp, &page)
	}()
	if page.Data.Total != 0 || len(page.Data.Items) != 0 || page.Data.Page != 1 || page.Data.PageSize != 20 {
		t.Errorf("empty list page = %+v, want {items:[],page:1,page_size:20,total:0}", page.Data)
	}

	// 不存在身份 → 404
	resp = env.get(t, "/api/v1/security/identities/00000000-0000-0000-0000-000000000000", cookies)
	s5Expect(t, resp, http.StatusNotFound, "get missing identity")
	// 非法 ID → 400
	resp = env.get(t, "/api/v1/security/identities/not-a-uuid", cookies)
	s5Expect(t, resp, http.StatusBadRequest, "get identity with bad uuid")
	// 非法筛选值 → 400
	resp = env.get(t, "/api/v1/security/identities?risk_level=NOPE", cookies)
	s5Expect(t, resp, http.StatusBadRequest, "list identities with bad risk_level")

	// AUDIT_ADMIN 无读权限（000100 收紧为纯审计角色）→ 403
	auditCookies, _ := env.s5Login(t, "id_audit", "AUDIT_ADMIN")
	resp = env.get(t, "/api/v1/security/identities", auditCookies)
	s5Expect(t, resp, http.StatusForbidden, "audit admin list identities")
}

// TestIdentityCollectorIntegration 采集器三种记录入库 + UPSERT 幂等 + 风险重算 + API 可读。
func TestIdentityCollectorIntegration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	dir := t.TempDir()
	logPath := filepath.Join(dir, "identity-events.log")
	ts := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	tsWindow := time.Now().UTC().Add(-time.Hour).Truncate(time.Minute).Format(time.RFC3339)

	lines := []string{
		// 身份观测（ik-it-1：JWT+API_KEY 凭据）
		fmt.Sprintf(`{"record_type":"identity_observation","request_id":"r-it-1","occurred_at":%q,"gateway_node":"gw-it-01","app_id":"","app_code":"shop","domain":"shop.example.com","method":"GET","path":"/api/orders","identity_key":"ik-it-1","identity_type":"HUMAN","client_ip":"203.0.113.10","user_agent":"Mozilla/5.0","tls_fingerprint":"tls1","browser_fingerprint":"br1","credentials":[{"type":"JWT","hash":"jwt-h1","account_id":"acc-1","jwt_subject":"sub-1"},{"type":"API_KEY","hash":"ak-h1"}]}`, ts),
		// 同 identity_key 第二次观测（request_count 应累计为 2；identity_type 已是 HUMAN 不被 BOT 覆盖）
		fmt.Sprintf(`{"record_type":"identity_observation","request_id":"r-it-2","occurred_at":%q,"gateway_node":"gw-it-01","app_id":"","app_code":"shop","domain":"shop.example.com","method":"GET","path":"/api/users","identity_key":"ik-it-1","identity_type":"BOT","client_ip":"203.0.113.10","user_agent":"Mozilla/5.0","credentials":[{"type":"JWT","hash":"jwt-h1","account_id":"acc-1","jwt_subject":"sub-1"}]}`, ts),
		// 行为快照（1m 窗口）
		fmt.Sprintf(`{"record_type":"behavior_snapshot","request_id":"r-it-3","occurred_at":%q,"gateway_node":"gw-it-01","identity_key":"ik-it-1","identity_type":"UNKNOWN","client_ip":"203.0.113.10","windows":{"1m":{"window_start":%q,"request_count":30,"unique_uri_count":12,"new_uri_count":9,"status_401_count":1,"status_403_count":0,"status_404_count":5,"status_405_count":0,"status_500_count":0,"auth_fail_count":1,"parameter_mutation_count":2,"sensitive_path_hits":0}}}`, ts, tsWindow),
		// 侦察信号 ×2（40 + 35 = 75 → CRITICAL）
		fmt.Sprintf(`{"record_type":"recon_signal","request_id":"r-it-4","occurred_at":%q,"gateway_node":"gw-it-01","identity_key":"ik-it-1","client_ip":"203.0.113.10","method":"GET","path":"/.git/config","rule_code":"JR-RECON-003","rule_version":"1","signal":"SENSITIVE_PATH_PROBE","risk_score_delta":40,"mode":"OBSERVE","reason":"命中敏感路径","window":"5m","metadata":{"hit_count":3}}`, ts),
		fmt.Sprintf(`{"record_type":"recon_signal","request_id":"r-it-5","occurred_at":%q,"gateway_node":"gw-it-01","identity_key":"ik-it-1","client_ip":"203.0.113.10","method":"GET","path":"/x1","rule_code":"JR-RECON-001","rule_version":"1","signal":"URI_ENUMERATION","risk_score_delta":35,"mode":"OBSERVE","reason":"URI 枚举","window":"5m","metadata":{}}`, ts),
		// 坏行（未知 record_type）→ 解析失败队列
		fmt.Sprintf(`{"record_type":"mystery","occurred_at":%q,"identity_key":"ik-it-1"}`, ts),
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	store := identityevents.NewStore(env.db)
	coll := identityevents.NewCollector(store, env.db.Begin, "identity-events-01",
		logPath, filepath.Join(dir, "identity-events.checkpoint"), "gw-it-01")
	n, err := coll.CollectOnce(ctx)
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 6 {
		t.Fatalf("processed = %d, want 6", n)
	}
	m := coll.Metrics()
	if m["failed_count"].(int64) != 1 {
		t.Errorf("failed_count = %v, want 1", m["failed_count"])
	}

	// client_identity：单行（UPSERT 幂等），request_count=2 次观测 + 快照 1m 窗 30 = 32，
	// identity_type 保持 HUMAN，
	// 派生列 account_id/jwt_subject/api_key_hash，risk 75/CRITICAL
	var id string
	var idType, accountID, jwtSubject, apiKeyHash, riskLevel string
	var reqCount, riskScore int64
	if err := env.db.QueryRow(ctx, `SELECT id::text, identity_type, request_count, account_id, jwt_subject,
api_key_hash, risk_score, risk_level FROM client_identity WHERE identity_key='ik-it-1'`).
		Scan(&id, &idType, &reqCount, &accountID, &jwtSubject, &apiKeyHash, &riskScore, &riskLevel); err != nil {
		t.Fatalf("query client_identity: %v", err)
	}
	if idType != "HUMAN" || reqCount != 32 || accountID != "acc-1" || jwtSubject != "sub-1" || apiKeyHash != "ak-h1" {
		t.Errorf("identity row = type %s req %d acc %s sub %s ak %s", idType, reqCount, accountID, jwtSubject, apiKeyHash)
	}
	if riskScore != 75 || riskLevel != "CRITICAL" {
		t.Errorf("risk = %d/%s, want 75/CRITICAL", riskScore, riskLevel)
	}

	// identity_ip_history：同 IP 两次观测累计 + 快照 1m 窗 30 = 32
	var ipReqCount int64
	if err := env.db.QueryRow(ctx,
		`SELECT request_count FROM identity_ip_history WHERE identity_id=$1 AND ip='203.0.113.10'`, id).Scan(&ipReqCount); err != nil {
		t.Fatalf("query identity_ip_history: %v", err)
	}
	if ipReqCount != 32 {
		t.Errorf("ip history request_count = %d, want 32", ipReqCount)
	}

	// identity_credential：JWT + API_KEY 两行
	var credCount int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM identity_credential WHERE identity_id=$1`, id).Scan(&credCount); err != nil {
		t.Fatalf("query identity_credential: %v", err)
	}
	if credCount != 2 {
		t.Errorf("credentials = %d, want 2", credCount)
	}

	// behavior_statistics：1m 窗口一行
	var statReq int64
	if err := env.db.QueryRow(ctx,
		`SELECT request_count FROM behavior_statistics WHERE identity_id=$1 AND window_type='1m'`, id).Scan(&statReq); err != nil {
		t.Fatalf("query behavior_statistics: %v", err)
	}
	if statReq != 30 {
		t.Errorf("behavior stat request_count = %d, want 30", statReq)
	}

	// identity_behavior_events：2 条信号
	var evCount int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM identity_behavior_events WHERE identity_id=$1`, id).Scan(&evCount); err != nil {
		t.Fatalf("query identity_behavior_events: %v", err)
	}
	if evCount != 2 {
		t.Errorf("behavior events = %d, want 2", evCount)
	}

	// 解析失败队列：坏行入 event_parse_failures
	var failCount int
	if err := env.db.QueryRow(ctx,
		`SELECT count(*) FROM event_parse_failures WHERE collector_id='identity-events-01'`).Scan(&failCount); err != nil {
		t.Fatalf("query event_parse_failures: %v", err)
	}
	if failCount != 1 {
		t.Errorf("parse failures = %d, want 1", failCount)
	}

	// ---- API 侧可读 ----
	cookies, _ := env.s5Login(t, "idc_sec", "SECURITY_ADMIN")

	// 列表（keyword 前缀命中）
	resp := env.get(t, "/api/v1/security/identities?keyword=ik-it", cookies)
	var page apiRespPage5
	func() {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list identities status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
		}
		readJSON(t, resp, &page)
	}()
	if page.Data.Total != 1 || len(page.Data.Items) != 1 {
		t.Fatalf("list by keyword total = %d, want 1", page.Data.Total)
	}
	item := page.Data.Items[0]
	if item["identity_key"] != "ik-it-1" || item["risk_level"] != "CRITICAL" {
		t.Errorf("list item = %+v", item)
	}
	if s5Num(t, item, "ip_count") != 1 || s5Num(t, item, "request_count") != 32 {
		t.Errorf("list item ip_count/request_count = %v/%v", item["ip_count"], item["request_count"])
	}

	// 详情：ip_history 1 行、credentials 2 行、recent_events 2 条
	resp = env.get(t, "/api/v1/security/identities/"+id, cookies)
	result := s5OK(t, resp, "get identity detail")
	if ipHistory, _ := result.Data["ip_history"].([]interface{}); len(ipHistory) != 1 {
		t.Errorf("detail ip_history len = %d, want 1", len(ipHistory))
	}
	if creds, _ := result.Data["credentials"].([]interface{}); len(creds) != 2 {
		t.Errorf("detail credentials len = %d, want 2", len(creds))
	}
	if events, _ := result.Data["recent_events"].([]interface{}); len(events) != 2 {
		t.Errorf("detail recent_events len = %d, want 2", len(events))
	}

	// 信号事件分页（signal 筛选）
	resp = env.get(t, "/api/v1/security/identities/"+id+"/events?signal=URI_ENUMERATION", cookies)
	func() {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list identity events status = %d", resp.StatusCode)
		}
		var evPage apiRespPage5
		readJSON(t, resp, &evPage)
		if evPage.Data.Total != 1 {
			t.Errorf("events by signal total = %d, want 1", evPage.Data.Total)
		}
	}()

	// 行为序列（默认最近 24h）
	resp = env.get(t, "/api/v1/security/identities/"+id+"/behavior", cookies)
	func() {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list identity behavior status = %d", resp.StatusCode)
		}
		var bPage apiRespPage5
		readJSON(t, resp, &bPage)
		if bPage.Data.Total != 1 {
			t.Errorf("behavior stats total = %d, want 1", bPage.Data.Total)
		}
	}()

	// IP 筛选
	resp = env.get(t, "/api/v1/security/identities?ip=203.0.113.10", cookies)
	func() {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list identities by ip status = %d", resp.StatusCode)
		}
		var ipPage apiRespPage5
		readJSON(t, resp, &ipPage)
		if ipPage.Data.Total != 1 {
			t.Errorf("list by ip total = %d, want 1", ipPage.Data.Total)
		}
	}()
}
