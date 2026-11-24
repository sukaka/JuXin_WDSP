// stage_attack_session_test.go Attack Session 聚合 + Business Security
// 集成测试（WDSP AI 自动化渗透防护增强 阶段4；真实 PG/Valkey，未设置环境或 -short 即 skip）。
// 覆盖：迁移 000103/000104/000105 种子；六类事件跨源聚合验收链（滑动窗单会话、
// 双落去重、request_id 首选关联、NAT 歧义跳过）；attack-sessions 列表/详情 API
// （筛选/校验/三角色只读）；api_assets business_type 全链路（PATCH/列表筛选/校验）；
// Business 滥用三判定器（BIZ-LOGIN/BIZ-EXPORT/BIZ-OBJENUM 产出、冷却幂等、
// 事件汇入会话驱动 attack_stage=DATA_ACCESS）。
package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// ---------- 种子辅助 ----------

// as4Identity 直插 client_identity 并返回身份 UUID。
func as4Identity(t *testing.T, env *testEnv, identityKey string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	now := time.Now().UTC()
	if err := env.db.QueryRow(context.Background(), `
INSERT INTO client_identity (identity_key, identity_type, first_seen_at, last_seen_at)
VALUES ($1, 'HUMAN', $2, $2) RETURNING id`, identityKey, now).Scan(&id); err != nil {
		t.Fatalf("insert client_identity %s: %v", identityKey, err)
	}
	return id
}

// as4IPHistory 直插 identity_ip_history（IP 反查归属依据）。
func as4IPHistory(t *testing.T, env *testEnv, identityID uuid.UUID, ip string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := env.db.Exec(context.Background(), `
INSERT INTO identity_ip_history (identity_id, ip, first_seen_at, last_seen_at, request_count)
VALUES ($1, $2, $3, $3, 1)`, identityID, ip, now); err != nil {
		t.Fatalf("insert identity_ip_history: %v", err)
	}
}

// as4BehaviorEvent 直插 identity_behavior_events（主锚 identity_id 直挂）。
func as4BehaviorEvent(t *testing.T, env *testEnv, identityID uuid.UUID, identityKey, requestID, ruleCode string,
	delta int, occurredAt time.Time) {
	t.Helper()
	if _, err := env.db.Exec(context.Background(), `
INSERT INTO identity_behavior_events (identity_id, identity_key, occurred_at, event_kind,
  rule_code, rule_version, signal, risk_score_delta, mode, request_id)
VALUES ($1, $2, $3, 'RECON_SIGNAL', $4, '1.0.0', 'TEST_SIGNAL', $5, 'OBSERVE', $6)`,
		identityID, identityKey, occurredAt, ruleCode, delta, requestID); err != nil {
		t.Fatalf("insert identity_behavior_events: %v", err)
	}
}

// as4SecurityEvent 直插 security_events（默认分区兜底任意 occurred_at）。
func as4SecurityEvent(t *testing.T, env *testEnv, requestID, attackType, clientIP string,
	anomaly int, occurredAt time.Time) {
	t.Helper()
	if _, err := env.db.Exec(context.Background(), `
INSERT INTO security_events (request_id, occurred_at, client_ip, attack_type, anomaly_score, request_method, request_path)
VALUES ($1, $2, $3::inet, $4, $5, 'GET', '/as4')`,
		requestID, occurredAt, clientIP, attackType, anomaly); err != nil {
		t.Fatalf("insert security_events: %v", err)
	}
}

// as4RuntimeEvent 直插 api_runtime_events（detailsJSON 为 NULL 时落 '[]'）。
func as4RuntimeEvent(t *testing.T, env *testEnv, requestID, endpointKey, clientIP, fingerprint, rawPath string,
	riskScore int, detailsJSON string, occurredAt time.Time) {
	t.Helper()
	details := "[]"
	if detailsJSON != "" {
		details = detailsJSON
	}
	if _, err := env.db.Exec(context.Background(), `
INSERT INTO api_runtime_events (request_id, endpoint_key, risk_score, details_json, occurred_at,
  client_ip, identity_fingerprint, raw_path, response_status)
VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, 200)`,
		requestID, endpointKey, riskScore, details, occurredAt, clientIP, fingerprint, rawPath); err != nil {
		t.Fatalf("insert api_runtime_events: %v", err)
	}
}

// as4AccessControlEvent 直插 access_control_events（details 携带 identity_key/score）。
func as4AccessControlEvent(t *testing.T, env *testEnv, requestID, clientIP, details string, occurredAt time.Time) {
	t.Helper()
	if _, err := env.db.Exec(context.Background(), `
INSERT INTO access_control_events (request_id, occurred_at, client_ip, event_type, action, details)
VALUES ($1, $2, $3::inet, 'RISK_POLICY_BLOCK', 'BLOCK', $4::jsonb)`,
		requestID, occurredAt, clientIP, details); err != nil {
		t.Fatalf("insert access_control_events: %v", err)
	}
}

// as4SessionRow 按身份查会话聚合字段。
func as4SessionRow(t *testing.T, env *testEnv, identityID uuid.UUID) (
	id string, eventCount, requestCount, riskScore int64, riskLevel, stage, status string) {
	t.Helper()
	err := env.db.QueryRow(context.Background(), `
SELECT id::text, event_count, request_count, risk_score, risk_level, attack_stage, status
FROM attack_session WHERE identity_id = $1`, identityID).
		Scan(&id, &eventCount, &requestCount, &riskScore, &riskLevel, &stage, &status)
	if err != nil {
		t.Fatalf("query attack_session for identity %s: %v", identityID, err)
	}
	return
}

func as4Count(t *testing.T, env *testEnv, query string, args ...interface{}) int {
	t.Helper()
	var n int
	if err := env.db.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	return n
}

// ---------- 迁移种子 ----------

// TestAttackSessionMigrations 迁移后两表/权限种子/三角色授权/business_type 列存在。
func TestAttackSessionMigrations(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	for _, table := range []string{"attack_session", "attack_session_event"} {
		var n int
		if err := env.db.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}

	// 权限种子（module=security）
	var module string
	if err := env.db.QueryRow(ctx,
		`SELECT module FROM permissions WHERE code='attack_sessions.read'`).Scan(&module); err != nil {
		t.Fatalf("permission attack_sessions.read missing: %v", err)
	}
	if module != "security" {
		t.Errorf("permission module = %s, want security", module)
	}

	// 000122 撤销审计管理员权限；000232 撤销系统管理员权限，仅运维管理员（SECURITY_ADMIN）持有
	if n := as4Count(t, env, `SELECT count(*) FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
WHERE p.code='attack_sessions.read' AND r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN','AUDIT_ADMIN')`); n != 1 {
		t.Errorf("attack_sessions.read role grants = %d, want 1 (SECURITY_ADMIN only)", n)
	}

	// api_assets.business_type 列（默认 OTHER，枚举应用层校验不落 CHECK）
	var colDefault *string
	if err := env.db.QueryRow(ctx, `SELECT column_default FROM information_schema.columns
WHERE table_name='api_assets' AND column_name='business_type'`).Scan(&colDefault); err != nil {
		t.Fatalf("api_assets.business_type column missing: %v", err)
	}
	if colDefault == nil || *colDefault == "" {
		t.Errorf("business_type default empty, want 'OTHER'")
	}
}

// ---------- 验收链 ----------

// TestAttackSessionAcceptanceChain 阶段4 验收链：六类事件跨源聚合为单会话（滑动窗）、
// WDSP 双落去重、request_id 首选关联、NAT 歧义跳过；API 列表/详情/筛选/权限。
func TestAttackSessionAcceptanceChain(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	rid := s5Rand()
	ik1 := "ik-chain-1-" + rid
	ik2 := "ik-chain-2-" + rid

	// 场景一：ik1 完整攻击链（t0 起 10min 内九条挂载 + 一条双落去重）
	id1 := as4Identity(t, env, ik1)
	as4IPHistory(t, env, id1, "203.0.113.66") // 唯一归属
	t0 := time.Now().UTC().Add(-20 * time.Minute)
	as4BehaviorEvent(t, env, id1, ik1, "r-chain-1-"+rid, "RECON-PATH-001", 15, t0)
	as4RuntimeEvent(t, env, "r-chain-2-"+rid, "", "203.0.113.66", "", "", 10,
		`[{"detector":"lifecycle","rule_id":"lifecycle.new_endpoint"}]`, t0.Add(1*time.Minute))
	as4BehaviorEvent(t, env, id1, ik1, "r-chain-3-"+rid, "AUTH-FAIL-001", 15, t0.Add(2*time.Minute))
	as4BehaviorEvent(t, env, id1, ik1, "r-chain-4-"+rid, "AUTH-FAIL-001", 15, t0.Add(3*time.Minute))
	as4BehaviorEvent(t, env, id1, ik1, "r-chain-5-"+rid, "AUTH-FAIL-001", 15, t0.Add(4*time.Minute))
	as4RuntimeEvent(t, env, "r-chain-6-"+rid, "", "203.0.113.66", "", "", 0, "", t0.Add(5*time.Minute))
	as4RuntimeEvent(t, env, "r-chain-7-"+rid, "", "203.0.113.66", "", "", 0, "", t0.Add(6*time.Minute))
	as4AccessControlEvent(t, env, "r-chain-9-"+rid, "203.0.113.66",
		fmt.Sprintf(`{"identity_key":%q,"score":5}`, ik1), t0.Add(7*time.Minute))
	as4SecurityEvent(t, env, "r-chain-8-"+rid, "SQLI", "203.0.113.66", 50, t0.Add(8*time.Minute))
	// WDSP 双落：同 request_id 的 api_runtime waf 明细（应被去重，不挂载）
	as4RuntimeEvent(t, env, "r-chain-8-"+rid, "", "203.0.113.66", "", "", 50,
		`[{"detector":"waf","rule_id":"waf.coraza_sqli"}]`, t0.Add(9*time.Minute))

	// 场景二：request_id 首选关联（client_ip 不在 IP 历史，经同请求行为信号挂上；
	// 跨源同 request_id 不做事件去重，request_count 去重为 1）
	id2 := as4Identity(t, env, ik2)
	t0b := t0
	as4BehaviorEvent(t, env, id2, ik2, "r-req-9-"+rid, "RECON-URI-001", 15, t0b)
	as4SecurityEvent(t, env, "r-req-9-"+rid, "XSS", "198.51.100.99", 30, t0b.Add(time.Minute))

	// 场景三：NAT 歧义（同 IP 两身份，security 事件不强挂，跳过不建会话）
	nat1 := as4Identity(t, env, "ik-nat-1-"+rid)
	nat2 := as4Identity(t, env, "ik-nat-2-"+rid)
	as4IPHistory(t, env, nat1, "192.0.2.50")
	as4IPHistory(t, env, nat2, "192.0.2.50")
	as4SecurityEvent(t, env, "r-nat-x-"+rid, "RCE", "192.0.2.50", 90, t0.Add(2*time.Minute))

	// 同步驱动一轮聚合
	stats, err := env.app.AttackSessionAggregator().SweepOnce(ctx)
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if stats.SourceErrors != 0 {
		t.Fatalf("SourceErrors = %d, want 0", stats.SourceErrors)
	}
	if stats.Deduped != 1 {
		t.Errorf("Deduped = %d, want 1（WDSP 双落去重）", stats.Deduped)
	}
	if stats.SkippedUnattributed != 1 {
		t.Errorf("SkippedUnattributed = %d, want 1（NAT 歧义跳过）", stats.SkippedUnattributed)
	}
	if stats.BizEventsEmitted != 0 {
		t.Errorf("BizEventsEmitted = %d, want 0（无业务滥用种子）", stats.BizEventsEmitted)
	}

	// 会话一：event_count=9（双落去重 1），risk=15+10+45+5+50=125→clamp 100/CRITICAL，stage=EXPLOIT
	sessA, evCount, reqCount, score, level, stage, status := as4SessionRow(t, env, id1)
	if evCount != 9 || reqCount != 9 {
		t.Errorf("session A events/requests = %d/%d, want 9/9", evCount, reqCount)
	}
	if score != 100 || level != "CRITICAL" {
		t.Errorf("session A risk = %d/%s, want 100/CRITICAL", score, level)
	}
	if stage != "EXPLOIT" || status != "OPEN" {
		t.Errorf("session A stage/status = %s/%s, want EXPLOIT/OPEN", stage, status)
	}

	// 会话二：跨源同 request_id 都计入（event_count=2），request_count=1，risk=45/HIGH
	sessB, evCount2, reqCount2, score2, level2, stage2, _ := as4SessionRow(t, env, id2)
	if evCount2 != 2 || reqCount2 != 1 {
		t.Errorf("session B events/requests = %d/%d, want 2/1（跨源同请求不去重）", evCount2, reqCount2)
	}
	if score2 != 45 || level2 != "HIGH" || stage2 != "EXPLOIT" {
		t.Errorf("session B = %d/%s/%s, want 45/HIGH/EXPLOIT", score2, level2, stage2)
	}

	// NAT：两个身份均无会话
	if n := as4Count(t, env, `SELECT count(*) FROM attack_session WHERE identity_id IN ($1,$2)`, nat1, nat2); n != 0 {
		t.Errorf("NAT sessions = %d, want 0（歧义不强挂）", n)
	}
	// 全库仅两个会话
	if n := as4Count(t, env, `SELECT count(*) FROM attack_session`); n != 2 {
		t.Errorf("total sessions = %d, want 2", n)
	}

	// ---------- API ----------
	cookies, _ := env.s5Login(t, "as4_sec", "SECURITY_ADMIN")

	// 列表：total=2
	resp := env.get(t, "/api/v1/security/attack-sessions", cookies)
	var page apiRespPage5
	func() {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list attack-sessions status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
		}
		readJSON(t, resp, &page)
	}()
	if page.Data.Total != 2 || len(page.Data.Items) != 2 {
		t.Fatalf("list total = %d, want 2", page.Data.Total)
	}
	itemA := map[string]interface{}{}
	for _, it := range page.Data.Items {
		if it["identity_key"] == ik1 {
			itemA = it
		}
		if it["session_key"] == nil || it["start_time"] == nil || it["end_time"] == nil ||
			it["created_at"] == nil || it["updated_at"] == nil {
			t.Errorf("list item missing fields: %+v", it)
		}
	}
	if len(itemA) == 0 {
		t.Fatalf("list missing session for %s", ik1)
	}
	if itemA["attack_stage"] != "EXPLOIT" || itemA["risk_level"] != "CRITICAL" || itemA["status"] != "OPEN" {
		t.Errorf("list item A = %+v", itemA)
	}
	if s5Num(t, itemA, "event_count") != 9 || s5Num(t, itemA, "request_count") != 9 ||
		s5Num(t, itemA, "risk_score") != 100 {
		t.Errorf("list item A counts = %v/%v/%v", itemA["event_count"], itemA["request_count"], itemA["risk_score"])
	}

	// 筛选
	for path, want := range map[string]int64{
		"?stage=EXPLOIT":       2,
		"?stage=RECON":         0,
		"?risk_level=CRITICAL": 1,
		"?risk_level=HIGH":     1,
		"?status=OPEN":         2,
		"?status=CLOSED":       0,
		"?from=" + time.Now().UTC().Add(-time.Hour).Format(time.RFC3339): 2,
		"?from=" + time.Now().UTC().Add(time.Hour).Format(time.RFC3339):  0,
	} {
		resp = env.get(t, "/api/v1/security/attack-sessions"+path, cookies)
		func() {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("list %s status = %d", path, resp.StatusCode)
				return
			}
			var p apiRespPage5
			readJSON(t, resp, &p)
			if p.Data.Total != want {
				t.Errorf("list %s total = %d, want %d", path, p.Data.Total, want)
			}
		}()
	}
	// 非法筛选值 → 400
	for _, path := range []string{"?stage=NOPE", "?risk_level=NOPE", "?status=NOPE", "?from=not-a-time"} {
		resp = env.get(t, "/api/v1/security/attack-sessions"+path, cookies)
		s5Expect(t, resp, http.StatusBadRequest, "list attack-sessions "+path)
	}

	// 详情：事件时间序 == event_count；双落去重行不挂载
	resp = env.get(t, "/api/v1/security/attack-sessions/"+sessA, cookies)
	result := s5OK(t, resp, "get attack session A")
	events, _ := result.Data["events"].([]interface{})
	if len(events) != 9 {
		t.Fatalf("session A events = %d, want 9", len(events))
	}
	prev := ""
	secLinked, runtimeDupLinked := false, false
	for i, e := range events {
		m, _ := e.(map[string]interface{})
		at, _ := m["occurred_at"].(string)
		if i > 0 && at < prev {
			t.Errorf("events not ordered by occurred_at: %s < %s", at, prev)
		}
		prev = at
		if m["source_table"] == "security_events" && m["request_id"] == "r-chain-8-"+rid {
			secLinked = true
		}
		if m["source_table"] == "api_runtime_events" && m["request_id"] == "r-chain-8-"+rid {
			runtimeDupLinked = true
		}
	}
	if !secLinked || runtimeDupLinked {
		t.Errorf("dedup link state: security linked=%v, runtime dup linked=%v, want true/false", secLinked, runtimeDupLinked)
	}

	// 详情 B：跨源同 request_id 两条都挂载
	resp = env.get(t, "/api/v1/security/attack-sessions/"+sessB, cookies)
	result = s5OK(t, resp, "get attack session B")
	eventsB, _ := result.Data["events"].([]interface{})
	if len(eventsB) != 2 {
		t.Fatalf("session B events = %d, want 2", len(eventsB))
	}
	srcs := map[string]bool{}
	for _, e := range eventsB {
		m, _ := e.(map[string]interface{})
		srcs[m["source_table"].(string)] = true
	}
	if !srcs["identity_behavior_events"] || !srcs["security_events"] {
		t.Errorf("session B event sources = %+v, want behavior+security", srcs)
	}

	// 404 / 400
	resp = env.get(t, "/api/v1/security/attack-sessions/00000000-0000-0000-0000-000000000000", cookies)
	s5Expect(t, resp, http.StatusNotFound, "get missing attack session")
	resp = env.get(t, "/api/v1/security/attack-sessions/not-a-uuid", cookies)
	s5Expect(t, resp, http.StatusBadRequest, "get attack session bad uuid")

	// 000122 与 000232 收敛后：SYSTEM_ADMIN 与 AUDIT_ADMIN 均无 attack_sessions.read → 403
	sysCookies, _ := env.s5Login(t, "as4_sys", "SYSTEM_ADMIN")
	resp = env.get(t, "/api/v1/security/attack-sessions", sysCookies)
	s5Expect(t, resp, http.StatusForbidden, "SYSTEM_ADMIN list attack-sessions")
	auditCookies, _ := env.s5Login(t, "as4_audit", "AUDIT_ADMIN")
	resp = env.get(t, "/api/v1/security/attack-sessions", auditCookies)
	s5Expect(t, resp, http.StatusForbidden, "AUDIT_ADMIN list attack-sessions")
	resp = env.get(t, "/api/v1/security/attack-sessions/"+sessA, auditCookies)
	s5Expect(t, resp, http.StatusForbidden, "AUDIT_ADMIN get attack session")
}

// ---------- business_type 全链路 ----------

// TestBusinessTypeAPI api_assets.business_type：PATCH 枚举校验与落库、列表筛选带出。
// （api-security 路由按 WDSP 产品形态门控，须用 setupStage8Env。）
func TestBusinessTypeAPI(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	cookies, csrf := env.s5Login(t, "bt_sec", "SECURITY_ADMIN")

	ep, err := apiassets.NewStore(env.db).UpsertDiscovery(ctx, apiassets.DiscoveryInput{
		Method: "GET", PathTemplate: "/bt-" + rid + "/export/{id}", Confidence: 0.9, IsAPI: true,
	})
	if err != nil {
		t.Fatalf("UpsertDiscovery: %v", err)
	}

	// PATCH 非法枚举 → 400
	resp := env.do(t, http.MethodPatch, "/api/v1/api-security/endpoints/"+ep.ID.String(),
		`{"business_type":"NOPE"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "patch endpoint with bad business_type")

	// PATCH EXPORT → 200，响应 asset.business_type=EXPORT
	resp = env.do(t, http.MethodPatch, "/api/v1/api-security/endpoints/"+ep.ID.String(),
		`{"purpose":"数据导出","business_type":"EXPORT"}`, cookies, csrf)
	result := s5OK(t, resp, "patch endpoint business_type EXPORT")
	endpoint := s5Obj(t, result, "endpoint")
	asset, _ := endpoint["asset"].(map[string]interface{})
	if asset["business_type"] != "EXPORT" {
		t.Errorf("patch response asset.business_type = %v, want EXPORT", asset["business_type"])
	}

	// 列表筛选 business_type=EXPORT 命中且带出字段
	resp = env.get(t, "/api/v1/api-security/endpoints?business_type=EXPORT", cookies)
	var page apiRespPage5
	func() {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list endpoints by business_type status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
		}
		readJSON(t, resp, &page)
	}()
	if page.Data.Total != 1 || len(page.Data.Items) != 1 {
		t.Fatalf("list by business_type=EXPORT total = %d, want 1", page.Data.Total)
	}
	if page.Data.Items[0]["business_type"] != "EXPORT" {
		t.Errorf("list item business_type = %v, want EXPORT", page.Data.Items[0]["business_type"])
	}
	// 列表非法筛选 → 400
	resp = env.get(t, "/api/v1/api-security/endpoints?business_type=NOPE", cookies)
	s5Expect(t, resp, http.StatusBadRequest, "list endpoints with bad business_type")

	// 详情 asset.business_type=EXPORT
	resp = env.get(t, "/api/v1/api-security/endpoints/"+ep.ID.String(), cookies)
	result = s5OK(t, resp, "get endpoint detail")
	detail := s5Obj(t, result, "endpoint")
	dasset, _ := detail["asset"].(map[string]interface{})
	if dasset["business_type"] != "EXPORT" {
		t.Errorf("detail asset.business_type = %v, want EXPORT", dasset["business_type"])
	}
}

// ---------- Business 滥用检测 ----------

// TestBusinessAbuseDetectors 三判定器产出（OBSERVE/BUSINESS_ABUSE/rule_version=1.0.0/delta=15）、
// 冷却重跑不重复、产出事件汇入会话驱动 attack_stage=DATA_ACCESS。
// （BIZ-EXPORT 依赖 api_assets.business_type，属 WDSP 形态，用 setupStage8Env。）
func TestBusinessAbuseDetectors(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	ik := "ik-biz-1-" + rid

	id := as4Identity(t, env, ik)
	as4IPHistory(t, env, id, "203.0.113.70") // 唯一归属（Export/ObjectEnum 经 IP 反查）

	// BIZ-LOGIN-001：5 个不同凭据 + 30m 窗认证失败累计 12（阈值 5 凭据/10 失败）
	now := time.Now().UTC()
	for i := 1; i <= 5; i++ {
		if _, err := env.db.Exec(ctx, `
INSERT INTO identity_credential (identity_id, credential_type, credential_hash, first_seen_at, last_seen_at)
VALUES ($1, 'JWT', $2, $3, $3)`, id, fmt.Sprintf("bizh-%s-%d", rid, i), now); err != nil {
			t.Fatalf("insert identity_credential: %v", err)
		}
	}
	if _, err := env.db.Exec(ctx, `
INSERT INTO behavior_statistics (identity_id, window_type, window_start, request_count, auth_fail_count)
VALUES ($1, '30m', $2, 40, 12)`, id, now.Add(-time.Hour)); err != nil {
		t.Fatalf("insert behavior_statistics: %v", err)
	}

	// BIZ-EXPORT-001：EXPORT 端点 10min 滑窗 20 次（阈值 20）
	assets := apiassets.NewStore(env.db)
	epExp, err := assets.UpsertDiscovery(ctx, apiassets.DiscoveryInput{
		Method: "POST", PathTemplate: "/biz-" + rid + "/export/{id}", Confidence: 0.9, IsAPI: true,
	})
	if err != nil {
		t.Fatalf("UpsertDiscovery export: %v", err)
	}
	if _, err := assets.UpsertAsset(ctx, epExp.ID, apiassets.AssetProfile{Purpose: "数据导出", Exposure: "PUBLIC", BusinessType: "EXPORT"}); err != nil {
		t.Fatalf("UpsertAsset: %v", err)
	}
	for i := 0; i < 20; i++ {
		as4RuntimeEvent(t, env, fmt.Sprintf("biz-exp-%s-%d", rid, i), epExp.EndpointKey,
			"203.0.113.70", "fp-biz-1", "/biz-"+rid+"/export/1", 0, "", now.Add(-9*time.Minute).Add(time.Duration(i)*20*time.Second))
	}

	// BIZ-OBJENUM-001：同路径模板 10 个不同数字对象 ID（阈值 10；2xx 成功）
	epObj, err := assets.UpsertDiscovery(ctx, apiassets.DiscoveryInput{
		Method: "GET", PathTemplate: "/biz-" + rid + "/users/{id}", Confidence: 0.9, IsAPI: true,
	})
	if err != nil {
		t.Fatalf("UpsertDiscovery users: %v", err)
	}
	for i := 0; i < 10; i++ {
		as4RuntimeEvent(t, env, fmt.Sprintf("biz-obj-%s-%d", rid, i), epObj.EndpointKey,
			"203.0.113.70", "fp-biz-1", fmt.Sprintf("/biz-%s/users/%d", rid, 1001+i), 0, "", now.Add(-8*time.Minute).Add(time.Duration(i)*20*time.Second))
	}

	// 第一轮：30 条运行时事件聚合成会话（IP 反查归属，stage UNKNOWN）；DetectOnce 产出 3 条 BIZ 事件
	stats, err := env.app.AttackSessionAggregator().SweepOnce(ctx)
	if err != nil {
		t.Fatalf("SweepOnce #1: %v", err)
	}
	if stats.SourceErrors != 0 {
		t.Fatalf("SourceErrors = %d, want 0", stats.SourceErrors)
	}
	if stats.BizEventsEmitted != 3 {
		t.Fatalf("BizEventsEmitted = %d, want 3", stats.BizEventsEmitted)
	}

	// 三条 BIZ 行为事件：OBSERVE / BUSINESS_ABUSE / rule_version=1.0.0 / delta=15
	if n := as4Count(t, env, `SELECT count(*) FROM identity_behavior_events
WHERE identity_id=$1 AND event_kind='BUSINESS_ABUSE' AND mode='OBSERVE'
  AND rule_version='1.0.0' AND risk_score_delta=15
  AND rule_code IN ('BIZ-LOGIN-001','BIZ-EXPORT-001','BIZ-OBJENUM-001')`, id); n != 3 {
		t.Errorf("business abuse events = %d, want 3", n)
	}
	// 身份风险分重算（3×15=45/HIGH）
	var idScore int
	var idLevel string
	if err := env.db.QueryRow(ctx,
		`SELECT risk_score, risk_level FROM client_identity WHERE id=$1`, id).Scan(&idScore, &idLevel); err != nil {
		t.Fatalf("query client_identity risk: %v", err)
	}
	if idScore != 45 || idLevel != "HIGH" {
		t.Errorf("identity risk = %d/%s, want 45/HIGH", idScore, idLevel)
	}

	// 第二轮：BIZ 事件汇入会话（主锚 identity_id 直挂），stage 最高 DATA_ACCESS（BIZ-EXPORT）
	stats, err = env.app.AttackSessionAggregator().SweepOnce(ctx)
	if err != nil {
		t.Fatalf("SweepOnce #2: %v", err)
	}
	_, evCount, _, score, level, stage, status := as4SessionRow(t, env, id)
	if evCount != 33 { // 30 运行时事件 + 3 BIZ 事件
		t.Errorf("session events = %d, want 33", evCount)
	}
	if stage != "DATA_ACCESS" {
		t.Errorf("session stage = %s, want DATA_ACCESS（BIZ-EXPORT 最高）", stage)
	}
	if score != 45 || level != "HIGH" || status != "OPEN" {
		t.Errorf("session risk/status = %d/%s/%s, want 45/HIGH/OPEN", score, level, status)
	}

	// 冷却：第三轮重跑不重复产出（30min 冷却窗），事件总数不变
	stats, err = env.app.AttackSessionAggregator().SweepOnce(ctx)
	if err != nil {
		t.Fatalf("SweepOnce #3: %v", err)
	}
	if stats.BizEventsEmitted != 0 {
		t.Errorf("BizEventsEmitted #3 = %d, want 0（冷却去重）", stats.BizEventsEmitted)
	}
	if n := as4Count(t, env, `SELECT count(*) FROM identity_behavior_events
WHERE identity_id=$1 AND event_kind='BUSINESS_ABUSE'`, id); n != 3 {
		t.Errorf("business abuse events after cooldown = %d, want 3", n)
	}
	// 会话字段不被重放污染
	_, evCount3, _, score3, _, _, _ := as4SessionRow(t, env, id)
	if evCount3 != 33 || score3 != 45 {
		t.Errorf("session after replay = events %d score %d, want 33/45", evCount3, score3)
	}
}

// ---------- 自动化攻击标注（阶段4 补充，迁移 000106）----------

// as4BehaviorEventSignal 直插行为事件（显式 signal——自动化标注指示信号来源）。
func as4BehaviorEventSignal(t *testing.T, env *testEnv, identityID uuid.UUID, identityKey, requestID, ruleCode, signal string,
	delta int, occurredAt time.Time) {
	t.Helper()
	if _, err := env.db.Exec(context.Background(), `
INSERT INTO identity_behavior_events (identity_id, identity_key, occurred_at, event_kind,
  rule_code, rule_version, signal, risk_score_delta, mode, request_id)
VALUES ($1, $2, $3, 'RECON_SIGNAL', $4, '1.0.0', $5, $6, 'OBSERVE', $7)`,
		identityID, identityKey, occurredAt, ruleCode, signal, delta, requestID); err != nil {
		t.Fatalf("insert identity_behavior_events: %v", err)
	}
}

// TestAttackSessionAutomationTag 疑似自动化攻击派生标注：有效阶段≥3 且命中指示信号
// （无头/枚举/低慢类）→ automation_suspected=true 且 basis 可解释；同链无指示信号 → 不标注。
func TestAttackSessionAutomationTag(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	rid := s5Rand()
	ikA, ikB := "ik-auto-a-"+rid, "ik-auto-b-"+rid
	t0 := time.Now().UTC().Add(-10 * time.Minute)

	// A：RECON（指示信号 SENSITIVE_PATH_PROBE）+ AUTH_PROBE + EXPLOIT 三阶段 → 标注
	idA := as4Identity(t, env, ikA)
	as4IPHistory(t, env, idA, "203.0.113.88")
	as4BehaviorEventSignal(t, env, idA, ikA, "r-auto-a1-"+rid, "RECON-PATH-001", "SENSITIVE_PATH_PROBE", 15, t0)
	as4RuntimeEvent(t, env, "r-auto-a2-"+rid, "", "203.0.113.88", "", "", 10,
		`[{"detector":"authentication","rule_id":"auth.unauthenticated_api"}]`, t0.Add(time.Minute))
	as4SecurityEvent(t, env, "r-auto-a3-"+rid, "SQLI", "203.0.113.88", 50, t0.Add(2*time.Minute))

	// B：同构三阶段但 signal 非指示值 → 不标注
	idB := as4Identity(t, env, ikB)
	as4IPHistory(t, env, idB, "203.0.113.89")
	as4BehaviorEventSignal(t, env, idB, ikB, "r-auto-b1-"+rid, "RECON-PATH-001", "TEST_SIGNAL", 15, t0)
	as4RuntimeEvent(t, env, "r-auto-b2-"+rid, "", "203.0.113.89", "", "", 10,
		`[{"detector":"authentication","rule_id":"auth.unauthenticated_api"}]`, t0.Add(time.Minute))
	as4SecurityEvent(t, env, "r-auto-b3-"+rid, "SQLI", "203.0.113.89", 50, t0.Add(2*time.Minute))

	if _, err := env.app.AttackSessionAggregator().SweepOnce(ctx); err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}

	var suspectedA, suspectedB bool
	var basisA string
	if err := env.db.QueryRow(ctx,
		`SELECT automation_suspected, automation_basis FROM attack_session WHERE identity_id=$1`, idA).
		Scan(&suspectedA, &basisA); err != nil {
		t.Fatalf("query session A automation: %v", err)
	}
	if !suspectedA {
		t.Errorf("session A must be flagged (3 stages + indicator), basis=%q", basisA)
	}
	if !strings.Contains(basisA, "indicator=SENSITIVE_PATH_PROBE") ||
		!strings.Contains(basisA, "RECON") || !strings.Contains(basisA, "EXPLOIT") {
		t.Errorf("session A basis not explainable: %q", basisA)
	}
	if err := env.db.QueryRow(ctx,
		`SELECT automation_suspected FROM attack_session WHERE identity_id=$1`, idB).
		Scan(&suspectedB); err != nil {
		t.Fatalf("query session B automation: %v", err)
	}
	if suspectedB {
		t.Errorf("session B without indicator signal must not be flagged")
	}

	// API 列表带出标注字段
	cookies, _ := env.s5Login(t, "as4_sec", "SECURITY_ADMIN")
	resp := env.get(t, "/api/v1/security/attack-sessions", cookies)
	var page apiRespPage5
	func() {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
		}
		readJSON(t, resp, &page)
	}()
	var itemA, itemB map[string]interface{}
	for _, it := range page.Data.Items {
		if it["identity_key"] == ikA {
			itemA = it
		}
		if it["identity_key"] == ikB {
			itemB = it
		}
	}
	if itemA["automation_suspected"] != true {
		t.Errorf("list item A automation_suspected = %v, want true", itemA["automation_suspected"])
	}
	if basis, _ := itemA["automation_basis"].(string); !strings.Contains(basis, "indicator=") {
		t.Errorf("list item A automation_basis = %q", basis)
	}
	if itemB["automation_suspected"] != false {
		t.Errorf("list item B automation_suspected = %v, want false", itemB["automation_suspected"])
	}
}
