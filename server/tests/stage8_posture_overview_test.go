// stage8_posture_overview_test.go W9-P101 API 态势补齐（任务书 §6）集成测试。
//
// 覆盖：
//   - GET /api/v1/api-security/posture/overview 顶部 12 项核心指标逐字段造数断言
//     （访问量/防护量/资产总数/新增/Shadow/Zombie/Deprecated/涉敏/高风险/无认证/待确认模型/Schema偏离）；
//   - GET /api/v1/api-security/posture/trends?days=N 六条按天曲线聚合、UTC 日界、补零连续点列、
//     days 缺省 7 与 1-30 边界、非法值 400；
//   - 权限：复用 api_runtime.read（AUDIT_ADMIN 000100 后 403、无权限角色 403、未认证 401）；
//   - 既有 GET /posture 契约不受影响（由 TestStage8RuntimeRisk 覆盖，本文件不重复）。
//
// 运行方式与纪律同 stage8_api_security_test.go（真实 PostgreSQL/Valkey，无口令 t.Skip）。
package tests

import (
	"net/http"
	"testing"
	"time"
)

// s8PosturePoints 解析 trends 响应为 日期→点 映射（断言按日期取点，不依赖数组下标）。
func s8PosturePoints(t *testing.T, result apiResp) map[string]map[string]interface{} {
	t.Helper()
	raw, ok := result.Data["points"].([]interface{})
	if !ok {
		t.Fatalf("points not array: %v", result.Data["points"])
	}
	out := make(map[string]map[string]interface{}, len(raw))
	for _, p := range raw {
		m, ok := p.(map[string]interface{})
		if !ok {
			t.Fatalf("point not object: %v", p)
		}
		date, _ := m["date"].(string)
		if date == "" {
			t.Fatalf("point missing date: %v", m)
		}
		out[date] = m
	}
	return out
}

// s8AssertPoint 断言单日点六个计数全等。
func s8AssertPoint(t *testing.T, pt map[string]map[string]interface{}, date string,
	traffic, protected, risk, newEndpoints, deviations, sensitive float64) {
	t.Helper()
	p, ok := pt[date]
	if !ok {
		t.Fatalf("trends missing point %s（点列 %v）", date, pt)
	}
	got := map[string]float64{
		"traffic":           s5Num(t, p, "traffic"),
		"protected":         s5Num(t, p, "protected"),
		"risk":              s5Num(t, p, "risk"),
		"new_endpoints":     s5Num(t, p, "new_endpoints"),
		"schema_deviations": s5Num(t, p, "schema_deviations"),
		"sensitive_hits":    s5Num(t, p, "sensitive_hits"),
	}
	want := map[string]float64{
		"traffic":           traffic,
		"protected":         protected,
		"risk":              risk,
		"new_endpoints":     newEndpoints,
		"schema_deviations": deviations,
		"sensitive_hits":    sensitive,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("trends %s %s = %v, want %v", date, k, got[k], w)
		}
	}
}

// TestStage8PostureOverview 顶部核心指标与按天趋势全量造数断言。
func TestStage8PostureOverview(t *testing.T) {
	env := setupStage8Env(t)
	cookies, _ := env.s5Login(t, "s8po", "SECURITY_ADMIN")
	kw := "s8po" + s5Rand()

	// ---- 端点资产：4 个 ----
	// epA：正常端点（有认证画像 + 涉敏字段 + 流量/事件）；
	// epB：ZOMBIE + HIGH；epC：DEPRECATED + CRITICAL；epD：2 天前创建（新增 24h 不计、趋势计入）。
	epA := s8SeedEndpoint(t, env, "GET", "/"+kw+"/pay/{id}", 0.9)
	epB := s8SeedEndpoint(t, env, "GET", "/"+kw+"/old/{id}", 0.8)
	epC := s8SeedEndpoint(t, env, "POST", "/"+kw+"/legacy", 0.8)
	epD := s8SeedEndpoint(t, env, "GET", "/"+kw+"/fresh", 0.7)
	s8Exec(t, env, `UPDATE api_endpoints SET asset_status='ZOMBIE', asset_value='HIGH' WHERE id=$1`, epB.ID)
	s8Exec(t, env, `UPDATE api_endpoints SET asset_status='DEPRECATED', asset_value='CRITICAL' WHERE id=$1`, epC.ID)
	s8Exec(t, env, `UPDATE api_endpoints SET created_at = now() - interval '2 days' WHERE id=$1`, epD.ID)

	now := time.Now().UTC()
	today := now.Truncate(24 * time.Hour)
	day2 := today.AddDate(0, 0, -2)
	day10 := today.AddDate(0, 0, -10)

	// ---- 流量桶（api_endpoint_traffic_buckets）----
	// 近 24h：epA 两桶共 5；day-2：7（overview 不计、days=7 趋势计）；day-10：11（仅 days=30 趋势计）
	s8Exec(t, env, `
INSERT INTO api_endpoint_traffic_buckets (endpoint_id, bucket_start, request_count)
VALUES ($1,$2,3),($1,$3,2),($1,$4,7),($1,$5,11)`,
		epA.ID, now, now.Add(-10*time.Minute), day2.Add(time.Hour), day10.Add(time.Hour))

	// ---- 运行时事件（api_runtime_events）----
	// 近 24h：ALLOW×1（不防护）、BLOCK×1、RATE_LIMIT×1、TEMP_BLOCK×1（含敏感明细）→ 防护量 3；
	// OBSERVE×1（含敏感明细，非防护动作）→ 敏感命中今日共 2；day-2：BLOCK×1（含敏感明细）。
	s8Exec(t, env, `
INSERT INTO api_runtime_events (request_id, endpoint_key, risk_level, final_action, details_json, occurred_at)
VALUES ('po-e1',$1,'NONE','ALLOW','[]',$2),
       ('po-e2',$1,'HIGH','BLOCK','[]',$2),
       ('po-e3',$1,'MEDIUM','RATE_LIMIT','[]',$2),
       ('po-e4',$1,'HIGH','TEMP_BLOCK','[{"detector":"sensitive_data","rule_id":"sensitive.phone"}]',$2),
       ('po-e5',$1,'LOW','OBSERVE','[{"detector":"sensitive_data","rule_id":"sensitive.id_card"}]',$2),
       ('po-e6',$1,'HIGH','BLOCK','[{"detector":"sensitive_data","rule_id":"sensitive.bank_card"}]',$3)`,
		"GET /"+kw+"/pay/{id}", now, day2.Add(time.Hour))

	// ---- 风险发现（api_runtime_findings）----
	// SHADOW NEW（今日，未闭环）+ SHADOW RESOLVED（今日，已闭环不计 shadow_open）+ BOLA CONFIRMED（day-2 新建）
	s8Exec(t, env, `
INSERT INTO api_runtime_findings (endpoint_id, request_id, finding_type, severity, status, title)
VALUES ($1,'po-f1','SHADOW','HIGH','NEW','影子API'),($1,'po-f2','SHADOW','LOW','RESOLVED','历史影子')`, epA.ID)
	s8Exec(t, env, `
INSERT INTO api_runtime_findings (endpoint_id, request_id, finding_type, severity, status, title, created_at)
VALUES ($1,'po-f3','BOLA','MEDIUM','CONFIRMED','越权迹象',$2)`, epA.ID, day2.Add(time.Hour))

	// ---- 涉敏字段（api_sensitive_fields）：epA 两条（双向）+ epB 一条 → 去重端点 2 ----
	s8Exec(t, env, `
INSERT INTO api_sensitive_fields (endpoint_id, direction, structured_path, data_type)
VALUES ($1,'REQUEST','$.phone','phone'),($1,'RESPONSE','$.idcard','id_card'),($2,'REQUEST','$.card','bank_card')`,
		epA.ID, epB.ID)

	// ---- 身份画像（api_identity_profiles）：epA 有认证（session）；epB 画像 auth_type 空；epC/epD 无画像 ----
	// → 无认证端点 = epB + epC + epD = 3
	s8Exec(t, env, `
INSERT INTO api_identity_profiles (identity_fingerprint, endpoint_id, auth_type)
VALUES ('fp-auth',$1,'session'),('fp-anon',$2,'')`, epA.ID, epB.ID)

	// ---- 模型版本：CANDIDATE / IN_REVIEW / FORMAL 各一 → 待确认 2 ----
	s8Exec(t, env, `
INSERT INTO api_model_versions (api_endpoint_id, endpoint_key, status, content_hash)
VALUES ($1,$2,'CANDIDATE','h-cand'),($1,$2,'IN_REVIEW','h-review'),($1,$2,'FORMAL','h-formal')`,
		epA.ID, "GET /"+kw+"/pay/{id}")

	// ---- Schema 违例：今日 2、day-2 1 → 24h 偏离 2 ----
	s8Exec(t, env, `
INSERT INTO api_schema_violations (endpoint_id, request_id, violation_type, occurred_at)
VALUES ($1,'po-v1','undefined_field',$2),($1,'po-v2','type_mismatch',$2),($1,'po-v3','missing_field',$3)`,
		epA.ID, now, day2.Add(time.Hour))

	// ==================== overview 全字段断言 ====================
	result := s5OK(t, env.get(t, "/api/v1/api-security/posture/overview", cookies), "posture overview")
	want := map[string]float64{
		"traffic_24h":               5,
		"protected_24h":             3,
		"assets_total":              4,
		"assets_new_24h":            3,
		"shadow_open":               1,
		"zombie_total":              1,
		"deprecated_total":          1,
		"sensitive_endpoints":       2,
		"high_risk_assets":          2,
		"unauthenticated_endpoints": 3,
		"models_pending":            2,
		"schema_deviations_24h":     2,
	}
	for k, w := range want {
		if got := s5Num(t, result.Data, k); got != w {
			t.Errorf("overview %s = %v, want %v（全量 %v）", k, got, w, result.Data)
		}
	}
	if result.Data["generated_at"] == nil {
		t.Errorf("overview missing generated_at: %v", result.Data)
	}

	// ==================== trends 聚合 / 补零 / days 参数 ====================
	// 缺省 days=7：7 个连续点
	result = s5OK(t, env.get(t, "/api/v1/api-security/posture/trends", cookies), "posture trends default")
	if s5Num(t, result.Data, "days") != 7 {
		t.Fatalf("trends default days = %v, want 7", result.Data["days"])
	}
	raw, _ := result.Data["points"].([]interface{})
	if len(raw) != 7 {
		t.Fatalf("trends default points = %d, want 7", len(raw))
	}
	pt := s8PosturePoints(t, result)
	// 今日：访问5 防护3 风险2 新增3 偏离2 敏感2
	s8AssertPoint(t, pt, today.Format("2006-01-02"), 5, 3, 2, 3, 2, 2)
	// day-2：访问7 防护1 风险1 新增1 偏离1 敏感1
	s8AssertPoint(t, pt, day2.Format("2006-01-02"), 7, 1, 1, 1, 1, 1)
	// day-1：全零（补零连续）
	s8AssertPoint(t, pt, today.AddDate(0, 0, -1).Format("2006-01-02"), 0, 0, 0, 0, 0, 0)
	// day-10 不在 7 天窗口
	if _, ok := pt[day10.Format("2006-01-02")]; ok {
		t.Errorf("days=7 不应包含 day-10 点")
	}

	// days=1：仅今日
	result = s5OK(t, env.get(t, "/api/v1/api-security/posture/trends?days=1", cookies), "posture trends days=1")
	if raw, _ := result.Data["points"].([]interface{}); len(raw) != 1 {
		t.Fatalf("trends days=1 points = %d, want 1", len(raw))
	}

	// days=30：30 点且含 day-10 流量 11
	result = s5OK(t, env.get(t, "/api/v1/api-security/posture/trends?days=30", cookies), "posture trends days=30")
	if raw, _ := result.Data["points"].([]interface{}); len(raw) != 30 {
		t.Fatalf("trends days=30 points = %d, want 30", len(raw))
	}
	pt = s8PosturePoints(t, result)
	if got := s5Num(t, pt[day10.Format("2006-01-02")], "traffic"); got != 11 {
		t.Errorf("trends day-10 traffic = %v, want 11", got)
	}

	// 非法 days：0 / 31 / 非数字 → 400（不静默回落）
	for _, q := range []string{"days=0", "days=31", "days=abc", "days=-1"} {
		resp := env.get(t, "/api/v1/api-security/posture/trends?"+q, cookies)
		s5Expect(t, resp, http.StatusBadRequest, "posture trends "+q)
	}
}

// TestStage8PostureOverviewPermission 态势新接口权限（复用 api_runtime.read）。
func TestStage8PostureOverviewPermission(t *testing.T) {
	env := setupStage8Env(t)

	// 审计管理员（000100 纯审计角色，api_runtime.read 已移除）：两接口 403
	auditCookies, _ := env.s5Login(t, "s8poa", "AUDIT_ADMIN")
	s5Expect(t, env.get(t, "/api/v1/api-security/posture/overview", auditCookies),
		http.StatusForbidden, "AUDIT_ADMIN GET overview")
	s5Expect(t, env.get(t, "/api/v1/api-security/posture/trends?days=7", auditCookies),
		http.StatusForbidden, "AUDIT_ADMIN GET trends")

	// 无权限角色（无任何权限点）：两接口 403
	s8Exec(t, env, `INSERT INTO roles (code, name, description) VALUES ('S8PO_NOPERM','无权限角色','W9-P101 权限测试')`)
	nopCookies, _ := env.s5Login(t, "s8pon", "S8PO_NOPERM")
	s5Expect(t, env.get(t, "/api/v1/api-security/posture/overview", nopCookies),
		http.StatusForbidden, "no-perm GET overview")
	s5Expect(t, env.get(t, "/api/v1/api-security/posture/trends", nopCookies),
		http.StatusForbidden, "no-perm GET trends")

	// 未认证：401
	s5Expect(t, env.do(t, http.MethodGet, "/api/v1/api-security/posture/overview", "", nil, ""),
		http.StatusUnauthorized, "unauthenticated GET overview")
	s5Expect(t, env.do(t, http.MethodGet, "/api/v1/api-security/posture/trends", "", nil, ""),
		http.StatusUnauthorized, "unauthenticated GET trends")
}
