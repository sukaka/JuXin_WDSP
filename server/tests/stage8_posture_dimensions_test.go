// stage8_posture_dimensions_test.go W10-SEC API 态势访问维度（任务书 §6.4/§6.5 残余）集成测试。
//
// 覆盖：
//   - GET /api/v1/api-security/posture/sources?days=N 访问来源聚合：客户端 IP Top（脱敏）、
//     Geo 维度（装配缺失时如实 geo_enabled=false）、身份指纹 Top（截断）、auth_type 分布、
//     days 1-30 校验；
//   - GET /api/v1/api-security/posture/targets?days=N 访问目标排名：API Top（请求量/findings
//     双口径）、应用 Top、涉敏 API Top、高风险 API Top（asset_value HIGH/CRITICAL 访问量）；
//   - Geo 启用路径：直连 Handler 注入假 CountryLookup 断言 本土/境外/内网/未知 分桶与国家 Top；
//   - 权限：复用 api_runtime.read（AUDIT_ADMIN 000100 后 403、无权限角色 403、未认证 401）。
//
// 说明：api_runtime_events 无 UA 列（000016 建表 + 000029/000030/000035 增补后仍无），
// User-Agent 族维度按任务书纪律不实现、不测试。
// 运行方式与纪律同 stage8_api_security_test.go（真实 PostgreSQL/Valkey，无口令 t.Skip）。
package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/apisecurity"
)

// s8pdList 从统一响应 data 中取对象数组字段（断言行内对象，不依赖数组下标之外的结构）。
func s8pdList(t *testing.T, data map[string]interface{}, key string) []map[string]interface{} {
	t.Helper()
	raw, ok := data[key].([]interface{})
	if !ok {
		t.Fatalf("data.%s missing or not an array: %+v", key, data)
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, it := range raw {
		m, ok := it.(map[string]interface{})
		if !ok {
			t.Fatalf("data.%s item not object: %v", key, it)
		}
		out = append(out, m)
	}
	return out
}

// s8pdSeedEvents 造来源维度事件（窗口内 5 条 + 窗口外 1 条）。
// 窗口内：1.2.3.4×2（fpA/api_key+bearer_or_basic）、2001:db8:...×1（fpB/cookie_session）、
// 5.6.7.8×1（匿名 fp/auth 空）、client_ip NULL×1（api_key）；窗口外（10 天前）9.9.9.9×1。
func s8pdSeedEvents(t *testing.T, env *testEnv, endpointKey string, now, day10 time.Time) (fpA, fpB string) {
	t.Helper()
	fpA = strings.Repeat("a", 64)
	fpB = strings.Repeat("b", 64)
	s8Exec(t, env, `
INSERT INTO api_runtime_events (request_id, endpoint_key, risk_level, final_action, occurred_at, client_ip, identity_fingerprint, auth_type)
VALUES ('pd-e1',$1,'HIGH','BLOCK',$2,'1.2.3.4',$4,'api_key'),
       ('pd-e2',$1,'MEDIUM','RATE_LIMIT',$2,'1.2.3.4',$4,'bearer_or_basic'),
       ('pd-e3',$1,'LOW','OBSERVE',$2,'2001:db8:85a3::8a2e:370:7334',$5,'cookie_session'),
       ('pd-e4',$1,'NONE','ALLOW',$2,'5.6.7.8','',''),
       ('pd-e5',$1,'LOW','OBSERVE',$2,NULL,'','api_key'),
       ('pd-e6',$1,'HIGH','BLOCK',$3,'9.9.9.9',$4,'api_key')`,
		endpointKey, now, day10, fpA, fpB)
	return fpA, fpB
}

// TestStage8PostureSources 访问来源聚合（真实装配：app 层未注入 GeoLookup → Geo 维度降级）。
func TestStage8PostureSources(t *testing.T) {
	env := setupStage8Env(t)
	cookies, _ := env.s5Login(t, "s8pd", "SECURITY_ADMIN")
	kw := "s8pd" + s5Rand()

	ep := s8SeedEndpoint(t, env, "GET", "/"+kw+"/orders/{id}", 0.9)
	now := time.Now().UTC()
	day10 := now.AddDate(0, 0, -10)
	fpA, fpB := s8pdSeedEvents(t, env, ep.EndpointKey, now, day10)

	// days=7（窗口含今天，10 天前事件不计）
	result := s5OK(t, env.get(t, "/api/v1/api-security/posture/sources?days=7", cookies), "posture sources days=7")
	if s5Num(t, result.Data, "days") != 7 {
		t.Fatalf("sources days = %v, want 7", result.Data["days"])
	}

	// 客户端 IP Top：脱敏（IPv4 末段 * / IPv6 前 48bit + :*）、计数降序、窗户外 IP 不出现
	ips := s8pdList(t, result.Data, "top_client_ips")
	if len(ips) != 3 {
		t.Fatalf("top_client_ips len = %d, want 3（%v）", len(ips), ips)
	}
	if ips[0]["client_ip"] != "1.2.3.*" || s5Num(t, ips[0], "count") != 2 {
		t.Errorf("top_client_ips[0] = %v, want 1.2.3.* ×2", ips[0])
	}
	if ips[1]["client_ip"] != "2001:db8:85a3:*" || s5Num(t, ips[1], "count") != 1 {
		t.Errorf("top_client_ips[1] = %v, want 2001:db8:85a3:* ×1", ips[1])
	}
	if ips[2]["client_ip"] != "5.6.7.*" || s5Num(t, ips[2], "count") != 1 {
		t.Errorf("top_client_ips[2] = %v, want 5.6.7.* ×1", ips[2])
	}
	for _, it := range ips {
		if strings.Contains(it["client_ip"].(string), "9.9.9") {
			t.Errorf("窗口外 IP 不应出现: %v", it)
		}
	}

	// Geo 降级：未装配 lookup → geo_enabled=false，Geo 维度如实为空
	if v, _ := result.Data["geo_enabled"].(bool); v {
		t.Errorf("geo_enabled = true, want false（未装配 lookup 应降级）")
	}
	if v, _ := result.Data["geo_truncated"].(bool); v {
		t.Errorf("geo_truncated = true, want false")
	}
	if n := len(s8pdList(t, result.Data, "geo_scopes")); n != 0 {
		t.Errorf("geo_scopes len = %d, want 0（降级留空）", n)
	}
	if n := len(s8pdList(t, result.Data, "top_countries")); n != 0 {
		t.Errorf("top_countries len = %d, want 0（降级留空）", n)
	}

	// 身份指纹 Top：截断 12 字符 + 省略号，匿名空串不参与
	ids := s8pdList(t, result.Data, "top_identities")
	if len(ids) != 2 {
		t.Fatalf("top_identities len = %d, want 2（%v）", len(ids), ids)
	}
	if ids[0]["fingerprint"] != fpA[:12]+"…" || s5Num(t, ids[0], "count") != 2 {
		t.Errorf("top_identities[0] = %v, want fpA 截断 ×2", ids[0])
	}
	if ids[1]["fingerprint"] != fpB[:12]+"…" || s5Num(t, ids[1], "count") != 1 {
		t.Errorf("top_identities[1] = %v, want fpB 截断 ×1", ids[1])
	}

	// auth_type 分布：api_key×2（含 client_ip NULL 事件），匿名/bearer_or_basic/cookie_session 各 1
	auths := s8pdList(t, result.Data, "auth_types")
	wantAuth := map[string]float64{"api_key": 2, "": 1, "bearer_or_basic": 1, "cookie_session": 1}
	if len(auths) != len(wantAuth) {
		t.Fatalf("auth_types len = %d, want %d（%v）", len(auths), len(wantAuth), auths)
	}
	for _, it := range auths {
		k := it["auth_type"].(string)
		if w, ok := wantAuth[k]; !ok || s5Num(t, it, "count") != w {
			t.Errorf("auth_types[%q] = %v, want %v", k, it["count"], wantAuth[k])
		}
	}

	// days=30：窗口外（10 天前）事件计入
	result = s5OK(t, env.get(t, "/api/v1/api-security/posture/sources?days=30", cookies), "posture sources days=30")
	ips = s8pdList(t, result.Data, "top_client_ips")
	if len(ips) != 4 {
		t.Fatalf("days=30 top_client_ips len = %d, want 4（%v）", len(ips), ips)
	}

	// days 缺省 7；非法 days → 400（不静默回落）
	result = s5OK(t, env.get(t, "/api/v1/api-security/posture/sources", cookies), "posture sources default")
	if s5Num(t, result.Data, "days") != 7 {
		t.Errorf("sources default days = %v, want 7", result.Data["days"])
	}
	for _, q := range []string{"days=0", "days=31", "days=abc", "days=-1"} {
		s5Expect(t, env.get(t, "/api/v1/api-security/posture/sources?"+q, cookies),
			http.StatusBadRequest, "posture sources "+q)
	}
}

// s8pdFakeGeoLookup 测试用国家码查询（ip.String() → 国家码；缺失键返回 "" 模拟 GeoIP 未收录）。
type s8pdFakeGeoLookup map[string]string

func (m s8pdFakeGeoLookup) LookupCountry(ip netip.Addr) (string, error) { return m[ip.String()], nil }

// TestStage8PostureSourcesGeo Geo 启用路径：注入假 lookup 直连 Handler，
// 断言 本土/境外/内网/未知 分桶、国家 Top、脏 IP 并入未知桶。
func TestStage8PostureSourcesGeo(t *testing.T) {
	env := setupStage8Env(t)
	kw := "s8pdg" + s5Rand()
	ep := s8SeedEndpoint(t, env, "GET", "/"+kw+"/items/{id}", 0.9)
	now := time.Now().UTC()

	// 确定性基准：本土地区固定 CN（与迁移 000058 种子一致，显式覆盖防种子变更）
	s8Exec(t, env, `
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('api_data', 'home_regions', '"CN"', 'string', 'W10-SEC 测试固定')
ON CONFLICT (setting_group, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value`)

	// 1.1.1.1→CN（本土）×2；8.8.8.8→US（境外）×1；10.1.2.3 内网×1（不经 lookup）；
	// 203.0.113.9 公网但假库未收录（未知）×1；"not-an-ip" 脏数据（并入未知）×1
	s8Exec(t, env, `
INSERT INTO api_runtime_events (request_id, endpoint_key, risk_level, final_action, occurred_at, client_ip)
VALUES ('pdg-e1',$1,'HIGH','BLOCK',$2,'1.1.1.1'),
       ('pdg-e2',$1,'HIGH','BLOCK',$2,'1.1.1.1'),
       ('pdg-e3',$1,'MEDIUM','OBSERVE',$2,'8.8.8.8'),
       ('pdg-e4',$1,'NONE','ALLOW',$2,'10.1.2.3'),
       ('pdg-e5',$1,'LOW','OBSERVE',$2,'203.0.113.9'),
       ('pdg-e6',$1,'LOW','OBSERVE',$2,'not-an-ip')`,
		ep.EndpointKey, now)

	h := apisecurity.NewHandler(apisecurity.NewStore(env.db), nil)
	h.SetGeoLookup(s8pdFakeGeoLookup{"1.1.1.1": "CN", "8.8.8.8": "US"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/posture/sources?days=7", nil)
	rr := httptest.NewRecorder()
	h.PostureSources(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("PostureSources status = %d, body: %s", rr.Code, rr.Body.String())
	}
	var result apiResp
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if v, _ := result.Data["geo_enabled"].(bool); !v {
		t.Fatalf("geo_enabled = false, want true（已注入 lookup）")
	}
	if v, _ := result.Data["geo_truncated"].(bool); v {
		t.Errorf("geo_truncated = true, want false")
	}
	// 四桶零补齐：HOME 2 / FOREIGN 1 / INTERNAL 1 / UNKNOWN 2（未收录 1 + 脏数据 1）
	scopes := s8pdList(t, result.Data, "geo_scopes")
	wantScopes := map[string]float64{"HOME": 2, "FOREIGN": 1, "INTERNAL": 1, "UNKNOWN": 2}
	if len(scopes) != len(wantScopes) {
		t.Fatalf("geo_scopes len = %d, want %d（%v）", len(scopes), len(wantScopes), scopes)
	}
	for i, it := range scopes {
		k := it["scope"].(string)
		w, ok := wantScopes[k]
		if !ok || s5Num(t, it, "count") != w {
			t.Errorf("geo_scopes[%d] %s = %v, want %v", i, k, it["count"], w)
		}
		delete(wantScopes, k)
	}
	// 国家 Top：CN×2 在前，US×1 随后
	countries := s8pdList(t, result.Data, "top_countries")
	if len(countries) != 2 {
		t.Fatalf("top_countries len = %d, want 2（%v）", len(countries), countries)
	}
	if countries[0]["country"] != "CN" || s5Num(t, countries[0], "count") != 2 {
		t.Errorf("top_countries[0] = %v, want CN ×2", countries[0])
	}
	if countries[1]["country"] != "US" || s5Num(t, countries[1], "count") != 1 {
		t.Errorf("top_countries[1] = %v, want US ×1", countries[1])
	}
	// 脏 IP 在 IP Top 中脱敏为 "*"
	ips := s8pdList(t, result.Data, "top_client_ips")
	masked := map[string]bool{}
	for _, it := range ips {
		masked[it["client_ip"].(string)] = true
	}
	if !masked["*"] {
		t.Errorf("脏 IP 应脱敏为 *: %v", ips)
	}
	if masked["not-an-ip"] {
		t.Errorf("脏 IP 不应原文展示: %v", ips)
	}
}

// TestStage8PostureTargets 访问目标排名聚合（双口径 API Top / 应用 / 涉敏 / 高风险）。
func TestStage8PostureTargets(t *testing.T) {
	env := setupStage8Env(t)
	cookies, _ := env.s5Login(t, "s8pt", "SECURITY_ADMIN")
	kw := "s8pt" + s5Rand()

	epA := s8SeedEndpoint(t, env, "GET", "/"+kw+"/pay/{id}", 0.9) // app1 + HIGH + 涉敏×2
	epB := s8SeedEndpoint(t, env, "POST", "/"+kw+"/refund", 0.8)  // app1 + CRITICAL + 涉敏×1
	epC := s8SeedEndpoint(t, env, "GET", "/"+kw+"/public", 0.7)   // 未分组 + 无评分
	epD := s8SeedEndpoint(t, env, "GET", "/"+kw+"/internal", 0.6) // 未分组 + LOW（不进高风险榜）
	s8Exec(t, env, `UPDATE api_endpoints SET asset_value='HIGH' WHERE id=$1`, epA.ID)
	s8Exec(t, env, `UPDATE api_endpoints SET asset_value='CRITICAL' WHERE id=$1`, epB.ID)
	s8Exec(t, env, `UPDATE api_endpoints SET asset_value='LOW' WHERE id=$1`, epD.ID)

	// 应用归属：epA/epB ∈ app1
	var appID string
	s8Exec(t, env, `INSERT INTO applications (code, name) VALUES ($1, '支付中心')`, "app-"+kw)
	row := env.db.QueryRow(context.Background(),
		`SELECT id FROM applications WHERE code = $1`, "app-"+kw)
	if err := row.Scan(&appID); err != nil {
		t.Fatalf("query app id: %v", err)
	}
	s8Exec(t, env, `UPDATE api_endpoints SET application_id=$1 WHERE id IN ($2,$3)`, appID, epA.ID, epB.ID)

	now := time.Now().UTC()
	day10 := now.AddDate(0, 0, -10)
	// 流量桶：epA 5（+10天前 11，days=7 不计）、epB 4、epC 1、epD 0
	s8Exec(t, env, `
INSERT INTO api_endpoint_traffic_buckets (endpoint_id, bucket_start, request_count)
VALUES ($1,$4,3),($1,$6,2),($1,$5,11),($2,$4,4),($3,$4,1)`,
		epA.ID, epB.ID, epC.ID, now, day10, now.Add(-5*time.Minute))

	// findings：epA 今日×2、epB 今日×1、epC 10天前×1（days=7 不计）、未关联端点×1（内连接剔除）
	s8Exec(t, env, `
INSERT INTO api_runtime_findings (endpoint_id, request_id, finding_type, severity, status, title)
VALUES ($1,'pt-f1','BOLA','HIGH','NEW','越权1'),($1,'pt-f2','BOLA','MEDIUM','CONFIRMED','越权2'),
       ($2,'pt-f3','SHADOW','LOW','NEW','影子'),(NULL,'pt-f5','SHADOW','LOW','NEW','无端点')`,
		epA.ID, epB.ID)
	s8Exec(t, env, `
INSERT INTO api_runtime_findings (endpoint_id, request_id, finding_type, severity, status, title, created_at)
VALUES ($1,'pt-f4','WEAK_AUTH','MEDIUM','NEW','历史', $2)`, epC.ID, day10)

	// 涉敏字段：epA×2、epB×1
	s8Exec(t, env, `
INSERT INTO api_sensitive_fields (endpoint_id, direction, structured_path, data_type)
VALUES ($1,'REQUEST','$.phone','phone'),($1,'RESPONSE','$.idcard','id_card'),($2,'REQUEST','$.card','bank_card')`,
		epA.ID, epB.ID)

	// ==================== days=7 全榜断言 ====================
	result := s5OK(t, env.get(t, "/api/v1/api-security/posture/targets?days=7", cookies), "posture targets days=7")
	if s5Num(t, result.Data, "days") != 7 {
		t.Fatalf("targets days = %v, want 7", result.Data["days"])
	}

	// API Top · 请求量：epA 5 > epB 4 > epC 1（epD 无流量不上榜；10 天前桶不计）
	traffic := s8pdList(t, result.Data, "top_by_traffic")
	if len(traffic) != 3 {
		t.Fatalf("top_by_traffic len = %d, want 3（%v）", len(traffic), traffic)
	}
	wantTraffic := []struct {
		key string
		req float64
	}{{epA.EndpointKey, 5}, {epB.EndpointKey, 4}, {epC.EndpointKey, 1}}
	for i, w := range wantTraffic {
		if traffic[i]["endpoint_key"] != w.key || s5Num(t, traffic[i], "request_count") != w.req {
			t.Errorf("top_by_traffic[%d] = %v, want %s ×%v", i, traffic[i], w.key, w.req)
		}
	}

	// API Top · 风险发现：epA 2 > epB 1（epC 10 天前不计、无端点发现剔除）
	findings := s8pdList(t, result.Data, "top_by_findings")
	if len(findings) != 2 {
		t.Fatalf("top_by_findings len = %d, want 2（%v）", len(findings), findings)
	}
	if findings[0]["endpoint_key"] != epA.EndpointKey || s5Num(t, findings[0], "findings_count") != 2 {
		t.Errorf("top_by_findings[0] = %v, want epA ×2", findings[0])
	}
	if findings[1]["endpoint_key"] != epB.EndpointKey || s5Num(t, findings[1], "findings_count") != 1 {
		t.Errorf("top_by_findings[1] = %v, want epB ×1", findings[1])
	}

	// 应用 Top：支付中心（epA+epB=9）> 未分组（epC+epD=1，application_id 空、name 空串）
	apps := s8pdList(t, result.Data, "top_applications")
	if len(apps) != 2 {
		t.Fatalf("top_applications len = %d, want 2（%v）", len(apps), apps)
	}
	if apps[0]["application_name"] != "支付中心" || s5Num(t, apps[0], "request_count") != 9 {
		t.Errorf("top_applications[0] = %v, want 支付中心 ×9", apps[0])
	}
	if apps[1]["application_name"] != "" || apps[1]["application_id"] != nil || s5Num(t, apps[1], "request_count") != 1 {
		t.Errorf("top_applications[1] = %v, want 未分组 ×1", apps[1])
	}

	// 涉敏 API Top：epA（字段2/访问5）> epB（字段1/访问4）
	sens := s8pdList(t, result.Data, "top_sensitive")
	if len(sens) != 2 {
		t.Fatalf("top_sensitive len = %d, want 2（%v）", len(sens), sens)
	}
	if sens[0]["endpoint_key"] != epA.EndpointKey || s5Num(t, sens[0], "request_count") != 5 || s5Num(t, sens[0], "sensitive_fields") != 2 {
		t.Errorf("top_sensitive[0] = %v, want epA 访问5 字段2", sens[0])
	}
	if sens[1]["endpoint_key"] != epB.EndpointKey || s5Num(t, sens[1], "request_count") != 4 || s5Num(t, sens[1], "sensitive_fields") != 1 {
		t.Errorf("top_sensitive[1] = %v, want epB 访问4 字段1", sens[1])
	}

	// 高风险 API Top：epA HIGH×5 > epB CRITICAL×4（epD LOW 不上榜）
	high := s8pdList(t, result.Data, "top_high_risk")
	if len(high) != 2 {
		t.Fatalf("top_high_risk len = %d, want 2（%v）", len(high), high)
	}
	if high[0]["endpoint_key"] != epA.EndpointKey || high[0]["asset_value"] != "HIGH" || s5Num(t, high[0], "request_count") != 5 {
		t.Errorf("top_high_risk[0] = %v, want epA HIGH ×5", high[0])
	}
	if high[1]["endpoint_key"] != epB.EndpointKey || high[1]["asset_value"] != "CRITICAL" || s5Num(t, high[1], "request_count") != 4 {
		t.Errorf("top_high_risk[1] = %v, want epB CRITICAL ×4", high[1])
	}

	// days=30：epA 10 天前流量桶计入（5+11=16）、epC 10 天前 finding 计入
	result = s5OK(t, env.get(t, "/api/v1/api-security/posture/targets?days=30", cookies), "posture targets days=30")
	traffic = s8pdList(t, result.Data, "top_by_traffic")
	if len(traffic) != 3 || s5Num(t, traffic[0], "request_count") != 16 {
		t.Errorf("days=30 top_by_traffic[0] = %v, want epA ×16", traffic)
	}
	findings = s8pdList(t, result.Data, "top_by_findings")
	if len(findings) != 3 {
		t.Errorf("days=30 top_by_findings len = %d, want 3（%v）", len(findings), findings)
	}

	// days 缺省 7；非法 days → 400
	result = s5OK(t, env.get(t, "/api/v1/api-security/posture/targets", cookies), "posture targets default")
	if s5Num(t, result.Data, "days") != 7 {
		t.Errorf("targets default days = %v, want 7", result.Data["days"])
	}
	for _, q := range []string{"days=0", "days=31", "days=abc", "days=-1"} {
		s5Expect(t, env.get(t, "/api/v1/api-security/posture/targets?"+q, cookies),
			http.StatusBadRequest, "posture targets "+q)
	}
}

// TestStage8PostureDimensionsPermission 态势访问维度接口权限（复用 api_runtime.read）。
func TestStage8PostureDimensionsPermission(t *testing.T) {
	env := setupStage8Env(t)

	// 审计管理员（000100 纯审计角色，api_runtime.read 已移除）：两接口 403
	auditCookies, _ := env.s5Login(t, "s8pda", "AUDIT_ADMIN")
	s5Expect(t, env.get(t, "/api/v1/api-security/posture/sources", auditCookies),
		http.StatusForbidden, "AUDIT_ADMIN GET sources")
	s5Expect(t, env.get(t, "/api/v1/api-security/posture/targets", auditCookies),
		http.StatusForbidden, "AUDIT_ADMIN GET targets")

	// 无权限角色：两接口 403
	s8Exec(t, env, `INSERT INTO roles (code, name, description) VALUES ('S8PD_NOPERM','无权限角色','W10-SEC 权限测试')`)
	nopCookies, _ := env.s5Login(t, "s8pdn", "S8PD_NOPERM")
	s5Expect(t, env.get(t, "/api/v1/api-security/posture/sources", nopCookies),
		http.StatusForbidden, "no-perm GET sources")
	s5Expect(t, env.get(t, "/api/v1/api-security/posture/targets", nopCookies),
		http.StatusForbidden, "no-perm GET targets")

	// 未认证：401
	s5Expect(t, env.do(t, http.MethodGet, "/api/v1/api-security/posture/sources", "", nil, ""),
		http.StatusUnauthorized, "unauthenticated GET sources")
	s5Expect(t, env.do(t, http.MethodGet, "/api/v1/api-security/posture/targets", "", nil, ""),
		http.StatusUnauthorized, "unauthenticated GET targets")
}
