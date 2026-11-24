// stage_jwt_trust_test.go 业务 JWT 信任链管理面接口测试（WDSP P0-03；
// 真实 PG/Valkey，未设置环境或 -short 即 skip）。覆盖：迁移建表与权限种子；
// 三个接口的权限拒绝/404/字段错误/409 并发/审计写入/预检门禁；JWT-13 跨应用隔离
// （默认策略不泄露、乐观锁按应用自身状态判定、版本记录按 application_id 隔离）；
// JWT-14 Store.ListForGuard 真实 DB 下发契约（guardconfig 供应链）。
// 真实网关发布与节点回执属集成步骤，不在本文件。
package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/jwttrust"
)

// jwtTestApp 创建测试应用，返回应用 ID。
func jwtTestApp(t *testing.T, env *testEnv, cookies []*http.Cookie, csrf, code string) string {
	t.Helper()
	resp := env.post(t, "/api/v1/applications",
		fmt.Sprintf(`{"code":%q,"name":"JWT测试","protection_mode":"OBSERVE"}`, code), cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create app status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var result apiResp
	readJSON(t, resp, &result)
	appID, _ := result.Data["id"].(string)
	if appID == "" {
		t.Fatal("no app id")
	}
	return appID
}

// jwtTestJWKS 生成本地专用 RSA 测试公钥 JWKS（仅公钥参数）。
func jwtTestJWKS(t *testing.T) string {
	t.Helper()
	return jwtTestJWKSKid(t, "it-k1")
}

// jwtTestJWKSKid 生成指定 kid 的本地专用 RSA 测试公钥 JWKS（仅公钥参数）。
func jwtTestJWKSKid(t *testing.T, kid string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	b64u := base64.RawURLEncoding.EncodeToString
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"alg":"RS256","n":%q,"e":%q}]}`,
		kid, b64u(key.N.Bytes()), b64u(big.NewInt(int64(key.E)).Bytes()))
}

// TestJWTTrustMigrations 迁移后表/权限/角色授权/设置种子存在。
func TestJWTTrustMigrations(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	var n int
	for _, table := range []string{"jwt_trust_policies", "jwt_trust_policy_versions"} {
		if err := env.db.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables
WHERE table_name=$1`, table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("table %s missing: n=%d err=%v", table, n, err)
		}
	}
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM permissions
WHERE code IN ('jwt_trust.read','jwt_trust.manage')`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("jwt_trust permissions = %d, want 2 (err %v)", n, err)
	}
	// 000232 后：SYSTEM_ADMIN 已剥离 jwt_trust.*；read 仅 SECURITY_ADMIN/AUDIT_ADMIN，manage 仅 SECURITY_ADMIN
	if err := env.db.QueryRow(ctx, `SELECT count(DISTINCT r.code) FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
WHERE p.code = 'jwt_trust.read' AND r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN','AUDIT_ADMIN')`).Scan(&n); err != nil || n != 2 {
		t.Errorf("jwt_trust.read granted roles = %d, want 2 (err %v)", n, err)
	}
	if err := env.db.QueryRow(ctx, `SELECT count(DISTINCT r.code) FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id JOIN permissions p ON p.id = rp.permission_id
WHERE p.code = 'jwt_trust.manage' AND r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN')`).Scan(&n); err != nil || n != 1 {
		t.Errorf("jwt_trust.manage granted roles = %d, want 1 (err %v)", n, err)
	}
	// remote_jwks_allowlist 设置种子（默认空=仅公网 HTTPS）
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM system_settings
WHERE setting_group='jwt_trust' AND setting_key='remote_jwks_allowlist'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("remote_jwks_allowlist setting seed = %d, want 1 (err %v)", n, err)
	}
}

// TestJWTTrustPolicyLifecycle GET 默认 OFF / PUT 草稿 / 409 并发 / 审计 / 预检门禁。
func TestJWTTrustPolicyLifecycle(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "jwt_sec", "SECURITY_ADMIN")
	appID := jwtTestApp(t, env, cookies, csrf, "jwt-app-"+s5Rand())
	path := "/api/v1/applications/" + appID + "/jwt-trust-policy"

	// 未配置应用 GET → 默认 OFF 空策略（version=0, NOT_CONFIGURED）
	result := s5OK(t, env.get(t, path, cookies), "get default jwt trust policy")
	policy := s5Obj(t, result, "policy")
	if policy["mode"] != "OFF" || int(s5Num(t, policy, "version")) != 0 {
		t.Fatalf("default policy = %+v", policy)
	}
	summary := s5Obj(t, result, "summary")
	if summary["state"] != "NOT_CONFIGURED" || int(s5Num(t, summary, "published_version")) != 0 {
		t.Fatalf("default summary = %+v", summary)
	}

	// 不存在应用 → 404
	s5Expect(t, env.get(t, "/api/v1/applications/"+uuid.NewString()+"/jwt-trust-policy", cookies),
		http.StatusNotFound, "get jwt trust policy of missing app")
	// 非法应用 ID → 400
	s5Expect(t, env.get(t, "/api/v1/applications/not-a-uuid/jwt-trust-policy", cookies),
		http.StatusBadRequest, "get jwt trust policy with bad id")

	// PUT 缺 reason → 400
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OBSERVE","expected_version":0,"selectors":[{"methods":["GET"],"path_prefix":"/api","token_required":true}],"issuers":[]}`,
		cookies, csrf), http.StatusBadRequest, "put without reason")

	// PUT OBSERVE 缺 issuers → 400
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OBSERVE","expected_version":0,"reason":"t","selectors":[{"methods":["GET"],"path_prefix":"/api","token_required":true}]}`,
		cookies, csrf), http.StatusBadRequest, "put observe without issuers")

	// PUT 静态 JWKS 含私钥参数 → 400（提交私钥立即拒绝）
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OBSERVE","expected_version":0,"reason":"t","selectors":[{"methods":["GET"],"path_prefix":"/api","token_required":true}],"issuers":[{"issuer":"https://idp.example.com/","audiences":["a"],"algorithms":["RS256"],"key_source":{"type":"STATIC_JWKS","jwks":"{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"x\",\"e\":\"AQAB\",\"d\":\"secret\"}]}"}}]}`,
		cookies, csrf), http.StatusBadRequest, "put static jwks with private param")

	// PUT REMOTE_JWKS 非 HTTPS → 400
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OBSERVE","expected_version":0,"reason":"t","selectors":[{"methods":["GET"],"path_prefix":"/api","token_required":true}],"issuers":[{"issuer":"https://idp.example.com/","audiences":["a"],"algorithms":["RS256"],"key_source":{"type":"REMOTE_JWKS","url":"http://idp.example.com/jwks"}}]}`,
		cookies, csrf), http.StatusBadRequest, "put remote jwks non-https")

	// PUT REMOTE_JWKS 私网地址 → 400（SSRF 拒绝；字面量私网 IP 无需 DNS）
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OBSERVE","expected_version":0,"reason":"t","selectors":[{"methods":["GET"],"path_prefix":"/api","token_required":true}],"issuers":[{"issuer":"https://idp.example.com/","audiences":["a"],"algorithms":["RS256"],"key_source":{"type":"REMOTE_JWKS","url":"https://169.254.169.254/jwks"}}]}`,
		cookies, csrf), http.StatusBadRequest, "put remote jwks metadata address")

	// PUT 合法草稿（方法小写自动大写去重；静态公钥集）→ 200 + version=1
	putBody := fmt.Sprintf(`{"mode":"OBSERVE","expected_version":0,"reason":"初次配置",
"selectors":[{"methods":["get","GET","post"],"path_prefix":"/api","token_required":true}],
"issuers":[{"issuer":"https://idp.example.com/","audiences":["shop-api"],"algorithms":["RS256"],
"key_source":{"type":"STATIC_JWKS","jwks":%q}}]}`, jwtTestJWKS(t))
	result = s5OK(t, env.do(t, http.MethodPut, path, putBody, cookies, csrf), "put valid draft")
	policy = s5Obj(t, result, "policy")
	if int(s5Num(t, policy, "version")) != 1 || policy["mode"] != "OBSERVE" {
		t.Fatalf("policy after put = %+v", policy)
	}
	sel := policy["selectors"].([]interface{})[0].(map[string]interface{})
	methods := sel["methods"].([]interface{})
	if len(methods) != 2 || methods[0] != "GET" || methods[1] != "POST" {
		t.Errorf("methods not normalized: %v", methods)
	}

	// GET 显示 DRAFT_PENDING（草稿未发布，发布走既有通道）
	result = s5OK(t, env.get(t, path, cookies), "get after put")
	summary = s5Obj(t, result, "summary")
	if summary["state"] != "DRAFT_PENDING" || int(s5Num(t, summary, "draft_version")) != 1 {
		t.Errorf("summary after put = %+v, want DRAFT_PENDING/1", summary)
	}

	// PUT expected_version 过期 → 409（防并发覆盖）
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OFF","expected_version":9,"reason":"并发冲突测试"}`, cookies, csrf),
		http.StatusConflict, "put with stale expected_version")
	// PUT expected_version=0 对已有草稿 → 409
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OFF","expected_version":0,"reason":"重复首建"}`, cookies, csrf),
		http.StatusConflict, "put create over existing draft")

	// PUT 升级为 PROTECT 草稿 → 200 + version=2（保存草稿不自动发布）
	result = s5OK(t, env.do(t, http.MethodPut, path,
		fmt.Sprintf(`{"mode":"PROTECT","expected_version":1,"reason":"升级强制验证",
"selectors":[{"methods":["GET"],"path_prefix":"/api","token_required":true}],
"issuers":[{"issuer":"https://idp.example.com/","audiences":["shop-api"],"algorithms":["RS256"],
"key_source":{"type":"STATIC_JWKS","jwks":%q}}]}`, jwtTestJWKS(t)), cookies, csrf), "put protect draft")
	policy = s5Obj(t, result, "policy")
	if int(s5Num(t, policy, "version")) != 2 || policy["mode"] != "PROTECT" {
		t.Fatalf("policy after protect put = %+v", policy)
	}

	// 不可变版本记录 = 2 行
	ctx := context.Background()
	var n int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM jwt_trust_policy_versions
WHERE application_id=$1`, appID).Scan(&n); err != nil || n != 2 {
		t.Errorf("version records = %d, want 2 (err %v)", n, err)
	}

	// 审计：update（OBSERVE→PROTECT 为高风险）+ 无 Token/JWKS 原文落审计
	var auditCount int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM operation_audits
WHERE object_type='jwt_trust_policy' AND action='update'`).Scan(&auditCount); err != nil || auditCount < 2 {
		t.Errorf("jwt_trust update audits = %d, want >= 2 (err %v)", auditCount, err)
	}
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM operation_audits
WHERE object_type='jwt_trust_policy' AND action='update' AND risk_level='HIGH'`).Scan(&auditCount); err != nil || auditCount < 1 {
		t.Errorf("OBSERVE→PROTECT high-risk audit missing (err %v)", err)
	}
	var afterSummary string
	if err := env.db.QueryRow(ctx, `SELECT after_summary FROM operation_audits
WHERE object_type='jwt_trust_policy' AND action='update' AND risk_level='HIGH'
ORDER BY occurred_at DESC LIMIT 1`).Scan(&afterSummary); err != nil {
		t.Fatalf("query audit summary: %v", err)
	}
	if !containsAll(afterSummary, "keyset_version", "PROTECT", "升级强制验证") ||
		strings.Contains(afterSummary, `"n":"`) {
		t.Errorf("audit summary must contain keyset fingerprint/reason but not raw JWKS: %s", afterSummary)
	}

	// 预检：草稿为 PROTECT 且测试环境 API 管线非 PROTECT → pipeline_gate FAIL 且 publishable=false
	result = s5OK(t, env.post(t, path+"/preflight", "", cookies, csrf), "preflight protect draft")
	data := result.Data
	if data["publishable"] != false {
		t.Errorf("preflight publishable = %v, want false (pipeline not PROTECT in test env)", data["publishable"])
	}
	checks, _ := data["checks"].([]interface{})
	gateSeen := false
	for _, c := range checks {
		cm := c.(map[string]interface{})
		if cm["name"] == "pipeline_gate" {
			gateSeen = true
			if cm["status"] != "FAIL" {
				t.Errorf("pipeline_gate = %+v, want FAIL", cm)
			}
		}
	}
	if !gateSeen {
		t.Errorf("pipeline_gate check missing: %+v", checks)
	}

	// 预检审计（低风险）
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM operation_audits
WHERE object_type='jwt_trust_policy' AND action='preflight'`).Scan(&auditCount); err != nil || auditCount < 1 {
		t.Errorf("preflight audit missing (err %v)", err)
	}
}

// TestJWTTrustPermissions 权限口径：AUDIT_ADMIN 只读（GET 200 / PUT / preflight 403）；
// 未登录 401。（角色种子见迁移 000126）
func TestJWTTrustPermissions(t *testing.T) {
	env := setupTestEnv(t)
	secCookies, secCSRF := env.s5Login(t, "jwt_psec", "SECURITY_ADMIN")
	appID := jwtTestApp(t, env, secCookies, secCSRF, "jwt-perm-"+s5Rand())
	path := "/api/v1/applications/" + appID + "/jwt-trust-policy"

	auditCookies, auditCSRF := env.s5Login(t, "jwt_pa", "AUDIT_ADMIN")
	s5Expect(t, env.get(t, path, auditCookies), http.StatusOK, "audit admin get jwt trust policy")
	s5Expect(t, env.do(t, http.MethodPut, path,
		`{"mode":"OFF","expected_version":0,"reason":"t"}`, auditCookies, auditCSRF),
		http.StatusForbidden, "audit admin put jwt trust policy")
	s5Expect(t, env.post(t, path+"/preflight", "", auditCookies, auditCSRF),
		http.StatusForbidden, "audit admin preflight")

	// 未登录
	s5Expect(t, env.get(t, path, nil), http.StatusUnauthorized, "anonymous get jwt trust policy")
}

// TestJWTTrustCrossAppIsolation JWT-13 跨应用隔离：应用 A 保存草稿不影响应用 B——
// GET B 仍返回默认 OFF 空策略（version=0 / NOT_CONFIGURED）；对 B 的 PUT 携带 A 的
// version 号按 B 自身状态判定（无草稿 + expected_version>0 → 409）；乐观锁版本序列
// 与 jwt_trust_policy_versions 不可变记录均按 application_id 隔离（直查 DB 验证）。
func TestJWTTrustCrossAppIsolation(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "jwt_iso", "SECURITY_ADMIN")
	appA := jwtTestApp(t, env, cookies, csrf, "jwt-iso-a-"+s5Rand())
	appB := jwtTestApp(t, env, cookies, csrf, "jwt-iso-b-"+s5Rand())
	pathA := "/api/v1/applications/" + appA + "/jwt-trust-policy"
	pathB := "/api/v1/applications/" + appB + "/jwt-trust-policy"
	ctx := context.Background()

	// 应用 A 保存 OBSERVE 草稿（version=1）
	putA := fmt.Sprintf(`{"mode":"OBSERVE","expected_version":0,"reason":"应用A初次配置",
"selectors":[{"methods":["GET"],"path_prefix":"/api","token_required":true}],
"issuers":[{"issuer":"https://idp-a.example.com/","audiences":["aud-a"],"algorithms":["RS256"],
"key_source":{"type":"STATIC_JWKS","jwks":%q}}]}`, jwtTestJWKS(t))
	result := s5OK(t, env.do(t, http.MethodPut, pathA, putA, cookies, csrf), "put app A draft")
	if v := int(s5Num(t, s5Obj(t, result, "policy"), "version")); v != 1 {
		t.Fatalf("app A policy version = %d, want 1", v)
	}

	// GET 应用 B → 默认 OFF 空策略，不得泄露 A 的内容
	result = s5OK(t, env.get(t, pathB, cookies), "get app B default policy")
	policy := s5Obj(t, result, "policy")
	if policy["application_id"] != appB {
		t.Errorf("app B policy application_id = %v, want %s", policy["application_id"], appB)
	}
	if policy["mode"] != "OFF" || int(s5Num(t, policy, "version")) != 0 {
		t.Errorf("app B default policy = %+v, want OFF/version=0", policy)
	}
	if sels, _ := policy["selectors"].([]interface{}); len(sels) != 0 {
		t.Errorf("app B selectors = %v, want empty (must not leak app A)", sels)
	}
	if iss, _ := policy["issuers"].([]interface{}); len(iss) != 0 {
		t.Errorf("app B issuers = %v, want empty (must not leak app A)", iss)
	}
	summary := s5Obj(t, result, "summary")
	if summary["state"] != "NOT_CONFIGURED" || int(s5Num(t, summary, "draft_version")) != 0 {
		t.Errorf("app B summary = %+v, want NOT_CONFIGURED/0", summary)
	}

	// 对 B 的 PUT 携带 A 的 version 号（expected_version=1）：按 B 自身状态判定，
	// B 无草稿 → 409（不得误用 A 的版本号判定通过）
	s5Expect(t, env.do(t, http.MethodPut, pathB,
		`{"mode":"OFF","expected_version":1,"reason":"携带A版本号"}`, cookies, csrf),
		http.StatusConflict, "put app B with app A's expected_version")
	// 409 后 B 仍为未配置
	summary = s5Obj(t, s5OK(t, env.get(t, pathB, cookies), "get app B after conflict"), "summary")
	if summary["state"] != "NOT_CONFIGURED" {
		t.Errorf("app B summary after conflict = %+v, want NOT_CONFIGURED", summary)
	}

	// B 以 expected_version=0 保存自己的草稿（内容区别于 A）→ 独立的 version=1
	putB := fmt.Sprintf(`{"mode":"OBSERVE","expected_version":0,"reason":"应用B初次配置",
"selectors":[{"methods":["POST"],"path_prefix":"/pay","token_required":true}],
"issuers":[{"issuer":"https://idp-b.example.com/","audiences":["aud-b"],"algorithms":["RS256"],
"key_source":{"type":"STATIC_JWKS","jwks":%q}}]}`, jwtTestJWKS(t))
	result = s5OK(t, env.do(t, http.MethodPut, pathB, putB, cookies, csrf), "put app B draft")
	policy = s5Obj(t, result, "policy")
	if int(s5Num(t, policy, "version")) != 1 || policy["application_id"] != appB {
		t.Errorf("app B policy after put = %+v, want version=1 owned by B", policy)
	}

	// A 的策略不受 B 写入影响
	result = s5OK(t, env.get(t, pathA, cookies), "get app A after B writes")
	policy = s5Obj(t, result, "policy")
	issuers := policy["issuers"].([]interface{})
	if int(s5Num(t, policy, "version")) != 1 || len(issuers) != 1 ||
		issuers[0].(map[string]interface{})["issuer"] != "https://idp-a.example.com/" {
		t.Errorf("app A policy contaminated by app B: %+v", policy)
	}

	// DB 直查：草稿行与不可变版本记录按 application_id 隔离，内容互不串行
	for appID, issuer := range map[string]string{appA: "idp-a.example.com", appB: "idp-b.example.com"} {
		other := "idp-b.example.com"
		if appID == appB {
			other = "idp-a.example.com"
		}
		var n int
		if err := env.db.QueryRow(ctx, `SELECT count(*) FROM jwt_trust_policies
WHERE application_id=$1 AND version=1 AND mode='OBSERVE'`, appID).Scan(&n); err != nil || n != 1 {
			t.Errorf("jwt_trust_policies row for %s = %d, want 1 (err %v)", appID, n, err)
		}
		if err := env.db.QueryRow(ctx, `SELECT count(*) FROM jwt_trust_policy_versions
WHERE application_id=$1`, appID).Scan(&n); err != nil || n != 1 {
			t.Errorf("version records for %s = %d, want 1 (err %v)", appID, n, err)
		}
		if err := env.db.QueryRow(ctx, `SELECT count(*) FROM jwt_trust_policy_versions
WHERE application_id=$1 AND issuers::text LIKE '%'||$2||'%'`, appID, issuer).Scan(&n); err != nil || n != 1 {
			t.Errorf("version record issuer mismatch for %s: n=%d (err %v)", appID, n, err)
		}
		if err := env.db.QueryRow(ctx, `SELECT count(*) FROM jwt_trust_policy_versions
WHERE application_id=$1 AND issuers::text LIKE '%'||$2||'%'`, appID, other).Scan(&n); err != nil || n != 0 {
			t.Errorf("version record for %s leaks %s: n=%d (err %v)", appID, other, n, err)
		}
	}
}

// TestJWTTrustListForGuard JWT-14 补全：Store.ListForGuard 真实 DB 覆盖（guardconfig
// 供应链经 JWTTrustLister 把策略编译进发布配置）。经 API 保存静态 JWKS 草稿后，
// 断言下发契约字段与保存内容一致、issuer_config_id 非空稳定、keyset_version 派生自
// 公钥集内容而非原文、不含任何私钥/对称参数；保存第二版草稿后返回最新草稿语义
// （读 store.go 确认：ListForGuard 查 jwt_trust_policies 当前草稿行而非
// access_control_versions 发布快照——下发的是最新草稿，由发布通道编译进整站
// 快照后才生效；OFF 策略同样下发以覆盖网关旧配置残留）。
func TestJWTTrustListForGuard(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "jwt_guard", "SECURITY_ADMIN")
	codeA := "jwtg-a-" + s5Rand()
	codeB := "jwtg-b-" + s5Rand()
	appA := jwtTestApp(t, env, cookies, csrf, codeA)
	jwtTestApp(t, env, cookies, csrf, codeB) // 无策略应用：不得出现在下发集合
	pathA := "/api/v1/applications/" + appA + "/jwt-trust-policy"
	ctx := context.Background()
	store := jwttrust.NewStore(env.db)

	jwks1 := jwtTestJWKS(t)
	issuer := "https://idp-guard.example.com/"
	putBody := fmt.Sprintf(`{"mode":"OBSERVE","expected_version":0,"reason":"下发契约首版",
"selectors":[{"methods":["GET"],"path_prefix":"/api","token_required":true}],
"issuers":[{"issuer":%q,"audiences":["guard-aud"],"algorithms":["RS256"],
"key_source":{"type":"STATIC_JWKS","jwks":%q}}]}`, issuer, jwks1)
	s5OK(t, env.do(t, http.MethodPut, pathA, putBody, cookies, csrf), "put guard draft v1")

	out, err := store.ListForGuard(ctx)
	if err != nil {
		t.Fatalf("ListForGuard: %v", err)
	}
	gp, ok := out[codeA]
	if !ok {
		t.Fatalf("ListForGuard missing app %s: keys=%v", codeA, out)
	}
	if _, ok := out[codeB]; ok {
		t.Errorf("app %s has no policy but appears in guard contract: %+v", codeB, out[codeB])
	}

	// 下发契约字段与保存内容一致
	if gp.SchemaVersion != jwttrust.SchemaVersion {
		t.Errorf("schema_version = %d, want %d", gp.SchemaVersion, jwttrust.SchemaVersion)
	}
	if gp.ApplicationID != appA || gp.Mode != "OBSERVE" || gp.Version != 1 {
		t.Errorf("guard policy header = app %s mode %s version %d, want %s/OBSERVE/1",
			gp.ApplicationID, gp.Mode, gp.Version, appA)
	}
	if len(gp.Selectors) != 1 || len(gp.Selectors[0].Methods) != 1 ||
		gp.Selectors[0].Methods[0] != "GET" || gp.Selectors[0].PathPrefix != "/api" ||
		!gp.Selectors[0].TokenRequired {
		t.Errorf("guard selectors = %+v, mismatch with saved draft", gp.Selectors)
	}
	if len(gp.Issuers) != 1 {
		t.Fatalf("guard issuers = %+v, want 1", gp.Issuers)
	}
	gi := gp.Issuers[0]
	if gi.Issuer != issuer || gi.KeySourceType != "STATIC_JWKS" || gi.RemoteURL != "" ||
		len(gi.Audiences) != 1 || gi.Audiences[0] != "guard-aud" ||
		len(gi.Algorithms) != 1 || gi.Algorithms[0] != "RS256" ||
		gi.ClockSkewSeconds != jwttrust.DefaultClockSkew {
		t.Errorf("guard issuer = %+v, mismatch with saved draft", gi)
	}
	// issuer_config_id 非空且稳定（应用+issuer 精确值派生）
	wantID := jwttrust.IssuerConfigID(uuid.MustParse(appA), issuer)
	if gi.IssuerConfigID == "" || !strings.HasPrefix(gi.IssuerConfigID, "jwtiss_") || gi.IssuerConfigID != wantID {
		t.Errorf("issuer_config_id = %q, want stable %q", gi.IssuerConfigID, wantID)
	}
	// 静态公钥集原文下发（公钥非秘密）
	if string(gi.JWKS) != jwks1 {
		t.Errorf("guard jwks = %s, want saved %s", gi.JWKS, jwks1)
	}
	// keyset_version 派生自公钥集内容而非原文：等价 JWKS 变体（仅空白差异）版本相同
	wantKV, err := jwttrust.KeysetVersion(jwks1)
	if err != nil {
		t.Fatalf("KeysetVersion: %v", err)
	}
	if gi.KeysetVersion != wantKV {
		t.Errorf("keyset_version = %q, want %q", gi.KeysetVersion, wantKV)
	}
	variantKV, err := jwttrust.KeysetVersion(strings.Replace(jwks1, `,"kid"`, `, "kid"`, 1))
	if err != nil || variantKV != wantKV {
		t.Errorf("keyset version must derive from key content not raw text: variant=%q err=%v", variantKV, err)
	}
	// 下发契约不含任何私钥/对称参数（d/p/q/dp/dq/qi/oth/k）
	raw, err := json.Marshal(gp)
	if err != nil {
		t.Fatalf("marshal guard policy: %v", err)
	}
	for _, p := range []string{`"d":`, `"p":`, `"q":`, `"dp":`, `"dq":`, `"qi":`, `"oth":`, `"k":`} {
		if strings.Contains(string(raw), p) {
			t.Errorf("guard contract contains private/symmetric param %s: %s", p, raw)
		}
	}

	// 同 kid 换 key（材料轮换）同样改变 keyset_version——轮换溯源的最小粒度。
	sameKidRotated := jwtTestJWKSKid(t, "it-k1")
	sameKidKV, err := jwttrust.KeysetVersion(sameKidRotated)
	if err != nil || sameKidKV == wantKV {
		t.Errorf("same-kid material rotation must change keyset_version: %q err=%v", sameKidKV, err)
	}

	// 保存第二版草稿（轮换公钥（新 kid）+ 改选择器/audience）→ ListForGuard 返回最新草稿语义。
	// KeysetVersion 哈希输入含规范化密钥材料（与网关 jwtverify.keysetVersion 逐字节一致），
	// 新 kid 或同 kid 换 key 均产生新版本。
	jwks2 := jwtTestJWKSKid(t, "it-k2")
	putBody = fmt.Sprintf(`{"mode":"OBSERVE","expected_version":1,"reason":"轮换密钥并调整范围",
"selectors":[{"methods":["POST"],"path_prefix":"/api/v2","token_required":true}],
"issuers":[{"issuer":%q,"audiences":["guard-aud-v2"],"algorithms":["RS256"],
"key_source":{"type":"STATIC_JWKS","jwks":%q}}]}`, issuer, jwks2)
	s5OK(t, env.do(t, http.MethodPut, pathA, putBody, cookies, csrf), "put guard draft v2")

	out, err = store.ListForGuard(ctx)
	if err != nil {
		t.Fatalf("ListForGuard after v2: %v", err)
	}
	gp2 := out[codeA]
	if gp2 == nil || gp2.Version != 2 {
		t.Fatalf("guard policy after v2 = %+v, want version 2 (latest draft semantics)", gp2)
	}
	if len(gp2.Selectors) != 1 || gp2.Selectors[0].PathPrefix != "/api/v2" ||
		len(gp2.Issuers) != 1 || len(gp2.Issuers[0].Audiences) != 1 ||
		gp2.Issuers[0].Audiences[0] != "guard-aud-v2" {
		t.Errorf("guard policy after v2 = %+v, want latest draft content", gp2)
	}
	// 密钥轮换后 keyset_version 变化；issuer_config_id 跨版本稳定
	wantKV2, err := jwttrust.KeysetVersion(jwks2)
	if err != nil {
		t.Fatalf("KeysetVersion v2: %v", err)
	}
	if gp2.Issuers[0].KeysetVersion != wantKV2 || gp2.Issuers[0].KeysetVersion == wantKV {
		t.Errorf("keyset_version after rotation = %q, want %q (changed from %q)",
			gp2.Issuers[0].KeysetVersion, wantKV2, wantKV)
	}
	if gp2.Issuers[0].IssuerConfigID != wantID {
		t.Errorf("issuer_config_id changed across versions: %q, want stable %q",
			gp2.Issuers[0].IssuerConfigID, wantID)
	}
}
