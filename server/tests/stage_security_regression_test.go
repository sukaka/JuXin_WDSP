// stage_security_regression_test.go 安全回归证据登记与发布门禁接口测试
// （WDSP P1-04 R3；真实 PG/Valkey，未设置环境或 -short 即 skip）。
// 覆盖：迁移建表与权限种子；六个 API + 受控对象上传端点的权限矩阵
// （未认证 401 / AUDIT_ADMIN 只读 / 写操作 403）；门禁策略 PUT 字段校验与
// expected_version 409；对象上传→离线签名→导入全链路（201/幂等 200/
// 同 run_id 异内容 409/伪造签名与未知 key_id 拒绝且不落库）；审计写入。
// 门禁 OFF/OBSERVE/ENFORCE 判定矩阵与发布挂接见 server/internal/regression
// 与 gatewayconfig 单测；真实发布门禁 E2E（隔离栈）不在本文件。
package tests

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/settings"
)

const sregFP = "cfgfpv1:a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
const sregHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const sregChunk = `{"cases":[{"case_id":"WAF-SQLI-001","case_version":1,"criticality":"MANDATORY","family":"sqli","status":"PASS","truth":"ATTACK"},{"case_id":"WAF-BENIGN-001","case_version":1,"criticality":"OPTIONAL","family":"benign","status":"PASS","truth":"BENIGN"}],"run_id":"20260908T010000-abcdef","schema_version":1}`

func sregManifest(chunkHash string, chunkSize int, runID string) string {
	return fmt.Sprintf(`{"candidate":{"build_digest":"sha256:bb","compiler":"go1.24","config_fingerprint":%q,"corpus_id":"p1-corpus","corpus_sha256":%q,"corpus_version":1,"plan_sha256":%q},"counts":{"blocked":0,"executed":2,"failed":0,"mandatory_failed":0,"mandatory_total":1,"not_run":0,"passed":2,"planned":2,"skipped":0},"created_at":"2026-09-08T01:00:00Z","declared_status":"PASS","files":[{"name":"cases-0.json","role":"CASES_CHUNK","sha256":%q,"size_bytes":%d}],"level":"FULL","run_finished_at":"2026-09-08T01:10:00Z","run_id":%q,"run_started_at":"2026-09-08T01:00:00Z","schema_version":1}`,
		sregFP, sregHash, sregHash, chunkHash, chunkSize, runID)
}

// TestSecurityRegressionMigrations 迁移后表/权限/角色授权种子存在。
func TestSecurityRegressionMigrations(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	var n int
	for _, table := range []string{
		"security_regression_objects", "security_regression_runs", "security_regression_cases",
		"security_regression_run_objects", "security_regression_policy", "security_regression_gate_decisions",
	} {
		if err := env.db.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables
WHERE table_name=$1`, table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("table %s missing (n=%d, err=%v)", table, n, err)
		}
	}
	// 策略单行默认 OFF
	var mode string
	if err := env.db.QueryRow(ctx, `SELECT mode FROM security_regression_policy WHERE id=1`).Scan(&mode); err != nil || mode != "OFF" {
		t.Fatalf("default gate policy mode=%q err=%v, want OFF", mode, err)
	}
	// read 三角色全授；import/policy 仅 SYSTEM_ADMIN/SECURITY_ADMIN
	if err := env.db.QueryRow(ctx, `SELECT count(DISTINCT r.code) FROM role_permissions rp
JOIN roles r ON r.id=rp.role_id JOIN permissions p ON p.id=rp.permission_id
WHERE p.code='security_regression.read' AND r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN','AUDIT_ADMIN')`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("security_regression.read role grants=%d, want 3 (err=%v)", n, err)
	}
	for _, code := range []string{"security_regression.import", "security_regression.policy"} {
		if err := env.db.QueryRow(ctx, `SELECT count(DISTINCT r.code) FROM role_permissions rp
JOIN roles r ON r.id=rp.role_id JOIN permissions p ON p.id=rp.permission_id
WHERE p.code=$1 AND r.code IN ('SYSTEM_ADMIN','SECURITY_ADMIN')`, code).Scan(&n); err != nil || n != 2 {
			t.Fatalf("%s role grants=%d, want 2 (err=%v)", code, n, err)
		}
	}
}

// TestSecurityRegressionPermissions 权限矩阵：未认证 401；AUDIT_ADMIN 只读
// （GET 200，写操作 403）；SECURITY_ADMIN 具备写权限（导入/上传/策略修改不再是 403）。
func TestSecurityRegressionPermissions(t *testing.T) {
	env := setupTestEnv(t)

	// 未认证
	resp, err := http.Get(env.server.URL + "/api/v1/security/regressions")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list status=%d, want 401", resp.StatusCode)
	}

	auditCookies, auditCSRF := env.s5Login(t, "sreg_audit", "AUDIT_ADMIN")
	s5Expect(t, env.get(t, "/api/v1/security/regressions", auditCookies), http.StatusOK, "audit list")
	s5Expect(t, env.get(t, "/api/v1/security/regression-policy", auditCookies), http.StatusOK, "audit policy get")
	s5Expect(t, env.post(t, "/api/v1/security/regressions/imports", `{}`, auditCookies, auditCSRF),
		http.StatusForbidden, "audit import")
	s5Expect(t, env.post(t, "/api/v1/security/regression-objects?kind=MANIFEST", `{}`, auditCookies, auditCSRF),
		http.StatusForbidden, "audit upload")
	s5Expect(t, env.do(t, http.MethodPut, "/api/v1/security/regression-policy",
		`{"mode":"OFF","required_level":"FULL","evidence_max_age_seconds":604800,"expected_version":1,"reason":"x"}`,
		auditCookies, auditCSRF), http.StatusForbidden, "audit policy put")

	secCookies, secCSRF := env.s5Login(t, "sreg_sec", "SECURITY_ADMIN")
	s5Expect(t, env.get(t, "/api/v1/security/regressions", secCookies), http.StatusOK, "sec list")
	// SECURITY_ADMIN 写路径不再被权限拦截（策略修改成功）
	s5Expect(t, env.do(t, http.MethodPut, "/api/v1/security/regression-policy",
		`{"mode":"OBSERVE","required_level":"FULL","evidence_max_age_seconds":604800,"expected_version":1,"reason":"开启观测"}`,
		secCookies, secCSRF), http.StatusOK, "sec policy put")
}

// TestSecurityRegressionPolicyValidationAndConflict 策略校验与乐观锁：
// 非法 mode/有效期/缺 reason → 400；过期 expected_version → 409；审计写入。
func TestSecurityRegressionPolicyValidationAndConflict(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "sreg_admin", "SYSTEM_ADMIN")

	// 默认 OFF / version=1
	result := s5OK(t, env.get(t, "/api/v1/security/regression-policy", cookies), "policy get")
	policy := result.Data["policy"].(map[string]interface{})
	if policy["mode"] != "OFF" || int(policy["version"].(float64)) != 1 {
		t.Fatalf("default policy: %+v", policy)
	}

	s5Expect(t, env.do(t, http.MethodPut, "/api/v1/security/regression-policy",
		`{"mode":"PROTECT","required_level":"FULL","evidence_max_age_seconds":604800,"expected_version":1,"reason":"x"}`,
		cookies, csrf), http.StatusBadRequest, "bad mode")
	s5Expect(t, env.do(t, http.MethodPut, "/api/v1/security/regression-policy",
		`{"mode":"ENFORCE","required_level":"FULL","evidence_max_age_seconds":60,"expected_version":1,"reason":"x"}`,
		cookies, csrf), http.StatusBadRequest, "too short max age")
	s5Expect(t, env.do(t, http.MethodPut, "/api/v1/security/regression-policy",
		`{"mode":"ENFORCE","required_level":"FULL","evidence_max_age_seconds":604800,"expected_version":1,"reason":""}`,
		cookies, csrf), http.StatusBadRequest, "empty reason")
	// skip_gate 类未知字段拒绝（DisallowUnknownFields）
	s5Expect(t, env.do(t, http.MethodPut, "/api/v1/security/regression-policy",
		`{"mode":"ENFORCE","required_level":"FULL","evidence_max_age_seconds":604800,"expected_version":1,"reason":"x","skip_gate":true}`,
		cookies, csrf), http.StatusBadRequest, "skip_gate field")

	// 正常升级 ENFORCE → version=2
	s5OK(t, env.do(t, http.MethodPut, "/api/v1/security/regression-policy",
		`{"mode":"ENFORCE","required_level":"FULL","evidence_max_age_seconds":604800,"expected_version":1,"reason":"开启强制"}`,
		cookies, csrf), "put enforce")
	// 过期 expected_version → 409
	s5Expect(t, env.do(t, http.MethodPut, "/api/v1/security/regression-policy",
		`{"mode":"OFF","required_level":"FULL","evidence_max_age_seconds":604800,"expected_version":1,"reason":"并发修改"}`,
		cookies, csrf), http.StatusConflict, "stale expected_version")
	// 正确版本可降级（高风险审计）
	s5OK(t, env.do(t, http.MethodPut, "/api/v1/security/regression-policy",
		`{"mode":"OFF","required_level":"FULL","evidence_max_age_seconds":604800,"expected_version":2,"reason":"回退到观测前"}`,
		cookies, csrf), "downgrade to off")

	var n int
	if err := env.db.QueryRow(context.Background(), `SELECT count(*) FROM operation_audits
WHERE object_type='security_regression_policy'`).Scan(&n); err != nil || n < 2 {
		t.Fatalf("policy audit rows=%d, want >=2 (err=%v)", n, err)
	}
}

// sregUpload 上传受控对象并返回 (id, sha256, size)。
func sregUpload(t *testing.T, env *testEnv, cookies []*http.Cookie, csrf, kind, content string) (string, string, int) {
	t.Helper()
	resp := env.post(t, "/api/v1/security/regression-objects?kind="+kind, content, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload %s status=%d, body: %s", kind, resp.StatusCode, readBodyString(t, resp))
	}
	var result apiResp
	readJSON(t, resp, &result)
	id, _ := result.Data["id"].(string)
	sha, _ := result.Data["sha256"].(string)
	size := int(result.Data["size_bytes"].(float64))
	return id, sha, size
}

// sregRegisterTrustedKey 生成 Ed25519 密钥并把公钥登记进管理配置，返回私钥与 key_id。
func sregRegisterTrustedKey(t *testing.T, env *testEnv, keyID string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	val := fmt.Sprintf(`[{"key_id":%q,"algorithm":"ed25519","public_key":%q,"status":"ACTIVE"}]`,
		keyID, base64.StdEncoding.EncodeToString(pub))
	svc := settings.NewService(env.db)
	if err := svc.UpsertString(context.Background(),
		"security_regression", "trusted_verify_keys", val, "test trusted key", uuid.Nil); err != nil {
		t.Fatalf("register trusted key: %v", err)
	}
	return priv
}

func sregSign(priv ed25519.PrivateKey, keyID, manifest string) string {
	return fmt.Sprintf(`{"algorithm":"ed25519","key_id":%q,"signature":%q}`,
		keyID, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(manifest))))
}

func sregImportBody(manifestID, sig, chunkID string) string {
	return fmt.Sprintf(`{"manifest_object_id":%q,"signature":%s,"objects":[{"object_id":%q,"role":"CASES_CHUNK","name":"cases-0.json"}]}`,
		manifestID, sig, chunkID)
}

// TestSecurityRegressionImportFlow 上传→签名→导入全链路：
// 201 登记；幂等重复导入 200；同 run_id 异内容 409；
// 伪造签名 / 未知 key_id 拒绝且不落库；列表/详情/用例分页可读。
func TestSecurityRegressionImportFlow(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "sreg_imp", "SECURITY_ADMIN")
	priv := sregRegisterTrustedKey(t, env, "verifier-stage")

	chunkID, chunkHash, chunkSize := sregUpload(t, env, cookies, csrf, "CASES_CHUNK", sregChunk)
	manifest := sregManifest(chunkHash, chunkSize, "20260908T010000-abcdef")
	manifestID, _, _ := sregUpload(t, env, cookies, csrf, "MANIFEST", manifest)

	// 1. 正常导入 → 201
	resp := env.post(t, "/api/v1/security/regressions/imports",
		sregImportBody(manifestID, sregSign(priv, "verifier-stage", manifest), chunkID), cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("import status=%d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var created apiResp
	readJSON(t, resp, &created)
	run := created.Data["run"].(map[string]interface{})
	runID := run["id"].(string)
	if run["verification_status"] != "PASSED" || run["declared_status"] != "PASS" {
		t.Fatalf("run status: %+v", run)
	}

	// 2. 幂等重复导入 → 200 idempotent
	resp2 := env.post(t, "/api/v1/security/regressions/imports",
		sregImportBody(manifestID, sregSign(priv, "verifier-stage", manifest), chunkID), cookies, csrf)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("idempotent import status=%d, body: %s", resp2.StatusCode, readBodyString(t, resp2))
	}
	var again apiResp
	readJSON(t, resp2, &again)
	if again.Data["idempotent"] != true {
		t.Fatalf("idempotent flag: %+v", again.Data)
	}

	// 3. 同 run_id 异内容 → 409（改 plan 哈希 → manifest 不同）
	manifest2 := strings.Replace(manifest, sregHash, "f"+sregHash[1:], 1)
	manifest2ID, _, _ := sregUpload(t, env, cookies, csrf, "MANIFEST", manifest2)
	chunk2ID, _, _ := sregUpload(t, env, cookies, csrf, "CASES_CHUNK", sregChunk)
	s5Expect(t, env.post(t, "/api/v1/security/regressions/imports",
		sregImportBody(manifest2ID, sregSign(priv, "verifier-stage", manifest2), chunk2ID), cookies, csrf),
		http.StatusConflict, "same run_id different content")

	// 4. 伪造签名 → 400 且不落库（攻击者私钥签名，冒用已登记 key_id）
	_, evilPriv, _ := ed25519.GenerateKey(rand.Reader)
	chunk3ID, chunk3Hash, chunk3Size := sregUpload(t, env, cookies, csrf, "CASES_CHUNK", sregChunk)
	manifest3 := sregManifest(chunk3Hash, chunk3Size, "20260908T020000-aaaaaa")
	manifest3ID, _, _ := sregUpload(t, env, cookies, csrf, "MANIFEST", manifest3)
	s5Expect(t, env.post(t, "/api/v1/security/regressions/imports",
		sregImportBody(manifest3ID, sregSign(evilPriv, "verifier-stage", manifest3), chunk3ID), cookies, csrf),
		http.StatusBadRequest, "forged signature")

	// 5. 未知 key_id → 400
	chunk4ID, _, _ := sregUpload(t, env, cookies, csrf, "CASES_CHUNK", sregChunk)
	manifest4ID, _, _ := sregUpload(t, env, cookies, csrf, "MANIFEST", manifest3)
	s5Expect(t, env.post(t, "/api/v1/security/regressions/imports",
		sregImportBody(manifest4ID, sregSign(priv, "ghost-key", manifest3), chunk4ID), cookies, csrf),
		http.StatusBadRequest, "unknown key_id")

	// 6. 伪造 PASS（declared_status=PASS 但计数与分块不一致）→ 400
	chunk5ID, chunk5Hash, chunk5Size := sregUpload(t, env, cookies, csrf, "CASES_CHUNK", sregChunk)
	manifest5 := strings.Replace(sregManifest(chunk5Hash, chunk5Size, "20260908T030000-bbbbbb"),
		`"planned":2`, `"planned":3`, 1)
	manifest5ID, _, _ := sregUpload(t, env, cookies, csrf, "MANIFEST", manifest5)
	s5Expect(t, env.post(t, "/api/v1/security/regressions/imports",
		sregImportBody(manifest5ID, sregSign(priv, "verifier-stage", manifest5), chunk5ID), cookies, csrf),
		http.StatusBadRequest, "forged counts")

	// 只有第 1 个运行落库
	var n int
	if err := env.db.QueryRow(context.Background(), `SELECT count(*) FROM security_regression_runs`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("stored runs=%d, want 1 (err=%v)", n, err)
	}

	// 7. 列表/详情/用例分页
	list := s5OK(t, env.get(t, "/api/v1/security/regressions?fingerprint="+sregFP, cookies), "list")
	if int(list.Data["total"].(float64)) != 1 {
		t.Fatalf("list total: %+v", list.Data)
	}
	detail := s5OK(t, env.get(t, "/api/v1/security/regressions/"+runID, cookies), "detail")
	assessment := detail.Data["gate_assessment"].(map[string]interface{})
	if assessment["usable_for_publish"] != true {
		t.Fatalf("gate assessment: %+v", assessment)
	}
	cases := s5OK(t, env.get(t, "/api/v1/security/regressions/"+runID+"/cases?status=PASS", cookies), "cases")
	if int(cases.Data["total"].(float64)) != 2 {
		t.Fatalf("cases total: %+v", cases.Data)
	}
	// 非法过滤参数 400
	s5Expect(t, env.get(t, "/api/v1/security/regressions?level=GREEN", cookies), http.StatusBadRequest, "bad level filter")
	s5Expect(t, env.get(t, "/api/v1/security/regressions/not-a-uuid", cookies), http.StatusBadRequest, "bad run id")

	// 导入审计（成功 1 + 失败 ≥3）
	if err := env.db.QueryRow(context.Background(), `SELECT count(*) FROM operation_audits
WHERE object_type='security_regression_run'`).Scan(&n); err != nil || n < 4 {
		t.Fatalf("import audit rows=%d, want >=4 (err=%v)", n, err)
	}
}

// TestSecurityRegressionUploadLimits 上传限额与非法类别。
func TestSecurityRegressionUploadLimits(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.s5Login(t, "sreg_lim", "SECURITY_ADMIN")
	s5Expect(t, env.post(t, "/api/v1/security/regression-objects?kind=EVIL", "x", cookies, csrf),
		http.StatusBadRequest, "bad kind")
	// 超限对象（manifest 限额 4MiB；构造 4MiB+16 正文）
	big := strings.Repeat("a", 4*1024*1024+16)
	s5Expect(t, env.post(t, "/api/v1/security/regression-objects?kind=MANIFEST", big, cookies, csrf),
		http.StatusBadRequest, "oversize manifest")
}
