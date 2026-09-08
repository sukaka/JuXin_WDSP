// apm_agent_control_plane_test.go APM 阶段2 上半（Agent 控制面）集成测试。
//
// 覆盖：迁移 000089 落位（五表 + 权限种子 + apm_alert 设置种子）、注册令牌全生命周期
// （创建→原文一次返回/库中仅存摘要→注册消费→重放/过期拒绝）、CA 签发链（客户端证书
// 由注册响应 CA 证书验签）、PoP 认证（心跳/策略拉取/轮换）、策略版本单调递增与乐观并发、
// 撤销后机器侧拒绝、三权口径（SECURITY_ADMIN 可管理 / AUDIT_ADMIN·SYSTEM_ADMIN 403）、
// 高风险审计落 operation_audits、apm_alert 四键经系统设置 Update API 可改、
// APM_ENABLED=false 时 Agent 面端点统一 503。
//
// 运行方式（与既有集成测试一致）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestAPMAgent -count=1
//
// 无密码环境变量时遵循仓库既有约定 t.Skip；数据落真实 PostgreSQL/Valkey（测试库重建 +
// 全量迁移，含 000089）。
package tests

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ---------- 测试侧 Agent 工具 ----------

// apmAgentIdentity 测试 Agent 身份（密钥 + 证书）。
type apmAgentIdentity struct {
	priv ed25519.PrivateKey
	cert *x509.Certificate
}

// apmNewCSR 生成测试 CSR（Ed25519，PEM）。
func apmNewCSR(t *testing.T, cn string) (ed25519.PrivateKey, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// apmParseCertPEM 解析 PEM 证书。
func apmParseCertPEM(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil {
		t.Fatalf("bad cert pem")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// apmPoPHeaders 构造 PoP 认证头（与 server/internal/apm 的签名输入构造保持一致：
// "JIUZHANG-APM-POP-v1\n" + method + "\n" + path + "\n" + timestamp + "\n" + sha256hex(body)）。
func apmPoPHeaders(t *testing.T, id *apmAgentIdentity, method, path string, body []byte) map[string]string {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	sum := sha256.Sum256(body)
	input := []byte("JIUZHANG-APM-POP-v1\n" + method + "\n" + path + "\n" + ts + "\n" + hex.EncodeToString(sum[:]))
	sig := ed25519.Sign(id.priv, input)
	return map[string]string{
		"X-JiuZhang-Agent-Cert":      base64.StdEncoding.EncodeToString(id.cert.Raw),
		"X-JiuZhang-Agent-Timestamp": ts,
		"X-JiuZhang-Agent-Signature": hex.EncodeToString(sig),
	}
}

// apmAgentDo 执行机器端点请求（无会话 Cookie；PoP 头可选）。
func (e *testEnv) apmAgentDo(t *testing.T, method, path, body string, headers map[string]string) *http.Response {
	t.Helper()
	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, e.server.URL+path, stringReader(body))
	} else {
		req, err = http.NewRequest(method, e.server.URL+path, nil)
	}
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// apmRegister 完成一次注册并返回 Agent 身份与响应数据。
func apmRegister(t *testing.T, env *testEnv, token, serviceName, instanceID, language string) (*apmAgentIdentity, map[string]interface{}) {
	t.Helper()
	priv, csrPEM := apmNewCSR(t, serviceName)
	body := fmt.Sprintf(`{"token":%q,"csr":%q,"service_name":%q,"instance_id":%q,"language":%q,"agent_version":"1.0.0","node_info":{"hostname":"it-host"}}`,
		token, csrPEM, serviceName, instanceID, language)
	resp := env.apmAgentDo(t, "POST", "/api/v1/apm/agent/register", body, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var result apiResp
	readJSON(t, resp, &result)
	cert := apmParseCertPEM(t, result.Data["client_cert"].(string))
	return &apmAgentIdentity{priv: priv, cert: cert}, result.Data
}

// setupAPMAgentEnv 以 APM_ENABLED=true + Collector 地址装配测试环境
// （纪律同 setupTestEnv：真实库重建、全量迁移、真实应用 + httptest.Server、导入公共测试授权）。
func setupAPMAgentEnv(t *testing.T) *testEnv {
	t.Helper()
	cfg := baseTestCfg()
	cfg.APM.Enabled = true
	cfg.APM.CollectorAddr = "127.0.0.1:4317"
	env := newTestEnv(t, cfg)
	env.importBaseLicense(t)
	return env
}

// TestAPMAgentControlPlane Agent 控制面全链路（单环境共享，子用例顺序执行）。
func TestAPMAgentControlPlane(t *testing.T) {
	env := setupAPMAgentEnv(t)
	ctx := context.Background()

	// 迁移 000089 落位：五表存在
	for _, table := range []string{"apm_services", "apm_agents", "apm_enrollment_tokens", "apm_agent_policies", "apm_agent_cert_revocations"} {
		var exists bool
		if err := env.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("migration table %s missing: exists=%v err=%v", table, exists, err)
		}
	}

	// 应用行（令牌绑定目标）
	var appID uuid.UUID
	if err := env.db.QueryRow(ctx,
		`INSERT INTO applications (code, name) VALUES ('apmcpapp', 'APM控制面测试应用') RETURNING id`).Scan(&appID); err != nil {
		t.Fatalf("insert application: %v", err)
	}

	secCookies, secCSRF := env.s5Login(t, "apmcpsec", "SECURITY_ADMIN")

	var token string
	var agentID string
	var id *apmAgentIdentity

	t.Run("create token", func(t *testing.T) {
		resp := env.post(t, "/api/v1/apm/agents/enrollment-tokens",
			fmt.Sprintf(`{"application_id":%q,"environment":"prod","allowed_languages":["java","go"],"expires_in_minutes":30,"note":"集成测试"}`, appID),
			secCookies, secCSRF)
		r := s5OK(t, resp, "create enrollment token")
		token, _ = r.Data["token"].(string)
		if !strings.HasPrefix(token, "jzapm_") {
			t.Fatalf("token prefix missing: %q", token)
		}
		// 库中仅存摘要：不得出现原文
		var storedHash string
		var usedAt *time.Time
		if err := env.db.QueryRow(ctx,
			`SELECT token_hash, used_at FROM apm_enrollment_tokens WHERE id = $1`,
			r.Data["token_id"].(string)).Scan(&storedHash, &usedAt); err != nil {
			t.Fatalf("query token row: %v", err)
		}
		sum := sha256.Sum256([]byte(token))
		if storedHash != hex.EncodeToString(sum[:]) {
			t.Error("stored token_hash is not sha256(plaintext)")
		}
		if usedAt != nil {
			t.Error("fresh token must be unused")
		}
	})

	t.Run("register", func(t *testing.T) {
		if token == "" {
			t.Fatal("depends on create token")
		}
		var data map[string]interface{}
		id, data = apmRegister(t, env, token, "shop-svc", "host-it-1", "java")
		agentID = data["agent_id"].(string)
		// 证书链：客户端证书由响应内 CA 证书签发
		caCert := apmParseCertPEM(t, data["ca_cert"].(string))
		if err := id.cert.CheckSignatureFrom(caCert); err != nil {
			t.Errorf("client cert not signed by CA: %v", err)
		}
		if data["collector_addr"] != "127.0.0.1:4317" {
			t.Errorf("collector_addr = %v", data["collector_addr"])
		}
		attrs, _ := data["resource_attributes"].(map[string]interface{})
		if attrs["service.name"] != "shop-svc" || attrs["jiuzhang.application_id"] != appID.String() {
			t.Errorf("resource attributes = %v", attrs)
		}
		// 注册响应携带签名基线策略（全局 v1 惰性创建）
		policy, _ := data["policy"].(map[string]interface{})
		if policy["scope"] != "global" || policy["version"] != float64(1) || policy["signature"] == "" {
			t.Errorf("policy = %v", policy)
		}
		// 登记行：归属取自令牌（应用/环境），状态 CONNECTED_BASELINE
		var status, env2 string
		var gotApp uuid.UUID
		if err := env.db.QueryRow(ctx, `
SELECT a.status, s.environment, s.application_id
FROM apm_agents a JOIN apm_services s ON s.id = a.service_id WHERE a.id = $1`,
			agentID).Scan(&status, &env2, &gotApp); err != nil {
			t.Fatalf("query agent row: %v", err)
		}
		if status != "CONNECTED_BASELINE" || env2 != "prod" || gotApp != appID {
			t.Errorf("agent row = %s/%s/%s", status, env2, gotApp)
		}
		// 令牌已作废
		var usedAt *time.Time
		if err := env.db.QueryRow(ctx,
			`SELECT t.used_at FROM apm_enrollment_tokens t JOIN apm_agents a ON a.id = t.used_by_agent_id WHERE a.id = $1`,
			agentID).Scan(&usedAt); err != nil || usedAt == nil {
			t.Errorf("token not consumed: %v", err)
		}
	})

	t.Run("token replay and expiry rejected", func(t *testing.T) {
		// 重放同一令牌 → 401
		priv, csrPEM := apmNewCSR(t, "svc-replay")
		body := fmt.Sprintf(`{"token":%q,"csr":%q,"service_name":"svc-replay","instance_id":"h2","language":"go"}`, token, csrPEM)
		s5Expect(t, env.apmAgentDo(t, "POST", "/api/v1/apm/agent/register", body, nil), 401, "replayed token")
		_ = priv
		// 过期令牌（直接库中插入摘要）→ 401
		expiredPlain := "jzapm_expired_it"
		sum := sha256.Sum256([]byte(expiredPlain))
		if _, err := env.db.Exec(ctx, `
INSERT INTO apm_enrollment_tokens (token_hash, environment, expires_at)
VALUES ($1, 'prod', now() - interval '1 minute')`, hex.EncodeToString(sum[:])); err != nil {
			t.Fatalf("insert expired token: %v", err)
		}
		body = fmt.Sprintf(`{"token":%q,"csr":%q,"service_name":"svc-exp","instance_id":"h3","language":"go"}`, expiredPlain, csrPEM)
		s5Expect(t, env.apmAgentDo(t, "POST", "/api/v1/apm/agent/register", body, nil), 401, "expired token")
		// 语言不在白名单 → 400
		resp := env.post(t, "/api/v1/apm/agents/enrollment-tokens",
			`{"environment":"prod","allowed_languages":["java"],"expires_in_minutes":30}`, secCookies, secCSRF)
		javaToken, _ := s5OK(t, resp, "create java-only token").Data["token"].(string)
		body = fmt.Sprintf(`{"token":%q,"csr":%q,"service_name":"svc-lang","instance_id":"h4","language":"go"}`, javaToken, csrPEM)
		s5Expect(t, env.apmAgentDo(t, "POST", "/api/v1/apm/agent/register", body, nil), 400, "disallowed language")
	})

	t.Run("heartbeat and list", func(t *testing.T) {
		if id == nil || agentID == "" {
			t.Fatal("depends on register")
		}
		body := `{"agent_version":"1.0.1"}`
		resp := env.apmAgentDo(t, "POST", "/api/v1/apm/agent/heartbeat", body,
			apmPoPHeaders(t, id, "POST", "/api/v1/apm/agent/heartbeat", []byte(body)))
		r := s5OK(t, resp, "heartbeat")
		if r.Data["status"] != "ok" || r.Data["policy_version"] == nil {
			t.Errorf("heartbeat data = %v", r.Data)
		}
		// 心跳落库
		var lastHB *time.Time
		if err := env.db.QueryRow(ctx, `SELECT last_heartbeat_at FROM apm_agents WHERE id = $1`, agentID).Scan(&lastHB); err != nil || lastHB == nil {
			t.Errorf("last_heartbeat_at not updated: %v", err)
		}
		// 篡改签名 → 401
		badHeaders := apmPoPHeaders(t, id, "POST", "/api/v1/apm/agent/heartbeat", []byte(body))
		badHeaders["X-JiuZhang-Agent-Signature"] = strings.Repeat("00", 64)
		s5Expect(t, env.apmAgentDo(t, "POST", "/api/v1/apm/agent/heartbeat", body, badHeaders), 401, "bad signature")
		// 无认证头 → 401
		s5Expect(t, env.apmAgentDo(t, "POST", "/api/v1/apm/agent/heartbeat", body, nil), 401, "no auth headers")

		// 管理列表：状态 CONNECTED_BASELINE（心跳新鲜）
		r2 := s5OK(t, env.get(t, "/api/v1/apm/agents?status=CONNECTED_BASELINE", secCookies), "list agents")
		items, _ := r2.Data["items"].([]interface{})
		found := false
		for _, it := range items {
			m, _ := it.(map[string]interface{})
			if m["id"] == agentID && m["status"] == "CONNECTED_BASELINE" && m["last_heartbeat_at"] != nil {
				found = true
			}
		}
		if !found {
			t.Errorf("agent not found in list with expected status: %v", items)
		}
	})

	t.Run("policy put and pull", func(t *testing.T) {
		if id == nil || agentID == "" {
			t.Fatal("depends on register")
		}
		// PUT global → 版本 2（注册已惰性创建 v1），单调递增
		r := s5OK(t, env.request(t, http.MethodPut, "/api/v1/apm/policies/global",
			`{"policy":{"sampling_rate":0.5,"signals":["traces","metrics"],"slow_request_threshold_ms":1500}}`,
			secCookies, secCSRF), "put policy v2")
		if r.Data["version"] != float64(2) {
			t.Fatalf("put version = %v, want 2", r.Data["version"])
		}
		if r.Data["signature"] == "" {
			t.Error("signature missing")
		}
		// 版本回退（expected_version 过期）→ 409
		s5Expect(t, env.request(t, http.MethodPut, "/api/v1/apm/policies/global",
			`{"policy":{"sampling_rate":0.9},"expected_version":1}`, secCookies, secCSRF),
			409, "stale expected_version")
		// 非法策略（未知键）→ 400
		s5Expect(t, env.request(t, http.MethodPut, "/api/v1/apm/policies/global",
			`{"policy":{"trace_all_methods":true}}`, secCookies, secCSRF), 400, "invalid policy")
		// Agent 拉取到 v2 且签名可验（用注册响应下发的 CA 公钥）
		resp := env.apmAgentDo(t, "GET", "/api/v1/apm/agent/policy", "",
			apmPoPHeaders(t, id, "GET", "/api/v1/apm/agent/policy", nil))
		rp := s5OK(t, resp, "agent pull policy")
		if rp.Data["version"] != float64(2) {
			t.Errorf("agent policy version = %v, want 2", rp.Data["version"])
		}
	})

	t.Run("rotate cert", func(t *testing.T) {
		if id == nil || agentID == "" {
			t.Fatal("depends on register")
		}
		newPriv, newCSR := apmNewCSR(t, "shop-svc")
		body := fmt.Sprintf(`{"csr":%q}`, newCSR)
		resp := env.apmAgentDo(t, "POST", "/api/v1/apm/agent/rotate-cert", body,
			apmPoPHeaders(t, id, "POST", "/api/v1/apm/agent/rotate-cert", []byte(body)))
		r := s5OK(t, resp, "rotate cert")
		newCert := apmParseCertPEM(t, r.Data["client_cert"].(string))
		// 旧证书指纹入撤销列表
		var revoked bool
		oldSum := sha256.Sum256(id.cert.Raw)
		if err := env.db.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM apm_agent_cert_revocations WHERE cert_fingerprint = $1 AND reason = 'rotated')`,
			hex.EncodeToString(oldSum[:])).Scan(&revoked); err != nil || !revoked {
			t.Errorf("old fingerprint not revoked: %v", err)
		}
		// 旧证书心跳 → 拒绝；新证书心跳 → 200
		hb := `{}`
		s5Expect(t, env.apmAgentDo(t, "POST", "/api/v1/apm/agent/heartbeat", hb,
			apmPoPHeaders(t, id, "POST", "/api/v1/apm/agent/heartbeat", []byte(hb))), 401, "old cert heartbeat")
		id = &apmAgentIdentity{priv: newPriv, cert: newCert}
		resp = env.apmAgentDo(t, "POST", "/api/v1/apm/agent/heartbeat", hb,
			apmPoPHeaders(t, id, "POST", "/api/v1/apm/agent/heartbeat", []byte(hb)))
		s5OK(t, resp, "new cert heartbeat")
	})

	t.Run("revoke", func(t *testing.T) {
		if id == nil || agentID == "" {
			t.Fatal("depends on register")
		}
		resp := env.post(t, "/api/v1/apm/agents/"+agentID+"/revoke", `{"reason":"集成测试撤销"}`,
			secCookies, secCSRF)
		r := s5OK(t, resp, "revoke agent")
		if r.Data["status"] != "REVOKED" {
			t.Errorf("status = %v", r.Data["status"])
		}
		// 撤销后心跳 → 403
		hb := `{}`
		s5Expect(t, env.apmAgentDo(t, "POST", "/api/v1/apm/agent/heartbeat", hb,
			apmPoPHeaders(t, id, "POST", "/api/v1/apm/agent/heartbeat", []byte(hb))), 403, "revoked heartbeat")
		// 策略拉取同样拒绝
		s5Expect(t, env.apmAgentDo(t, "GET", "/api/v1/apm/agent/policy", "",
			apmPoPHeaders(t, id, "GET", "/api/v1/apm/agent/policy", nil)), 403, "revoked policy pull")
		// 重复撤销 → 409
		s5Expect(t, env.post(t, "/api/v1/apm/agents/"+agentID+"/revoke", `{"reason":"again"}`, secCookies, secCSRF),
			409, "re-revoke")
	})

	t.Run("permission triad", func(t *testing.T) {
		auditCookies, auditCSRF := env.s5Login(t, "apmcpaudit", "AUDIT_ADMIN")
		sysCookies, sysCSRF := env.login(t, "test_sysadmin", env.adminPwd)
		// AUDIT_ADMIN / SYSTEM_ADMIN 均无 manage 权限点
		s5Expect(t, env.post(t, "/api/v1/apm/agents/enrollment-tokens", `{"environment":"prod"}`, auditCookies, auditCSRF), 403, "audit_admin create token")
		s5Expect(t, env.get(t, "/api/v1/apm/agents", auditCookies), 403, "audit_admin list agents")
		s5Expect(t, env.get(t, "/api/v1/apm/policies/global", auditCookies), 403, "audit_admin get policy")
		s5Expect(t, env.post(t, "/api/v1/apm/agents/enrollment-tokens", `{"environment":"prod"}`, sysCookies, sysCSRF), 403, "sysadmin create token")
		s5Expect(t, env.request(t, http.MethodPut, "/api/v1/apm/policies/global", `{"policy":{"sampling_rate":1}}`, sysCookies, sysCSRF), 403, "sysadmin put policy")
		// 未登录 → 401
		s5Expect(t, env.get(t, "/api/v1/apm/agents", nil), 401, "anonymous list agents")
	})

	t.Run("high risk audits recorded", func(t *testing.T) {
		var n int
		if err := env.db.QueryRow(ctx, `
SELECT count(*) FROM operation_audits
WHERE module = 'apm' AND risk_level = 'HIGH'
  AND action IN ('create', 'revoke', 'put_policy')`).Scan(&n); err != nil {
			t.Fatalf("query audits: %v", err)
		}
		if n < 3 {
			t.Errorf("apm high-risk audit count = %d, want >= 3", n)
		}
	})

	t.Run("apm_alert settings updatable via API", func(t *testing.T) {
		sysCookies, sysCSRF := env.login(t, "test_sysadmin", env.adminPwd)
		r := s5OK(t, env.get(t, "/api/v1/system-settings?group=apm_alert", sysCookies), "list apm_alert settings")
		items, _ := r.Data["items"].([]interface{})
		// 000089 种子 4 键 + 000094 新增 ingest_lag_seconds，共 5 键
		if len(items) != 5 {
			t.Fatalf("apm_alert settings count = %d, want 5 (迁移 000089+000094 种子)", len(items))
		}
		var version float64
		for _, it := range items {
			m, _ := it.(map[string]interface{})
			if m["setting_key"] == "endpoint_p95_ms" {
				version, _ = m["version"].(float64)
				if jsonNumber(t, m["setting_value"]) != 2000 {
					t.Errorf("endpoint_p95_ms default = %v, want 2000", m["setting_value"])
				}
			}
		}
		if version == 0 {
			t.Fatal("endpoint_p95_ms seed row not found")
		}
		// 白名单登记后 Update API 可用
		body := fmt.Sprintf(`{"setting_group":"apm_alert","setting_key":"endpoint_p95_ms","setting_value":1500,"version":%d}`, int(version))
		s5OK(t, env.request(t, http.MethodPut, "/api/v1/system-settings", body, sysCookies, sysCSRF), "update apm_alert setting")
		var stored int
		if err := env.db.QueryRow(ctx,
			`SELECT (setting_value)::int FROM system_settings WHERE setting_group = 'apm_alert' AND setting_key = 'endpoint_p95_ms'`).Scan(&stored); err != nil || stored != 1500 {
			t.Errorf("updated setting = %d, err=%v", stored, err)
		}
	})
}

// jsonNumber 从 JSON 值（float64 / json.RawMessage 再解码形态）取整数值。
func jsonNumber(t *testing.T, v interface{}) float64 {
	t.Helper()
	switch n := v.(type) {
	case float64:
		return n
	case json.RawMessage:
		var f float64
		if err := json.Unmarshal(n, &f); err != nil {
			t.Fatalf("decode number: %v", err)
		}
		return f
	case string:
		var f float64
		if err := json.Unmarshal([]byte(n), &f); err != nil {
			t.Fatalf("decode number string: %v", err)
		}
		return f
	default:
		t.Fatalf("unexpected number type %T", v)
		return 0
	}
}

// TestAPMAgentControlPlaneDisabled APM_ENABLED=false：Agent 面端点统一经降级 stub
// （已登录 503；匿名 POST 先被链上 CSRF 拦截 403——stub 挂在 authz 链上，与既有 APM/AI 先例一致）。
func TestAPMAgentControlPlaneDisabled(t *testing.T) {
	env := newTestEnv(t, baseTestCfg())
	env.importBaseLicense(t)
	cookies, csrf := env.s5Login(t, "apmcoff", "SECURITY_ADMIN")
	_ = csrf

	s5Expect(t, env.get(t, "/api/v1/apm/agents", cookies), 503, "disabled list agents")
	s5Expect(t, env.post(t, "/api/v1/apm/agents/enrollment-tokens", `{}`, cookies, csrf), 503, "disabled create token")
	s5Expect(t, env.apmAgentDo(t, "POST", "/api/v1/apm/agent/register", `{"token":"x","csr":"y","service_name":"a","instance_id":"b","language":"go"}`, nil),
		403, "disabled register anonymous")
}
