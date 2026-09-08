package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/certificates"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/validation"
)

// ---------- 校验逻辑单元测试（不依赖DB） ----------

func TestAppCodeValidation(t *testing.T) {
	cases := []struct {
		code    string
		wantErr bool
	}{
		{"portal-system", false}, {"finance-api", false}, {"ab", true},
		{"A-Upper", true}, {"double--dash", true}, {"with_underscore", true},
	}
	for _, c := range cases {
		err := validation.ValidateAppCode(c.code)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateAppCode(%q) err=%v wantErr=%v", c.code, err, c.wantErr)
		}
	}
}

func TestDomainNormalization(t *testing.T) {
	if got := validation.NormalizeHostname("WWW.Example.COM."); got != "www.example.com" {
		t.Errorf("normalize = %q", got)
	}
}

func TestWildcardRules(t *testing.T) {
	if _, _, err := validation.ValidateHostname("*.example.com"); err != nil {
		t.Errorf("valid wildcard rejected: %v", err)
	}
	if _, _, err := validation.ValidateHostname("*example.com"); err == nil {
		t.Error("invalid wildcard *example.com should be rejected")
	}
	if _, _, err := validation.ValidateHostname("api.*.example.com"); err == nil {
		t.Error("mid wildcard should be rejected")
	}
}

func TestSSRFAddressValidation(t *testing.T) {
	// 云元数据应被阻止
	if _, err := validation.ResolveAndValidate("169.254.169.254", false); err == nil {
		t.Error("cloud metadata address should be blocked")
	}
	// 回环地址默认被阻止
	if _, err := validation.ResolveAndValidate("127.0.0.1", false); err == nil {
		t.Error("loopback should be blocked by default")
	}
	// 公网 IP 允许
	if _, err := validation.ResolveAndValidate("8.8.8.8", false); err != nil {
		t.Errorf("public ip should be allowed: %v", err)
	}
	// 私网在 allowPrivate=true 时允许
	if _, err := validation.ResolveAndValidate("192.168.1.1", true); err != nil {
		t.Errorf("private ip with allowPrivate should pass: %v", err)
	}
}

func TestEncryptionRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	svc, _ := encryption.NewWithKey(key)
	secret := "private-key-content-12345"
	enc, err := svc.Encrypt(secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if enc == secret {
		t.Error("ciphertext equals plaintext")
	}
	dec, err := svc.Decrypt(enc)
	if err != nil || dec != secret {
		t.Errorf("roundtrip failed: %v", err)
	}
}

// ---------- 配置生成器确定性（不依赖DB） ----------

func TestGeneratorDeterminism(t *testing.T) {
	apps := []gatewayconfig.AppData{
		{
			Code:           "app1",
			ProtectionMode: applications.ModeProtect,
			Domains: []applications.Domain{
				{NormalizedHostname: "a.com", DomainType: "EXACT", HTTPEnabled: true, HTTPPort: intPtrTest(8080), Status: "ACTIVE"},
			},
			Upstreams: []applications.Upstream{
				{NormalizedHost: "192.0.2.1", Port: 9001, Weight: 10, Status: "ACTIVE", ConnectTimeoutMs: 3000, ResponseHeaderTimeoutMs: 10000},
			},
		},
	}
	in := gatewayconfig.GenerateInput{Apps: apps, AdminSocket: "/var/run/caddy/admin.sock"}
	g1, err1 := gatewayconfig.Generate(in)
	g2, err2 := gatewayconfig.Generate(in)
	if err1 != nil || err2 != nil {
		t.Fatalf("generate: %v %v", err1, err2)
	}
	if g1.Hash != g2.Hash {
		t.Errorf("determinism failed: %s vs %s", g1.Hash, g2.Hash)
	}
}

func intPtrTest(v int) *int { return &v }

// ---------- 集成测试（依赖DB） ----------

// TestStage3CreateApplication 创建应用与重复编码冲突。
func TestStage3CreateApplication(t *testing.T) {
	env := setupTestEnv(t)
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	// 系统管理员创建业务应用应被拒绝（三权边界）
	resp := env.post(t, "/api/v1/applications", `{"code":"biz-app","name":"业务","protection_mode":"OBSERVE"}`, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("sysadmin create app status = %d, want 403", resp.StatusCode)
	}
}

// TestStage3SecurityAdminCRUD 安全管理员应用 CRUD。
func TestStage3SecurityAdminCRUD(t *testing.T) {
	env := setupTestEnv(t)
	// 创建安全管理员
	env.createUserDirect(t, "sec_s3_test", "SecS3@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s3_test", "SecS3@Test2026!")

	// 创建应用
	resp := env.post(t, "/api/v1/applications", `{"code":"test-app-1","name":"测试应用","protection_mode":"PROTECT"}`, cookies, csrf)
	var result apiResp
	readJSON(t, resp, &result)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create app status = %d", resp.StatusCode)
	}
	appID, _ := result.Data["id"].(string)
	if appID == "" {
		t.Fatal("no app id")
	}

	// 重复编码冲突
	resp2 := env.post(t, "/api/v1/applications", `{"code":"test-app-1","name":"重复","protection_mode":"OBSERVE"}`, cookies, csrf)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("duplicate code status = %d, want 409", resp2.StatusCode)
	}
}

// TestStage3DomainValidation 域名校验。
func TestStage3DomainValidation(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s3_dom", "SecS3@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s3_dom", "SecS3@Test2026!")
	resp := env.post(t, "/api/v1/applications", `{"code":"dom-test","name":"域名测试","protection_mode":"OBSERVE"}`, cookies, csrf)
	var result apiResp
	readJSON(t, resp, &result)
	resp.Body.Close()
	appID, _ := result.Data["id"].(string)

	// 合法域名
	r1 := env.post(t, fmt.Sprintf("/api/v1/applications/%s/domains", appID),
		`{"hostname":"www.example.com","is_primary":true,"http_enabled":true,"http_port":8080}`, cookies, csrf)
	r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Errorf("valid domain status = %d", r1.StatusCode)
	}
	// 泛域名
	r2 := env.post(t, fmt.Sprintf("/api/v1/applications/%s/domains", appID),
		`{"hostname":"*.api.example.com","http_enabled":true,"http_port":8081}`, cookies, csrf)
	r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Errorf("wildcard domain status = %d", r2.StatusCode)
	}
	// 非法泛域名
	r3 := env.post(t, fmt.Sprintf("/api/v1/applications/%s/domains", appID),
		`{"hostname":"*example.com","http_enabled":true,"http_port":8082}`, cookies, csrf)
	r3.Body.Close()
	if r3.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid wildcard status = %d, want 400", r3.StatusCode)
	}
	// 含协议的域名
	r4 := env.post(t, fmt.Sprintf("/api/v1/applications/%s/domains", appID),
		`{"hostname":"http://evil.com","http_enabled":true,"http_port":8083}`, cookies, csrf)
	r4.Body.Close()
	if r4.StatusCode != http.StatusBadRequest {
		t.Errorf("protocol domain status = %d, want 400", r4.StatusCode)
	}
}

// TestStage3DomainUpdateSelfNoConflict MED-18 回归：更新自身 ACTIVE 域名不得与自己冲突；
// 跨应用同域名同端口仍必须报冲突。
func TestStage3DomainUpdateSelfNoConflict(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s3_dupd", "SecS3@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s3_dupd", "SecS3@Test2026!")

	suffix := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	host := "upd-" + suffix + ".example.com"

	resp := env.post(t, "/api/v1/applications",
		fmt.Sprintf(`{"code":"dom-upd-%s","name":"域名更新测试","protection_mode":"OBSERVE"}`, suffix), cookies, csrf)
	var result apiResp
	readJSON(t, resp, &result)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create app status = %d", resp.StatusCode)
	}
	appID, _ := result.Data["id"].(string)

	// 添加 ACTIVE 域名（AddDomain 默认 status=ACTIVE）
	resp = env.post(t, fmt.Sprintf("/api/v1/applications/%s/domains", appID),
		fmt.Sprintf(`{"hostname":%q,"is_primary":true,"http_enabled":true,"http_port":8080}`, host), cookies, csrf)
	readJSON(t, resp, &result)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add domain status = %d, data=%v", resp.StatusCode, result.Data)
	}
	domainID, _ := result.Data["id"].(string)
	if domainID == "" {
		t.Fatalf("no domain id in response: %+v", result.Data)
	}

	// 更新自身：同域名同端口仅改跳转开关，不得报与自身冲突（修复前 excludeID 未生效会 409）
	resp = env.request(t, http.MethodPut, fmt.Sprintf("/api/v1/applications/%s/domains/%s", appID, domainID),
		fmt.Sprintf(`{"hostname":%q,"is_primary":true,"http_enabled":true,"http_port":8080,"redirect_http_to_https":false}`, host),
		cookies, csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("update own domain status = %d, want 200（不得与自身冲突）", resp.StatusCode)
	}

	// 跨应用冲突仍须检出：另一应用添加同域名同端口
	resp = env.post(t, "/api/v1/applications",
		fmt.Sprintf(`{"code":"dom-upd-b-%s","name":"域名冲突方","protection_mode":"OBSERVE"}`, suffix), cookies, csrf)
	readJSON(t, resp, &result)
	resp.Body.Close()
	appID2, _ := result.Data["id"].(string)
	resp = env.post(t, fmt.Sprintf("/api/v1/applications/%s/domains", appID2),
		fmt.Sprintf(`{"hostname":%q,"http_enabled":true,"http_port":8080}`, host), cookies, csrf)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("cross-app domain conflict status = %d, want 409", resp.StatusCode)
	}
}

// TestStage3UpstreamSSRF 源站 SSRF 防护。
func TestStage3UpstreamSSRF(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s3_ssrf", "SecS3@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s3_ssrf", "SecS3@Test2026!")

	// 云元数据地址应被阻止
	resp := env.post(t, "/api/v1/upstreams/test",
		`{"scheme":"http","host":"169.254.169.254","port":80}`, cookies, csrf)
	defer resp.Body.Close()
	var result apiResp
	readJSON(t, resp, &result)
	errCode, _ := result.Data["error_code"].(string)
	if errCode != "SSRF_BLOCKED" {
		t.Errorf("metadata test error_code = %q, want SSRF_BLOCKED", errCode)
	}

	// 回环地址默认被阻止
	resp2 := env.post(t, "/api/v1/upstreams/test",
		`{"scheme":"http","host":"127.0.0.1","port":8080}`, cookies, csrf)
	defer resp2.Body.Close()
	var result2 apiResp
	readJSON(t, resp2, &result2)
	errCode2, _ := result2.Data["error_code"].(string)
	if errCode2 != "SSRF_BLOCKED" {
		t.Errorf("loopback test error_code = %q, want SSRF_BLOCKED", errCode2)
	}

	// 非法协议被拒绝（由测试器或校验层）
	resp3 := env.post(t, "/api/v1/upstreams/test",
		`{"scheme":"file","host":"etc","port":0}`, cookies, csrf)
	defer resp3.Body.Close()
	var result3 apiResp
	readJSON(t, resp3, &result3)
	if result3.Data["error_code"] == nil {
		t.Error("file scheme should be rejected")
	}
}

// TestStage3CertificateUpload 证书上传与校验。
func TestStage3CertificateUpload(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s3_cert", "SecS3@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s3_cert", "SecS3@Test2026!")

	// 生成测试证书
	certPEM, keyPEM := generateTestCertPEM(t, "www.example.com", []string{"www.example.com"})

	// 上传合法证书
	body := fmt.Sprintf(`{"name":"test-cert","cert_pem":%q,"key_pem":%q}`, certPEM, keyPEM)
	resp := env.post(t, "/api/v1/certificates", body, cookies, csrf)
	defer resp.Body.Close()
	var result apiResp
	readJSON(t, resp, &result)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload cert status = %d, msg: %v", resp.StatusCode, result.Message)
	}
	certID, _ := result.Data["id"].(string)
	if certID == "" {
		t.Fatal("no cert id")
	}

	// 重复证书（相同指纹）应被拒绝
	resp2 := env.post(t, "/api/v1/certificates", body, cookies, csrf)
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Error("duplicate cert should be rejected")
	}
}

// TestStage3CertificateKeyMismatch 私钥不匹配拒绝。
func TestStage3CertificateKeyMismatch(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s3_mm", "SecS3@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s3_mm", "SecS3@Test2026!")

	certPEM, _ := generateTestCertPEM(t, "a.com", []string{"a.com"})
	_, otherKeyPEM := generateTestCertPEM(t, "b.com", []string{"b.com"})

	body := fmt.Sprintf(`{"name":"mismatch-cert","cert_pem":%q,"key_pem":%q}`, certPEM, otherKeyPEM)
	resp := env.post(t, "/api/v1/certificates", body, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("mismatched key should be rejected")
	}
}

// TestStage3CertificateExpired 过期证书拒绝。
func TestStage3CertificateExpired(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s3_exp", "SecS3@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s3_exp", "SecS3@Test2026!")

	certPEM, keyPEM := generateTestCertPEMWithValidity(t, "expired.com",
		time.Now().Add(-72*time.Hour), time.Now().Add(-time.Hour))
	body := fmt.Sprintf(`{"name":"expired-cert","cert_pem":%q,"key_pem":%q}`, certPEM, keyPEM)
	resp := env.post(t, "/api/v1/certificates", body, cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Error("expired cert should be rejected")
	}
}

// TestStage3PrivateKeyNotExposed 私钥不通过API泄露。
func TestStage3PrivateKeyNotExposed(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s3_pk", "SecS3@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s3_pk", "SecS3@Test2026!")
	certPEM, keyPEM := generateTestCertPEM(t, "pk.com", []string{"pk.com"})
	body := fmt.Sprintf(`{"name":"pk-cert","cert_pem":%q,"key_pem":%q}`, certPEM, keyPEM)
	resp := env.post(t, "/api/v1/certificates", body, cookies, csrf)
	var result apiResp
	readJSON(t, resp, &result)
	resp.Body.Close()
	certID, _ := result.Data["id"].(string)

	// 列表与详情不得包含私钥内容
	for _, path := range []string{"/api/v1/certificates", "/api/v1/certificates/" + certID} {
		resp2 := env.get(t, path, cookies)
		body := readBodyString(t, resp2)
		resp2.Body.Close()
		if contains(body, "PRIVATE KEY") || contains(body, "BEGIN RSA") {
			t.Errorf("%s leaks private key", path)
		}
	}
}

// generateTestCertPEM 生成测试用自签名证书（有效期1年）。
func generateTestCertPEM(t *testing.T, cn string, sans []string) (string, string) {
	t.Helper()
	return generateTestCertPEMWithValidity(t, cn, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), sans...)
}

func generateTestCertPEMWithValidity(t *testing.T, cn string, notBefore, notAfter time.Time, sans ...string) (string, string) {
	t.Helper()
	hash, _ := security.HashPassword("seed")
	_ = hash
	certPEM, keyPEM, _ := makeTestCertUtil(t, cn, sans, notBefore, notAfter)
	return certPEM, keyPEM
}

// TestStage3UpstreamWeightValidation 源站权重校验。
func TestStage3UpstreamWeightValidation(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "sec_s3_w", "SecS3@Test2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "sec_s3_w", "SecS3@Test2026!")
	resp := env.post(t, "/api/v1/applications", `{"code":"weight-app","name":"权重","protection_mode":"OBSERVE"}`, cookies, csrf)
	var result apiResp
	readJSON(t, resp, &result)
	resp.Body.Close()
	appID, _ := result.Data["id"].(string)

	// 权重超范围
	r1 := env.post(t, fmt.Sprintf("/api/v1/applications/%s/upstreams", appID),
		`{"name":"b1","scheme":"http","host":"192.0.2.1","port":8080,"weight":0}`, cookies, csrf)
	r1.Body.Close()
	if r1.StatusCode != http.StatusBadRequest {
		t.Errorf("weight 0 status = %d, want 400", r1.StatusCode)
	}
	r2 := env.post(t, fmt.Sprintf("/api/v1/applications/%s/upstreams", appID),
		`{"name":"b2","scheme":"http","host":"192.0.2.2","port":8080,"weight":101}`, cookies, csrf)
	r2.Body.Close()
	if r2.StatusCode != http.StatusBadRequest {
		t.Errorf("weight 101 status = %d, want 400", r2.StatusCode)
	}
}

var _ = uuid.Nil
var _ = context.Background
var _ = certificates.Certificate{}
