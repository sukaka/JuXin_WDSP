// license_test.go 离线授权门控与导入流程接口集成测试（迁移 000078 / license 包）。
//
// 覆盖：
//
//	a. 无授权锁定：登录/健康检查/授权管理白名单可用，业务接口 423（LICENSE_INVALID）；
//	b. 导入 wdsp 授权后业务接口解锁、status.valid=true；
//	c. product=waf 授权（覆盖 wdsp）后 /api/v1/api-security/* 403（LICENSE_FEATURE_DENIED）；
//	d. 配额 max_applications=1 时第二个应用创建 403（LICENSE_QUOTA_EXCEEDED）；
//	e. 已过期授权导入 400、篡改签名 422、机器指纹绑定不匹配 409、绑定本机指纹可导入；
//	f. 重复导入同 license_id 409；新授权导入后旧授权 SUPERSEDED（history 验证）。
//
// 与存量套件差异：本文件用例各自需要"无授权/特定授权"状态，故直接用 newTestEnv
// 构造环境（重建独立测试库、app 装配前注入测试验签公钥与宿主机指纹文件），
// 不调用 importBaseLicense——各用例按需经 API 导入特定授权。
//
// 运行方式（与既有集成测试同一纪律）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestLicense -count=1
package tests

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/license"
)

// licenseStatus GET /api/v1/license/status 并解析响应（200 为前置，失败即 Fatal）。
func licenseStatus(t *testing.T, env *testEnv, cookies []*http.Cookie) apiResp {
	t.Helper()
	resp := env.get(t, "/api/v1/license/status", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("license status = %d, want 200, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var result apiResp
	readJSON(t, resp, &result)
	return result
}

// expectEnvelope 断言响应状态码与信封业务码。
func expectEnvelope(t *testing.T, resp *http.Response, wantStatus int, wantCode, what string) {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s status = %d, want %d, body: %s", what, resp.StatusCode, wantStatus, readBodyString(t, resp))
	}
	var result apiResp
	readJSON(t, resp, &result)
	if result.Code != wantCode {
		t.Fatalf("%s code = %q, want %q（授权业务码词表不得漂移）", what, result.Code, wantCode)
	}
}

// TestLicenseGateLockedWithoutLicense 用例 a：无授权时登录可用、授权状态可查、业务接口 423。
func TestLicenseGateLockedWithoutLicense(t *testing.T) {
	env := newTestEnv(t, baseTestCfg())

	// 白名单：健康检查无需登录即可达
	resp := env.get(t, "/api/v1/health", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want 200（锁定态白名单）", resp.StatusCode)
	}

	// 白名单：登录可用（captcha + login 不经授权门控）
	cookies, _ := env.login(t, "test_sysadmin", env.adminPwd)

	// 白名单：授权状态可查，valid=false 且如实给出原因与本机指纹
	st := licenseStatus(t, env, cookies)
	if valid, _ := st.Data["valid"].(bool); valid {
		t.Fatalf("无授权时 status.valid = %v, want false", st.Data["valid"])
	}
	if st.Data["license_id"] != "" && st.Data["license_id"] != nil {
		t.Fatalf("无授权时 license_id 应为空, got %v", st.Data["license_id"])
	}
	if fp, _ := st.Data["host_fingerprint"].(string); fp != testHostFingerprint {
		t.Fatalf("status.host_fingerprint = %q, want %q（env 指向的测试指纹文件）", fp, testHostFingerprint)
	}

	// 业务接口：已登录仍 423 LICENSE_INVALID（门控在权限校验之前）
	expectEnvelope(t, env.get(t, "/api/v1/applications", cookies),
		http.StatusLocked, license.CodeLicenseInvalid, "locked GET /applications")
	expectEnvelope(t, env.get(t, "/api/v1/users", cookies),
		http.StatusLocked, license.CodeLicenseInvalid, "locked GET /users")

	// 白名单：产品能力探测可达且如实返回锁定态字段
	edition := s5OK(t, env.get(t, "/api/v1/product/edition", cookies), "product edition while locked")
	if lv, _ := edition.Data["license_valid"].(bool); lv {
		t.Fatalf("无授权时 product/edition license_valid = %v, want false", edition.Data["license_valid"])
	}
	if ed, _ := edition.Data["edition"].(string); ed != "" {
		t.Fatalf("无授权时 product/edition edition = %q, want 空", ed)
	}
}

// TestLicenseImportUnlocksBusinessAPIs 用例 b：导入 wdsp 授权后业务接口解锁、status.valid=true。
func TestLicenseImportUnlocksBusinessAPIs(t *testing.T) {
	env := newTestEnv(t, baseTestCfg())
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	// 导入前：业务接口 423
	expectEnvelope(t, env.get(t, "/api/v1/users", cookies),
		http.StatusLocked, license.CodeLicenseInvalid, "before import GET /users")

	// 导入 wdsp 永久授权（配额全 0 不限制）：响应即最新状态快照
	importResp := s5OK(t, env.importLicense(t, buildTestLicense(t, baseTestLicenseSpec()), cookies, csrf),
		"import wdsp license")
	if valid, _ := importResp.Data["valid"].(bool); !valid {
		t.Fatalf("导入成功后响应 valid = %v, want true", importResp.Data["valid"])
	}
	if p, _ := importResp.Data["product"].(string); p != "wdsp" {
		t.Fatalf("导入成功后响应 product = %q, want wdsp", p)
	}

	// status.valid=true，license_id/customer 与样本一致
	st := licenseStatus(t, env, cookies)
	if valid, _ := st.Data["valid"].(bool); !valid {
		t.Fatalf("导入后 status.valid = %v, want true", st.Data["valid"])
	}
	if id, _ := st.Data["license_id"].(string); id != "LIC-IT-BASE-0001" {
		t.Fatalf("导入后 status.license_id = %q, want LIC-IT-BASE-0001", id)
	}

	// 业务接口解锁（系统管理员域接口 200；应用列表需安全管理员身份验证非 423）
	s5OK(t, env.get(t, "/api/v1/users", cookies), "after import GET /users")
	secCookies, _ := env.s5Login(t, "licsec", "SECURITY_ADMIN")
	s5OK(t, env.get(t, "/api/v1/applications", secCookies), "after import GET /applications")
}

// TestLicenseProductWAFDeniesAPISecurity 用例 c：product=waf 授权覆盖 wdsp 后，
// /api/v1/api-security/* 403 LICENSE_FEATURE_DENIED（WDSP 装配下路由已注册，门控实时判定）。
func TestLicenseProductWAFDeniesAPISecurity(t *testing.T) {
	env := newTestEnv(t, stage8TestCfg(t))
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	// 先导入 wdsp 授权：api-security 端点列表解锁（000100 后 api_asset.read 归 SECURITY_ADMIN）
	s5OK(t, env.importLicense(t, buildTestLicense(t, baseTestLicenseSpec()), cookies, csrf),
		"import wdsp license")
	secCookies, _ := env.s5Login(t, "licwafsec", "SECURITY_ADMIN")
	s5OK(t, env.get(t, "/api/v1/api-security/endpoints", secCookies), "wdsp GET api-security/endpoints")

	// 导入 product=waf 授权（新 license_id，旧授权被取代）：API 动态防护能力域实时关闭
	wafSpec := baseTestLicenseSpec()
	wafSpec.LicenseID = "LIC-IT-WAF-0001"
	wafSpec.Product = "waf"
	importResp := s5OK(t, env.importLicense(t, buildTestLicense(t, wafSpec), cookies, csrf),
		"import waf license")
	if p, _ := importResp.Data["product"].(string); p != "waf" {
		t.Fatalf("waf 授权导入后 product = %q, want waf", p)
	}
	expectEnvelope(t, env.get(t, "/api/v1/api-security/endpoints", secCookies),
		http.StatusForbidden, license.CodeLicenseFeatureDenied, "waf GET api-security/endpoints")

	// Web 防护域不受影响（waf 授权仍解锁管理面业务接口）
	s5OK(t, env.get(t, "/api/v1/users", cookies), "waf GET /users")
}

// TestLicenseApplicationQuotaExceeded 用例 d：配额 max_applications=1 时
// 第一个应用创建成功，第二个 403 LICENSE_QUOTA_EXCEEDED。
func TestLicenseApplicationQuotaExceeded(t *testing.T) {
	env := newTestEnv(t, baseTestCfg())
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	quotaSpec := baseTestLicenseSpec()
	quotaSpec.LicenseID = "LIC-IT-QUOTA-0001"
	quotaSpec.MaxApplications = 1
	s5OK(t, env.importLicense(t, buildTestLicense(t, quotaSpec), cookies, csrf),
		"import quota=1 license")

	// 应用创建走安全管理员（三权边界：系统管理员创建应用 403）
	secCookies, secCsrf := env.s5Login(t, "licquota", "SECURITY_ADMIN")
	s5OK(t, env.post(t, "/api/v1/applications",
		`{"code":"quota-app-1","name":"配额应用一","protection_mode":"OBSERVE"}`, secCookies, secCsrf),
		"create first app within quota")
	expectEnvelope(t, env.post(t, "/api/v1/applications",
		`{"code":"quota-app-2","name":"配额应用二","protection_mode":"OBSERVE"}`, secCookies, secCsrf),
		http.StatusForbidden, license.CodeLicenseQuotaExceeded, "create second app over quota")
}

// TestLicenseImportRejections 用例 e：已过期 400、篡改签名 422、指纹绑定不匹配 409；
// 附正向用例——绑定本机指纹的授权可正常导入（测试指纹文件由 configureTestLicense 写入）。
func TestLicenseImportRejections(t *testing.T) {
	env := newTestEnv(t, baseTestCfg())
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	// 已到期授权（expires_at 昨天）：400 INVALID_ARGUMENT（拒绝导入即锁定）
	yesterday := time.Now().UTC().AddDate(0, 0, -1)
	expiredSpec := baseTestLicenseSpec()
	expiredSpec.LicenseID = "LIC-IT-EXPIRED-0001"
	expiredSpec.Perpetual = false
	expiredSpec.ExpiresAt = &yesterday
	expectEnvelope(t, env.importLicense(t, buildTestLicense(t, expiredSpec), cookies, csrf),
		http.StatusBadRequest, "INVALID_ARGUMENT", "import expired license")

	// 篡改签名：payload 改 customer 后不重签，422 LICENSE_INVALID（验签 fail-closed）
	tamperedSpec := baseTestLicenseSpec()
	tamperedSpec.LicenseID = "LIC-IT-TAMPER-0001"
	licBytes := buildTestLicense(t, tamperedSpec)
	var file struct {
		Payload   json.RawMessage `json:"payload"`
		Signature string          `json:"signature"`
	}
	if err := json.Unmarshal(licBytes, &file); err != nil {
		t.Fatalf("unmarshal lic: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(file.Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	payload["customer"] = "被篡改的客户"
	tamperedPayload, _ := json.Marshal(payload)
	tampered, _ := json.Marshal(map[string]interface{}{
		"payload":   json.RawMessage(tamperedPayload),
		"signature": file.Signature,
	})
	expectEnvelope(t, env.importLicense(t, tampered, cookies, csrf),
		http.StatusUnprocessableEntity, license.CodeLicenseInvalid, "import tampered license")

	// 机器指纹绑定不匹配（授权绑定其他指纹，本机为 testHostFingerprint）：409 LICENSE_INVALID
	mismatchSpec := baseTestLicenseSpec()
	mismatchSpec.LicenseID = "LIC-IT-FPMISMATCH-0001"
	mismatchSpec.MachineFingerprint = "sha256:another-host-fingerprint"
	expectEnvelope(t, env.importLicense(t, buildTestLicense(t, mismatchSpec), cookies, csrf),
		http.StatusConflict, license.CodeLicenseInvalid, "import fingerprint mismatch license")

	// 全部被拒后仍处于无授权锁定态（失败导入不得改变生效状态）
	st := licenseStatus(t, env, cookies)
	if valid, _ := st.Data["valid"].(bool); valid {
		t.Fatalf("拒绝用例全部失败后 status.valid = %v, want false", st.Data["valid"])
	}

	// 正向：绑定本机指纹的授权导入成功（指纹精确一致，ConstantTimeCompare 口径）
	boundSpec := baseTestLicenseSpec()
	boundSpec.LicenseID = "LIC-IT-FPBOUND-0001"
	boundSpec.MachineFingerprint = testHostFingerprint
	s5OK(t, env.importLicense(t, buildTestLicense(t, boundSpec), cookies, csrf),
		"import host-bound license")
}

// TestLicenseDuplicateImportAndSupersede 用例 f：重复导入同 license_id 409；
// 导入新授权后旧授权 SUPERSEDED（GET /api/v1/license/history 验证状态）。
func TestLicenseDuplicateImportAndSupersede(t *testing.T) {
	env := newTestEnv(t, baseTestCfg())
	cookies, csrf := env.login(t, "test_sysadmin", env.adminPwd)

	specA := baseTestLicenseSpec()
	specA.LicenseID = "LIC-IT-DUP-A001"
	licA := buildTestLicense(t, specA)
	s5OK(t, env.importLicense(t, licA, cookies, csrf), "import license A")

	// 重复导入同 license_id（A 仍 ACTIVE）：409 RESOURCE_CONFLICT
	expectEnvelope(t, env.importLicense(t, licA, cookies, csrf),
		http.StatusConflict, "RESOURCE_CONFLICT", "re-import active license A")

	// 导入新授权 B：A 被取代（SUPERSEDED），B 生效
	specB := baseTestLicenseSpec()
	specB.LicenseID = "LIC-IT-DUP-B001"
	importB := s5OK(t, env.importLicense(t, buildTestLicense(t, specB), cookies, csrf), "import license B")
	if id, _ := importB.Data["license_id"].(string); id != "LIC-IT-DUP-B001" {
		t.Fatalf("导入 B 后生效 license_id = %q, want LIC-IT-DUP-B001", id)
	}

	// 重复导入同 license_id（A 已 SUPERSEDED）：唯一约束覆盖全部历史行，仍 409
	expectEnvelope(t, env.importLicense(t, licA, cookies, csrf),
		http.StatusConflict, "RESOURCE_CONFLICT", "re-import superseded license A")

	// 导入历史：B ACTIVE、A SUPERSEDED（按 imported_at 倒序，B 在前）
	resp := env.get(t, "/api/v1/license/history", cookies)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("license history status = %d, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var page apiResp
	readJSON(t, resp, &page)
	items, _ := page.Data["items"].([]interface{})
	if len(items) != 2 {
		t.Fatalf("history items = %d, want 2: %v", len(items), page.Data["items"])
	}
	statusByID := map[string]string{}
	for _, it := range items {
		m, _ := it.(map[string]interface{})
		id, _ := m["license_id"].(string)
		status, _ := m["status"].(string)
		statusByID[id] = status
		// 历史列表不得带出敏感原文
		if _, ok := m["payload"]; ok {
			t.Fatalf("history 不得返回 payload 敏感原文: %v", m)
		}
		if _, ok := m["signature"]; ok {
			t.Fatalf("history 不得返回 signature 敏感原文: %v", m)
		}
	}
	if statusByID["LIC-IT-DUP-A001"] != license.StatusSuperseded {
		t.Fatalf("A status = %q, want SUPERSEDED", statusByID["LIC-IT-DUP-A001"])
	}
	if statusByID["LIC-IT-DUP-B001"] != license.StatusActive {
		t.Fatalf("B status = %q, want ACTIVE", statusByID["LIC-IT-DUP-B001"])
	}
}
