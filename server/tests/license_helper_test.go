// license_helper_test.go 离线授权集成测试公共辅助：
//
//   - 固定测试 Ed25519 密钥对（确定性种子派生，仅测试进程内使用），经 app 装配层
//     显式依赖注入验签公钥；
//   - 宿主机指纹材料写入测试临时文件，经 LICENSE_HOST_FINGERPRINT_FILE 指向
//     （NewService 装配时解析路径，周期复核按文件内容重读）；
//   - buildTestLicense 复刻签发侧 buildPayload/canonicalJSON 构造样本 .lic 并签名
//     （语义来源：server/internal/license/license_test.go buildPayloadForTest，不得偏离）；
//   - importBaseLicense 供存量套件 setup 调用：登录系统管理员并经
//     POST /api/v1/license/import 导入 wdsp/永久/配额不限的公共测试授权，
//     使存量接口用例在授权门控下保持既有语义。
package tests

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/license"
)

// 测试验签密钥 key_id 与宿主机指纹材料（仅集成测试使用，与任何真实签发密钥无关）。
const (
	testLicenseKeyID    = "it-license-key-20260827"
	testHostFingerprint = "sha256:it-host-fingerprint-20260827"
)

// testLicensePrivKey 由固定 32 字节种子确定性派生的测试签名私钥
// （测试进程每次运行同一密钥，样本授权字节可复现；绝不进入生产路径——
// 生产验签公钥表为 go:embed vendor_pubkey.hex，测试公钥不进入生产路径）。
var testLicensePrivKey = ed25519.NewKeyFromSeed([]byte("jiuzhang-it-license-key-seed-001"))

// configureTestLicense 准备授权测试依赖：返回显式注入应用装配层的验签公钥，
// 并通过环境变量提供测试用宿主机指纹文件路径。
func configureTestLicense(t *testing.T) map[string]ed25519.PublicKey {
	t.Helper()
	fpPath := filepath.Join(t.TempDir(), "host_fingerprint")
	if err := os.WriteFile(fpPath, []byte(testHostFingerprint+"\n"), 0600); err != nil {
		t.Fatalf("write host fingerprint: %v", err)
	}
	pub := testLicensePrivKey.Public().(ed25519.PublicKey)
	t.Setenv(license.HostFingerprintFileEnv, fpPath)
	return map[string]ed25519.PublicKey{testLicenseKeyID: pub}
}

// testLicenseSpec 测试样本授权参数（quotas 三键 0 = 不限制）。
type testLicenseSpec struct {
	LicenseID          string
	LicenseType        string // 缺省 FORMAL
	Product            string // waf / wdsp / api
	Customer           string
	Perpetual          bool
	ExpiresAt          *time.Time // 非永久授权必填（YYYY-MM-DD 口径）
	MachineFingerprint string     // '' = 不绑定机器指纹
	MaxApplications    int64
	MaxAPIEndpoints    int64
	MaxQPS             int64
	Features           []string
}

// buildTestLicense 构造并用测试私钥签发 .lic 文件字节。
// 签名输入 = json.Marshal(payload map)（Go map 键字典序紧凑序列化），
// 与签发侧 canonicalJSON 及产品侧验签重构字节逐字节一致。
func buildTestLicense(t *testing.T, spec testLicenseSpec) []byte {
	t.Helper()
	var expires interface{}
	if !spec.Perpetual && spec.ExpiresAt != nil {
		expires = spec.ExpiresAt.Format("2006-01-02")
	}
	var fingerprint interface{}
	if spec.MachineFingerprint != "" {
		fingerprint = spec.MachineFingerprint
	}
	licenseType := spec.LicenseType
	if licenseType == "" {
		licenseType = license.TypeFormal
	}
	features := spec.Features
	if features == nil {
		features = []string{}
	}
	sort.Strings(features)
	payload := map[string]interface{}{
		"license_id":          spec.LicenseID,
		"license_type":        licenseType,
		"product":             spec.Product,
		"customer":            spec.Customer,
		"issued_at":           time.Now().UTC().Format(time.RFC3339),
		"expires_at":          expires,
		"perpetual":           spec.Perpetual,
		"machine_fingerprint": fingerprint,
		"quotas": map[string]int64{
			"max_applications":  spec.MaxApplications,
			"max_api_endpoints": spec.MaxAPIEndpoints,
			"max_qps":           spec.MaxQPS,
		},
		"features": features,
		"version":  1,
		"key_id":   testLicenseKeyID,
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("canonical payload: %v", err)
	}
	sig := ed25519.Sign(testLicensePrivKey, canonical)
	out, err := json.Marshal(map[string]interface{}{
		"payload":   payload,
		"signature": hex.EncodeToString(sig),
	})
	if err != nil {
		t.Fatalf("marshal lic file: %v", err)
	}
	return out
}

// baseTestLicenseSpec 存量套件公共授权：wdsp 产品（门控不拒绝任何能力域）、
// 永久有效、配额全 0（不限制）、不绑定机器指纹。
func baseTestLicenseSpec() testLicenseSpec {
	return testLicenseSpec{
		LicenseID: "LIC-IT-BASE-0001",
		Product:   "wdsp",
		Customer:  "集成测试公共授权",
		Perpetual: true,
		Features:  []string{"waf", "api"},
	}
}

// importBaseLicense 登录系统管理员并经 API 导入公共测试授权（存量套件 setup 统一调用，
// 使全部业务接口在授权门控下解锁；导入失败即 setup 失败，如实暴露）。
func (e *testEnv) importBaseLicense(t *testing.T) {
	t.Helper()
	cookies, csrf := e.login(t, "test_sysadmin", e.adminPwd)
	resp := e.importLicense(t, buildTestLicense(t, baseTestLicenseSpec()), cookies, csrf)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("import base license: status %d body %s", resp.StatusCode, readBodyString(t, resp))
	}
}

// importLicense POST /api/v1/license/import（JSON {file_content}），返回原始响应由调用方断言。
func (e *testEnv) importLicense(t *testing.T, licBytes []byte, cookies []*http.Cookie, csrf string) *http.Response {
	t.Helper()
	return e.post(t, "/api/v1/license/import",
		fmt.Sprintf(`{"file_content":%q}`, string(licBytes)), cookies, csrf)
}
